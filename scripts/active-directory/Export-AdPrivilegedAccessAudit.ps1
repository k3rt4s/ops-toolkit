<#
.SYNOPSIS
Audit Active Directory for the privilege and delegation misconfigurations that still lead to domain compromise.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads directory objects and writes reports. It changes nothing, so
  it has no -WhatIf.
- Requires the ActiveDirectory module (RSAT) and read access to the domain. Domain
  User is normally enough; a few attributes need higher rights and are reported as
  not read rather than guessed.
- Run it against one domain at a time with -Server. In a multi-domain forest, run it
  once per domain, because privileged groups exist per domain and Enterprise Admins
  and Schema Admins live only in the forest root.
- Findings are ordered by severity. Confirm each one against the account's purpose
  before changing anything, because a few are legitimate by design.
- Generated reports are written under reports\active-directory by default.

Purpose:
Use this to see the standing attack paths in a domain in one pass: AS-REP roastable
accounts, Kerberoastable service accounts, unconstrained and constrained delegation,
accounts that do not require a password, reversible encryption, orphaned adminCount
objects left behind by adminSDHolder, krbtgt password age, and who is actually in
the tier-0 groups once nesting is expanded. These are read-only observations, not
changes, and the report is meant to be reviewed with someone who knows what each
service account is for.

Tier-0 groups are resolved by well-known SID rather than by name, so the audit works
on a non-English domain and cannot be defeated by a renamed group.

Group Managed Service Accounts are identified and excluded from the Kerberoastable
finding. Their passwords are 240 characters, rotated by the domain, and are not
crackable offline, so reporting them is noise that buries the real findings.

Required syntax:
pwsh -File .\scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1
pwsh -File .\scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1 -Server dc01.example.com
pwsh -File .\scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1 -SearchBase "OU=Servers,DC=example,DC=com" -StalePasswordDays 365

.OUTPUTS
Writes findings, a per-finding-type rollup, tier-0 group membership, and a run
summary as CSV and JSON under reports\active-directory by default. Returns a summary
object with output paths and counts by severity.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StalePasswordDays = 180,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$KrbtgtWarningDays = 180,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleLogonDays = 90,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'ad-privileged-access-audit'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# userAccountControl bits this audit cares about.
$script:UacFlag = @{
    AccountDisabled = 0x0002
    PasswordNotRequired = 0x0020
    TrustedForDelegation = 0x80000
    NotDelegated = 0x100000
    DoesNotRequirePreAuth = 0x400000
    TrustedToAuthForDelegation = 0x1000000
    ReversibleEncryption = 0x0080
}

# Tier-0 groups by well-known RID or absolute SID. Names are localized and can be
# renamed; SIDs cannot. Forest-root-only groups are marked so a child-domain run
# does not report them as missing.
$script:Tier0Group = @(
    [pscustomobject]@{ Key = 'DomainAdmins'; Rid = 512; ForestRootOnly = $false; Label = 'Domain Admins' }
    [pscustomobject]@{ Key = 'EnterpriseAdmins'; Rid = 519; ForestRootOnly = $true; Label = 'Enterprise Admins' }
    [pscustomobject]@{ Key = 'SchemaAdmins'; Rid = 518; ForestRootOnly = $true; Label = 'Schema Admins' }
    [pscustomobject]@{ Key = 'GroupPolicyCreatorOwners'; Rid = 520; ForestRootOnly = $false; Label = 'Group Policy Creator Owners' }
    [pscustomobject]@{ Key = 'KeyAdmins'; Rid = 526; ForestRootOnly = $false; Label = 'Key Admins' }
    [pscustomobject]@{ Key = 'EnterpriseKeyAdmins'; Rid = 527; ForestRootOnly = $true; Label = 'Enterprise Key Admins' }
    [pscustomobject]@{ Key = 'CertPublishers'; Rid = 517; ForestRootOnly = $false; Label = 'Cert Publishers' }
    [pscustomobject]@{ Key = 'Administrators'; Sid = 'S-1-5-32-544'; ForestRootOnly = $false; Label = 'Administrators (builtin)' }
    [pscustomobject]@{ Key = 'AccountOperators'; Sid = 'S-1-5-32-548'; ForestRootOnly = $false; Label = 'Account Operators' }
    [pscustomobject]@{ Key = 'ServerOperators'; Sid = 'S-1-5-32-549'; ForestRootOnly = $false; Label = 'Server Operators' }
    [pscustomobject]@{ Key = 'PrintOperators'; Sid = 'S-1-5-32-550'; ForestRootOnly = $false; Label = 'Print Operators' }
    [pscustomobject]@{ Key = 'BackupOperators'; Sid = 'S-1-5-32-551'; ForestRootOnly = $false; Label = 'Backup Operators' }
    [pscustomobject]@{ Key = 'Replicator'; Sid = 'S-1-5-32-552'; ForestRootOnly = $false; Label = 'Replicator' }
)

function Test-UacFlag {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$UserAccountControl,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FlagName
    )

    if ($null -eq $UserAccountControl) {
        return $false
    }

    $flag = $script:UacFlag[$FlagName]
    if (-not $flag) {
        throw "Unknown userAccountControl flag: $FlagName"
    }

    ([int]$UserAccountControl -band $flag) -eq $flag
}

function Test-ManagedServiceAccount {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$AdObject
    )

    # Get-ADUser returns ObjectClass as the single most specific class; a raw
    # directory entry returns the whole class chain as an array. Property lookup is
    # case-insensitive, so one read covers both ObjectClass and objectClass.
    $objectClass = Get-OpsPropertyValue -InputObject $AdObject -Name 'ObjectClass'
    foreach ($entry in @($objectClass)) {
        if ([string]$entry -match '(?i)^(msDS-)?(Group)?ManagedServiceAccount$') {
            return $true
        }
    }

    $false
}

function Get-FindingRecord {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FindingId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$AdObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Detail,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Evidence = '',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Recommendation,

        # Named for the AD attribute rather than "PasswordAge..." so the analyzer does
        # not read it as a plaintext password parameter.
        [Parameter()]
        [AllowNull()]
        [object]$PwdLastSetAgeDays,

        [Parameter()]
        [AllowNull()]
        [object]$LastLogonDays,

        [Parameter()]
        [bool]$IsTier0 = $false
    )

    [pscustomobject]@{
        FindingId = $FindingId
        Severity = $Severity
        Category = $Category
        SamAccountName = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'SamAccountName')
        Name = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'Name')
        ObjectClass = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'ObjectClass')
        Enabled = Get-OpsPropertyValue -InputObject $AdObject -Name 'Enabled'
        IsTier0 = $IsTier0
        DistinguishedName = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'DistinguishedName')
        Detail = $Detail
        Evidence = $Evidence
        PasswordAgeDays = $PwdLastSetAgeDays
        LastLogonDays = $LastLogonDays
        Recommendation = $Recommendation
    }
}

$adParameter = @{}
if ($Server) {
    $adParameter['Server'] = $Server
}
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
    $adParameter['Credential'] = $Credential
}

$searchParameter = $adParameter.Clone()
if ($SearchBase) {
    $searchParameter['SearchBase'] = $SearchBase
}

$domain = Get-ADDomain @adParameter
$forest = Get-ADForest @adParameter
$domainSid = [string]$domain.DomainSID
$isForestRoot = $domain.DNSRoot -eq $forest.RootDomain
$asOfUtc = (Get-Date).ToUniversalTime()

$resolvedOutputDirectory = Resolve-OpsOutputDirectory -Path $OutputDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDirectory = Join-Path $resolvedOutputDirectory "$OutputPrefix-$timestamp"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

Write-Verbose "Auditing $($domain.DNSRoot). Forest root: $($forest.RootDomain)."

# Resolve tier-0 groups and expand nesting once, up front. Everything else asks
# "is this principal tier-0" against this set.
$tier0Members = [System.Collections.Generic.List[object]]::new()
$tier0Sids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$groupInventory = [System.Collections.Generic.List[object]]::new()

foreach ($groupSpec in $script:Tier0Group) {
    if ($groupSpec.ForestRootOnly -and -not $isForestRoot) {
        continue
    }

    $sid = if ($groupSpec.PSObject.Properties['Sid'] -and $groupSpec.Sid) { $groupSpec.Sid } else { "$domainSid-$($groupSpec.Rid)" }

    $group = $null
    try {
        $group = Get-ADGroup -Identity $sid -Properties Members, DistinguishedName @adParameter
    } catch {
        Write-Warning "Tier-0 group $($groupSpec.Label) ($sid) could not be read: $($_.Exception.Message)"
        $groupInventory.Add([pscustomobject]@{
                GroupKey = $groupSpec.Key
                GroupLabel = $groupSpec.Label
                Sid = $sid
                Resolved = $false
                MemberCount = 0
                Note = $_.Exception.Message
            })
        continue
    }

    # LDAP_MATCHING_RULE_IN_CHAIN expands nested membership in one query, which is
    # both faster and more complete than walking Get-ADGroupMember recursively.
    $members = @()
    try {
        $members = @(Get-ADObject -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($group.DistinguishedName))" -Properties SamAccountName, Name, ObjectClass, userAccountControl, pwdLastSet, lastLogonTimestamp, adminCount @searchParameter)
    } catch {
        Write-Warning "Nested membership for $($groupSpec.Label) could not be expanded: $($_.Exception.Message)"
    }

    foreach ($member in $members) {
        $memberSid = [string](Get-OpsPropertyValue -InputObject $member -Name 'objectSid')
        if ($memberSid) {
            $tier0Sids.Add($memberSid) | Out-Null
        }

        $dn = [string](Get-OpsPropertyValue -InputObject $member -Name 'DistinguishedName')
        if ($dn) {
            $tier0Sids.Add($dn) | Out-Null
        }

        $uac = Get-OpsPropertyValue -InputObject $member -Name 'userAccountControl'
        $tier0Members.Add([pscustomobject]@{
                GroupKey = $groupSpec.Key
                GroupLabel = $groupSpec.Label
                SamAccountName = [string](Get-OpsPropertyValue -InputObject $member -Name 'SamAccountName')
                Name = [string](Get-OpsPropertyValue -InputObject $member -Name 'Name')
                ObjectClass = [string](Get-OpsPropertyValue -InputObject $member -Name 'ObjectClass')
                DistinguishedName = $dn
                Enabled = if ($null -eq $uac) { $null } else { -not (Test-UacFlag -UserAccountControl $uac -FlagName 'AccountDisabled') }
                PasswordAgeDays = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $member -Name 'pwdLastSet') -AsOf $asOfUtc
                LastLogonDays = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $member -Name 'lastLogonTimestamp') -AsOf $asOfUtc
            })
    }

    $groupInventory.Add([pscustomobject]@{
            GroupKey = $groupSpec.Key
            GroupLabel = $groupSpec.Label
            Sid = $sid
            Resolved = $true
            MemberCount = @($members).Count
            Note = ''
        })
}

function Test-Tier0Object {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$AdObject
    )

    $dn = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'DistinguishedName')
    if ($dn -and $tier0Sids.Contains($dn)) {
        return $true
    }

    $sid = [string](Get-OpsPropertyValue -InputObject $AdObject -Name 'SID')
    if ($sid -and $tier0Sids.Contains($sid)) {
        return $true
    }

    $false
}

$findings = [System.Collections.Generic.List[object]]::new()
$userProperties = @('SamAccountName', 'Name', 'Enabled', 'DistinguishedName', 'userAccountControl', 'servicePrincipalName', 'pwdLastSet', 'lastLogonTimestamp', 'adminCount', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'SID', 'objectClass')

Write-Verbose 'Reading user and service accounts.'
$users = @(Get-ADUser -Filter * -Properties $userProperties @searchParameter)

Write-Verbose 'Reading computer accounts.'
$computerProperties = @('SamAccountName', 'Name', 'Enabled', 'DistinguishedName', 'userAccountControl', 'servicePrincipalName', 'pwdLastSet', 'lastLogonTimestamp', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'SID', 'PrimaryGroupID', 'objectClass')
$computers = @(Get-ADComputer -Filter * -Properties $computerProperties @searchParameter)

foreach ($user in $users) {
    $uac = Get-OpsPropertyValue -InputObject $user -Name 'userAccountControl'
    $enabled = Get-OpsPropertyValue -InputObject $user -Name 'Enabled'
    $isTier0 = Test-Tier0Object -AdObject $user
    $passwordAge = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $user -Name 'pwdLastSet') -AsOf $asOfUtc
    $logonAge = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $user -Name 'lastLogonTimestamp') -AsOf $asOfUtc
    $isManaged = Test-ManagedServiceAccount -AdObject $user
    $common = @{ AdObject = $user; PwdLastSetAgeDays = $passwordAge; LastLogonDays = $logonAge; IsTier0 = $isTier0 }

    if (Test-UacFlag -UserAccountControl $uac -FlagName 'DoesNotRequirePreAuth') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-ASREP-001' -Category 'Kerberos' `
                    -Severity $(if ($isTier0) { 'Critical' } else { 'High' }) `
                    -Detail 'Kerberos pre-authentication is disabled, so any unauthenticated attacker can request an AS-REP encrypted with this account password hash and crack it offline.' `
                    -Evidence "userAccountControl=$uac (DONT_REQ_PREAUTH)" `
                    -Recommendation 'Re-enable pre-authentication unless a documented legacy dependency requires it. If it must stay, give the account a long random password and keep it out of every privileged group.'))
    }

    $spns = @(Get-OpsPropertyValue -InputObject $user -Name 'servicePrincipalName' | Where-Object { $_ })
    if ($spns.Count -gt 0 -and -not $isManaged) {
        $severity = if ($isTier0) {
            'Critical'
        } elseif ($null -ne $passwordAge -and $passwordAge -gt $StalePasswordDays) {
            'High'
        } else {
            'Medium'
        }

        $findings.Add((Get-FindingRecord @common -FindingId 'AD-KRBRST-001' -Category 'Kerberos' -Severity $severity `
                    -Detail 'User account carries a service principal name, so any domain user can request a service ticket for it and crack the password offline.' `
                    -Evidence "servicePrincipalName=$($spns -join ';')" `
                    -Recommendation 'Move the service to a Group Managed Service Account, or give the account a 25-plus character random password and rotate it. A gMSA removes the finding outright.'))
    }

    if (Test-UacFlag -UserAccountControl $uac -FlagName 'TrustedForDelegation') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-001' -Category 'Delegation' -Severity 'Critical' `
                    -Detail 'Account is trusted for unconstrained delegation, so it caches the TGT of every user that authenticates to it. Compromising it yields those tickets.' `
                    -Evidence "userAccountControl=$uac (TRUSTED_FOR_DELEGATION)" `
                    -Recommendation 'Replace with constrained delegation or resource-based constrained delegation. Add sensitive accounts to Protected Users and mark them as not delegated.'))
    }

    if (Test-UacFlag -UserAccountControl $uac -FlagName 'TrustedToAuthForDelegation') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-002' -Category 'Delegation' -Severity 'High' `
                    -Detail 'Account is configured for protocol transition, so it can obtain a service ticket for any user without that user ever authenticating.' `
                    -Evidence "userAccountControl=$uac (TRUSTED_TO_AUTH_FOR_DELEGATION)" `
                    -Recommendation 'Use Kerberos-only constrained delegation where possible, and scope msDS-AllowedToDelegateTo as tightly as the application allows.'))
    }

    $allowedToDelegate = @(Get-OpsPropertyValue -InputObject $user -Name 'msDS-AllowedToDelegateTo' | Where-Object { $_ })
    if ($allowedToDelegate.Count -gt 0) {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-003' -Category 'Delegation' -Severity 'Medium' `
                    -Detail 'Account has constrained delegation configured to specific services.' `
                    -Evidence "msDS-AllowedToDelegateTo=$($allowedToDelegate -join ';')" `
                    -Recommendation 'Confirm every target service is still required and that none of them are tier-0.'))
    }

    if (Get-OpsPropertyValue -InputObject $user -Name 'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-004' -Category 'Delegation' -Severity 'Medium' `
                    -Detail 'Resource-based constrained delegation is configured on this account, meaning some other principal may impersonate users to it.' `
                    -Evidence 'msDS-AllowedToActOnBehalfOfOtherIdentity is set' `
                    -Recommendation 'Read the security descriptor and confirm the principal allowed to act on its behalf is the one you expect. This attribute is writable by anyone holding write rights on the object.'))
    }

    if ($enabled -and (Test-UacFlag -UserAccountControl $uac -FlagName 'PasswordNotRequired')) {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-PWD-001' -Category 'Password policy' `
                    -Severity $(if ($isTier0) { 'Critical' } else { 'High' }) `
                    -Detail 'Enabled account is flagged as not requiring a password, so it may have an empty password regardless of domain policy.' `
                    -Evidence "userAccountControl=$uac (PASSWD_NOTREQD)" `
                    -Recommendation 'Clear the flag and set a password, or disable the account if it is unused.'))
    }

    if ($enabled -and (Test-UacFlag -UserAccountControl $uac -FlagName 'ReversibleEncryption')) {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-PWD-002' -Category 'Password policy' -Severity 'High' `
                    -Detail 'Password is stored with reversible encryption, which is effectively plaintext to anyone who can read the directory database.' `
                    -Evidence "userAccountControl=$uac (ENCRYPTED_TEXT_PWD_ALLOWED)" `
                    -Recommendation 'Clear the flag and force a password change. Reversible encryption is only needed by a small number of legacy protocols.'))
    }

    $adminCount = Get-OpsPropertyValue -InputObject $user -Name 'adminCount'
    if ($adminCount -eq 1 -and -not $isTier0) {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-ADMCNT-001' -Category 'Privilege residue' -Severity 'Medium' `
                    -Detail 'adminCount is 1 but the account is no longer in any tier-0 group. It keeps the adminSDHolder ACL, so normal delegated administration silently does not apply to it.' `
                    -Evidence 'adminCount=1 with no current tier-0 membership' `
                    -Recommendation 'Confirm the account should no longer be privileged, then clear adminCount and re-enable inheritance on the object.'))
    }
}

foreach ($computer in $computers) {
    $uac = Get-OpsPropertyValue -InputObject $computer -Name 'userAccountControl'
    $isTier0 = Test-Tier0Object -AdObject $computer
    $isDomainController = (Get-OpsPropertyValue -InputObject $computer -Name 'PrimaryGroupID') -in @(516, 521)
    $common = @{
        AdObject = $computer
        PwdLastSetAgeDays = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $computer -Name 'pwdLastSet') -AsOf $asOfUtc
        LastLogonDays = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $computer -Name 'lastLogonTimestamp') -AsOf $asOfUtc
        IsTier0 = $isTier0
    }

    if (Test-UacFlag -UserAccountControl $uac -FlagName 'TrustedForDelegation') {
        # Domain controllers are unconstrained by design. Reporting them as Critical
        # buries the one member server that should not be.
        if ($isDomainController) {
            $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-005' -Category 'Delegation' -Severity 'Informational' `
                        -Detail 'Domain controller is trusted for unconstrained delegation, which is expected and not a finding on its own.' `
                        -Evidence "userAccountControl=$uac (TRUSTED_FOR_DELEGATION, domain controller)" `
                        -Recommendation 'No action. Listed so the unconstrained delegation inventory is complete.'))
        } else {
            $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-001' -Category 'Delegation' -Severity 'Critical' `
                        -Detail 'Member server is trusted for unconstrained delegation, so it caches the TGT of every user and computer that authenticates to it, including domain admins.' `
                        -Evidence "userAccountControl=$uac (TRUSTED_FOR_DELEGATION)" `
                        -Recommendation 'Replace with constrained or resource-based constrained delegation. Treat this host as tier-0 until it is fixed.'))
        }
    }

    if (Test-UacFlag -UserAccountControl $uac -FlagName 'TrustedToAuthForDelegation') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-002' -Category 'Delegation' -Severity 'High' `
                    -Detail 'Computer is configured for protocol transition and can obtain service tickets for arbitrary users.' `
                    -Evidence "userAccountControl=$uac (TRUSTED_TO_AUTH_FOR_DELEGATION)" `
                    -Recommendation 'Restrict to Kerberos-only constrained delegation where the application supports it.'))
    }

    $allowedToDelegate = @(Get-OpsPropertyValue -InputObject $computer -Name 'msDS-AllowedToDelegateTo' | Where-Object { $_ })
    if ($allowedToDelegate.Count -gt 0) {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-003' -Category 'Delegation' -Severity 'Medium' `
                    -Detail 'Computer has constrained delegation configured to specific services.' `
                    -Evidence "msDS-AllowedToDelegateTo=$($allowedToDelegate -join ';')" `
                    -Recommendation 'Confirm every target service is still required and that none of them are tier-0.'))
    }

    if (Get-OpsPropertyValue -InputObject $computer -Name 'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        $findings.Add((Get-FindingRecord @common -FindingId 'AD-DELEG-004' -Category 'Delegation' -Severity 'Medium' `
                    -Detail 'Resource-based constrained delegation is configured on this computer.' `
                    -Evidence 'msDS-AllowedToActOnBehalfOfOtherIdentity is set' `
                    -Recommendation 'Read the security descriptor and confirm the principal allowed to act on its behalf is expected. Anyone who can write this attribute can take over the host.'))
    }
}

Write-Verbose 'Checking krbtgt password age.'
try {
    $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties SamAccountName, Name, Enabled, DistinguishedName, pwdLastSet, SID, objectClass @adParameter
    $krbtgtAge = Get-OpsAge -Timestamp $krbtgt.pwdLastSet -AsOf $asOfUtc
    if ($null -ne $krbtgtAge -and $krbtgtAge -gt $KrbtgtWarningDays) {
        $findings.Add((Get-FindingRecord -AdObject $krbtgt -FindingId 'AD-KRBTGT-001' -Category 'Kerberos' `
                    -Severity $(if ($krbtgtAge -gt ($KrbtgtWarningDays * 2)) { 'High' } else { 'Medium' }) `
                    -Detail "The krbtgt password is $krbtgtAge days old. Any golden ticket forged before the last reset stays valid until the password has been reset twice." `
                    -Evidence "pwdLastSet age = $krbtgtAge days" `
                    -PwdLastSetAgeDays $krbtgtAge -LastLogonDays $null -IsTier0 $true `
                    -Recommendation 'Reset the krbtgt password twice, waiting at least one full replication cycle plus the maximum ticket lifetime between resets. Never reset it twice in quick succession.'))
    }
} catch {
    Write-Warning "krbtgt could not be read: $($_.Exception.Message)"
}

foreach ($member in $tier0Members) {
    if ($member.Enabled -eq $false) {
        $findings.Add([pscustomobject]@{
                FindingId = 'AD-TIER0-001'
                Severity = 'Medium'
                Category = 'Privileged access'
                SamAccountName = $member.SamAccountName
                Name = $member.Name
                ObjectClass = $member.ObjectClass
                Enabled = $false
                IsTier0 = $true
                DistinguishedName = $member.DistinguishedName
                Detail = "Disabled account is still a member of $($member.GroupLabel). A disabled tier-0 account is a re-enable away from full privilege and is rarely monitored."
                Evidence = "Group: $($member.GroupLabel)"
                PasswordAgeDays = $member.PasswordAgeDays
                LastLogonDays = $member.LastLogonDays
                Recommendation = 'Remove the account from the privileged group. Disabling is not removal.'
            })
        continue
    }

    if ($null -ne $member.LastLogonDays -and $member.LastLogonDays -gt $StaleLogonDays) {
        $findings.Add([pscustomobject]@{
                FindingId = 'AD-TIER0-002'
                Severity = 'Medium'
                Category = 'Privileged access'
                SamAccountName = $member.SamAccountName
                Name = $member.Name
                ObjectClass = $member.ObjectClass
                Enabled = $member.Enabled
                IsTier0 = $true
                DistinguishedName = $member.DistinguishedName
                Detail = "Enabled member of $($member.GroupLabel) has not logged on for $($member.LastLogonDays) days."
                Evidence = "Group: $($member.GroupLabel), lastLogonTimestamp age = $($member.LastLogonDays) days"
                PasswordAgeDays = $member.PasswordAgeDays
                LastLogonDays = $member.LastLogonDays
                Recommendation = 'Confirm the account is still needed at this privilege level. Unused privileged accounts are the cheapest thing to remove and the most valuable to an attacker.'
            })
    }
}

$allFindings = @($findings) | Sort-Object -Property @{ Expression = { Get-OpsSeverityRank -Severity $_.Severity } }, FindingId, SamAccountName

$findingRollup = foreach ($group in (@($allFindings) | Group-Object -Property FindingId)) {
    $first = $group.Group[0]
    [pscustomobject]@{
        FindingId = $group.Name
        Severity = $first.Severity
        Category = $first.Category
        Count = $group.Count
        Tier0Count = @($group.Group | Where-Object { $_.IsTier0 }).Count
        EnabledCount = @($group.Group | Where-Object { $_.Enabled -eq $true }).Count
        Recommendation = $first.Recommendation
    }
}

$exports = @(
    Export-OpsReport -Name 'findings' -Record $allFindings -Directory $runDirectory
    Export-OpsReport -Name 'finding-rollup' -Record @($findingRollup) -Directory $runDirectory
    Export-OpsReport -Name 'tier0-membership' -Record @($tier0Members) -Directory $runDirectory
    Export-OpsReport -Name 'tier0-groups' -Record @($groupInventory) -Directory $runDirectory
)

$summaryPath = Join-Path $runDirectory 'summary.json'
$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    Domain = $domain.DNSRoot
    DomainSid = $domainSid
    ForestRoot = $forest.RootDomain
    IsForestRoot = $isForestRoot
    SearchBase = $SearchBase
    Server = $Server
    OutputDirectory = (Resolve-Path -LiteralPath $runDirectory).Path
    UsersRead = @($users).Count
    ComputersRead = @($computers).Count
    Tier0GroupsResolved = @($groupInventory | Where-Object { $_.Resolved }).Count
    Tier0MemberCount = @($tier0Members).Count
    FindingCount = @($allFindings).Count
    CriticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    HighCount = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    MediumCount = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    LowCount = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    InformationalCount = @($allFindings | Where-Object { $_.Severity -eq 'Informational' }).Count
    Exports = @($exports)
}

Set-Content -LiteralPath $summaryPath -Value ($summary | ConvertTo-Json -Depth 8) -Encoding utf8
$summary | Add-Member -NotePropertyName SummaryPath -NotePropertyValue (Resolve-Path -LiteralPath $summaryPath).Path -Force
$summary
