<#
.SYNOPSIS
Report Active Directory permissions that let a non-privileged principal take over a privileged object or replicate the directory.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads security descriptors and writes reports. It modifies no ACL.
- Requires the ActiveDirectory module and read access to nTSecurityDescriptor on the
  objects in scope. Domain User can read most of it.
- Scope defaults to tier-0 objects plus the domain root. Widen with -SearchBase only
  when you mean it: reading every ACL in a large domain is slow and produces a report
  nobody reads.
- Inherited ACEs are reported separately from directly assigned ones. Both matter,
  but they are remediated in different places.
- Generated reports are written under reports\active-directory by default.

Purpose:
This is the companion to Export-AdPrivilegedAccessAudit.ps1, split out because the
two answer different questions. That script asks who is privileged; this asks who
can make themselves privileged. Active Directory permissions are inherited and
almost never cleaned up, so rights accumulate on service accounts and old delegation
groups until some ordinary account can reset a Domain Admin password or replicate
every hash in the directory. None of that shows up in group membership.

The dangerous rights are a short list: GenericAll, WriteDacl, WriteOwner,
WriteProperty on member, ForceChangePassword, and the two replication extended
rights that together permit DCSync.

Required syntax:
pwsh -File .\scripts\active-directory\Export-AdAclRiskReport.ps1
pwsh -File .\scripts\active-directory\Export-AdAclRiskReport.ps1 -Server dc01.example.com
pwsh -File .\scripts\active-directory\Export-AdAclRiskReport.ps1 -SearchBase "OU=Servers,DC=example,DC=com" -IncludeInherited

.OUTPUTS
Writes ACL findings, a per-principal rollup, the scoped object list, and a run
summary as CSV and JSON under reports\active-directory by default. Returns a summary
object.

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
    [switch]$IncludeInherited,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaxObject = 5000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'ad-acl-risk-report'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# Extended rights are identified by GUID, not by name, in the security descriptor.
$script:ExtendedRight = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = [pscustomobject]@{ Name = 'DS-Replication-Get-Changes'; Severity = 'High'; Note = 'Half of DCSync. Combined with Get-Changes-All it permits replicating every credential in the domain.' }
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = [pscustomobject]@{ Name = 'DS-Replication-Get-Changes-All'; Severity = 'Critical'; Note = 'The other half of DCSync. A principal holding both can extract every password hash including krbtgt.' }
    '89e95b76-444d-4c62-991a-0facbeda640c' = [pscustomobject]@{ Name = 'DS-Replication-Get-Changes-In-Filtered-Set'; Severity = 'Medium'; Note = 'Replication of the filtered attribute set.' }
    '00299570-246d-11d0-a768-00aa006e0529' = [pscustomobject]@{ Name = 'User-Force-Change-Password'; Severity = 'High'; Note = 'Reset this account password without knowing the current one.' }
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = [pscustomobject]@{ Name = 'Self-Membership (member)'; Severity = 'High'; Note = 'Add or remove members, including self, on this group.' }
}

# Principals that hold sweeping rights by design. Reporting them buries the finding.
$script:ExpectedPrincipalSid = @(
    'S-1-5-18'      # Local System
    'S-1-5-32-544'  # Builtin Administrators
    'S-1-5-9'       # Enterprise Domain Controllers
    'S-1-5-10'      # Self
    'S-1-3-0'       # Creator Owner
)

$script:Tier0Rid = @(512, 516, 518, 519, 520, 521, 526, 527)
$script:Tier0BuiltinSid = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551')

function Get-DangerousRight {
    <#
    .SYNOPSIS
    Return the dangerous rights an access rule grants, or nothing when it grants none.

    .DESCRIPTION
    An access rule can carry several rights in one mask, so this returns a list. Only
    Allow rules are considered: a Deny rule granting GenericAll is not a grant.

    .PARAMETER AccessRule
    An ActiveDirectoryAccessRule.

    .OUTPUTS
    Zero or more PSCustomObjects with Right, Severity, and Note.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$AccessRule
    )

    if ([string](Get-OpsPropertyValue -InputObject $AccessRule -Name 'AccessControlType') -ne 'Allow') {
        return
    }

    $rights = [string](Get-OpsPropertyValue -InputObject $AccessRule -Name 'ActiveDirectoryRights')
    $objectType = [string](Get-OpsPropertyValue -InputObject $AccessRule -Name 'ObjectType')

    if ($rights -match 'GenericAll') {
        [pscustomobject]@{ Right = 'GenericAll'; Severity = 'Critical'; Note = 'Full control of the object, including its ACL and its password.' }
    }

    if ($rights -match 'WriteDacl') {
        [pscustomobject]@{ Right = 'WriteDacl'; Severity = 'Critical'; Note = 'Can rewrite the object ACL and grant itself anything else.' }
    }

    if ($rights -match 'WriteOwner') {
        [pscustomobject]@{ Right = 'WriteOwner'; Severity = 'Critical'; Note = 'Can take ownership, and an owner can rewrite the ACL.' }
    }

    if ($rights -match 'GenericWrite') {
        [pscustomobject]@{ Right = 'GenericWrite'; Severity = 'High'; Note = 'Can write most attributes, which on a user permits an SPN write and a Kerberoast, and on a group permits adding members.' }
    }

    # An ExtendedRight or WriteProperty ACE with an all-zero object type applies to
    # every right of that class, which is far broader than a single named right.
    if ($rights -match 'ExtendedRight' -or $rights -match 'WriteProperty') {
        if ($objectType -and $objectType -ne '00000000-0000-0000-0000-000000000000') {
            $known = $script:ExtendedRight[$objectType.ToLowerInvariant()]
            if ($known) {
                [pscustomobject]@{ Right = $known.Name; Severity = $known.Severity; Note = $known.Note }
            }
        } elseif ($rights -match 'ExtendedRight') {
            [pscustomobject]@{ Right = 'AllExtendedRights'; Severity = 'Critical'; Note = 'Every extended right on the object, which includes forcing a password change and, on the domain root, replication.' }
        } elseif ($rights -match 'WriteProperty') {
            [pscustomobject]@{ Right = 'WriteAllProperties'; Severity = 'High'; Note = 'WriteProperty with no object type means every property, which is GenericWrite in practice: an SPN can be written for a Kerberoast, or members added to a group.' }
        }
    }
}

function Test-ExpectedPrincipal {
    <#
    .SYNOPSIS
    Return true when a principal is one that holds broad rights by design.

    .PARAMETER Sid
    The principal SID as a string.

    .PARAMETER DomainSid
    The domain SID, used to recognise tier-0 principals in this domain.

    .OUTPUTS
    Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Sid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$DomainSid
    )

    if (-not $Sid) {
        return $false
    }

    if ($script:ExpectedPrincipalSid -contains $Sid) {
        return $true
    }

    if ($script:Tier0BuiltinSid -contains $Sid) {
        return $true
    }

    if ($DomainSid) {
        foreach ($rid in $script:Tier0Rid) {
            if ($Sid -eq "$DomainSid-$rid") {
                return $true
            }
        }
    }

    $false
}

$adParameter = @{}
if ($Server) { $adParameter['Server'] = $Server }
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $adParameter['Credential'] = $Credential }

$domain = Get-ADDomain @adParameter
$domainSid = [string]$domain.DomainSID
$asOf = Get-Date

# Scope. Tier-0 groups and their members plus the domain root, unless told otherwise.
$scopedObjects = [System.Collections.Generic.List[object]]::new()
$scopedObjects.Add([pscustomobject]@{ DistinguishedName = $domain.DistinguishedName; Name = $domain.DNSRoot; Class = 'domainDNS'; Why = 'Domain root. Replication rights here permit DCSync.' })

if ($SearchBase) {
    foreach ($item in (Get-ADObject -SearchBase $SearchBase -Filter * -ResultSetSize $MaxObject @adParameter)) {
        $scopedObjects.Add([pscustomobject]@{ DistinguishedName = $item.DistinguishedName; Name = $item.Name; Class = $item.ObjectClass; Why = 'In the requested SearchBase.' })
    }
} else {
    foreach ($rid in $script:Tier0Rid) {
        $sid = "$domainSid-$rid"
        try {
            $group = Get-ADGroup -Identity $sid -Properties DistinguishedName @adParameter
        } catch {
            Write-Verbose "Tier-0 group $sid not present in this domain, skipped."
            continue
        }

        $scopedObjects.Add([pscustomobject]@{ DistinguishedName = $group.DistinguishedName; Name = $group.Name; Class = 'group'; Why = 'Tier-0 group.' })

        try {
            foreach ($member in (Get-ADObject -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($group.DistinguishedName))" -ResultSetSize $MaxObject @adParameter)) {
                $scopedObjects.Add([pscustomobject]@{ DistinguishedName = $member.DistinguishedName; Name = $member.Name; Class = $member.ObjectClass; Why = "Member of $($group.Name)." })
            }
        } catch {
            Write-Warning "Could not expand $($group.Name): $($_.Exception.Message)"
        }
    }
}

$scoped = @($scopedObjects | Sort-Object DistinguishedName -Unique)

# -MaxObject bounds each LDAP query, so a wide tier-0 expansion can still add up to
# more than it. Cap the total too, and say so rather than silently truncating.
if ($scoped.Count -gt $MaxObject) {
    Write-Warning "Scoped $($scoped.Count) objects, over the $MaxObject cap. Reading the first $MaxObject only; this report is incomplete. Raise -MaxObject or narrow with -SearchBase."
    $scoped = @($scoped | Select-Object -First $MaxObject)
}

Write-Verbose "Reading security descriptors on $($scoped.Count) objects."

$findings = [System.Collections.Generic.List[object]]::new()
$unreadable = 0

# Get-Acl on AD: needs the AD provider drive, which the module supplies.
foreach ($item in $scoped) {
    $acl = $null
    try {
        $acl = Get-Acl -Path "AD:\$($item.DistinguishedName)" -ErrorAction Stop
    } catch {
        $unreadable++
        Write-Verbose "Could not read the descriptor on $($item.DistinguishedName): $($_.Exception.Message)"
        continue
    }

    foreach ($rule in @($acl.Access)) {
        if (-not $IncludeInherited -and (Get-OpsPropertyValue -InputObject $rule -Name 'IsInherited')) {
            continue
        }

        $dangerous = @(Get-DangerousRight -AccessRule $rule)
        if ($dangerous.Count -eq 0) {
            continue
        }

        $identity = [string](Get-OpsPropertyValue -InputObject $rule -Name 'IdentityReference')
        $sid = ''
        $resolved = $true
        try {
            $sid = ([System.Security.Principal.NTAccount]$identity).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            # Either the ACE already holds a raw SID because the account is gone, or a
            # foreign or unresolvable principal did not translate. Both are reported;
            # neither is suppressed, because a principal whose SID is unknown cannot be
            # matched against the expected list and must not be assumed harmless.
            $resolved = $false
            $sid = if ($identity -match '^S-1-') { $identity } else { '' }
        }

        if ($resolved -and (Test-ExpectedPrincipal -Sid $sid -DomainSid $domainSid)) {
            continue
        }

        foreach ($right in $dangerous) {
            $findings.Add([pscustomobject]@{
                    Severity = $right.Severity
                    Right = $right.Right
                    Principal = $identity
                    PrincipalSid = $sid
                    PrincipalResolved = $resolved
                    PrincipalIsOrphaned = [bool]($identity -match '^S-1-')
                    TargetName = $item.Name
                    TargetClass = $item.Class
                    TargetDistinguishedName = $item.DistinguishedName
                    WhyInScope = $item.Why
                    IsInherited = [bool](Get-OpsPropertyValue -InputObject $rule -Name 'IsInherited')
                    AccessControlType = [string](Get-OpsPropertyValue -InputObject $rule -Name 'AccessControlType')
                    RawRights = [string](Get-OpsPropertyValue -InputObject $rule -Name 'ActiveDirectoryRights')
                    ObjectTypeGuid = [string](Get-OpsPropertyValue -InputObject $rule -Name 'ObjectType')
                    Note = $right.Note
                })
        }
    }
}

$sortedFindings = @($findings) | Sort-Object -Property @{ Expression = { Get-OpsSeverityRank -Severity $_.Severity } }, Principal, TargetName

$principalRollup = foreach ($group in (@($sortedFindings) | Group-Object -Property Principal)) {
    $rows = @($group.Group)
    $rights = @($rows | ForEach-Object { $_.Right } | Select-Object -Unique)

    # Both replication rights on one principal is DCSync, which is a different and
    # worse fact than holding either one alone.
    $hasDcSync = ($rights -contains 'DS-Replication-Get-Changes' -and $rights -contains 'DS-Replication-Get-Changes-All') -or ($rights -contains 'AllExtendedRights' -and @($rows | Where-Object { $_.TargetClass -eq 'domainDNS' }).Count -gt 0)

    [pscustomobject]@{
        Principal = $group.Name
        PrincipalSid = $rows[0].PrincipalSid
        PrincipalResolved = $rows[0].PrincipalResolved
        IsOrphaned = $rows[0].PrincipalIsOrphaned
        FindingCount = $rows.Count
        HighestSeverity = (@($rows | Sort-Object { Get-OpsSeverityRank -Severity $_.Severity } | Select-Object -First 1).Severity)
        DistinctRights = ($rights -join ';')
        TargetCount = @($rows | ForEach-Object { $_.TargetDistinguishedName } | Select-Object -Unique).Count
        GrantsDcSync = $hasDcSync
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'acl-findings' -Record $sortedFindings -Directory $runDirectory
    Export-OpsReport -Name 'principal-rollup' -Record @($principalRollup) -Directory $runDirectory
    Export-OpsReport -Name 'scoped-objects' -Record $scoped -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    Domain = $domain.DNSRoot
    SearchBase = $SearchBase
    IncludeInherited = [bool]$IncludeInherited
    ObjectsScoped = $scoped.Count
    ObjectsUnreadable = $unreadable
    UnresolvedPrincipals = @($principalRollup | Where-Object { -not $_.PrincipalResolved }).Count
    FindingCount = $sortedFindings.Count
    CriticalCount = @($sortedFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    HighCount = @($sortedFindings | Where-Object { $_.Severity -eq 'High' }).Count
    MediumCount = @($sortedFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    DistinctPrincipals = @($principalRollup).Count
    PrincipalsWithDcSync = @($principalRollup | Where-Object { $_.GrantsDcSync }).Count
    OrphanedPrincipals = @($principalRollup | Where-Object { $_.IsOrphaned }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
