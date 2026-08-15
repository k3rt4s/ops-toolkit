<#
.SYNOPSIS
Report which Entra ID users still depend on SMS or voice before Microsoft stops delivering them.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads the authentication method registration report and writes
  reports. It changes no user, method, or policy.
- Requires Microsoft.Graph.Authentication only. Everything goes through
  Invoke-MgGraphRequest rather than a per-workload module.
- Use -Connect when the shell is not already connected. Delegated scopes requested:
  UserAuthenticationMethod.Read.All, AuditLog.Read.All, and Directory.Read.All. The
  registration report needs an Entra ID P1 or P2 licence.
- No phone number, secret, or method identifier is written to a report. Only which
  method types a user has registered.
- Generated reports are written under reports\entra by default.

Purpose:
Two dates make telephony-based MFA a migration rather than a preference. From
1 September 2026 passkeys become the default sign-in method for users on SMS and
voice, and from 1 February 2027 Microsoft stops providing telephony delivery
altogether, after which an organisation that still needs it has to bring its own
telecom provider. The work is not flipping a setting; it is finding the users who
have nothing else registered, which is a different and much smaller list than the
users who have a phone number on file.

The accounts that matter most are the ones with no strong method at all, and the
break-glass accounts, which are deliberately excluded from policy and therefore
never show up in the reports people usually look at.

Required syntax:
pwsh -File .\scripts\entra\Export-EntraAuthMethodReadiness.ps1 -Connect
pwsh -File .\scripts\entra\Export-EntraAuthMethodReadiness.ps1 -Connect -IncludeGuests
pwsh -File .\scripts\entra\Export-EntraAuthMethodReadiness.ps1 -Connect -TenantId "<tenant-id>"

.OUTPUTS
Writes per-user readiness, a method rollup, the telephony-only subset, and a run
summary as CSV and JSON under reports\entra by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [switch]$IncludeGuests,

    [Parameter()]
    [ValidateRange(100, 500000)]
    [int]$MaxUser = 100000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$GraphScope,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$DisconnectWhenFinished,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\entra'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'entra-auth-method-readiness'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# Methods that stop being delivered by Microsoft on 1 February 2027.
$script:TelephonyMethod = @('sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice', 'mobilePhone', 'alternateMobilePhone', 'officePhone')

# Methods that count as phishing-resistant. A user holding one of these is finished.
$script:PhishingResistantMethod = @('passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'fido2SecurityKey', 'windowsHelloForBusiness', 'x509CertificateSingleFactor', 'x509CertificateMultiFactor')

# Methods that are strong but not phishing-resistant.
$script:StrongMethod = @('microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless', 'softwareOneTimePasscode', 'hardwareOneTimePasscode', 'temporaryAccessPass', 'temporaryAccessPassMultiUse')

function Invoke-GraphCollection {
    <#
    .SYNOPSIS
    Read every page of a Graph collection and return the items.

    .PARAMETER Uri
    The starting request URI.

    .PARAMETER MaxItem
    Stop after this many items and warn, so an unexpectedly large tenant cannot run
    unbounded.

    .OUTPUTS
    The collected items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [int]$MaxItem
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri

    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
        foreach ($item in @(Get-OpsPropertyValue -InputObject $response -Name 'value')) {
            $items.Add($item)
        }

        if ($items.Count -ge $MaxItem) {
            Write-Warning "Stopped reading at the $MaxItem item cap. The report is incomplete; raise -MaxUser."
            break
        }

        $next = Join-OpsValue (Get-OpsPropertyValue -InputObject $response -Name '@odata.nextLink')
    }

    $items
}

if ($Connect) {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Connect-MgGraph is not available. Install Microsoft.Graph.Authentication.'
    }

    $scopes = if ($GraphScope) { @($GraphScope) } else { @('UserAuthenticationMethod.Read.All', 'AuditLog.Read.All', 'Directory.Read.All') }
    $connectParameter = @{ Scopes = $scopes }
    if ($TenantId) { $connectParameter['TenantId'] = $TenantId }
    if ($UseDeviceCode) { $connectParameter['UseDeviceCode'] = $true }
    Connect-MgGraph @connectParameter | Out-Null
} elseif ($TenantId -or $UseDeviceCode -or $GraphScope) {
    throw 'TenantId, UseDeviceCode, and GraphScope apply only to a new connection. Add -Connect, or drop them and reuse the current Microsoft Graph session.'
}

if (-not (Get-MgContext)) {
    throw 'No Microsoft Graph session. Run again with -Connect, or connect first with Connect-MgGraph.'
}

$asOf = Get-Date
Write-Verbose 'Reading authentication method registration details.'

$registrations = @()
$readError = ''
try {
    $registrations = @(Invoke-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' -MaxItem $MaxUser)
} catch {
    $readError = $_.Exception.Message
    throw "Could not read the authentication method registration report. This report requires Entra ID P1 or P2 and the UserAuthenticationMethod.Read.All scope. $readError"
}

$records = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $registrations) {
    $userType = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'userType')
    if (-not $IncludeGuests -and $userType -eq 'Guest') {
        continue
    }

    $methods = @(Get-OpsPropertyValue -InputObject $entry -Name 'methodsRegistered' | ForEach-Object { [string]$_ })
    $isAdmin = [bool](Get-OpsPropertyValue -InputObject $entry -Name 'isAdmin')
    $mfaCapable = [bool](Get-OpsPropertyValue -InputObject $entry -Name 'isMfaCapable')
    $mfaRegistered = [bool](Get-OpsPropertyValue -InputObject $entry -Name 'isMfaRegistered')
    $passwordlessCapable = [bool](Get-OpsPropertyValue -InputObject $entry -Name 'isPasswordlessCapable')

    $telephony = @($methods | Where-Object { $script:TelephonyMethod -contains $_ })
    $phishingResistant = @($methods | Where-Object { $script:PhishingResistantMethod -contains $_ })
    $strong = @($methods | Where-Object { $script:StrongMethod -contains $_ })

    # The distinction that matters is not "has a phone number" but "has nothing
    # else". A user with Authenticator and a phone number needs no work at all.
    $readiness = if (-not $mfaRegistered) {
        'NoMfaRegistered'
    } elseif ($telephony.Count -gt 0 -and $phishingResistant.Count -eq 0 -and $strong.Count -eq 0) {
        'TelephonyOnly'
    } elseif ($phishingResistant.Count -gt 0) {
        'PhishingResistant'
    } elseif ($strong.Count -gt 0) {
        'StrongNotPhishingResistant'
    } else {
        'Unclassified'
    }

    $records.Add([pscustomobject]@{
            UserPrincipalName = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'userPrincipalName')
            DisplayName = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'userDisplayName')
            Readiness = $readiness
            IsAdmin = $isAdmin
            UserType = $userType
            IsMfaRegistered = $mfaRegistered
            IsMfaCapable = $mfaCapable
            IsPasswordlessCapable = $passwordlessCapable
            IsSsprRegistered = [bool](Get-OpsPropertyValue -InputObject $entry -Name 'isSsprRegistered')
            MethodCount = $methods.Count
            MethodsRegistered = ($methods -join ';')
            TelephonyMethods = ($telephony -join ';')
            PhishingResistantMethods = ($phishingResistant -join ';')
            # The v1.0 resource calls this userPreferredMethodForSecondaryAuthentication.
            # An earlier version of this script read defaultMfaMethod, which exists only
            # in beta, so the column was silently empty on every row.
            PreferredMethod = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'userPreferredMethodForSecondaryAuthentication')
            # System-preferred authentication is what actually promotes a user off SMS
            # and voice, so it is the field that says whether the September 2026
            # passkey default will move them or leave them where they are.
            SystemPreferredEnabled = Get-OpsPropertyValue -InputObject $entry -Name 'isSystemPreferredAuthenticationMethodEnabled'
            SystemPreferredMethods = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'systemPreferredAuthenticationMethods')
            IsSsprCapable = Get-OpsPropertyValue -InputObject $entry -Name 'isSsprCapable'
            LastUpdated = Get-OpsPropertyValue -InputObject $entry -Name 'lastUpdatedDateTime'
            UserId = Join-OpsValue (Get-OpsPropertyValue -InputObject $entry -Name 'id')
        })
}

# Sort the work to the front: admins first, then whoever has the least to fall back on.
$readinessRank = { param($r) switch ($r) { 'NoMfaRegistered' { 0 } 'TelephonyOnly' { 1 } 'Unclassified' { 2 } 'StrongNotPhishingResistant' { 3 } default { 4 } } }
$inventory = @($records) | Sort-Object -Property @{ Expression = { -not $_.IsAdmin } }, @{ Expression = { & $readinessRank $_.Readiness } }, UserPrincipalName
$telephonyOnly = @($inventory | Where-Object { $_.Readiness -eq 'TelephonyOnly' })

$methodRollup = foreach ($group in (@($records) | ForEach-Object { $_.MethodsRegistered -split ';' } | Where-Object { $_ } | Group-Object)) {
    [pscustomobject]@{
        Method = $group.Name
        UserCount = $group.Count
        IsTelephony = $script:TelephonyMethod -contains $group.Name
        IsPhishingResistant = $script:PhishingResistantMethod -contains $group.Name
    }
}

$readinessRollup = foreach ($group in (@($inventory) | Group-Object -Property Readiness)) {
    [pscustomobject]@{
        Readiness = $group.Name
        UserCount = $group.Count
        AdminCount = @($group.Group | Where-Object { $_.IsAdmin }).Count
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'auth-method-readiness' -Record $inventory -Directory $runDirectory
    Export-OpsReport -Name 'telephony-only-users' -Record $telephonyOnly -Directory $runDirectory
    Export-OpsReport -Name 'method-rollup' -Record @($methodRollup) -Directory $runDirectory
    Export-OpsReport -Name 'readiness-rollup' -Record @($readinessRollup) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    TenantId = (Get-MgContext).TenantId
    IncludedGuests = [bool]$IncludeGuests
    UsersRead = @($registrations).Count
    UsersReported = $inventory.Count
    NoMfaRegisteredCount = @($inventory | Where-Object { $_.Readiness -eq 'NoMfaRegistered' }).Count
    TelephonyOnlyCount = $telephonyOnly.Count
    TelephonyOnlyAdminCount = @($telephonyOnly | Where-Object { $_.IsAdmin }).Count
    StrongNotPhishingResistantCount = @($inventory | Where-Object { $_.Readiness -eq 'StrongNotPhishingResistant' }).Count
    PhishingResistantCount = @($inventory | Where-Object { $_.Readiness -eq 'PhishingResistant' }).Count
    AdminCount = @($inventory | Where-Object { $_.IsAdmin }).Count
    AdminsWithoutMfa = @($inventory | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered }).Count
    SystemPreferredEnabledCount = @($inventory | Where-Object { $_.SystemPreferredEnabled -eq $true }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($DisconnectWhenFinished) {
    Disconnect-MgGraph | Out-Null
}
