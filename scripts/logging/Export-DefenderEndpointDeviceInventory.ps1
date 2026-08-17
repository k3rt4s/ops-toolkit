<#
.SYNOPSIS
Export the Defender for Endpoint device list with onboarding coverage and how long each agent has been silent.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads the device list and writes reports. It onboards, offboards,
  isolates, and tags nothing.
- Needs an Entra application with the Machine.Read.All application permission on
  WindowsDefenderATP, granted admin consent. Supply either -AccessToken, when a token
  was obtained elsewhere, or -TenantId, -ClientId, and -ClientSecret to fetch one.
- The secret and the token are held as SecureString, are never written to a report,
  and are never emitted to verbose or debug output.
- -ApiBaseUri targets a sovereign cloud. The default is the commercial endpoint.
- Every page of the device list is followed. A partial read is reported as a failure
  rather than written as a short but clean-looking inventory.
- Generated reports are written under reports\logging by default.

Purpose:
An EDR console reports the machines it knows about, which is not the same as the
machines that exist. The gap between those two numbers is the coverage question, and
it is invisible from inside the console because a machine that was never onboarded
does not appear in it to be counted.

This produces the device list as an inventory that can be reconciled against the other
authorities that should know about the same machine: the directory, an asset system,
and the IP space. It also answers the question a console dashboard does not ask, which
is how long since each agent last said anything. An agent silenced on Tuesday still
shows as a managed device on Friday, and the count of managed devices does not move.

Design rule, the same one the rest of this repo follows: a device whose last contact
cannot be read is Unmeasured, never Reporting. A silent agent and an agent that was
never asked look identical in a count and are opposite in meaning.

Required syntax:
pwsh -File .\scripts\logging\Export-DefenderEndpointDeviceInventory.ps1 -AccessToken $token
pwsh -File .\scripts\logging\Export-DefenderEndpointDeviceInventory.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" -ClientSecret $secret
pwsh -File .\scripts\logging\Export-DefenderEndpointDeviceInventory.ps1 -AccessToken $token -SilenceThresholdDays 3

.OUTPUTS
Writes the device inventory, the devices needing attention, a platform rollup, and a
run summary as CSV and JSON under reports\logging by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.

Unverified against a live tenant as of 2026-08-17. Every field is read defensively and
the shapes come from the documented Machine resource, but no run against a licensed
Defender for Endpoint tenant has happened. See FUTURE_FEATURES.md.
#>
#requires -Version 7
[CmdletBinding()]
param(
    [Parameter()]
    [securestring]$AccessToken,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter()]
    [securestring]$ClientSecret,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$SilenceThresholdDays = 7,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactiveThresholdDays = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApiBaseUri = 'https://api.securitycenter.microsoft.com',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LoginBaseUri = 'https://login.microsoftonline.com',

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxPage = 200,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\logging'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'defender-endpoint-devices'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Get-DeviceContactStatus {
    <#
    .SYNOPSIS
    Grade how long a device has been silent against the silence and inactive thresholds.

    .DESCRIPTION
    Four outcomes. Unmeasured is the one that matters: a device whose last contact
    could not be read is not reporting, and it is not silent either. It is unknown,
    and folding it into Reporting is how a silenced agent stays inside the managed
    device count for as long as anyone cares to look.

    .PARAMETER LastSeen
    Last contact timestamp, or null when absent.

    .PARAMETER AsOf
    The time to measure against.

    .PARAMETER SilenceThresholdDays
    Days of silence after which a device is no longer considered reporting.

    .PARAMETER InactiveThresholdDays
    Days of silence after which a device is considered gone rather than silent.

    .OUTPUTS
    String. One of Reporting, Silent, Inactive, or Unmeasured.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$LastSeen,

        [Parameter(Mandatory = $true)]
        [datetime]$AsOf,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 365)]
        [int]$SilenceThresholdDays,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 3650)]
        [int]$InactiveThresholdDays
    )

    if ($null -eq $LastSeen -or -not $LastSeen) {
        return 'Unmeasured'
    }

    $parsed = $LastSeen -as [datetime]
    if ($null -eq $parsed) {
        return 'Unmeasured'
    }

    $days = ($AsOf - $parsed).TotalDays
    if ($days -ge $InactiveThresholdDays) {
        return 'Inactive'
    }

    if ($days -ge $SilenceThresholdDays) {
        return 'Silent'
    }

    'Reporting'
}

function Get-DeviceCoverageStatus {
    <#
    .SYNOPSIS
    Grade a device's onboarding state as coverage, a coverage gap, or unknown.

    .DESCRIPTION
    The API's onboardingStatus carries four documented values and, in practice,
    sometimes an empty one. CanBeOnboarded is the coverage gap worth surfacing: the
    service can see the device and it is not protected. Unsupported is a real answer,
    not a gap, because no action would fix it. Anything unrecognised is Unknown rather
    than being assumed either way.

    .PARAMETER OnboardingStatus
    The onboardingStatus value from the Machine resource.

    .PARAMETER HealthStatus
    The healthStatus value from the Machine resource.

    .OUTPUTS
    String. One of Onboarded, NotOnboarded, Unsupported, or Unknown.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$OnboardingStatus,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$HealthStatus
    )

    switch -Regex ([string]$OnboardingStatus) {
        '^Onboarded$' { return 'Onboarded' }
        '^CanBeOnboarded$' { return 'NotOnboarded' }
        '^Unsupported$' { return 'Unsupported' }
        '^InsufficientInfo$' { return 'Unknown' }
    }

    # An empty onboarding status with a live health reading still evidences an agent
    # talking to the service, which is worth more than the empty field.
    if ([string]$HealthStatus -and [string]$HealthStatus -notmatch '^Unknown$') {
        return 'Onboarded'
    }

    'Unknown'
}

function Get-DeviceVerdict {
    <#
    .SYNOPSIS
    Combine coverage and contact state into the single per-device verdict.

    .DESCRIPTION
    Coverage is asked before contact, because a device that was never onboarded has no
    contact history to grade and reporting it as Unmeasured would hide the larger fact.

    .PARAMETER Coverage
    Output of Get-DeviceCoverageStatus.

    .PARAMETER Contact
    Output of Get-DeviceContactStatus.

    .OUTPUTS
    String. One of Protected, Silent, Inactive, NotOnboarded, Unsupported, or Undetermined.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Onboarded', 'NotOnboarded', 'Unsupported', 'Unknown')][string]$Coverage,
        [Parameter(Mandatory = $true)][ValidateSet('Reporting', 'Silent', 'Inactive', 'Unmeasured')][string]$Contact
    )

    if ($Coverage -eq 'NotOnboarded') { return 'NotOnboarded' }
    if ($Coverage -eq 'Unsupported') { return 'Unsupported' }
    if ($Coverage -eq 'Unknown') { return 'Undetermined' }

    switch ($Contact) {
        'Reporting' { 'Protected' }
        'Silent' { 'Silent' }
        'Inactive' { 'Inactive' }
        default { 'Undetermined' }
    }
}

function ConvertFrom-OpsSecureString {
    <#
    .SYNOPSIS
    Read a SecureString into a plain string for the duration of one call.

    .DESCRIPTION
    Kept in one place so the unmanaged buffer is always freed, and so there is exactly
    one line in this script where a secret exists in plain text. Nothing here logs,
    returns, or stores the result beyond the caller's immediate use.

    .PARAMETER Secure
    The SecureString to read.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [securestring]$Secure
    )

    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

# ---------------------------------------------------------------------------
# Authentication. Refuse before writing anything, so a run that could not
# authenticate leaves no report to be mistaken for an empty estate.
# ---------------------------------------------------------------------------
$token = $null
if ($AccessToken) {
    $token = ConvertFrom-OpsSecureString -Secure $AccessToken
} elseif ($TenantId -and $ClientId -and $ClientSecret) {
    $body = @{
        grant_type = 'client_credentials'
        client_id = $ClientId
        client_secret = (ConvertFrom-OpsSecureString -Secure $ClientSecret)
        scope = "$ApiBaseUri/.default"
    }

    try {
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "$LoginBaseUri/$TenantId/oauth2/v2.0/token" `
            -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    } catch {
        # The response body of a failed token request can echo the client secret back
        # in some error shapes, so only the status line is surfaced.
        throw "Token request failed: $($_.Exception.Message). Confirm the application has Machine.Read.All on WindowsDefenderATP with admin consent granted."
    } finally {
        $body['client_secret'] = $null
        $body = $null
    }

    $token = [string](Get-OpsPropertyValue -InputObject $tokenResponse -Name 'access_token')
    if (-not $token) {
        throw 'The token endpoint returned no access_token. Nothing was read and no report was written.'
    }
} else {
    throw 'No credentials supplied. Pass -AccessToken, or all three of -TenantId, -ClientId, and -ClientSecret. Nothing was read and no report was written.'
}

# ---------------------------------------------------------------------------
# Device list. Every page, or the run fails.
# ---------------------------------------------------------------------------
$asOf = Get-Date
$devices = [System.Collections.Generic.List[object]]::new()
$uri = "$ApiBaseUri/api/machines"
$page = 0

while ($uri) {
    $page++
    if ($page -gt $MaxPage) {
        # Stopping quietly here would write a truncated inventory that reads as a
        # complete one, which is the specific failure this collector is meant to find
        # in other systems.
        throw "The device list exceeded $MaxPage pages. Raise -MaxPage. The partial result was discarded rather than written as a complete inventory."
    }

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop
    } catch {
        throw "Device list request failed on page $page : $($_.Exception.Message). No report was written, because a partial device list is indistinguishable from a small estate."
    }

    foreach ($device in @(Get-OpsPropertyValue -InputObject $response -Name 'value' | Where-Object { $_ })) {
        $devices.Add($device)
    }

    $uri = [string](Get-OpsPropertyValue -InputObject $response -Name '@odata.nextLink')
}

$deviceRecords = [System.Collections.Generic.List[object]]::new()
foreach ($device in $devices) {
    $lastSeen = Get-OpsPropertyValue -InputObject $device -Name 'lastSeen'
    $firstSeen = Get-OpsPropertyValue -InputObject $device -Name 'firstSeen'
    $onboarding = [string](Get-OpsPropertyValue -InputObject $device -Name 'onboardingStatus')
    $health = [string](Get-OpsPropertyValue -InputObject $device -Name 'healthStatus')

    $contact = Get-DeviceContactStatus -LastSeen $lastSeen -AsOf $asOf `
        -SilenceThresholdDays $SilenceThresholdDays -InactiveThresholdDays $InactiveThresholdDays
    $coverage = Get-DeviceCoverageStatus -OnboardingStatus $onboarding -HealthStatus $health
    $verdict = Get-DeviceVerdict -Coverage $coverage -Contact $contact

    $parsedLastSeen = $lastSeen -as [datetime]
    $silentDays = if ($null -eq $parsedLastSeen) { $null } else { [math]::Round(($asOf - $parsedLastSeen).TotalDays, 1) }

    $deviceRecords.Add([pscustomobject]@{
            DeviceId = [string](Get-OpsPropertyValue -InputObject $device -Name 'id')
            ComputerDnsName = [string](Get-OpsPropertyValue -InputObject $device -Name 'computerDnsName')
            EntraDeviceId = [string](Get-OpsPropertyValue -InputObject $device -Name 'aadDeviceId')
            Verdict = $verdict
            CoverageStatus = $coverage
            ContactStatus = $contact
            DaysSinceLastSeen = $silentDays
            SilenceThresholdDays = $SilenceThresholdDays
            OnboardingStatus = $onboarding
            HealthStatus = $health
            DefenderAvStatus = [string](Get-OpsPropertyValue -InputObject $device -Name 'defenderAvStatus')
            OsPlatform = [string](Get-OpsPropertyValue -InputObject $device -Name 'osPlatform')
            OsVersion = [string](Get-OpsPropertyValue -InputObject $device -Name 'version')
            AgentVersion = [string](Get-OpsPropertyValue -InputObject $device -Name 'agentVersion')
            LastIpAddress = [string](Get-OpsPropertyValue -InputObject $device -Name 'lastIpAddress')
            LastExternalIpAddress = [string](Get-OpsPropertyValue -InputObject $device -Name 'lastExternalIpAddress')
            RiskScore = [string](Get-OpsPropertyValue -InputObject $device -Name 'riskScore')
            ExposureLevel = [string](Get-OpsPropertyValue -InputObject $device -Name 'exposureLevel')
            RbacGroupName = [string](Get-OpsPropertyValue -InputObject $device -Name 'rbacGroupName')
            MachineTags = Join-OpsValue -Value (Get-OpsPropertyValue -InputObject $device -Name 'machineTags')
            IsExcluded = Get-OpsPropertyValue -InputObject $device -Name 'isExcluded'
            FirstSeen = $firstSeen
            LastSeen = $lastSeen
        })
}

$needsAttention = @($deviceRecords | Where-Object { $_.Verdict -in @('Silent', 'Inactive', 'NotOnboarded', 'Undetermined') })

$platformRollup = foreach ($group in (@($deviceRecords) | Group-Object -Property OsPlatform)) {
    [pscustomobject]@{
        OsPlatform = if ($group.Name) { $group.Name } else { 'Unknown' }
        DeviceCount = $group.Count
        ProtectedCount = @($group.Group | Where-Object { $_.Verdict -eq 'Protected' }).Count
        SilentCount = @($group.Group | Where-Object { $_.Verdict -eq 'Silent' }).Count
        InactiveCount = @($group.Group | Where-Object { $_.Verdict -eq 'Inactive' }).Count
        NotOnboardedCount = @($group.Group | Where-Object { $_.Verdict -eq 'NotOnboarded' }).Count
        UndeterminedCount = @($group.Group | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'devices' -Record @($deviceRecords) -Directory $runDirectory
    Export-OpsReport -Name 'devices-needing-attention' -Record @($needsAttention) -Directory $runDirectory
    Export-OpsReport -Name 'platform-rollup' -Record @($platformRollup) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    ApiBaseUri = $ApiBaseUri
    PagesRead = $page
    DeviceCount = $deviceRecords.Count
    ProtectedCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'Protected' }).Count
    SilentCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'Silent' }).Count
    InactiveCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'Inactive' }).Count
    NotOnboardedCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'NotOnboarded' }).Count
    UnsupportedCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'Unsupported' }).Count
    UndeterminedCount = @($deviceRecords | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    UnmeasuredContactCount = @($deviceRecords | Where-Object { $_.ContactStatus -eq 'Unmeasured' }).Count
    NeedsAttentionCount = $needsAttention.Count
    SilenceThresholdDays = $SilenceThresholdDays
    InactiveThresholdDays = $InactiveThresholdDays
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
