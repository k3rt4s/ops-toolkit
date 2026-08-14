<#
.SYNOPSIS
Export Conditional Access policies, compare them against a saved baseline, and report gaps and drift.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only against the tenant. It reads policies and writes files locally. It
  creates, edits, and deletes no policy.
- Requires Microsoft.Graph.Authentication only. Everything goes through
  Invoke-MgGraphRequest.
- Use -Connect when the shell is not already connected. Delegated scope requested:
  Policy.Read.All.
- -BaselinePath points at a previously exported baseline JSON. Without it the run
  is an export and a gap analysis only, with no drift comparison.
- -UpdateBaseline overwrites the baseline with the current state. Do that
  deliberately, after reviewing the drift, never as a habit, or the baseline
  silently becomes a record of whatever happened rather than of what was agreed.
- Generated reports are written under reports\entra by default.

Purpose:
Conditional Access is the control that actually enforces identity security, and it
is edited by several people, by templates, and by Microsoft itself as policy
capabilities change. Without a baseline there is no way to answer the only question
that matters during an incident or an audit: is this the policy set we agreed on.

The gap analysis is separate from the drift comparison on purpose. Drift says what
changed since last time; gaps say what was never right, and a tenant can be perfectly
stable and still have no policy blocking legacy authentication.

Required syntax:
pwsh -File .\scripts\entra\Export-EntraConditionalAccessBaseline.ps1 -Connect
pwsh -File .\scripts\entra\Export-EntraConditionalAccessBaseline.ps1 -Connect -BaselinePath .\ca-baseline.json
pwsh -File .\scripts\entra\Export-EntraConditionalAccessBaseline.ps1 -Connect -BaselinePath .\ca-baseline.json -UpdateBaseline

.OUTPUTS
Writes the policy export, a gap analysis, a drift report when a baseline is
supplied, and a run summary as CSV and JSON under reports\entra by default. Returns
a summary object.

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
    [ValidateNotNullOrEmpty()]
    [string]$BaselinePath,

    [Parameter()]
    [switch]$UpdateBaseline,

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
    [string]$OutputPrefix = 'entra-conditional-access-baseline'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Get-PolicySignature {
    <#
    .SYNOPSIS
    Return a stable string describing a policy's enforced behaviour.

    .DESCRIPTION
    Compares behaviour rather than the whole object, because the raw policy carries
    modifiedDateTime and other fields that change without the policy changing. Two
    policies with the same signature enforce the same thing.

    .PARAMETER Policy
    The policy as returned by Graph.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    $conditions = Get-OpsPropertyValue -InputObject $Policy -Name 'conditions'
    $grant = Get-OpsPropertyValue -InputObject $Policy -Name 'grantControls'
    $session = Get-OpsPropertyValue -InputObject $Policy -Name 'sessionControls'

    $parts = @(
        "state=$(Join-OpsValue (Get-OpsPropertyValue -InputObject $Policy -Name 'state'))"
        "users=$(($conditions | ForEach-Object { $_ } | Out-Null); Join-OpsValue ((Get-OpsPropertyValue -InputObject $conditions -Name 'users') | ConvertTo-Json -Depth 6 -Compress))"
        "apps=$(Join-OpsValue ((Get-OpsPropertyValue -InputObject $conditions -Name 'applications') | ConvertTo-Json -Depth 6 -Compress))"
        "platforms=$(Join-OpsValue ((Get-OpsPropertyValue -InputObject $conditions -Name 'platforms') | ConvertTo-Json -Depth 6 -Compress))"
        "locations=$(Join-OpsValue ((Get-OpsPropertyValue -InputObject $conditions -Name 'locations') | ConvertTo-Json -Depth 6 -Compress))"
        "clientAppTypes=$(Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'clientAppTypes'))"
        "risk=$(Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'signInRiskLevels'))/$(Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'userRiskLevels'))"
        "grant=$(Join-OpsValue ($grant | ConvertTo-Json -Depth 6 -Compress))"
        "session=$(Join-OpsValue ($session | ConvertTo-Json -Depth 6 -Compress))"
    )

    $parts -join '|'
}

function Get-PolicyRecord {
    <#
    .SYNOPSIS
    Flatten a Conditional Access policy into one reportable row.

    .PARAMETER Policy
    The policy as returned by Graph.

    .OUTPUTS
    PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    $conditions = Get-OpsPropertyValue -InputObject $Policy -Name 'conditions'
    $users = Get-OpsPropertyValue -InputObject $conditions -Name 'users'
    $apps = Get-OpsPropertyValue -InputObject $conditions -Name 'applications'
    $grant = Get-OpsPropertyValue -InputObject $Policy -Name 'grantControls'

    [pscustomobject]@{
        Id = Join-OpsValue (Get-OpsPropertyValue -InputObject $Policy -Name 'id')
        DisplayName = Join-OpsValue (Get-OpsPropertyValue -InputObject $Policy -Name 'displayName')
        State = Join-OpsValue (Get-OpsPropertyValue -InputObject $Policy -Name 'state')
        CreatedDateTime = Get-OpsPropertyValue -InputObject $Policy -Name 'createdDateTime'
        ModifiedDateTime = Get-OpsPropertyValue -InputObject $Policy -Name 'modifiedDateTime'
        IncludeUsers = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'includeUsers')
        ExcludeUsers = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeUsers')
        IncludeGroups = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'includeGroups')
        ExcludeGroups = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeGroups')
        IncludeRoles = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'includeRoles')
        ExcludeRoles = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeRoles')
        IncludeApplications = Join-OpsValue (Get-OpsPropertyValue -InputObject $apps -Name 'includeApplications')
        ExcludeApplications = Join-OpsValue (Get-OpsPropertyValue -InputObject $apps -Name 'excludeApplications')
        ClientAppTypes = Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'clientAppTypes')
        SignInRiskLevels = Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'signInRiskLevels')
        UserRiskLevels = Join-OpsValue (Get-OpsPropertyValue -InputObject $conditions -Name 'userRiskLevels')
        GrantOperator = Join-OpsValue (Get-OpsPropertyValue -InputObject $grant -Name 'operator')
        BuiltInControls = Join-OpsValue (Get-OpsPropertyValue -InputObject $grant -Name 'builtInControls')
        AuthenticationStrength = Join-OpsValue ((Get-OpsPropertyValue -InputObject $grant -Name 'authenticationStrength') | ForEach-Object { Get-OpsPropertyValue -InputObject $_ -Name 'displayName' })
        CustomAuthenticationFactors = Join-OpsValue (Get-OpsPropertyValue -InputObject $grant -Name 'customAuthenticationFactors')
        Signature = Get-PolicySignature -Policy $Policy
    }
}

if ($Connect) {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Connect-MgGraph is not available. Install Microsoft.Graph.Authentication.'
    }

    $scopes = if ($GraphScope) { @($GraphScope) } else { @('Policy.Read.All') }
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
Write-Verbose 'Reading Conditional Access policies.'

$policies = [System.Collections.Generic.List[object]]::new()
$uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
while ($uri) {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Hashtable -ErrorAction Stop
    foreach ($policy in @(Get-OpsPropertyValue -InputObject $response -Name 'value')) {
        $policies.Add($policy)
    }

    $uri = Join-OpsValue (Get-OpsPropertyValue -InputObject $response -Name '@odata.nextLink')
}

$records = @($policies | ForEach-Object { Get-PolicyRecord -Policy $_ })
$enabled = @($records | Where-Object { $_.State -eq 'enabled' })

# Gap analysis. Each gap is a control that either exists and is enforcing, or does
# not. A policy in reportOnly is not enforcing, which is the trap here: it looks
# present in the portal and does nothing.
$gaps = [System.Collections.Generic.List[object]]::new()
function Add-Gap {
    param($Name, $Present, $Severity, $Why, $Matched = '')
    $gaps.Add([pscustomobject]@{
            Control = $Name
            Status = if ($Present) { 'Present' } else { 'Missing' }
            Severity = if ($Present) { 'Informational' } else { $Severity }
            MatchingPolicies = $Matched
            Why = $Why
        })
}

function Get-PolicyNameList {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Policy)
    (@($Policy | ForEach-Object { $_.DisplayName }) -join ';')
}

$legacyAuthBlocked = @($enabled | Where-Object { $_.ClientAppTypes -match 'exchangeActiveSync|other' -and $_.BuiltInControls -match 'block' })
$whyLegacy = 'Legacy authentication bypasses MFA entirely. Without a policy blocking it, every other identity control is optional.'
Add-Gap 'BlockLegacyAuthentication' ($legacyAuthBlocked.Count -gt 0) 'Critical' $whyLegacy (Get-PolicyNameList -Policy $legacyAuthBlocked)

$adminMfa = @($enabled | Where-Object { $_.IncludeRoles -and $_.BuiltInControls -match 'mfa' })
$whyAdminMfa = 'Directory role holders should be covered by an explicit MFA policy rather than relying on the tenant-wide default.'
Add-Gap 'RequireMfaForAdmins' ($adminMfa.Count -gt 0) 'Critical' $whyAdminMfa (Get-PolicyNameList -Policy $adminMfa)

$allUserMfa = @($enabled | Where-Object { $_.IncludeUsers -match 'All' -and $_.BuiltInControls -match 'mfa' })
$whyAllUserMfa = 'A tenant-wide MFA requirement is the baseline every other policy carves exceptions out of.'
Add-Gap 'RequireMfaForAllUsers' ($allUserMfa.Count -gt 0) 'High' $whyAllUserMfa (Get-PolicyNameList -Policy $allUserMfa)

$phishingResistantAdmin = @($enabled | Where-Object { $_.IncludeRoles -and $_.AuthenticationStrength })
$whyPhishingResistant = 'Help desk social engineering and device code phishing both defeat push and telephony MFA. An authentication strength requirement on admins does not fall to either.'
Add-Gap 'PhishingResistantForAdmins' ($phishingResistantAdmin.Count -gt 0) 'High' $whyPhishingResistant (Get-PolicyNameList -Policy $phishingResistantAdmin)

$riskPolicy = @($enabled | Where-Object { $_.SignInRiskLevels -or $_.UserRiskLevels })
$whyRisk = 'Risk-based policies are what catch a session that was legitimate at sign-in and is not any more.'
Add-Gap 'RiskBasedPolicy' ($riskPolicy.Count -gt 0) 'Medium' $whyRisk (Get-PolicyNameList -Policy $riskPolicy)

$deviceCompliance = @($enabled | Where-Object { $_.BuiltInControls -match 'compliantDevice|domainJoinedDevice' })
$whyDevice = 'Without a device requirement, a stolen token works from anywhere.'
Add-Gap 'RequireCompliantDevice' ($deviceCompliance.Count -gt 0) 'Medium' $whyDevice (Get-PolicyNameList -Policy $deviceCompliance)

# Report-only and disabled policies are worth surfacing on their own: they are the
# ones people believe are protecting them.
foreach ($policy in @($records | Where-Object { $_.State -ne 'enabled' })) {
    $gaps.Add([pscustomobject]@{
            Control = "NotEnforcing:$($policy.DisplayName)"
            Status = 'NotEnforcing'
            Severity = if ($policy.State -eq 'enabledForReportingButNotEnforced') { 'Medium' } else { 'Low' }
            MatchingPolicies = $policy.DisplayName
            Why = "Policy state is '$($policy.State)', so it is visible in the portal but changes no sign-in outcome."
        })
}

# Drift against a saved baseline.
$drift = [System.Collections.Generic.List[object]]::new()
$baselineLoaded = $false
if ($BaselinePath -and (Test-Path -LiteralPath $BaselinePath)) {
    $baselineLoaded = $true
    $baseline = @(Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json)
    $baselineById = @{}
    foreach ($item in $baseline) {
        $id = Join-OpsValue (Get-OpsPropertyValue -InputObject $item -Name 'Id')
        if ($id) { $baselineById[$id] = $item }
    }

    $currentById = @{}
    foreach ($item in $records) {
        if ($item.Id) { $currentById[$item.Id] = $item }
    }

    foreach ($id in $currentById.Keys) {
        $current = $currentById[$id]
        if (-not $baselineById.ContainsKey($id)) {
            $drift.Add([pscustomobject]@{ Change = 'Added'; PolicyId = $id; DisplayName = $current.DisplayName; BaselineValue = ''; CurrentValue = $current.State; Detail = 'Policy exists now and was not in the baseline.' })
            continue
        }

        $previous = $baselineById[$id]
        if ((Join-OpsValue (Get-OpsPropertyValue -InputObject $previous -Name 'Signature')) -ne $current.Signature) {
            $drift.Add([pscustomobject]@{
                    Change = 'Modified'
                    PolicyId = $id
                    DisplayName = $current.DisplayName
                    BaselineValue = Join-OpsValue (Get-OpsPropertyValue -InputObject $previous -Name 'State')
                    CurrentValue = $current.State
                    Detail = 'Enforced behaviour differs from the baseline. Compare the exported policy JSON for the specific field.'
                })
        }
    }

    foreach ($id in $baselineById.Keys) {
        if (-not $currentById.ContainsKey($id)) {
            $previous = $baselineById[$id]
            $drift.Add([pscustomobject]@{
                    Change = 'Removed'
                    PolicyId = $id
                    DisplayName = Join-OpsValue (Get-OpsPropertyValue -InputObject $previous -Name 'DisplayName')
                    BaselineValue = Join-OpsValue (Get-OpsPropertyValue -InputObject $previous -Name 'State')
                    CurrentValue = ''
                    Detail = 'Policy was in the baseline and no longer exists.'
                })
        }
    }
} elseif ($BaselinePath) {
    Write-Warning "Baseline not found at $BaselinePath. This run is an export and gap analysis only, with no drift comparison."
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix

# The full policy objects go out verbatim as well, because the flattened row is for
# reading and the raw JSON is what you diff when the drift report says Modified.
$rawPath = Join-Path $runDirectory 'conditional-access-policies-raw.json'
Set-Content -LiteralPath $rawPath -Value (@($policies) | ConvertTo-Json -Depth 20) -Encoding utf8

$exports = @(
    Export-OpsReport -Name 'conditional-access-policies' -Record $records -Directory $runDirectory
    Export-OpsReport -Name 'gap-analysis' -Record @($gaps) -Directory $runDirectory
    Export-OpsReport -Name 'baseline-drift' -Record @($drift) -Directory $runDirectory
)

if ($UpdateBaseline) {
    if (-not $BaselinePath) {
        throw 'UpdateBaseline needs -BaselinePath so there is somewhere to write.'
    }

    Set-Content -LiteralPath $BaselinePath -Value (@($records) | ConvertTo-Json -Depth 10) -Encoding utf8
    Write-Warning "Baseline overwritten at $BaselinePath. It now records the tenant's current state, whatever that state is."
}

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    TenantId = (Get-MgContext).TenantId
    RawPolicyPath = (Resolve-Path -LiteralPath $rawPath).Path
    PolicyCount = $records.Count
    EnabledCount = $enabled.Count
    ReportOnlyCount = @($records | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
    DisabledCount = @($records | Where-Object { $_.State -eq 'disabled' }).Count
    GapCount = @($gaps | Where-Object { $_.Status -eq 'Missing' }).Count
    CriticalGapCount = @($gaps | Where-Object { $_.Status -eq 'Missing' -and $_.Severity -eq 'Critical' }).Count
    BaselineLoaded = $baselineLoaded
    BaselinePath = $BaselinePath
    BaselineUpdated = [bool]$UpdateBaseline
    DriftCount = $drift.Count
    PoliciesAdded = @($drift | Where-Object { $_.Change -eq 'Added' }).Count
    PoliciesRemoved = @($drift | Where-Object { $_.Change -eq 'Removed' }).Count
    PoliciesModified = @($drift | Where-Object { $_.Change -eq 'Modified' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($DisconnectWhenFinished) {
    Disconnect-MgGraph | Out-Null
}
