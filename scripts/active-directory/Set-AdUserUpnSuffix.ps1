<#
.SYNOPSIS
Plan and update Active Directory user UPN suffixes with scoped reporting.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Always run with -WhatIf first and review the generated plan/state reports.
- Pass -SearchBase and -OldSuffix to keep the update scope explicit.
- Use -MailboxEnabledOnly to limit updates to users with homeMDB populated.
- Generated reports are written under reports\active-directory by default.

.PURPOSE
This script replaces the separate mailbox-enabled and OU-scoped UPN suffix
update helpers with one report-first command. It can preserve the existing UPN
local part or rebuild the UPN from SamAccountName.

.REQUIRED SYNTAX
pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf
pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -NewSuffix example.com -MailboxEnabledOnly -LocalPartSource SamAccountName -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON files under reports\active-directory by default.
Returns a summary object with report paths and update counts.

.STATUS
Active script kept in the reorganized ops-toolkit repo. Replaces
Set-AdMailboxEnabledUserUpnSuffix.ps1 and Set-AdOuUserUpnSuffix.ps1.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$OldSuffix,

    [Parameter()]
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$NewSuffix,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [Parameter()]
    [switch]$MailboxEnabledOnly,

    [Parameter()]
    [switch]$IncludeDisabledUsers,

    [Parameter()]
    [ValidateSet('ExistingUpn', 'SamAccountName')]
    [string]$LocalPartSource = 'ExistingUpn',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf
  pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -NewSuffix example.com -MailboxEnabledOnly -LocalPartSource SamAccountName -WhatIf

Options:
  -SearchBase            Distinguished name used to limit the AD search scope.
  -OldSuffix             Optional current UPN suffix filter, for example old.example.com.
  -NewSuffix             New UPN suffix to apply, for example example.com.
  -Server                Optional domain controller to target.
  -SearchScope           AD search scope: Base, OneLevel, or Subtree. Defaults to Subtree.
  -MailboxEnabledOnly    Limit updates to AD users with homeMDB populated.
  -IncludeDisabledUsers  Include disabled AD user accounts.
  -LocalPartSource       ExistingUpn or SamAccountName. Defaults to ExistingUpn.
  -ReportDirectory       Plan and state output directory.
  -WhatIf                Preview UPN updates without changing AD.
'@
}

function Get-AdUserQueryParameter {
    $queryParameters = @{
        Filter = '*'
        Properties = @(
            'Enabled',
            'homeMDB',
            'SamAccountName',
            'UserPrincipalName',
            'DistinguishedName'
        )
    }

    if ($SearchBase) {
        $queryParameters.SearchBase = $SearchBase
        $queryParameters.SearchScope = $SearchScope
    }
    if ($Server) {
        $queryParameters.Server = $Server
    }

    $queryParameters
}

function Get-UpnLocalPart {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    if ($LocalPartSource -eq 'SamAccountName' -or -not $User.UserPrincipalName -or $User.UserPrincipalName -notlike '*@*') {
        return [string]$User.SamAccountName
    }

    ([string]$User.UserPrincipalName).Split('@', 2)[0]
}

function Get-UpnUpdatePlan {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$User
    )

    foreach ($adUser in $User) {
        $oldUpn = [string]$adUser.UserPrincipalName
        $suffixMatches = -not $OldSuffix -or $oldUpn -like "*@$OldSuffix"
        $isEnabled = [bool]$adUser.Enabled
        $isMailboxEnabled = [bool]$adUser.homeMDB
        $newUpn = '{0}@{1}' -f (Get-UpnLocalPart -User $adUser), $NewSuffix
        $action = if (-not $suffixMatches) {
            'Skipped'
        } elseif (-not $IncludeDisabledUsers -and -not $isEnabled) {
            'Skipped'
        } elseif ($MailboxEnabledOnly -and -not $isMailboxEnabled) {
            'Skipped'
        } elseif ($oldUpn -eq $newUpn) {
            'NoChange'
        } else {
            'SetUserPrincipalName'
        }

        [pscustomobject]@{
            Action = $action
            SamAccountName = $adUser.SamAccountName
            DistinguishedName = $adUser.DistinguishedName
            Enabled = $isEnabled
            MailboxEnabled = $isMailboxEnabled
            OldUserPrincipalName = $oldUpn
            NewUserPrincipalName = $newUpn
            LocalPartSource = $LocalPartSource
            Reason = switch ($action) {
                'SetUserPrincipalName' { 'User is in scope and UPN suffix will be updated.' }
                'NoChange' { 'User already has the requested UPN.' }
                'Skipped' {
                    if (-not $suffixMatches) { 'OldSuffix filter did not match.' }
                    elseif (-not $IncludeDisabledUsers -and -not $isEnabled) { 'Disabled user excluded.' }
                    elseif ($MailboxEnabledOnly -and -not $isMailboxEnabled) { 'MailboxEnabledOnly was requested and user has no homeMDB.' }
                    else { 'User skipped.' }
                }
            }
        }
    }
}

function Set-PlannedUpn {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -ne 'SetUserPrincipalName') {
        return 'Skipped'
    }

    if ($PSCmdlet.ShouldProcess($Item.DistinguishedName, "Set UPN to $($Item.NewUserPrincipalName)")) {
        $setParameters = @{
            Identity = $Item.DistinguishedName
            UserPrincipalName = $Item.NewUserPrincipalName
        }
        if ($Server) {
            $setParameters.Server = $Server
        }

        Set-ADUser @setParameters
        return 'Changed'
    }

    'Previewed'
}

if (-not $NewSuffix) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$planPath = Join-Path $resolvedReportDirectory "ad-user-upn-suffix-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "ad-user-upn-suffix-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "ad-user-upn-suffix-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "ad-user-upn-suffix-state-$timestamp.json"

$queryParameters = Get-AdUserQueryParameter
$users = @(Get-ADUser @queryParameters | Sort-Object SamAccountName)
$plan = @(Get-UpnUpdatePlan -User $users)
$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $planJsonPath -Value (@($plan) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = try {
        Set-PlannedUpn -Item $item -WhatIf:$WhatIfPreference
    } catch {
        "Failed: $($_.Exception.Message)"
    }

    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $stateJsonPath -Value (@($state) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    SearchBase = $SearchBase
    SearchScope = if ($SearchBase) { $SearchScope } else { $null }
    OldSuffix = $OldSuffix
    NewSuffix = $NewSuffix
    Server = $Server
    MailboxEnabledOnly = [bool]$MailboxEnabledOnly
    IncludeDisabledUsers = [bool]$IncludeDisabledUsers
    LocalPartSource = $LocalPartSource
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    UserCount = @($users).Count
    PlannedChangeCount = @($plan | Where-Object Action -eq 'SetUserPrincipalName').Count
    ChangedCount = @($state | Where-Object Result -eq 'Changed').Count
    PreviewedCount = @($state | Where-Object Result -eq 'Previewed').Count
    SkippedCount = @($state | Where-Object Result -eq 'Skipped').Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Results = @($state)
}
