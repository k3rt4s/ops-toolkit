<#
.SYNOPSIS
Prepare an Az PowerShell session, connect to Azure, select context, and write a session report.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Uses current Az modules only; do not add AzureRM cleanup or AzureRM import behavior.
- Installs Az.Accounts only when -InstallIfMissing is supplied.
- Pass -TenantId, -SubscriptionId, and -AzureEnvironment explicitly when targeting a known tenant.
- Generated session reports are written under reports\azure by default.

.PURPOSE
Use this as the safe bootstrap step before running other Azure scripts in this
repo. It verifies Az.Accounts, optionally installs it for the selected scope,
connects only when needed or requested, selects the requested subscription, and
writes a JSON session summary for review.

.REQUIRED SYNTAX
pwsh -File .\scripts\azure\Initialize-AzPowerShellSession.ps1
pwsh -File .\scripts\azure\Initialize-AzPowerShellSession.ps1 -TenantId "<tenant-id>" -SubscriptionId "<subscription-id>" -UseDeviceAuthentication
pwsh -File .\scripts\azure\Initialize-AzPowerShellSession.ps1 -InstallIfMissing -ModuleInstallScope CurrentUser -WhatIf

.OUTPUTS
Writes an Az session JSON report under reports\azure by default. Returns the
selected Az context, module version, and report path.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$InstallIfMissing,

    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$ModuleInstallScope = 'CurrentUser',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AzureEnvironment,

    [Parameter()]
    [switch]$UseDeviceAuthentication,

    [Parameter()]
    [switch]$ForceLogin,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-ReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Get-AzAccountsModule {
    Get-Module -ListAvailable -Name Az.Accounts |
        Sort-Object Version -Descending |
        Select-Object -First 1
}

$module = Get-AzAccountsModule
if (-not $module) {
    if (-not $InstallIfMissing) {
        throw 'Az.Accounts is not installed. Re-run with -InstallIfMissing or install it with Install-Module Az.Accounts -Scope CurrentUser.'
    }

    if ($PSCmdlet.ShouldProcess("Az.Accounts ($ModuleInstallScope)", 'Install PowerShell module from PSGallery')) {
        Install-Module -Name Az.Accounts -Scope $ModuleInstallScope -Repository PSGallery -AllowClobber -Force
    }

    $module = Get-AzAccountsModule
}

if (-not $module) {
    $resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $resolvedReportDirectory "az-powershell-session-$timestamp.json"
    $summary = [pscustomobject]@{
        GeneratedAt = Get-Date
        LoginResult = 'ModuleInstallPreviewed'
        AzAccountsModuleVersion = $null
        ModuleInstallScope = if ($InstallIfMissing) { $ModuleInstallScope } else { $null }
        TenantIdRequested = $TenantId
        SubscriptionIdRequested = $SubscriptionId
        AzureEnvironmentRequested = $AzureEnvironment
        UseDeviceAuthentication = [bool]$UseDeviceAuthentication
        ForceLogin = [bool]$ForceLogin
        ContextAccount = $null
        ContextTenantId = $null
        ContextSubscriptionId = $null
        ContextSubscriptionName = $null
        ContextEnvironment = $null
        ReportPath = $reportPath
    }
    Set-Content -LiteralPath $reportPath -Value ($summary | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false
    $summary
    return
}

if ($module) {
    Import-Module Az.Accounts -ErrorAction Stop
}

$connectParameters = @{}
if ($TenantId) {
    $connectParameters.Tenant = $TenantId
}
if ($AzureEnvironment) {
    $connectParameters.Environment = $AzureEnvironment
}
if ($UseDeviceAuthentication) {
    $connectParameters.UseDeviceAuthentication = $true
}

$contextBefore = Get-AzContext -ErrorAction SilentlyContinue
$loginResult = 'ExistingContext'
if ($ForceLogin -or -not $contextBefore) {
    if ($PSCmdlet.ShouldProcess('Azure account context', 'Connect to Azure with Az.Accounts')) {
        Connect-AzAccount @connectParameters | Out-Null
        $loginResult = 'Connected'
    } else {
        $loginResult = 'Previewed'
    }
}

if ($SubscriptionId -and $loginResult -ne 'Previewed') {
    if ($PSCmdlet.ShouldProcess($SubscriptionId, 'Select Azure subscription context')) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    } else {
        $loginResult = 'SubscriptionSelectionPreviewed'
    }
}

$contextAfter = Get-AzContext -ErrorAction SilentlyContinue
$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportPath = Join-Path $resolvedReportDirectory "az-powershell-session-$timestamp.json"

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    LoginResult = $loginResult
    AzAccountsModuleVersion = if ($module) { [string]$module.Version } else { $null }
    ModuleInstallScope = if ($InstallIfMissing) { $ModuleInstallScope } else { $null }
    TenantIdRequested = $TenantId
    SubscriptionIdRequested = $SubscriptionId
    AzureEnvironmentRequested = $AzureEnvironment
    UseDeviceAuthentication = [bool]$UseDeviceAuthentication
    ForceLogin = [bool]$ForceLogin
    ContextAccount = if ($contextAfter) { $contextAfter.Account.Id } else { $null }
    ContextTenantId = if ($contextAfter) { $contextAfter.Tenant.Id } else { $null }
    ContextSubscriptionId = if ($contextAfter) { $contextAfter.Subscription.Id } else { $null }
    ContextSubscriptionName = if ($contextAfter) { $contextAfter.Subscription.Name } else { $null }
    ContextEnvironment = if ($contextAfter) { $contextAfter.Environment.Name } else { $null }
    ReportPath = $reportPath
}

Set-Content -LiteralPath $reportPath -Value ($summary | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false
$summary
