<#
.SYNOPSIS
Install or import Az.Accounts, connect to Azure, and optionally select a subscription.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Initialize-AzPowerShellSession.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$InstallIfMissing,

    [Parameter()]
    [string]$SubscriptionId,

    [Parameter()]
    [switch]$UseDeviceAuthentication
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$azAccounts = Get-Module -ListAvailable -Name Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1
if (-not $azAccounts) {
    if (-not $InstallIfMissing) {
        throw 'Az.Accounts is not installed. Re-run with -InstallIfMissing or install it with Install-Module Az.Accounts -Scope CurrentUser.'
    }

    if ($PSCmdlet.ShouldProcess('Az.Accounts', 'Install PowerShell module for current user')) {
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository PSGallery -AllowClobber -Force
    }
}

Import-Module Az.Accounts -ErrorAction Stop

$connectParameters = @{}
if ($UseDeviceAuthentication) {
    $connectParameters.UseDeviceAuthentication = $true
}

if (-not (Get-AzContext)) {
    Connect-AzAccount @connectParameters | Out-Null
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

Get-AzContext


