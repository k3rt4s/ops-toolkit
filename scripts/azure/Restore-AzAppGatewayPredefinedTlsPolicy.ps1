<#
.SYNOPSIS
Restore an Azure Application Gateway to a predefined TLS policy.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Restore-AzAppGatewayPredefinedTlsPolicy.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationGatewayName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyName = 'AppGwSslPolicy20170401S'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\Restore-AzAppGatewayPredefinedTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyName AppGwSslPolicy20220101S -WhatIf

Options:
  -ResourceGroupName        Application Gateway resource group.
  -ApplicationGatewayName   Application Gateway name.
  -PolicyName               Predefined policy name. Defaults to AppGwSslPolicy20170401S.
  -WhatIf                   Preview the gateway update.
'@
}

if (-not $ResourceGroupName -or -not $ApplicationGatewayName) {
    Show-Usage
    exit 2
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Network -ErrorAction Stop

if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

$gateway = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name $ApplicationGatewayName
Set-AzApplicationGatewaySslPolicy `
    -ApplicationGateway $gateway `
    -PolicyType Predefined `
    -PolicyName $PolicyName | Out-Null

if ($PSCmdlet.ShouldProcess($ApplicationGatewayName, "Apply predefined Application Gateway TLS policy $PolicyName")) {
    Set-AzApplicationGateway -ApplicationGateway $gateway | Out-Null
}

Get-AzApplicationGatewaySslPolicy -ApplicationGateway $gateway


