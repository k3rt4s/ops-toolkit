<#
.SYNOPSIS
Apply a hardened custom TLS policy to an Azure Application Gateway.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-AzAppGatewayHardenedTlsPolicy.ps1 -Full or by opening the script.
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
    [ValidateSet('TLSv1_2', 'TLSv1_3')]
    [string]$MinimumProtocolVersion = 'TLSv1_2',

    [Parameter()]
    [string[]]$CipherSuite = @(
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    )
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\Set-AzAppGatewayHardenedTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -WhatIf

Options:
  -ResourceGroupName        Application Gateway resource group.
  -ApplicationGatewayName   Application Gateway name.
  -MinimumProtocolVersion   TLSv1_2 or TLSv1_3. Defaults to TLSv1_2.
  -CipherSuite              Cipher suites to allow.
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
    -PolicyType Custom `
    -MinProtocolVersion $MinimumProtocolVersion `
    -CipherSuite $CipherSuite | Out-Null

if ($PSCmdlet.ShouldProcess($ApplicationGatewayName, 'Apply hardened Application Gateway TLS policy')) {
    Set-AzApplicationGateway -ApplicationGateway $gateway | Out-Null
}

Get-AzApplicationGatewaySslPolicy -ApplicationGateway $gateway


