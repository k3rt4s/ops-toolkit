<#
.SYNOPSIS
Apply a custom or predefined TLS policy to an Azure Application Gateway with plan/state reports.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires Az.Accounts and Az.Network.
- Connect first with Initialize-AzPowerShellSession.ps1 when working in a known tenant.
- Always run with -WhatIf first and review the generated plan/state reports.
- Generated reports are written under reports\azure by default.

.PURPOSE
This script replaces the separate hardened and predefined Application Gateway
TLS policy helpers with one command. It records the current policy, prepares the
requested custom or predefined policy, persists it with Set-AzApplicationGateway,
and writes rollback guidance that captures the previous policy values.

.REQUIRED SYNTAX
pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode CustomHardened -WhatIf
pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode Predefined -PolicyName AppGwSslPolicy20220101S -WhatIf

.OUTPUTS
Writes plan, state, and rollback JSON reports under reports\azure by default.
Returns a summary object with the requested policy and report paths.

.STATUS
Active script kept in the reorganized ops-toolkit repo. Replaces
Set-AzAppGatewayHardenedTlsPolicy.ps1 and Restore-AzAppGatewayPredefinedTlsPolicy.ps1.
#>
#Requires -Modules Az.Accounts, Az.Network
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationGatewayName,

    [Parameter()]
    [ValidateSet('CustomHardened', 'Predefined')]
    [string]$PolicyMode = 'CustomHardened',

    [Parameter()]
    [ValidateSet('TLSv1_2', 'TLSv1_3')]
    [string]$MinimumProtocolVersion = 'TLSv1_2',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$CipherSuite = @(
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyName = 'AppGwSslPolicy20220101S',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode CustomHardened -WhatIf
  pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode Predefined -PolicyName AppGwSslPolicy20220101S -WhatIf

Options:
  -ResourceGroupName        Application Gateway resource group.
  -ApplicationGatewayName   Application Gateway name.
  -PolicyMode               CustomHardened or Predefined. Defaults to CustomHardened.
  -MinimumProtocolVersion   TLSv1_2 or TLSv1_3 for CustomHardened mode. Defaults to TLSv1_2.
  -CipherSuite              Cipher suites to allow for CustomHardened mode.
  -PolicyName               Predefined policy name for Predefined mode.
  -ReportDirectory          Plan/state/rollback output directory.
  -WhatIf                   Preview the gateway update.
'@
}

function Resolve-ReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Join-PolicyValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return (@($Value) | Where-Object { $null -ne $_ }) -join ';'
    }

    [string]$Value
}

function Get-SslPolicyRecord {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Policy
    )

    if (-not $Policy) {
        return [pscustomobject]@{
            PolicyType = $null
            PolicyName = $null
            MinProtocolVersion = $null
            CipherSuites = ''
            DisabledSslProtocols = ''
        }
    }

    [pscustomobject]@{
        PolicyType = $Policy.PolicyType
        PolicyName = $Policy.PolicyName
        MinProtocolVersion = $Policy.MinProtocolVersion
        CipherSuites = Join-PolicyValue $Policy.CipherSuites
        DisabledSslProtocols = Join-PolicyValue $Policy.DisabledSslProtocols
    }
}

if (-not $ResourceGroupName -or -not $ApplicationGatewayName) {
    Show-Usage
    exit 2
}

if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$planPath = Join-Path $resolvedReportDirectory "appgateway-tls-policy-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "appgateway-tls-policy-state-$timestamp.json"
$rollbackPath = Join-Path $resolvedReportDirectory "appgateway-tls-policy-rollback-$timestamp.json"

$gateway = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name $ApplicationGatewayName
$beforePolicy = Get-AzApplicationGatewaySslPolicy -ApplicationGateway $gateway
$beforeRecord = Get-SslPolicyRecord -Policy $beforePolicy

$plan = [pscustomobject]@{
    GeneratedAt = Get-Date
    ResourceGroupName = $ResourceGroupName
    ApplicationGatewayName = $ApplicationGatewayName
    PolicyMode = $PolicyMode
    RequestedPolicyType = if ($PolicyMode -eq 'Predefined') { 'Predefined' } else { 'Custom' }
    RequestedPolicyName = if ($PolicyMode -eq 'Predefined') { $PolicyName } else { $null }
    RequestedMinimumProtocolVersion = if ($PolicyMode -eq 'CustomHardened') { $MinimumProtocolVersion } else { $null }
    RequestedCipherSuites = if ($PolicyMode -eq 'CustomHardened') { $CipherSuite -join ';' } else { '' }
    ExistingPolicy = $beforeRecord
}
Set-Content -LiteralPath $planPath -Value ($plan | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false

$requestedGateway = if ($PolicyMode -eq 'Predefined') {
    Set-AzApplicationGatewaySslPolicy -ApplicationGateway $gateway -PolicyType Predefined -PolicyName $PolicyName
} else {
    Set-AzApplicationGatewaySslPolicy `
        -ApplicationGateway $gateway `
        -PolicyType Custom `
        -MinProtocolVersion $MinimumProtocolVersion `
        -CipherSuite $CipherSuite
}
$result = if ($PSCmdlet.ShouldProcess($ApplicationGatewayName, "Apply Application Gateway TLS policy mode $PolicyMode")) {
    Set-AzApplicationGateway -ApplicationGateway $requestedGateway | Out-Null
    'Applied'
} else {
    'Previewed'
}

$afterPolicy = if ($result -eq 'Applied') {
    $updatedGateway = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name $ApplicationGatewayName
    Get-AzApplicationGatewaySslPolicy -ApplicationGateway $updatedGateway
} else {
    Get-AzApplicationGatewaySslPolicy -ApplicationGateway $requestedGateway
}
$afterRecord = Get-SslPolicyRecord -Policy $afterPolicy

$rollback = [pscustomobject]@{
    GeneratedAt = Get-Date
    ResourceGroupName = $ResourceGroupName
    ApplicationGatewayName = $ApplicationGatewayName
    PreviousPolicy = $beforeRecord
    RestoreMode = if ($beforeRecord.PolicyType -eq 'Predefined') { 'Predefined' } elseif ($beforeRecord.PolicyType) { 'CustomHardened' } else { 'ManualReview' }
    RestoreCommand = if ($beforeRecord.PolicyType -eq 'Predefined' -and $beforeRecord.PolicyName) {
        "pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName '$ResourceGroupName' -ApplicationGatewayName '$ApplicationGatewayName' -PolicyMode Predefined -PolicyName '$($beforeRecord.PolicyName)' -WhatIf"
    } elseif ($beforeRecord.PolicyType -eq 'Custom' -and $beforeRecord.MinProtocolVersion -and $beforeRecord.CipherSuites) {
        "pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName '$ResourceGroupName' -ApplicationGatewayName '$ApplicationGatewayName' -PolicyMode CustomHardened -MinimumProtocolVersion '$($beforeRecord.MinProtocolVersion)' -CipherSuite '$($beforeRecord.CipherSuites -replace ';', ''',''')' -WhatIf"
    } else {
        'Previous TLS policy was empty or could not be converted to an automatic restore command. Review PreviousPolicy.'
    }
}

$state = [pscustomobject]@{
    GeneratedAt = Get-Date
    ResourceGroupName = $ResourceGroupName
    ApplicationGatewayName = $ApplicationGatewayName
    Result = $result
    PolicyBefore = $beforeRecord
    PolicyAfter = $afterRecord
}
Set-Content -LiteralPath $statePath -Value ($state | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $rollbackPath -Value ($rollback | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    ResourceGroupName = $ResourceGroupName
    ApplicationGatewayName = $ApplicationGatewayName
    Result = $result
    PolicyMode = $PolicyMode
    PolicyBefore = $beforeRecord
    PolicyAfter = $afterRecord
    PlanPath = (Resolve-Path -LiteralPath $planPath).Path
    StatePath = (Resolve-Path -LiteralPath $statePath).Path
    RollbackPath = (Resolve-Path -LiteralPath $rollbackPath).Path
}
