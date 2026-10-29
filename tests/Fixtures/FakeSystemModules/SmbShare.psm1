<#
.SYNOPSIS
Stand-in for the SmbShare module so scripts that change SMB server or client settings never change the real machine.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_SMB_SERVER_SMB1 to 'true' to plant a server with SMB1 enabled
  (unset or anything else means disabled).
- Set OPSTOOLKIT_TEST_SMB_SERVER_SIGNING and OPSTOOLKIT_TEST_SMB_CLIENT_SIGNING to 'true'
  to plant RequireSecuritySignature already enabled.
- Set OPSTOOLKIT_TEST_SMB_UNREADABLE to 'true' to make every Get-* throw, as an
  unelevated session does on a real machine.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Scripts under test call Get-SmbServerConfiguration, Get-SmbClientConfiguration,
Set-SmbServerConfiguration and Set-SmbClientConfiguration. A same-named function does not
reliably shadow commands exported by a system module, so this module is found first on
PSModulePath and the real SmbShare module is never loaded. Every setter only records a
JSON line; none changes anything.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeSmbMutation {
    param([string]$Command, [string]$Target, [string]$Detail)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Test-FakeSmbFlag {
    param([string]$Name)
    ([string][Environment]::GetEnvironmentVariable($Name)) -eq 'true'
}

function Get-SmbServerConfiguration {
    [CmdletBinding()]
    param()

    if (Test-FakeSmbFlag 'OPSTOOLKIT_TEST_SMB_UNREADABLE') { throw 'Access is denied.' }
    [pscustomobject]@{
        EnableSMB1Protocol = (Test-FakeSmbFlag 'OPSTOOLKIT_TEST_SMB_SERVER_SMB1')
        EnableSMB2Protocol = $true
        RequireSecuritySignature = (Test-FakeSmbFlag 'OPSTOOLKIT_TEST_SMB_SERVER_SIGNING')
        EnableSecuritySignature = $true
    }
}

function Get-SmbClientConfiguration {
    [CmdletBinding()]
    param()

    if (Test-FakeSmbFlag 'OPSTOOLKIT_TEST_SMB_UNREADABLE') { throw 'Access is denied.' }
    [pscustomobject]@{
        RequireSecuritySignature = (Test-FakeSmbFlag 'OPSTOOLKIT_TEST_SMB_CLIENT_SIGNING')
        EnableSecuritySignature = $true
    }
}

function Set-SmbServerConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()][bool]$EnableSMB1Protocol,
        [Parameter()][bool]$EnableSMB2Protocol,
        [Parameter()][bool]$RequireSecuritySignature,
        [Parameter()][bool]$EnableSecuritySignature,
        [Parameter()][switch]$Force
    )

    $detail = (@($PSBoundParameters.Keys | Where-Object { $_ -notin @('Force', 'Confirm', 'WhatIf') } |
                Sort-Object | ForEach-Object { "$_=$($PSBoundParameters[$_])" })) -join ';'
    Write-FakeSmbMutation -Command 'Set-SmbServerConfiguration' -Target 'SmbServer' -Detail $detail
}

function Set-SmbClientConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()][bool]$RequireSecuritySignature,
        [Parameter()][bool]$EnableSecuritySignature,
        [Parameter()][switch]$Force
    )

    $detail = (@($PSBoundParameters.Keys | Where-Object { $_ -notin @('Force', 'Confirm', 'WhatIf') } |
                Sort-Object | ForEach-Object { "$_=$($PSBoundParameters[$_])" })) -join ';'
    Write-FakeSmbMutation -Command 'Set-SmbClientConfiguration' -Target 'SmbClient' -Detail $detail
}

Export-ModuleMember -Function 'Get-SmbServerConfiguration', 'Get-SmbClientConfiguration', 'Set-SmbServerConfiguration', 'Set-SmbClientConfiguration'
