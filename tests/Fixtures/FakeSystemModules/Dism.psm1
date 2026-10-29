<#
.SYNOPSIS
Stand-in for the Dism module so scripts that enable or disable Windows optional features never change the real machine.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_OPTFEATURES to a semicolon-separated list of Name=State pairs
  describing the features this pretend build has, for example
  'SMB1Protocol=Enabled;MicrosoftWindowsPowerShellV2Root=Disabled'. A feature that is not
  listed does not exist on the pretend build and Get-WindowsOptionalFeature throws the
  "unknown feature" error for it.
- Set OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE to 'true' to make every read throw the
  elevation error an unelevated session gets on a real machine.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Scripts under test call Get-WindowsOptionalFeature, Enable-WindowsOptionalFeature and
Disable-WindowsOptionalFeature. A same-named function does not reliably shadow commands
exported by a system module, so this module is found first on PSModulePath and the real
Dism module is never loaded. Every mutating function only records a JSON line.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeDismMutation {
    param([string]$Command, [string]$Target, [string]$Detail)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-FakeFeatureTable {
    $table = [ordered]@{}
    foreach ($pair in @(([string][Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_OPTFEATURES')) -split ';')) {
        if (-not $pair) { continue }
        $parts = $pair -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0]) { $table[$parts[0]] = $parts[1] }
    }
    $table
}

function Get-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param(
        [Parameter()][switch]$Online,
        [Parameter()][string]$FeatureName
    )

    if (([string][Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE')) -eq 'true') {
        throw 'The requested operation requires elevation.'
    }
    $table = Get-FakeFeatureTable
    if ($FeatureName) {
        if (-not $table.Contains($FeatureName)) { throw "Feature name $FeatureName is unknown." }
        return [pscustomobject]@{ FeatureName = $FeatureName; State = $table[$FeatureName] }
    }
    foreach ($key in $table.Keys) { [pscustomobject]@{ FeatureName = $key; State = $table[$key] } }
}

function Disable-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()][switch]$Online,
        [Parameter(Mandatory = $true)][string[]]$FeatureName,
        [Parameter()][switch]$NoRestart,
        [Parameter()][switch]$Remove
    )

    foreach ($name in $FeatureName) {
        Write-FakeDismMutation -Command 'Disable-WindowsOptionalFeature' -Target $name -Detail 'RestartNeeded=False'
    }
    [pscustomobject]@{ RestartNeeded = $false }
}

function Enable-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()][switch]$Online,
        [Parameter(Mandatory = $true)][string[]]$FeatureName,
        [Parameter()][switch]$NoRestart,
        [Parameter()][switch]$All
    )

    foreach ($name in $FeatureName) {
        Write-FakeDismMutation -Command 'Enable-WindowsOptionalFeature' -Target $name -Detail 'RestartNeeded=False'
    }
    [pscustomobject]@{ RestartNeeded = $false }
}

Export-ModuleMember -Function 'Get-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Enable-WindowsOptionalFeature'
