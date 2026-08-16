<#
.SYNOPSIS
Stand-in for the Defender module so scripts that add exclusions never change real antivirus settings.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_MP_EXCLUSIONPATH and OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS to
  semicolon-separated lists describing the exclusions that already exist.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Relying on a same-named function in the caller's scope to shadow Add-MpPreference did
not work, and a test run added three real Defender path exclusions to a development
machine before that was noticed. An antivirus exclusion is a security control, so this
module exists to make it impossible for a test to create one: the real Defender module
is never loaded, because this one is found first.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeMpMutation {
    param([string]$Command, [string]$Target)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = '' } | ConvertTo-Json -Compress)
}

function Get-MpPreference {
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        ExclusionPath    = @(($env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH -split ';') | Where-Object { $_ })
        ExclusionProcess = @(($env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS -split ';') | Where-Object { $_ })
    }
}

function Add-MpPreference {
    [CmdletBinding()]
    param([Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force)
    Write-FakeMpMutation -Command 'Add-MpPreference' -Target ((@($ExclusionPath) + @($ExclusionProcess) | Where-Object { $_ }) -join ';')
}

function Set-MpPreference {
    [CmdletBinding()]
    param([Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force)
    Write-FakeMpMutation -Command 'Set-MpPreference' -Target ((@($ExclusionPath) + @($ExclusionProcess) | Where-Object { $_ }) -join ';')
}

function Remove-MpPreference {
    [CmdletBinding()]
    param([Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force)
    Write-FakeMpMutation -Command 'Remove-MpPreference' -Target ((@($ExclusionPath) + @($ExclusionProcess) | Where-Object { $_ }) -join ';')
}

Export-ModuleMember -Function 'Get-MpPreference', 'Add-MpPreference', 'Set-MpPreference', 'Remove-MpPreference'
