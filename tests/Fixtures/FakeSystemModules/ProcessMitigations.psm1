<#
.SYNOPSIS
Stand-in for the ProcessMitigations module so scripts that set exploit protection never change real mitigations.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_PM_SYSTEM to a semicolon-separated list of Name=State pairs describing
  the system-wide mitigations that already exist, for example `DEP=ON;BottomUp=ON;SEHOP=OFF`.
  Names: DEP, BottomUp, HighEntropy, ForceRelocateImages, SEHOP, CFG. States: ON, OFF, NOTSET.
  A name that is not listed reads NOTSET. The value `UNREADABLE` makes Get-ProcessMitigation throw.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Get-ProcessMitigation and Set-ProcessMitigation come from a system module, so a same-named
function in the caller's scope does not reliably shadow them. Exploit protection is a
security control, so this module exists to make it impossible for a test to change it.
Get-ProcessMitigation with -RegistryConfigFilePath records the export and writes a small
placeholder file so the export can be checked for; the real cmdlet writes an XML policy file.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakePmMutation {
    param([string]$Command, [string]$Target, [string]$Detail)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-FakePmState {
    param([string]$Name)
    foreach ($pair in @(([string]$env:OPSTOOLKIT_TEST_PM_SYSTEM) -split ';')) {
        $parts = $pair -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0].Trim() -eq $Name) { return $parts[1].Trim() }
    }
    'NOTSET'
}

function Get-ProcessMitigation {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$System,
        [Parameter()][string]$Name,
        [Parameter()][int]$Id,
        [Parameter()][string]$RegistryConfigFilePath,
        [Parameter()][switch]$FullPolicy
    )

    if ($RegistryConfigFilePath) {
        Write-FakePmMutation -Command 'Get-ProcessMitigation' -Target $RegistryConfigFilePath -Detail 'RegistryConfigFilePath export'
        Set-Content -LiteralPath $RegistryConfigFilePath -Value '<MitigationPolicy />' -Encoding utf8
        return
    }

    if ($env:OPSTOOLKIT_TEST_PM_SYSTEM -eq 'UNREADABLE') { throw 'Fake Get-ProcessMitigation: unreadable.' }

    [pscustomobject]@{
        Name = 'System'
        DEP = [pscustomobject]@{ Enable = (Get-FakePmState 'DEP'); EmulateAtlThunks = 'NOTSET' }
        ASLR = [pscustomobject]@{
            BottomUp = (Get-FakePmState 'BottomUp')
            ForceRelocateImages = (Get-FakePmState 'ForceRelocateImages')
            HighEntropy = (Get-FakePmState 'HighEntropy')
            DisallowStripped = 'NOTSET'
        }
        SEHOP = [pscustomobject]@{ Enable = (Get-FakePmState 'SEHOP') }
        CFG = [pscustomobject]@{ Enable = (Get-FakePmState 'CFG') }
    }
}

function Set-ProcessMitigation {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$System,
        [Parameter()][string]$Name,
        [Parameter()][int]$Id,
        [Parameter()][string[]]$Enable,
        [Parameter()][string[]]$Disable,
        [Parameter()][string]$PolicyFilePath,
        [Parameter()][switch]$Remove
    )

    $target = if ($System) { 'System' } elseif ($Name) { $Name } elseif ($PolicyFilePath) { $PolicyFilePath } else { '' }
    $detail = @(
        if ($Enable) { 'Enable:' + (@($Enable) -join ',') }
        if ($Disable) { 'Disable:' + (@($Disable) -join ',') }
        if ($PolicyFilePath) { 'PolicyFilePath' }
    ) -join ' '
    Write-FakePmMutation -Command 'Set-ProcessMitigation' -Target $target -Detail $detail
}

Export-ModuleMember -Function 'Get-ProcessMitigation', 'Set-ProcessMitigation'
