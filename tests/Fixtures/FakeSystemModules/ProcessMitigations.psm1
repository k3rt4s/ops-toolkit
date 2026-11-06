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
- Set-ProcessMitigation -System -Enable/-Disable updates the state in OPSTOOLKIT_TEST_PM_SYSTEM
  (ON / OFF), so a read-back sees the change like the real cmdlet. Set OPSTOOLKIT_TEST_PM_DROP_ON_SET
  to a comma-separated list of names (for example `DEP,SEHOP`) that the fake accepts without error
  but does not store, the shape a real machine returned for DEP and SEHOP.
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
    Add-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
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
        Set-Content -LiteralPath $RegistryConfigFilePath -Value '<MitigationPolicy />' -Encoding utf8 -WhatIf:$false
        return
    }

    if ($env:OPSTOOLKIT_TEST_PM_SYSTEM -eq 'UNREADABLE') { throw 'Fake Get-ProcessMitigation: unreadable.' }

    # -Name and -Id ask about one process's own policy, not the system defaults the fixture describes, so
    # such a process reports nothing set rather than the system values.
    if (-not $System -and ($Name -or $Id)) {
        return [pscustomobject]@{
            Name = if ($Name) { $Name } else { "$Id" }
            DEP = [pscustomobject]@{ Enable = 'NOTSET'; EmulateAtlThunks = 'NOTSET' }
            ASLR = [pscustomobject]@{ BottomUp = 'NOTSET'; ForceRelocateImages = 'NOTSET'; HighEntropy = 'NOTSET'; DisallowStripped = 'NOTSET' }
            SEHOP = [pscustomobject]@{ Enable = 'NOTSET' }
            CFG = [pscustomobject]@{ Enable = 'NOTSET' }
        }
    }

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

    if ($System -and $env:OPSTOOLKIT_TEST_PM_SYSTEM -ne 'UNREADABLE') {
        $dropped = @(([string]$env:OPSTOOLKIT_TEST_PM_DROP_ON_SET) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $map = [ordered]@{}
        foreach ($pair in @(([string]$env:OPSTOOLKIT_TEST_PM_SYSTEM) -split ';')) {
            $parts = $pair -split '=', 2
            if ($parts.Count -eq 2 -and $parts[0].Trim()) { $map[$parts[0].Trim()] = $parts[1].Trim() }
        }
        foreach ($n in @($Enable)) { if ($n -and $n -notin $dropped) { $map[$n] = 'ON' } }
        foreach ($n in @($Disable)) { if ($n -and $n -notin $dropped) { $map[$n] = 'OFF' } }
        $env:OPSTOOLKIT_TEST_PM_SYSTEM = (@($map.Keys | ForEach-Object { "$_=$($map[$_])" }) -join ';')
    }
}

Export-ModuleMember -Function 'Get-ProcessMitigation', 'Set-ProcessMitigation'
