#Requires -Modules Pester

# An unelevated -WhatIf run of a hardening script lists what it would change instead of listing skips.
#   - A read item that needs a change goes through ShouldProcess and is 'Previewed'.
#   - An item whose current value could not be read is 'Skipped: requires elevation (not read)', never
#     'Previewed', because the checker counts Previewed as Drifted and that would hide that it was never read.
#   - An unelevated live run is unchanged: 'Skipped: requires elevation', nothing recorded.
#   - Nothing is recorded under -WhatIf.
# Three scripts: a registry-only one (Set-WindowsCredentialProtection), Set-WindowsFirewallBaseline and
# Enable-BitLockerOsVolume. The staged fake modules and recorders stand in for the machine. The assertions only
# hold in an unelevated session; an elevated one skips them (it would apply the fixture changes to the recorders).

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'HostContextFixture.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-unelwhatif-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:hostFixture = Use-FakeHostContext -Directory $script:workRoot
    $script:savedHostEnvironment = Set-FakeHostEnvironment -Fixture $script:hostFixture -Confirm:$false

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $script:noOrgSettings = "`$env:OPSTOOLKIT_TEST_ORGSETTINGS_PATH = '$(Join-Path $script:workRoot 'no-such-settings.json')'`n"

    function Get-ItemResult {
        param($Run, [string]$Setting)
        @(@($Run.Summary.Items) | Where-Object { $_.Setting -eq $Setting })
    }

    function Assert-Unelevated {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'; return $false }
        $true
    }

    # ---- registry-only: Set-WindowsCredentialProtection ----
    $script:credScript = 'scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1'
    $script:lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $script:registryShadow = @'

function Get-ItemProperty {
    param($Path, $LiteralPath, $Name, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($env:OPSTOOLKIT_TEST_REGISTRY_ON -ne '1' -or $target -notlike 'HKLM:*') {
        return Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
    }
    $map = $env:OPSTOOLKIT_TEST_REGISTRY | ConvertFrom-Json
    $entry = $map.PSObject.Properties[$target]
    if ($null -eq $entry) { throw [System.Management.Automation.ItemNotFoundException]::new("Cannot find path '$target'") }
    $entry.Value
}

function Test-Path {
    param($Path, $LiteralPath, $PathType, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($env:OPSTOOLKIT_TEST_REGISTRY_ON -ne '1' -or $target -notlike 'HKLM:*') {
        return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
    }
    $map = $env:OPSTOOLKIT_TEST_REGISTRY | ConvertFrom-Json
    return ($null -ne $map.PSObject.Properties[$target])
}
'@

    # ---- Set-WindowsFirewallBaseline ----
    $script:fwScript = 'scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1'
    $script:netshStub = @'
function netsh.exe {
    if ($args.Count -ge 3 -and $args[0] -eq 'advfirewall' -and $args[1] -eq 'export') {
        Set-Content -LiteralPath $args[2] -Value 'fake wfw' -WhatIf:$false
        Write-OpsTestMutation -Command 'netsh.exe' -Target ($args -join ' ') -Detail ''
        return
    }
    Write-OpsTestMutation -Command 'netsh.exe' -Target ($args -join ' ') -Detail 'unexpected'
}
'@
    function New-FirewallFixture {
        param([string]$Name, [string[]]$ProfileName)
        $rulesFile = Join-Path $script:workRoot "$Name-rules.json"
        $profilesFile = Join-Path $script:workRoot "$Name-profiles.json"
        ConvertTo-Json -InputObject @() -Depth 5 | Set-Content -LiteralPath $rulesFile
        $profiles = @($ProfileName | ForEach-Object {
                @{ Name = $_; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow'
                    NotifyOnListen = 'True'; LogBlocked = 'False'; LogMaxSizeKilobytes = 4096 }
            })
        ConvertTo-Json -InputObject $profiles -Depth 5 | Set-Content -LiteralPath $profilesFile
        "`$env:OPSTOOLKIT_TEST_FW_RULES_FILE = '$rulesFile'`n`$env:OPSTOOLKIT_TEST_FW_PROFILES_FILE = '$profilesFile'`n"
    }

    # ---- Enable-BitLockerOsVolume ----
    $script:blScript = 'scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1'
    $script:blGoodEnv = @"
`$env:SystemDrive = 'Q:'
`$env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyDecrypted","ProtectionStatus":"Off","EncryptionMethod":"None","KeyProtector":[]}]'
`$env:OPSTOOLKIT_TEST_TPM_PRESENT = '1'
`$env:OPSTOOLKIT_TEST_TPM_READY = '1'
`$env:OPSTOOLKIT_TEST_SECUREBOOT = 'true'
"@
}

AfterAll {
    if ($script:savedHostEnvironment) { Restore-FakeHostEnvironment -Saved $script:savedHostEnvironment -Confirm:$false }
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsCredentialProtection, unelevated (registry only)' {
    BeforeAll {
        # RunAsPPL exists with a null value (the read cannot give a value: unknown); every other value is absent (read).
        $registry = @{ $script:lsa = @{ RunAsPPL = $null } } | ConvertTo-Json -Depth 5 -Compress
        $fixture = "`$env:OPSTOOLKIT_TEST_REGISTRY_ON = '1'`n`$env:OPSTOOLKIT_TEST_REGISTRY = '$registry'`n`$env:OPSTOOLKIT_TEST_SECUREBOOT = 'true'`n"
        $script:cred = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:credScript -Tag 'unel-cred' -ExtraSetup ($script:registryShadow + $script:noOrgSettings) -FixtureEnvironment $fixture `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'unel-cred') }
    }

    It 'completes both runs' {
        $script:cred.WhatIf.ExitCode | Should -Be 0 -Because $script:cred.WhatIf.Output
        $script:cred.Execute.ExitCode | Should -Be 0 -Because $script:cred.Execute.Output
    }

    It 'previews a value that was read and needs a change' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:cred.WhatIf -Setting 'UseLogonCredential').Result | Should -Be 'Previewed'
    }

    It 'does not call a value that could not be read Previewed' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:cred.WhatIf -Setting 'RunAsPPL').Result | Should -Be 'Skipped: requires elevation (not read)'
    }

    It 'records nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:cred
    }

    It 'still skips every admin item on an unelevated live run, with nothing recorded' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:cred.Execute -Setting 'UseLogonCredential').Result | Should -Be 'Skipped: requires elevation'
        (Get-ItemResult -Run $script:cred.Execute -Setting 'RunAsPPL').Result | Should -Be 'Skipped: requires elevation'
        @(Get-OpsMutationRecord -Path $script:cred.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WindowsFirewallBaseline, unelevated' {
    BeforeAll {
        # The Public profile is missing from the read, so its rows are unknown; Domain and Private are read and open.
        $fixture = New-FirewallFixture -Name 'unel-fw' -ProfileName 'Domain', 'Private'
        $script:fw = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:fwScript -Tag 'unel-fw' -FixtureEnvironment ($script:noOrgSettings + $fixture) -ExtraSetup $script:netshStub `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'unel-fw') }
    }

    It 'completes both runs' {
        $script:fw.WhatIf.ExitCode | Should -Be 0 -Because $script:fw.WhatIf.Output
        $script:fw.Execute.ExitCode | Should -Be 0 -Because $script:fw.Execute.Output
    }

    It 'previews a profile setting that was read and needs a change' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:fw.WhatIf -Setting 'Domain.DefaultInboundAction').Result | Should -Be 'Previewed'
    }

    It 'does not call a profile setting that could not be read Previewed' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:fw.WhatIf -Setting 'Public.DefaultInboundAction').Result | Should -Be 'Skipped: requires elevation (not read)'
    }

    It 'records nothing but the firewall backup under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:fw -IgnoreCommand 'netsh.exe'
    }

    It 'still skips on an unelevated live run, with nothing recorded but the backup' {
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:fw.Execute -Setting 'Domain.DefaultInboundAction').Result | Should -Be 'Skipped: requires elevation'
        (Get-ItemResult -Run $script:fw.Execute -Setting 'Public.DefaultInboundAction').Result | Should -Be 'Skipped: requires elevation'
        @(Get-OpsMutationRecord -Path $script:fw.ExecuteLog | Where-Object { $_.Command -ne 'netsh.exe' }).Count | Should -Be 0
    }
}

Describe 'Enable-BitLockerOsVolume, unelevated' {
    BeforeAll {
        $script:blKeys = Join-Path $script:workRoot 'unel-bl-keys'
        New-Item -ItemType Directory -Path $script:blKeys -Force | Out-Null
        $arg = { param($Tag) @{ ReportDirectory = (Join-Path $script:workRoot $Tag); RecoveryKeyDirectory = $script:blKeys } }
        $script:blRead = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:blScript -Tag 'unel-bl-read' -FixtureEnvironment ($script:noOrgSettings + $script:blGoodEnv + "`n") -Argument (& $arg 'unel-bl-read')
        $script:blUnread = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:blScript -Tag 'unel-bl-unread' `
            -FixtureEnvironment ($script:noOrgSettings + $script:blGoodEnv + "`n`$env:OPSTOOLKIT_TEST_BL_READERROR = '1'`n") -Argument (& $arg 'unel-bl-unread')
    }

    It 'previews the enable when the volume state was read' {
        $script:blRead.WhatIf.ExitCode | Should -Be 0 -Because $script:blRead.WhatIf.Output
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:blRead.WhatIf -Setting 'Q:').Result | Should -Be 'Previewed'
    }

    It 'does not call the enable Previewed when the volume state could not be read' {
        $script:blUnread.WhatIf.ExitCode | Should -Be 0 -Because $script:blUnread.WhatIf.Output
        if (-not (Assert-Unelevated)) { return }
        (Get-ItemResult -Run $script:blUnread.WhatIf -Setting 'Q:').Result | Should -Be 'Skipped: requires elevation (not read)'
    }

    It 'records nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:blRead
        Assert-OpsNoChangeUnderWhatIf -Pair $script:blUnread
    }

    It 'still fails an unelevated live run with the enable skipped and nothing changed' {
        if (-not (Assert-Unelevated)) { return }
        $script:blRead.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $script:blRead.ExecuteLog | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
        $file = Get-ChildItem -LiteralPath (Join-Path $script:workRoot 'unel-bl-read') -Filter '*-apply-state-*.json' -File | Sort-Object LastWriteTime | Select-Object -Last 1
        $row = @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Setting -eq 'Q:' }
        $row.Result | Should -Be 'Skipped: requires elevation'
    }
}
