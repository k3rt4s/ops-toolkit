#Requires -Modules Pester

# Set-WindowsNetworkProtocolHardening.ps1 as a pair: -WhatIf must record nothing, and the
# executing run must record the SMB, optional feature and registry changes it promised.
#
# SmbShare and Dism are reached through staged fake modules (tests\Fixtures\FakeSystemModules),
# whose state comes from OPSTOOLKIT_TEST_* variables set below. Registry writes are stubbed
# by Get-WindowsMutationStubText; registry READS are real, so the registry-backed items show
# this machine's current values and are only asserted on their targets and desired values.
#
# Every control needs administrator rights. The suite is normally run unelevated, where the
# script previews each item whose value was read under -WhatIf (an unread one is 'Skipped: requires
# elevation (not read)', a live run 'Skipped: requires elevation') and the mutation assertions are
# skipped; the plan JSON assertions still run because an unelevated run writes the plan.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-netproto-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    Import-Module (Join-Path $PSScriptRoot 'HostContextFixture.psm1') -Force
    $script:hostFixture = Use-FakeHostContext -Directory $script:workRoot
    $script:savedHostEnvironment = Set-FakeHostEnvironment -Fixture $script:hostFixture -Confirm:$false
    $script:relativePath = 'scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1'

    # Under pwsh 7 the script reads and changes optional features through dism.exe, so every run
    # below is pointed at a stand-in executable (Dism.psm1, Write-FakeDismExecutable). The real
    # dism.exe is never started: Get-FixtureEnvironment makes -DismPath default to the stand-in for
    # any script a run launches, and the 'stand-in' test proves that default is the one in force.
    Import-Module (Join-Path $PSScriptRoot 'Fixtures\FakeSystemModules\Dism.psm1') -Function Write-FakeDismExecutable
    $script:fakeDism = Write-FakeDismExecutable -Directory (Join-Path $script:workRoot 'fake-dism')

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    function Get-FixtureEnvironment {
        param([string]$Smb1 = 'false', [string]$Features = '', [string]$Unreadable = 'false', [string]$Extra = '')
        @"

`$env:OPSTOOLKIT_TEST_TASKS = ''
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''
`$env:OPSTOOLKIT_TEST_PRINTERS = ''
`$env:OPSTOOLKIT_TEST_SMB_SERVER_SMB1 = '$Smb1'
`$env:OPSTOOLKIT_TEST_SMB_UNREADABLE = '$Unreadable'
`$env:OPSTOOLKIT_TEST_OPTFEATURES = '$Features'
`$env:OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE = '$Unreadable'
`$PSDefaultParameterValues['*:DismPath'] = '$($script:fakeDism)'
$Extra
"@
    }

    function Get-DismChange {
        param($Record, [string]$Verb)
        @($Record | Where-Object { $_.Command -eq 'Dism.exe' -and $_.Detail -eq "/$Verb" })
    }

    function Get-PlanItem {
        param($Pair)
        @(Get-Content -LiteralPath $Pair.Execute.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
    }

    # A copy of the script that reports itself elevated, so the executing half can run in an
    # unelevated session, and that imports the module by absolute path because the copy sits in the
    # work root. Every write still goes to the mutation stubs.
    function New-ElevatedScriptCopy {
        param([string]$Name)
        $source = Join-Path (Get-RepositoryRoot) $script:relativePath
        $text = Get-Content -LiteralPath $source -Raw
        $elevated = '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
        $text.Contains($elevated) | Should -BeTrue -Because 'the elevation check this copy replaces must still exist'
        $import = "(Join-Path `$PSScriptRoot '..\..\..\modules\OpsToolkit.Hardening')"
        $text.Contains($import) | Should -BeTrue -Because 'the module import this copy replaces must still exist'
        $module = Join-Path (Get-RepositoryRoot) 'modules\OpsToolkit.Hardening'
        $patched = $text.Replace($elevated, '$true').Replace($import, "'$module'")
        $copy = Join-Path $script:workRoot "$Name.ps1"
        Set-Content -LiteralPath $copy -Value $patched -Encoding utf8
        [System.IO.Path]::GetRelativePath((Get-RepositoryRoot), $copy)
    }

    # Replaces the MSV1_0 key read with a table so no NTLM assertion depends on this machine.
    # Values is 'none' (key present, no values) or 'Name=1;Other=2'.
    $script:msv1ShadowPath = Join-Path $PSScriptRoot 'Fixtures\Msv1Shadow.ps1'
    function Get-Msv1FixtureText {
        param([string]$Values = 'none')
        "`n`$env:OPSTOOLKIT_TEST_MSV1 = '$Values'`n" + (Get-Content -LiteralPath $script:msv1ShadowPath -Raw)
    }
}

AfterAll {
    if ($script:savedHostEnvironment) { Restore-FakeHostEnvironment -Saved $script:savedHostEnvironment -Confirm:$false }
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsNetworkProtocolHardening with SMB1 and features enabled' {
    BeforeAll {
        $features = 'SMB1Protocol=Enabled;SMB1Protocol-Client=Enabled;SMB1Protocol-Server=Enabled;MicrosoftWindowsPowerShellV2Root=Enabled;MicrosoftWindowsPowerShellV2=Enabled'
        $script:on = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-on' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'true' -Features $features) `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'on')
            DisableMulticastDns = $true
            NetbiosInterface = @('Tcpip_{no-such-interface}')
        }
    }

    It 'runs to completion in both modes' {
        $script:on.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:on.WhatIf.Output)"
        $script:on.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:on.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:on
    }

    It 'plans SMB1 server, feature, signing, LLMNR and mDNS changes in the plan JSON' {
        $plan = Get-PlanItem -Pair $script:on
        $smb = @($plan | Where-Object Category -eq 'Smb1Server')
        $smb.Count | Should -Be 1
        $smb[0].CurrentValue | Should -Be 'True'
        $smb[0].DesiredValue | Should -Be 'False'
        $smb[0].RequiresAdmin | Should -BeTrue

        foreach ($name in 'SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') {
            $f = @($plan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq $name })
            $f.Count | Should -Be 1 -Because $name
            $f[0].CurrentValue | Should -Be 'Enabled'
            $f[0].DesiredValue | Should -Be 'Disabled'
            $f[0].RequiresReboot | Should -BeTrue
            $f[0].Action | Should -Not -BeLike 'No change*'
        }

        # The sub-feature SMB1Protocol-Deprecation is not planted, so it does not exist here.
        $dep = @($plan | Where-Object Setting -eq 'SMB1Protocol-Deprecation')
        $dep[0].CurrentValue | Should -Be 'absent'
        $dep[0].Action | Should -BeLike 'No change*'

        $values = @{}
        foreach ($i in @($plan | Where-Object Kind -eq 'Registry')) { $values["$($i.RegistryPath)\$($i.ValueName)"] = "$($i.DesiredValue)" }
        $values['HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'] | Should -Be '1'
        $values['HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature'] | Should -Be '1'
        $values['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'] | Should -Be '0'
        $values['HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS'] | Should -Be '0'
    }

    It 'adds no NetBIOS item when the interface filter matches nothing' {
        @(Get-PlanItem -Pair $script:on | Where-Object Category -eq 'NetBIOS').Count | Should -Be 0
    }

    It 'disables SMB1 and the features when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'session is not elevated; the plan assertions above still ran'; return }
        $m = @(Get-OpsMutationRecord -Path $script:on.ExecuteLog)
        $smb = @($m | Where-Object Command -eq 'Set-SmbServerConfiguration')
        $smb.Count | Should -Be 1
        $smb[0].Detail | Should -Be 'EnableSMB1Protocol=False'
        $feat = @(Get-DismChange -Record $m -Verb 'Disable-Feature' | ForEach-Object { $_.Target })
        $feat | Should -Contain 'SMB1Protocol'
        $feat | Should -Contain 'MicrosoftWindowsPowerShellV2Root'
        @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*EnableMulticast' }).Count | Should -Be 1
        $script:on.Execute.Summary.RebootRequired | Should -BeTrue
        $script:on.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
    }

    It 'applies nothing and writes no rollback file when not elevated' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'session is elevated'; return }
        @(Get-OpsMutationRecord -Path $script:on.ExecuteLog | Where-Object { $_.Command -ne 'New-Item' }).Count | Should -Be 0
        $script:on.Execute.Summary.RebootRequired | Should -BeFalse
        $script:on.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
        @($script:on.Execute.Summary.Items | Where-Object { $_.Result -like 'Skipped: requires elevation' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Set-WindowsNetworkProtocolHardening opt-in -DisableWpad' {
    BeforeAll {
        $script:wpadPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        $script:wpadDefault = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-wpad-default' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'false' -Features 'SMB1Protocol=Disabled') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'wpad-default'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $script:wpadOn = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-wpad-on' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'false' -Features 'SMB1Protocol=Disabled') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'wpad-on'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}'); DisableWpad = $true }
    }

    It 'runs to completion in both modes' {
        $script:wpadDefault.Execute.ExitCode | Should -Be 0 -Because $script:wpadDefault.Execute.Output
        $script:wpadOn.WhatIf.ExitCode | Should -Be 0 -Because $script:wpadOn.WhatIf.Output
        $script:wpadOn.Execute.ExitCode | Should -Be 0 -Because $script:wpadOn.Execute.Output
    }

    It 'does not plan WPAD in the default run' {
        $plan = @(Get-PlanItem -Pair $script:wpadDefault)
        $plan.Count | Should -BeGreaterThan 0
        @($plan | Where-Object Category -eq 'Wpad').Count | Should -Be 0
        @($plan | Where-Object { $_.ValueName -eq 'DisableWpad' }).Count | Should -Be 0
    }

    It 'plans DisableWpad = 1 under the WinHttp key with the switch' {
        $plan = @(Get-PlanItem -Pair $script:wpadOn)
        $plan.Count | Should -BeGreaterThan 0
        $wpad = @($plan | Where-Object Category -eq 'Wpad')
        $wpad.Count | Should -Be 1
        $wpad[0].Kind | Should -Be 'Registry'
        $wpad[0].RegistryPath | Should -Be $script:wpadPath
        $wpad[0].ValueName | Should -Be 'DisableWpad'
        "$($wpad[0].DesiredValue)" | Should -Be '1'
        $wpad[0].RequiresAdmin | Should -BeTrue
    }

    It 'writes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:wpadOn
    }

    It 'writes the value, creating the key only when missing, when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'session is not elevated; the plan assertions above still ran'; return }
        $wpad = @(Get-PlanItem -Pair $script:wpadOn | Where-Object Category -eq 'Wpad')
        $wpad.Count | Should -Be 1
        if ($wpad[0].Action -like 'No change*') { Set-ItResult -Skipped -Because 'this machine already has DisableWpad = 1'; return }
        $m = @(Get-OpsMutationRecord -Path $script:wpadOn.ExecuteLog)
        @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*DisableWpad' }).Count | Should -Be 1
    }

    It 'applies nothing for WPAD when not elevated' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'session is elevated'; return }
        @(Get-OpsMutationRecord -Path $script:wpadOn.ExecuteLog | Where-Object { $_.Command -ne 'New-Item' }).Count | Should -Be 0
        $item = @($script:wpadOn.Execute.Summary.Items | Where-Object Category -eq 'Wpad')
        $item.Count | Should -Be 1
        $item[0].Result | Should -BeIn @('Skipped: requires elevation', 'NoChange')
    }

    It 'restores the prior value, or removes the value the run added, on rollback' {
        $dir = Join-Path $script:workRoot 'wpad-rb'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $entry = { param($prior) [pscustomobject]@{ Category = 'Wpad'; Setting = 'WinHttp DisableWpad'; Kind = 'Registry'; RegistryPath = $script:wpadPath; ValueName = 'DisableWpad'; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $false; PriorValue = $prior; AppliedValue = 1 } }
        [pscustomobject]@{ Timestamp = '20250101_000000'; ChangedSettings = @(& $entry 'absent') } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'network-protocol-hardening-rollback-20250101_000000.json') -Encoding utf8
        $rb = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-wpad-rb' `
            -FixtureEnvironment (Get-FixtureEnvironment) `
            -Argument @{ ReportDirectory = $dir; Rollback = $true }
        $rb.Execute.ExitCode | Should -Be 0 -Because $rb.Execute.Output
        Assert-OpsNoChangeUnderWhatIf -Pair $rb
        $plan = @(Get-PlanItem -Pair $rb)
        $plan.Count | Should -Be 1
        $plan[0].Category | Should -Be 'Wpad'
        $plan[0].DesiredValue | Should -Be 'absent'
        if ($script:isElevated) {
            $m = @(Get-OpsMutationRecord -Path $rb.ExecuteLog)
            @($m | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -like '*DisableWpad' }).Count | Should -Be 1
        }
    }

    It 'restores a recorded numeric prior value on rollback' {
        $dir = Join-Path $script:workRoot 'wpad-rb0'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [pscustomobject]@{ Timestamp = '20250101_000000'; ChangedSettings = @([pscustomobject]@{ Category = 'Wpad'; Setting = 'WinHttp DisableWpad'; Kind = 'Registry'; RegistryPath = $script:wpadPath; ValueName = 'DisableWpad'; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $false; PriorValue = 0; AppliedValue = 1 }) } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'network-protocol-hardening-rollback-20250101_000000.json') -Encoding utf8
        $rb = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-wpad-rb0' `
            -FixtureEnvironment (Get-FixtureEnvironment) `
            -Argument @{ ReportDirectory = $dir; Rollback = $true }
        $rb.Execute.ExitCode | Should -Be 0 -Because $rb.Execute.Output
        $plan = @(Get-PlanItem -Pair $rb)
        $plan.Count | Should -Be 1
        "$($plan[0].DesiredValue)" | Should -Be '0'
        if ($script:isElevated) {
            $m = @(Get-OpsMutationRecord -Path $rb.ExecuteLog)
            $set = @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*DisableWpad' })
            $set.Count | Should -Be 1
            $set[0].Detail | Should -Be '0'
        }
    }
}

Describe 'Set-WindowsNetworkProtocolHardening when already hardened or absent' {
    BeforeAll {
        # SMB1 off, SMB1Protocol disabled, the other SMB1 features and PowerShell 2.0 absent.
        $script:off = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-off' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'false' -Features 'SMB1Protocol=Disabled') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'off'); SkipSmbSigning = $true }
    }

    It 'runs to completion and changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:off
        $script:off.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:off.Execute.Output)"
    }

    It 'reports the SMB1, SMB1 feature and PowerShell 2.0 items as NoChange and never touches them' {
        $items = @($script:off.Execute.Summary.Items | Where-Object { $_.Category -in @('Smb1Server', 'Smb1Feature', 'PowerShellV2Feature') })
        $items.Count | Should -Be 7
        foreach ($i in $items) {
            $i.Result | Should -Be 'NoChange' -Because "$($i.Setting) is $($i.CurrentValue)"
        }
        @($items | Where-Object Setting -eq 'MicrosoftWindowsPowerShellV2Root')[0].CurrentValue | Should -Be 'absent'
        $m = @(Get-OpsMutationRecord -Path $script:off.ExecuteLog)
        @($m | Where-Object { $_.Command -in @('Set-SmbServerConfiguration', 'Dism.exe') }).Count | Should -Be 0
    }

    It 'leaves out the SMB signing items under -SkipSmbSigning and out of the opt-in mDNS item by default' {
        $plan = Get-PlanItem -Pair $script:off
        @($plan | Where-Object Category -like 'SmbSigning*').Count | Should -Be 0
        @($plan | Where-Object Category -eq 'Mdns').Count | Should -Be 0
    }

    It 'plans every NetBIOS interface as its own item targeting NetbiosOptions = 2' {
        foreach ($i in @(Get-PlanItem -Pair $script:off | Where-Object Category -eq 'NetBIOS')) {
            $i.Setting | Should -BeLike 'Tcpip_*'
            $i.ValueName | Should -Be 'NetbiosOptions'
            "$($i.DesiredValue)" | Should -Be '2'
            $i.RegistryPath | Should -BeLike '*\NetBT\Parameters\Interfaces\Tcpip_*'
        }
    }
}

Describe 'Set-WindowsNetworkProtocolHardening when state cannot be read' {
    BeforeAll {
        $script:unk = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-unk' `
            -FixtureEnvironment (Get-FixtureEnvironment -Unreadable 'true') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'unk'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
    }

    It 'marks unreadable items unknown, never compliant, and changes nothing' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:unk
        $script:unk.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:unk.Execute.Output)"
        $plan = Get-PlanItem -Pair $script:unk
        $smb = @($plan | Where-Object Category -eq 'Smb1Server')
        $smb[0].CurrentValue | Should -Be 'unknown'
        $smb[0].Action | Should -BeLike 'Unreadable*'
        @($plan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.CurrentValue -ne 'unknown' }).Count | Should -Be 0
        @($script:unk.Execute.Summary.Items | Where-Object { $_.Category -in @('Smb1Server', 'Smb1Feature') -and $_.Result -eq 'NoChange' }).Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $script:unk.ExecuteLog | Where-Object { $_.Command -in @('Set-SmbServerConfiguration', 'Dism.exe') }).Count | Should -Be 0
    }
}

Describe 'Set-WindowsNetworkProtocolHardening rollback' {
    BeforeAll {
        $dir = Join-Path $script:workRoot 'rb'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $netbtKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{test-rollback}'
        [pscustomobject]@{
            Timestamp = '20250101_000000'
            ChangedSettings = @(
                [pscustomobject]@{ Category = 'Smb1Server'; Setting = 'EnableSMB1Protocol'; Kind = 'SmbServerSmb1'; RegistryPath = ''; ValueName = ''; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $false; PriorValue = 'True'; AppliedValue = 'False' }
                [pscustomobject]@{ Category = 'Smb1Feature'; Setting = 'SMB1Protocol'; Kind = 'OptionalFeature'; RegistryPath = ''; ValueName = ''; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $true; PriorValue = 'Enabled'; AppliedValue = 'Disabled' }
                [pscustomobject]@{ Category = 'Llmnr'; Setting = 'DNSClient EnableMulticast'; Kind = 'Registry'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; ValueName = 'EnableMulticast'; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $false; PriorValue = 'absent'; AppliedValue = 0 }
                [pscustomobject]@{ Category = 'NetBIOS'; Setting = 'Tcpip_{test-rollback}'; Kind = 'Registry'; RegistryPath = $netbtKey; ValueName = 'NetbiosOptions'; PropertyType = 'DWord'; RequiresAdmin = $true; RequiresReboot = $false; PriorValue = 1; AppliedValue = 2 }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'network-protocol-hardening-rollback-20250101_000000.json') -Encoding utf8

        $script:rb = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-rb' `
            -FixtureEnvironment (Get-FixtureEnvironment) `
            -Argument @{ ReportDirectory = $dir; Rollback = $true }
    }

    It 'previews the rollback without recording a change' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:rb
    }

    It 'plans to restore exactly the recorded prior values in reverse order' {
        $script:rb.Execute.ExitCode | Should -Be 0 -Because "the rollback run failed: $($script:rb.Execute.Output)"
        $plan = Get-PlanItem -Pair $script:rb
        $plan.Count | Should -Be 4
        $plan[0].Category | Should -Be 'NetBIOS'
        "$($plan[0].DesiredValue)" | Should -Be '1'
        $plan[3].Category | Should -Be 'Smb1Server'
        "$($plan[3].DesiredValue)" | Should -Be 'True'
        @($plan | Where-Object Category -eq 'Llmnr')[0].DesiredValue | Should -Be 'absent'
        @($plan | Where-Object Category -eq 'Smb1Feature')[0].DesiredValue | Should -Be 'Enabled'
    }

    It 'restores SMB1, the feature and the registry values when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'session is not elevated; the plan assertions above still ran'; return }
        $m = @(Get-OpsMutationRecord -Path $script:rb.ExecuteLog)
        @($m | Where-Object Command -eq 'Set-SmbServerConfiguration')[0].Detail | Should -Be 'EnableSMB1Protocol=True'
        @(Get-DismChange -Record $m -Verb 'Enable-Feature')[0].Target | Should -Be 'SMB1Protocol'
        @($m | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -like '*EnableMulticast' }).Count | Should -Be 1
        $nb = @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*Tcpip_{test-rollback}*NetbiosOptions' })
        $nb[0].Detail | Should -Be '1'
    }

    It 'fails clearly when there is no rollback file' {
        $empty = Join-Path $script:workRoot 'rb-empty'
        $r = Invoke-ScriptUnderTest -RelativePath $script:relativePath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath (Join-Path $script:workRoot 'rb-empty.log')) + (Get-FixtureEnvironment)) `
            -Argument @{ ReportDirectory = $empty; Rollback = $true; WhatIf = $true }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*Nothing to roll back*'
    }
}

Describe 'Set-WindowsNetworkProtocolHardening rollback safety' {
    BeforeAll {
        $script:rbDirCounter = 0
        $script:npScriptFullPath = Join-Path (Get-RepositoryRoot) $script:relativePath
        $script:rbName = 'network-protocol-hardening-rollback-20260101_000000.json'
        $script:llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $script:netbtRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'

        function Get-LiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:npScriptFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        # A copy of the script that reports itself elevated, so the executing half of a rollback can
        # be exercised in an unelevated session. Every SMB, Dism and registry write still goes to the
        # staged fake modules and stubs, so nothing real is changed. FailSmb makes the SMB1 restore throw.
        function New-ScriptCopy {
            param([string]$Name, [switch]$FailSmb)
            $text = Get-Content -LiteralPath $script:npScriptFullPath -Raw
            $elevated = '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
            $text.Contains($elevated) | Should -BeTrue -Because 'the elevation check this copy replaces must still exist'
            $import = "(Join-Path `$PSScriptRoot '..\..\..\modules\OpsToolkit.Hardening')"
            $text.Contains($import) | Should -BeTrue -Because 'the module import this copy replaces must still exist'
            $patched = $text.Replace($elevated, '$true').Replace($import, "'$(Join-Path (Get-RepositoryRoot) 'modules\OpsToolkit.Hardening')'")
            if ($FailSmb) {
                $restore = 'Set-SmbServerConfiguration -EnableSMB1Protocol $enable -Force -Confirm:$false -ErrorAction Stop'
                $patched.Contains($restore) | Should -BeTrue -Because 'the SMB1 restore this copy replaces must still exist'
                $patched = $patched.Replace($restore, "throw 'injected failure'")
            }
            $copy = Join-Path $script:workRoot "$Name.ps1"
            Set-Content -LiteralPath $copy -Value $patched -Encoding utf8
            [System.IO.Path]::GetRelativePath((Get-RepositoryRoot), $copy)
        }

        function New-RollbackDir {
            $script:rbDirCounter++
            $dir = Join-Path $script:workRoot "npSafety$($script:rbDirCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        # Defaults describe an LLMNR change; the Kind switch builds the other two entry shapes.
        function New-NpEntry {
            param(
                $Category = 'Llmnr', $Setting = 'DNSClient EnableMulticast', $Kind = 'Registry',
                $RegistryPath = $script:llmnrPath, $ValueName = 'EnableMulticast',
                $Prior = 'absent', $Applied = 0, $RequiresAdmin = $true, $RequiresReboot = $false
            )
            [pscustomobject]@{
                Category = $Category; Setting = $Setting; Kind = $Kind; RegistryPath = $RegistryPath; ValueName = $ValueName
                PropertyType = 'DWord'; RequiresAdmin = $RequiresAdmin; RequiresReboot = $RequiresReboot
                PriorValue = $Prior; AppliedValue = $Applied
            }
        }
        function New-NpSmbEntry {
            param($Prior = 'True', $Applied = 'False')
            New-NpEntry -Category 'Smb1Server' -Setting 'EnableSMB1Protocol' -Kind 'SmbServerSmb1' -RegistryPath '' -ValueName '' -Prior $Prior -Applied $Applied
        }
        function New-NpFeatureEntry {
            param($Category = 'Smb1Feature', $Setting = 'SMB1Protocol', $Prior = 'Enabled', $Applied = 'Disabled', $RequiresReboot = $true)
            New-NpEntry -Category $Category -Setting $Setting -Kind 'OptionalFeature' -RegistryPath '' -ValueName '' -Prior $Prior -Applied $Applied -RequiresReboot $RequiresReboot
        }

        function Write-NpRollbackFile {
            param([string]$Dir, [string]$Name = $script:rbName, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-NpRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute, [string]$Relative = $script:relativePath)
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $setup = (Get-WindowsMutationStubText -MutationLogPath $log) + (Get-FixtureEnvironment)
            $run = Invoke-ScriptUnderTest -RelativePath $Relative -ModulePath $script:systemModulePath -Setup $setup -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Get-NpPlan {
            param($Run)
            @(Get-Content -LiteralPath $Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        }

        function Assert-NpRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-NpRollback -Dir $Dir -Tag "npRefused$($script:rbDirCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'network-protocol-hardening-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'network-protocol-hardening-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because $Because
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the controls the forward plan sets, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'unknown category'; Entry = (New-NpEntry -Category 'Wpad' -Setting 'WpadOverride') },
            @{ Name = 'kind of another category'; Entry = (New-NpEntry -Kind 'SmbServerSmb1') },
            @{ Name = 'unknown kind'; Entry = (New-NpEntry -Kind 'Service') },
            @{ Name = 'setting outside the category list'; Entry = (New-NpFeatureEntry -Setting 'Windows-Defender-Default-Definitions') },
            @{ Name = 'setting of another category'; Entry = (New-NpFeatureEntry -Category 'PowerShellV2Feature' -Setting 'SMB1Protocol') },
            @{ Name = 'registry path redirected'; Entry = (New-NpEntry -RegistryPath 'HKLM:\SOFTWARE\Policies\Evil') },
            @{ Name = 'value name changed'; Entry = (New-NpEntry -ValueName 'EnableMDNS') },
            @{ Name = 'registry path on a feature entry'; Entry = (New-NpEntry -Category 'Smb1Feature' -Setting 'SMB1Protocol' -Kind 'OptionalFeature' -Prior 'Enabled' -Applied 'Disabled' -RequiresReboot $true) },
            @{ Name = 'NetBIOS setting that is not an interface key'; Entry = (New-NpEntry -Category 'NetBIOS' -Setting 'Interfaces' -RegistryPath "$script:netbtRoot\Interfaces" -ValueName 'NetbiosOptions' -Prior 1 -Applied 2) },
            @{ Name = 'NetBIOS setting that climbs out of the interfaces key'; Entry = (New-NpEntry -Category 'NetBIOS' -Setting 'Tcpip_{x}\..\..\Evil' -RegistryPath "$script:netbtRoot\Tcpip_{x}\..\..\Evil" -ValueName 'NetbiosOptions' -Prior 1 -Applied 2) },
            @{ Name = 'NetBIOS path outside the interfaces key'; Entry = (New-NpEntry -Category 'NetBIOS' -Setting 'Tcpip_{x}' -RegistryPath 'HKLM:\SOFTWARE\Evil\Tcpip_{x}' -ValueName 'NetbiosOptions' -Prior 1 -Applied 2) },
            @{ Name = 'NetBIOS path of another interface'; Entry = (New-NpEntry -Category 'NetBIOS' -Setting 'Tcpip_{x}' -RegistryPath "$script:netbtRoot\Tcpip_{y}" -ValueName 'NetbiosOptions' -Prior 1 -Applied 2) },
            @{ Name = 'applied value the forward plan never sets'; Entry = (New-NpEntry -Applied 1) },
            @{ Name = 'SMB1 applied True'; Entry = (New-NpSmbEntry -Applied 'True') },
            @{ Name = 'SMB1 prior False'; Entry = (New-NpSmbEntry -Prior 'False') },
            @{ Name = 'feature applied Enabled'; Entry = (New-NpFeatureEntry -Prior 'Disabled' -Applied 'Enabled') },
            @{ Name = 'prior equal to the applied value'; Entry = (New-NpEntry -Prior 0 -Applied 0) },
            @{ Name = 'feature prior Disabled'; Entry = (New-NpFeatureEntry -Prior 'Disabled') },
            @{ Name = 'feature prior absent'; Entry = (New-NpFeatureEntry -Prior 'absent') },
            @{ Name = 'feature prior unknown'; Entry = (New-NpFeatureEntry -Prior 'unknown') },
            @{ Name = 'RequiresAdmin false'; Entry = (New-NpEntry -RequiresAdmin $false) },
            @{ Name = 'RequiresReboot wrong for a feature'; Entry = (New-NpFeatureEntry -RequiresReboot $false) },
            @{ Name = 'RequiresReboot wrong for a registry value'; Entry = (New-NpEntry -RequiresReboot $true) }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $null = Write-NpRollbackFile -Dir $dir -Entry @((New-NpEntry), $case.Entry)
            Assert-NpRefused -Dir $dir -FileName $script:rbName -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-RollbackDir
        $null = Write-NpRollbackFile -Dir $dir -Entry @((New-NpEntry), (New-NpEntry -Category 'Wpad' -Setting 'WpadOverride'))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 1 '
        $r.Run.Output | Should -Match 'Wpad'
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $good = '{ "Category": "Llmnr", "Setting": "DNSClient EnableMulticast", "Kind": "Registry", "RegistryPath": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "ValueName": "EnableMulticast", "RequiresAdmin": true, "RequiresReboot": false, "PriorValue": "absent", "AppliedValue": 0 }'
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "Llmnr" } }'
            'ChangedSettings a string'  = '{ "ChangedSettings": "Llmnr" }'
            'ChangedSettings one valid entry, not in an array' = "{ `"ChangedSettings`": $good }"
            'top level is an array'     = '[ { "Category": "Llmnr" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "Llmnr" ] }'
            'entry lacks AppliedValue'  = '{ "ChangedSettings": [ { "Category": "Llmnr", "Setting": "DNSClient EnableMulticast", "Kind": "Registry", "RegistryPath": "x", "ValueName": "EnableMulticast", "RequiresAdmin": true, "RequiresReboot": false, "PriorValue": "absent" } ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-RollbackDir
            Set-Content -LiteralPath (Join-Path $dir $script:rbName) -Value $bodies[$label] -Encoding utf8
            Assert-NpRefused -Dir $dir -FileName $script:rbName -Because $label
        }
    }

    It 'refuses a value of the wrong type' {
        $cases = @(
            @{ Name = 'registry PriorValue abc'; Entry = (New-NpEntry -Prior 'abc') },
            @{ Name = 'registry PriorValue unknown'; Entry = (New-NpEntry -Prior 'unknown') },
            @{ Name = 'registry PriorValue numeric string'; Entry = (New-NpEntry -Prior '1') },
            @{ Name = 'registry PriorValue boolean'; Entry = (New-NpEntry -Prior $true) },
            @{ Name = 'registry PriorValue array'; Entry = (New-NpEntry -Prior @(1, 2)) },
            @{ Name = 'registry PriorValue null'; Entry = (New-NpEntry -Prior $null) },
            @{ Name = 'registry PriorValue fraction'; Entry = (New-NpEntry -Prior 0.5) },
            @{ Name = 'registry PriorValue out of range'; Entry = (New-NpEntry -Prior 99999999999) },
            @{ Name = 'registry AppliedValue string'; Entry = (New-NpEntry -Applied '0') },
            @{ Name = 'registry AppliedValue absent'; Entry = (New-NpEntry -Applied 'absent') },
            @{ Name = 'registry AppliedValue null'; Entry = (New-NpEntry -Applied $null) },
            @{ Name = 'SMB1 PriorValue boolean'; Entry = (New-NpSmbEntry -Prior $true) },
            @{ Name = 'SMB1 AppliedValue boolean'; Entry = (New-NpSmbEntry -Applied $false) },
            @{ Name = 'feature PriorValue number'; Entry = (New-NpFeatureEntry -Prior 1) },
            @{ Name = 'feature PriorValue with punctuation'; Entry = (New-NpFeatureEntry -Prior 'Enabled; Remove-Item') },
            @{ Name = 'feature PriorValue array'; Entry = (New-NpFeatureEntry -Prior @('Enabled')) },
            @{ Name = 'feature AppliedValue number'; Entry = (New-NpFeatureEntry -Applied 0) },
            @{ Name = 'Setting empty'; Entry = (New-NpEntry -Setting '') },
            @{ Name = 'Category array'; Entry = (New-NpEntry -Category @('Llmnr', 'Mdns')) },
            @{ Name = 'RegistryPath null'; Entry = (New-NpEntry -RegistryPath $null) }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $null = Write-NpRollbackFile -Dir $dir -Entry @($case.Entry)
            Assert-NpRefused -Dir $dir -FileName $script:rbName -Because $case.Name
        }
    }

    It 'does not pick a consumed file: the older unconsumed file is planned instead' {
        $dir = New-RollbackDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'network-protocol-hardening-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-NpRollbackFile -Dir $dir -Entry @((New-NpEntry))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        @(Get-NpPlan -Run $r.Run | ForEach-Object { $_.Category }) | Should -Be @('Llmnr')
    }

    It 'picks the newest file by name, not by write time' {
        $dir = New-RollbackDir
        $newer = Write-NpRollbackFile -Dir $dir -Name 'network-protocol-hardening-rollback-20260301_000000.json' -Entry @((New-NpEntry))
        $older = Write-NpRollbackFile -Dir $dir -Name 'network-protocol-hardening-rollback-20260101_000000.json' -Entry @((New-NpSmbEntry))
        (Get-Item -LiteralPath $newer).LastWriteTime = (Get-Date).AddDays(-30)
        (Get-Item -LiteralPath $older).LastWriteTime = (Get-Date)
        $r = Invoke-NpRollback -Dir $dir -Tag 'npByName'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $newer)
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-RollbackDir
        $file = Write-NpRollbackFile -Dir $dir -Entry @((New-NpEntry))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npUnelevatedExec' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:rbName
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf, even from a session that reports itself elevated' {
        $elevated = New-ScriptCopy -Name 'np-elevated-whatif'
        $dir = New-RollbackDir
        $file = Write-NpRollbackFile -Dir $dir -Entry @((New-NpEntry))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npWhatIfKeeps' -Relative $elevated
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('Previewed')
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:rbName
        $r.Run.Summary.RollbackNote | Should -Match 'WhatIf'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
    }

    It 'consumes the file after an executing rollback that restored every item, and does not pick it again' {
        $elevated = New-ScriptCopy -Name 'np-elevated-consume'
        $dir = New-RollbackDir
        $file = Write-NpRollbackFile -Dir $dir -Entry @((New-NpSmbEntry), (New-NpEntry), (New-NpFeatureEntry))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npConsume' -Execute -Relative $elevated
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('Reverted', 'Reverted', 'Reverted')
        $m = @(Get-OpsMutationRecord -Path $r.Log)
        @($m | Where-Object Command -eq 'Set-SmbServerConfiguration').Count | Should -Be 1
        @(Get-DismChange -Record $m -Verb 'Enable-Feature').Count | Should -Be 1
        @($m | Where-Object Command -eq 'Remove-ItemProperty').Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'network-protocol-hardening-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:rbName
        $again = Invoke-NpRollback -Dir $dir -Tag 'npConsume2' -Execute -Relative $elevated
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
    }

    It 'leaves the file unconsumed when an executing rollback fails on an item' {
        $failing = New-ScriptCopy -Name 'np-elevated-fail' -FailSmb
        $dir = New-RollbackDir
        # Rollback runs newest entry first: the LLMNR value is restored, then the SMB1 restore throws.
        $file = Write-NpRollbackFile -Dir $dir -Entry @((New-NpSmbEntry), (New-NpEntry))
        $r = Invoke-NpRollback -Dir $dir -Tag 'npPartial' -Execute -Relative $failing
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('Reverted', 'Failed: injected failure')
        Test-Path -LiteralPath $file | Should -BeTrue -Because 'a partial rollback can be run again'
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'decides consumption in a pure function lifted from the script' {
        $text = Get-LiftedFunctionText -Name 'Test-RollbackFileConsumable'
        $decide = [scriptblock]::Create("param(`$State, [bool]`$Preview)`n$text`nTest-RollbackFileConsumable -State `$State -Preview `$Preview")
        function New-State { param([string[]]$Result) @($Result | ForEach-Object { [pscustomobject]@{ Result = $_ } }) }

        & $decide (New-State 'Reverted', 'NoChange', 'Reverted') $false | Should -BeTrue
        & $decide (New-State 'NoChange') $false | Should -BeTrue
        & $decide (New-State 'Reverted', 'Failed: access denied') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Skipped: requires elevation') $false | Should -BeFalse
        & $decide (New-State 'Previewed', 'Previewed') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Previewed') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Reverted') $true | Should -BeFalse -Because '-WhatIf never consumes'
        & $decide (New-State 'NoChange') $true | Should -BeFalse
    }

    It 'validates one entry in a pure function lifted from the script, against whatever control table it is given' {
        $text = (Get-LiftedFunctionText -Name 'Get-OptionalProperty') + "`n" + (Get-LiftedFunctionText -Name 'Test-RollbackDword') + "`n" + (Get-LiftedFunctionText -Name 'Get-RollbackEntryProblem')
        $check = [scriptblock]::Create("param(`$Entry, `$Controls)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -Controls `$Controls")
        $row = { param($Category, $Kind, $Settings, $Path, $Name, $Desired, $Reboot = $false, $Root = $null, $Pattern = $null, $Floor = $false)
            $r = [pscustomobject]@{ Category = $Category; Kind = $Kind; Settings = $Settings; Path = $Path; Name = $Name; PathRoot = $Root; Pattern = $Pattern; Desired = $Desired; RequiresReboot = $Reboot }
            if ($Floor) { $r | Add-Member -NotePropertyName KeepIfAtLeast -NotePropertyValue $true }
            $r }
        $controls = @(
            (& $row 'Reg' 'Registry' @('R') 'HKLM:\X' 'V' 7)
            (& $row 'Feat' 'OptionalFeature' @('F1', 'F2') '' '' 'Disabled' $true)
            (& $row 'One' 'SmbServerSmb1' @('S') '' '' 'False')
            (& $row 'Keyed' 'Registry' $null $null 'V' 2 $false 'HKLM:\Root' '^K_[0-9a-z]+$')
            (& $row 'Floor' 'Registry' @('L') 'HKLM:\X' 'V' 1 $false $null $null $true)
        )
        function New-Probe {
            param($Category = 'Reg', $Setting = 'R', $Kind = 'Registry', $Path = 'HKLM:\X', $Name = 'V', $Prior = 'absent', $Applied = 7, $Admin = $true, $Reboot = $false)
            [pscustomobject]@{ Category = $Category; Setting = $Setting; Kind = $Kind; RegistryPath = $Path; ValueName = $Name; RequiresAdmin = $Admin; RequiresReboot = $Reboot; PriorValue = $Prior; AppliedValue = $Applied }
        }

        & $check (New-Probe) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Prior 3) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'Feat' -Setting 'F2' -Kind 'OptionalFeature' -Path '' -Name '' -Prior 'Enabled' -Applied 'Disabled' -Reboot $true) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'One' -Setting 'S' -Kind 'SmbServerSmb1' -Path '' -Name '' -Prior 'True' -Applied 'False') $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'Keyed' -Setting 'K_ab12' -Path 'HKLM:\Root\K_ab12' -Applied 2) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Setting 'X') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Other') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Kind 'OptionalFeature') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Path 'HKLM:\Y') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Name 'W') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Applied 8) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Prior 7) $controls | Should -Not -BeNullOrEmpty -Because 'a forward run only changes a value that differs from the target'
        & $check (New-Probe -Prior 'unknown') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Admin $false) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Reboot $true) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Feat' -Setting 'F1' -Kind 'OptionalFeature' -Path '' -Name '' -Prior 'Disabled' -Applied 'Disabled' -Reboot $true) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Keyed' -Setting 'K_AB' -Path 'HKLM:\Root\K_AB' -Applied 2) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Keyed' -Setting 'K_ab12' -Path 'HKLM:\Root\K_other' -Applied 2) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe) @() | Should -Not -BeNullOrEmpty -Because 'a table without the entry allows nothing'
        # A floor control (KeepIfAtLeast) never records a prior above the applied value; a plain one may.
        & $check (New-Probe -Category 'Floor' -Setting 'L' -Prior 2 -Applied 1) $controls | Should -Not -BeNullOrEmpty -Because 'the forward plan leaves a stricter value alone'
        & $check (New-Probe -Category 'Floor' -Setting 'L' -Prior 0 -Applied 1) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'Floor' -Setting 'L' -Prior 'absent' -Applied 1) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Prior 9) $controls | Should -BeNullOrEmpty -Because 'a plain control has no floor'
        $twice = @($controls[0], $controls[0])
        & $check (New-Probe) $twice | Should -Not -BeNullOrEmpty -Because 'a category that matches two rows is ambiguous, so nothing is allowed'
    }

    It 'accepts every control the forward plan can produce, so the validator cannot drift from it' {
        $features = 'SMB1Protocol=Enabled;SMB1Protocol-Client=Enabled;SMB1Protocol-Server=Enabled;SMB1Protocol-Deprecation=Enabled;MicrosoftWindowsPowerShellV2Root=Enabled;MicrosoftWindowsPowerShellV2=Enabled'
        $plan = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'npDrift' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'true' -Features $features) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'npDrift'); DisableMulticastDns = $true; DisableWpad = $true }
        $plan.WhatIf.ExitCode | Should -Be 0 -Because $plan.WhatIf.Output
        $forward = @(Get-NpPlan -Run $plan.WhatIf)
        foreach ($category in 'Smb1Server', 'Smb1Feature', 'PowerShellV2Feature', 'SmbSigningClient', 'SmbSigningServer', 'Llmnr', 'Mdns', 'Wpad') {
            @($forward | Where-Object Category -eq $category).Count | Should -BeGreaterThan 0 -Because $category
        }
        # Every planned item becomes a recorded change (whatever the machine's registry holds now).
        $entries = @($forward | ForEach-Object {
                $prior = switch ($_.Kind) { 'SmbServerSmb1' { 'True' } 'OptionalFeature' { 'Enabled' } default { 'absent' } }
                $applied = if ($_.Kind -eq 'Registry') { [int]$_.DesiredValue } else { "$($_.DesiredValue)" }
                New-NpEntry -Category $_.Category -Setting $_.Setting -Kind $_.Kind -RegistryPath $_.RegistryPath -ValueName $_.ValueName `
                    -Prior $prior -Applied $applied -RequiresReboot ([bool]$_.RequiresReboot)
            })
        $dir = New-RollbackDir
        $null = Write-NpRollbackFile -Dir $dir -Entry $entries
        $r = Invoke-NpRollback -Dir $dir -Tag 'npDriftRollback'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items).Count | Should -Be $forward.Count
    }

    It 'rolls back newest first and consumes each file as it goes' {
        $elevated = New-ScriptCopy -Name 'np-elevated-lifo'
        $dir = New-RollbackDir
        # Apply 1 disables SMB1Protocol; apply 2 (a second later) also disables PowerShell 2.0.
        $log1 = Join-Path $script:workRoot 'npLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'npLifoApply2.log'
        $apply1 = Invoke-ScriptUnderTest -RelativePath $elevated -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + (Get-FixtureEnvironment -Smb1 'true' -Features 'SMB1Protocol=Enabled')) `
            -Argument @{ ReportDirectory = $dir; SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}'); Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $apply2 = Invoke-ScriptUnderTest -RelativePath $elevated -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + (Get-FixtureEnvironment -Smb1 'true' -Features 'SMB1Protocol=Enabled;MicrosoftWindowsPowerShellV2Root=Enabled')) `
            -Argument @{ ReportDirectory = $dir; SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}'); Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-NpRollback -Dir $dir -Tag 'npLifoRollback1' -Execute -Relative $elevated
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        $rb1.Run.Summary.RollbackConsumedPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $rb1.Run.Summary.RollbackConsumedPath | Should -BeTrue
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $rb1.Run.Summary.RollbackConsumedPath | Should -Match 'rollback-\d{8}_\d{6}\.consumed-\d{8}_\d{6}\.json$'
        @(Get-DismChange -Record (Get-OpsMutationRecord -Path $rb1.Log) -Verb 'Enable-Feature' | ForEach-Object { $_.Target }) |
            Should -Contain 'MicrosoftWindowsPowerShellV2Root'

        $rb2 = Invoke-NpRollback -Dir $dir -Tag 'npLifoRollback2' -Execute -Relative $elevated
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply1.Summary.RollbackJsonPath | Should -BeFalse
        @(Get-DismChange -Record (Get-OpsMutationRecord -Path $rb2.Log) -Verb 'Enable-Feature' | ForEach-Object { $_.Target }) |
            Should -Not -Contain 'MicrosoftWindowsPowerShellV2Root'

        $rb3 = Invoke-NpRollback -Dir $dir -Tag 'npLifoRollback3' -Execute -Relative $elevated
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 2
    }
}

Describe 'Set-WindowsNetworkProtocolHardening reads features through dism.exe under PowerShell 7' {
    BeforeAll {
        $script:dismLog = Join-Path $script:workRoot 'dism-calls.jsonl'
        $features = 'SMB1Protocol=Enabled;SMB1Protocol-Client=Disabled with Payload Removed;MicrosoftWindowsPowerShellV2Root=Disabled'
        $extra = "`$env:OPSTOOLKIT_TEST_DISM_LOG = '$($script:dismLog)'"
        $script:sw = [Diagnostics.Stopwatch]::StartNew()
        $script:dz = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-dism' `
            -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'false' -Features $features -Extra $extra) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'dz'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $script:sw.Stop()
        $script:dzPlan = Get-PlanItem -Pair $script:dz
    }

    It 'runs both modes and reads the features in seconds, not minutes' {
        $script:dz.WhatIf.ExitCode | Should -Be 0 -Because $script:dz.WhatIf.Output
        $script:dz.Execute.ExitCode | Should -Be 0 -Because $script:dz.Execute.Output
        $script:sw.Elapsed.TotalSeconds | Should -BeLessThan 120
    }

    It 'reads the SMB1 and PowerShell 2.0 items from dism /Get-FeatureInfo, not from the cmdlets' {
        $smb = @($script:dzPlan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'SMB1Protocol' })
        $smb[0].CurrentValue | Should -Be 'Enabled'
        $client = @($script:dzPlan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'SMB1Protocol-Client' })
        $client[0].CurrentValue | Should -Be 'DisabledWithPayloadRemoved'
        $client[0].Action | Should -BeLike 'No change*'
        $ps2 = @($script:dzPlan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'MicrosoftWindowsPowerShellV2Root' })
        $ps2[0].CurrentValue | Should -Be 'Disabled'
        $calls = @(Get-Content -LiteralPath $script:dismLog | ForEach-Object { $_ | ConvertFrom-Json })
        $read = @($calls | Where-Object Verb -eq 'Get-FeatureInfo' | ForEach-Object { $_.Feature })
        $read | Should -Contain 'SMB1Protocol'
        $read | Should -Contain 'MicrosoftWindowsPowerShellV2Root'
        $calls[0].Arguments | Should -Match '/English'
        $calls[0].Arguments | Should -Match '/Online'
    }

    It 'counts a feature dism reports unknown as compliant and the reason says absent' {
        $dep = @($script:dzPlan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'SMB1Protocol-Deprecation' })
        $dep[0].CurrentValue | Should -Be 'absent'
        $dep[0].Action | Should -BeLike 'No change*absent*'
        $item = @($script:dz.Execute.Summary.Items | Where-Object Setting -eq 'SMB1Protocol-Deprecation')
        $item[0].Result | Should -Be 'NoChange'
    }

    It 'changes nothing under -WhatIf, including through dism.exe' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:dz
    }

    It 'uses the stand-in dism, because -DismPath defaults to it in every launched script' {
        $calls = @(Get-Content -LiteralPath $script:dismLog | ForEach-Object { $_ | ConvertFrom-Json })
        $calls.Count | Should -BeGreaterThan 0
        $script:fakeDism | Should -BeLike '*fake-dism.cmd'
    }

    It 'disables an enabled feature with dism /Disable-Feature /NoRestart when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'session is not elevated'; return }
        $m = @(Get-OpsMutationRecord -Path $script:dz.ExecuteLog)
        @(Get-DismChange -Record $m -Verb 'Disable-Feature' | ForEach-Object { $_.Target }) | Should -Be @('SMB1Protocol')
        $calls = @(Get-Content -LiteralPath $script:dismLog | ForEach-Object { $_ | ConvertFrom-Json })
        @($calls | Where-Object Verb -eq 'Disable-Feature')[0].Arguments | Should -Match '/NoRestart'
    }
}

Describe 'Set-WindowsNetworkProtocolHardening dism.exe failure handling' {
    It 'leaves a feature unread when dism hangs, stops only that process, and still reads the others' {
        $log = Join-Path $script:workRoot 'hang-calls.jsonl'
        $extra = "`$env:OPSTOOLKIT_TEST_DISM_LOG = '$log'`n`$env:OPSTOOLKIT_TEST_DISM_HANG = 'SMB1Protocol'"
        $r = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-hang' `
            -FixtureEnvironment (Get-FixtureEnvironment -Features 'SMB1Protocol=Enabled;MicrosoftWindowsPowerShellV2Root=Enabled' -Extra $extra) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'hang'); SkipSmbSigning = $true; DismTimeoutSeconds = 3; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
        $plan = Get-PlanItem -Pair $r
        $hung = @($plan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'SMB1Protocol' })
        $hung[0].CurrentValue | Should -Be 'unknown'
        $hung[0].Action | Should -BeLike 'Unreadable*'
        $other = @($plan | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'MicrosoftWindowsPowerShellV2Root' })
        $other[0].CurrentValue | Should -Be 'Enabled'
        $calls = @(Get-Content -LiteralPath $log | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.Verb -eq 'Get-FeatureInfo' -and $_.Feature -eq 'SMB1Protocol' })
        $killedPid = $calls[0].ProcessId
        $killedPid | Should -Not -BeNullOrEmpty
        Get-Process -Id $killedPid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because 'the timed-out dism process must be killed'
        Assert-OpsNoChangeUnderWhatIf -Pair $r
    }

    It 'leaves a feature unread when dism exits 0 with no State line' {
        $r = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-garbage' `
            -FixtureEnvironment (Get-FixtureEnvironment -Features 'SMB1Protocol=Enabled' -Extra "`$env:OPSTOOLKIT_TEST_DISM_GARBAGE = 'true'") `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'garbage'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
        $features = @(Get-PlanItem -Pair $r | Where-Object Kind -eq 'OptionalFeature')
        $features.Count | Should -BeGreaterThan 0
        @($features | Where-Object CurrentValue -ne 'unknown').Count | Should -Be 0
        Assert-OpsNoChangeUnderWhatIf -Pair $r
    }

    It 'leaves a feature unread when dism needs elevation (error 740) instead of calling it absent' {
        $r = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-740' `
            -FixtureEnvironment (Get-FixtureEnvironment -Features 'SMB1Protocol=Enabled' -Unreadable 'true') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot '740'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        @(Get-PlanItem -Pair $r | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.CurrentValue -ne 'unknown' }).Count | Should -Be 0
    }

    It 'reports a failed dism change as Failed, not as applied, when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'session is not elevated'; return }
        $r = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-failchange' `
            -FixtureEnvironment (Get-FixtureEnvironment -Features 'SMB1Protocol=Enabled' -Extra "`$env:OPSTOOLKIT_TEST_DISM_FAIL = 'SMB1Protocol'") `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'failchange'); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $item = @($r.Execute.Summary.Items | Where-Object Setting -eq 'SMB1Protocol')
        $item[0].Result | Should -BeLike 'Failed*'
    }

    It 'keeps the cmdlet route when forced with -FeatureProvider Cmdlet' {
        $r = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Tag 'netproto-cmdlet' `
            -FixtureEnvironment (Get-FixtureEnvironment -Features 'SMB1Protocol=Enabled') `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'cmdlet'); SkipSmbSigning = $true; FeatureProvider = 'Cmdlet'; NetbiosInterface = @('Tcpip_{no-such-interface}') }
        $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
        $smb = @(Get-PlanItem -Pair $r | Where-Object { $_.Kind -eq 'OptionalFeature' -and $_.Setting -eq 'SMB1Protocol' })
        $smb[0].CurrentValue | Should -Be 'Enabled'
    }
}

Describe 'Set-WindowsNetworkProtocolHardening NTLM auditing and the opt-in restriction' {
    BeforeAll {
        $script:ntlmCopy = New-ElevatedScriptCopy -Name 'np-ntlm-elevated'
        $script:ntlmFeatures = 'SMB1Protocol=Disabled'
        function Invoke-NtlmRun {
            param([string]$Tag, [string]$Msv1 = 'none', [string]$HostKind = 'Physical', [switch]$Restrict)
            $arguments = @{ ReportDirectory = (Join-Path $script:workRoot $Tag); SkipSmbSigning = $true; NetbiosInterface = @('Tcpip_{no-such-interface}') }
            if ($Restrict) { $arguments['RestrictOutgoingNtlm'] = $true }
            $extra = (Get-Msv1FixtureText -Values $Msv1) + (Get-FakeHostSetupText -Fixture $script:hostFixture -Kind $HostKind)
            Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath -RelativePath $script:ntlmCopy -Tag $Tag `
                -FixtureEnvironment (Get-FixtureEnvironment -Smb1 'false' -Features $script:ntlmFeatures -Extra $extra) -Argument $arguments
        }
        function Get-NtlmPlan { param($Pair) @(Get-PlanItem -Pair $Pair | Where-Object { $_.Category -like 'Ntlm*' } | Sort-Object Category) }
        function Get-MsvWrite {
            param($Pair, [string]$Name)
            @(Get-OpsMutationRecord -Path $Pair.ExecuteLog | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like "*\MSV1_0\$Name" })
        }
        $script:ntlmDefault = Invoke-NtlmRun -Tag 'ntlm-default'
        $script:ntlmStrict = Invoke-NtlmRun -Tag 'ntlm-strict' -Msv1 'RestrictSendingNTLMTraffic=2'
        $script:ntlmRestrict = Invoke-NtlmRun -Tag 'ntlm-restrict' -Restrict
        $script:ntlmAvd = Invoke-NtlmRun -Tag 'ntlm-avd' -Restrict -HostKind 'Avd'
        $script:ntlmUnread = Invoke-NtlmRun -Tag 'ntlm-unread' -Restrict -HostKind 'AvdUnread'
        $script:ntlmDomain = Invoke-NtlmRun -Tag 'ntlm-domain' -HostKind 'Domain'
    }

    It 'runs to completion in both modes' -ForEach @(
        @{ Name = 'ntlmDefault' }, @{ Name = 'ntlmStrict' }, @{ Name = 'ntlmRestrict' }, @{ Name = 'ntlmAvd' }, @{ Name = 'ntlmUnread' }, @{ Name = 'ntlmDomain' }
    ) {
        $pair = Get-Variable -Name $Name -Scope Script -ValueOnly
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
    }

    It 'audits incoming and outgoing NTLM by default and offers no restriction' {
        $ntlm = Get-NtlmPlan -Pair $script:ntlmDefault
        $ntlm.Count | Should -Be 2
        $ntlm[0].Category | Should -Be 'NtlmAuditOutgoing'
        $ntlm[1].Category | Should -Be 'NtlmAuditReceiving'
        $ntlm[0].ValueName | Should -Be 'RestrictSendingNTLMTraffic'
        "$($ntlm[0].DesiredValue)" | Should -Be '1'
        $ntlm[1].ValueName | Should -Be 'AuditReceivingNTLMTraffic'
        "$($ntlm[1].DesiredValue)" | Should -Be '2'
        $ntlm[0].CurrentValue | Should -Be 'absent'
        @(Get-PlanItem -Pair $script:ntlmDefault | Where-Object { $_.ValueName -eq 'RestrictReceivingNTLMTraffic' }).Count | Should -Be 0
    }

    It 'writes only the two audit values on the executing run and nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:ntlmDefault
        @(Get-OpsMutationRecord -Path $script:ntlmDefault.ExecuteLog | Where-Object { $_.Target -like '*\MSV1_0\*' }).Count | Should -Be 2
        $send = @(Get-MsvWrite -Pair $script:ntlmDefault -Name 'RestrictSendingNTLMTraffic')
        $send.Count | Should -Be 1
        $send[0].Detail | Should -Be '1'
        $recv = @(Get-MsvWrite -Pair $script:ntlmDefault -Name 'AuditReceivingNTLMTraffic')
        $recv.Count | Should -Be 1
        $recv[0].Detail | Should -Be '2'
    }

    It 'never downgrades an outgoing restriction that is already stricter than audit' {
        $ntlm = Get-NtlmPlan -Pair $script:ntlmStrict
        $ntlm.Count | Should -Be 2
        $ntlm[0].Category | Should -Be 'NtlmAuditOutgoing'
        $ntlm[0].CurrentValue | Should -Be 2
        $ntlm[0].Action | Should -BeLike 'No change*stricter*'
        $ntlm[1].Action | Should -BeLike 'Audit incoming*'
        (Get-MsvWrite -Pair $script:ntlmStrict -Name 'RestrictSendingNTLMTraffic').Count | Should -Be 0
        (Get-MsvWrite -Pair $script:ntlmStrict -Name 'AuditReceivingNTLMTraffic').Count | Should -Be 1
    }

    It 'records the prior values so the audit settings can be rolled back, then restores them' {
        $recorded = Get-Content -LiteralPath $script:ntlmDefault.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        $entries = @($recorded.ChangedSettings | Where-Object { $_.Category -like 'Ntlm*' } | Sort-Object Category)
        $entries.Count | Should -Be 2
        $entries[0].PriorValue | Should -Be 'absent'
        $entries[0].AppliedValue | Should -Be 1
        $entries[1].PriorValue | Should -Be 'absent'
        $entries[1].AppliedValue | Should -Be 2

        $dir = Join-Path $script:workRoot 'ntlm-default'
        $rb = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath -RelativePath $script:ntlmCopy -Tag 'ntlm-rollback' `
            -FixtureEnvironment (Get-FixtureEnvironment -Extra (Get-Msv1FixtureText -Values 'none')) -Argument @{ ReportDirectory = $dir; Rollback = $true }
        Assert-OpsNoChangeUnderWhatIf -Pair $rb
        $rb.Execute.ExitCode | Should -Be 0 -Because $rb.Execute.Output
        $removed = @(Get-OpsMutationRecord -Path $rb.ExecuteLog | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -like '*\MSV1_0\*' })
        $removed.Count | Should -Be 2
        @($removed | ForEach-Object { ($_.Target -split '\\')[-1] } | Sort-Object) | Should -Be @('AuditReceivingNTLMTraffic', 'RestrictSendingNTLMTraffic')
    }

    It 'plans the outgoing restriction only with the switch, in place of the outgoing audit' {
        $ntlm = Get-NtlmPlan -Pair $script:ntlmRestrict
        $ntlm.Count | Should -Be 2
        $ntlm[0].Category | Should -Be 'NtlmAuditReceiving'
        $ntlm[1].Category | Should -Be 'NtlmRestrictOutgoing'
        "$($ntlm[1].DesiredValue)" | Should -Be '2'
        $ntlm[1].Action | Should -BeLike 'DENY*'
        Assert-OpsNoChangeUnderWhatIf -Pair $script:ntlmRestrict
        $send = @(Get-MsvWrite -Pair $script:ntlmRestrict -Name 'RestrictSendingNTLMTraffic')
        $send.Count | Should -Be 1
        $send[0].Detail | Should -Be '2'
        # And without the switch no run ever writes a 2 to that value.
        @(Get-MsvWrite -Pair $script:ntlmDefault -Name 'RestrictSendingNTLMTraffic' | Where-Object { $_.Detail -eq '2' }).Count | Should -Be 0
    }

    It 'refuses the restriction on a session host and when that cannot be determined' -ForEach @(
        @{ Name = 'ntlmAvd'; Reason = 'Skipped: AVD session host*' }
        @{ Name = 'ntlmUnread'; Reason = 'Skipped: could not determine whether this is an AVD session host*' }
    ) {
        $pair = Get-Variable -Name $Name -Scope Script -ValueOnly
        $ntlm = Get-NtlmPlan -Pair $pair
        $ntlm.Count | Should -Be 2
        $ntlm[1].Category | Should -Be 'NtlmRestrictOutgoing'
        $ntlm[1].Action | Should -BeLike $Reason
        $result = @($pair.Execute.Summary.Items | Where-Object Category -eq 'NtlmRestrictOutgoing')
        $result.Count | Should -Be 1
        $result[0].Result | Should -BeLike $Reason
        (Get-MsvWrite -Pair $pair -Name 'RestrictSendingNTLMTraffic').Count | Should -Be 0
        # Audit is safe anywhere, so the audit item is still applied.
        (Get-MsvWrite -Pair $pair -Name 'AuditReceivingNTLMTraffic').Count | Should -Be 1
    }

    It 'notes that policy may override local writes on a domain-joined host' {
        $script:ntlmDomain.Execute.Summary.HostContext.JoinType | Should -Be 'DomainJoined'
        $script:ntlmDomain.Execute.Summary.HostNote | Should -Match 'policy'
        $script:ntlmDefault.Execute.Summary.HostNote | Should -BeNullOrEmpty
    }
}