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
# script marks each item 'Skipped: requires elevation' and the mutation assertions are
# skipped; the plan JSON assertions still run because an unelevated run writes the plan.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-netproto-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:relativePath = 'scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1'

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    function Get-FixtureEnvironment {
        param([string]$Smb1 = 'false', [string]$Features = '', [string]$Unreadable = 'false')
        @"

`$env:OPSTOOLKIT_TEST_TASKS = ''
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''
`$env:OPSTOOLKIT_TEST_PRINTERS = ''
`$env:OPSTOOLKIT_TEST_SMB_SERVER_SMB1 = '$Smb1'
`$env:OPSTOOLKIT_TEST_SMB_UNREADABLE = '$Unreadable'
`$env:OPSTOOLKIT_TEST_OPTFEATURES = '$Features'
`$env:OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE = '$Unreadable'
"@
    }

    function Get-PlanItem {
        param($Pair)
        @(Get-Content -LiteralPath $Pair.Execute.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
    }
}

AfterAll {
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
        $feat = @($m | Where-Object Command -eq 'Disable-WindowsOptionalFeature' | ForEach-Object { $_.Target })
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
        @($m | Where-Object { $_.Command -in @('Set-SmbServerConfiguration', 'Disable-WindowsOptionalFeature') }).Count | Should -Be 0
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
        @(Get-OpsMutationRecord -Path $script:unk.ExecuteLog | Where-Object { $_.Command -in @('Set-SmbServerConfiguration', 'Disable-WindowsOptionalFeature') }).Count | Should -Be 0
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
        @($m | Where-Object Command -eq 'Enable-WindowsOptionalFeature')[0].Target | Should -Be 'SMB1Protocol'
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
