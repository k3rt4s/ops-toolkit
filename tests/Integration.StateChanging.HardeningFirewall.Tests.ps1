#Requires -Modules Pester

# Set-WindowsFirewallBaseline: profile defaults, the firewall backup, and the opt-in rule controls.
#
# The NetSecurity module is replaced by tests\Fixtures\FakeSystemModules\NetSecurity.psm1 and
# netsh.exe is a function stub, so nothing here reads or changes the real firewall. Each script
# runs twice: -WhatIf, where only the firewall backup may be recorded, and executing. The session
# is normally not elevated, so assertions that need the executing half to reach the cmdlets are
# skipped, and the plan JSON, which an unelevated run still writes, is asserted instead.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-fw-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $script:scriptPath = 'scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1'

    # A program that exists and one that does not, both outside any real application.
    $script:livePath = Join-Path $script:workRoot 'live-program.exe'
    Set-Content -LiteralPath $script:livePath -Value 'x'
    $script:missingPath = Join-Path $script:workRoot 'gone\missing-program.exe'

    # netsh export creates its target file, as the real tool does; any other call is flagged.
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
    $script:netshFailStub = @'
function netsh.exe {
    Write-OpsTestMutation -Command 'netsh.exe' -Target ($args -join ' ') -Detail 'failed'
    $global:LASTEXITCODE = 1
}
'@

    function New-FirewallFixture {
        param([string]$Name, [object[]]$Rules, [object[]]$Profiles)
        $rulesFile = Join-Path $script:workRoot "$Name-rules.json"
        $profilesFile = Join-Path $script:workRoot "$Name-profiles.json"
        ConvertTo-Json -InputObject @($Rules) -Depth 5 | Set-Content -LiteralPath $rulesFile
        ConvertTo-Json -InputObject @($Profiles) -Depth 5 | Set-Content -LiteralPath $profilesFile
        "`$env:OPSTOOLKIT_TEST_FW_RULES_FILE = '$rulesFile'`n`$env:OPSTOOLKIT_TEST_FW_PROFILES_FILE = '$profilesFile'`n"
    }

    $script:rules = @(
        @{ Name = 'fw-stale'; DisplayName = 'Stale App'; Program = $script:missingPath; Profile = 'Public' },
        @{ Name = 'fw-live'; DisplayName = 'Live App'; Program = $script:livePath; Profile = 'Public' },
        @{ Name = 'fw-feature'; DisplayName = 'Feature Rule'; Group = 'TestFeatureGroup'; DisplayGroup = 'Test Feature'; Profile = 'Public, Private' },
        @{ Name = 'fw-feature-private'; DisplayName = 'Feature Rule Private'; Group = 'TestFeatureGroup'; DisplayGroup = 'Test Feature'; Profile = 'Private' },
        @{ Name = 'fw-scope'; DisplayName = 'Test Scope App'; Program = $script:livePath; Profile = 'Public, Private'; RemoteAddress = 'Any' }
    )
    $script:openProfiles = @('Domain', 'Private', 'Public' | ForEach-Object {
            @{ Name = $_; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow'
                NotifyOnListen = 'True'; LogBlocked = 'False'; LogMaxSizeKilobytes = 4096 }
        })
    $script:targetProfiles = @('Domain', 'Private', 'Public' | ForEach-Object {
            @{ Name = $_; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'
                NotifyOnListen = 'False'; LogBlocked = 'True'; LogMaxSizeKilobytes = 16384 }
        })

    function Read-PlanJson {
        param($Summary)
        @(Get-Content -LiteralPath $Summary.PlanJsonPath -Raw | ConvertFrom-Json)
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsFirewallBaseline with every control enabled' {
    BeforeAll {
        $fixture = New-FirewallFixture -Name 'full' -Rules $script:rules -Profiles $script:openProfiles
        $script:full = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptPath -Tag 'fw-full' -FixtureEnvironment $fixture -ExtraSetup $script:netshStub `
            -Argument @{
                ReportDirectory = (Join-Path $script:workRoot 'full')
                BlockAllInboundOnPublic = $true
                DisableStaleProgramRules = $true
                DisablePublicFeatureGroup = @('TestFeatureGroup')
                ScopeRuleDisplayName = @('Test Scope App')
            }
    }

    It 'runs to completion in both modes' {
        $script:full.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:full.WhatIf.Output)"
        $script:full.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:full.Execute.Output)"
    }

    It 'changes nothing under -WhatIf except the firewall backup' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:full -IgnoreCommand 'netsh.exe'
        $netsh = @(Get-OpsMutationRecord -Path $script:full.WhatIfLog | Where-Object { $_.Command -eq 'netsh.exe' })
        $netsh.Count | Should -Be 1
        $netsh[0].Target | Should -Match '^advfirewall export .*firewall-backup-\d{8}_\d{6}\.wfw$'
        Test-Path -LiteralPath $script:full.WhatIf.Summary.BackupPath | Should -BeTrue
    }

    It 'takes the backup on the executing run too' {
        $netsh = @(Get-OpsMutationRecord -Path $script:full.ExecuteLog | Where-Object { $_.Command -eq 'netsh.exe' })
        $netsh.Count | Should -Be 1
        Test-Path -LiteralPath $script:full.Execute.Summary.BackupPath | Should -BeTrue
    }

    It 'plans the profile defaults and the opt-in controls, and leaves the other rules alone' {
        $plan = Read-PlanJson -Summary $script:full.Execute.Summary
        $byName = @{}
        foreach ($i in $plan) { $byName["$($i.Setting)"] = $i }

        $byName['Public.DefaultInboundAction'].DesiredValue | Should -Be 'Block'
        $byName['Public.DefaultInboundAction'].CurrentValue | Should -Be 'Allow'
        $byName['Domain.DefaultOutboundAction'].DesiredValue | Should -Be 'Allow'
        $byName['Private.NotifyOnListen'].DesiredValue | Should -Be 'False'
        $byName['Private.NotifyOnListen'].CurrentValue | Should -Be 'True'
        $byName['Private.LogBlocked'].DesiredValue | Should -Be 'True'
        $byName['Domain.LogMaxSizeKilobytes'].DesiredValue | Should -Be '16384'
        $byName['Public.AllowInboundRules'].DesiredValue | Should -Be 'False'

        $byName['fw-stale'].Category | Should -Be 'StaleProgramRule'
        $byName['fw-stale'].DesiredValue | Should -Be 'False'
        $byName['fw-feature'].Category | Should -Be 'PublicFeatureRule'
        $byName['fw-scope'].DesiredProfile | Should -Be 'Private'
        $byName['fw-scope'].DesiredRemoteAddress | Should -Be 'LocalSubnet'
        $byName['fw-scope'].CurrentProfile | Should -Be 'Public,Private'
        $byName['fw-scope'].CurrentRemoteAddress | Should -Be 'Any'

        $byName.ContainsKey('fw-live') | Should -BeFalse -Because 'its program exists'
        $byName.ContainsKey('fw-feature-private') | Should -BeFalse -Because 'its profile does not include Public'
        foreach ($i in $plan) { $i.RequiresAdmin | Should -BeTrue }
    }

    It 'disables only the stale and feature rules, pins the profiles and scopes the named rule when executing' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $mutations = @(Get-OpsMutationRecord -Path $script:full.ExecuteLog)
        @($mutations | Where-Object { $_.Command -eq 'Disable-NetFirewallRule' } | ForEach-Object { $_.Target } | Sort-Object) |
            Should -Be @('fw-feature', 'fw-stale')
        @($mutations | Where-Object { $_.Command -eq 'Enable-NetFirewallRule' }).Count | Should -Be 0

        $scope = @($mutations | Where-Object { $_.Command -eq 'Set-NetFirewallRule' })
        $scope.Count | Should -Be 1
        $scope[0].Target | Should -Be 'fw-scope'
        $scope[0].Detail | Should -Be 'Profile=Private;RemoteAddress=LocalSubnet'

        $profiles = @($mutations | Where-Object { $_.Command -eq 'Set-NetFirewallProfile' })
        ($profiles | Where-Object { $_.Target -eq 'Public' -and $_.Detail -eq 'DefaultInboundAction=Block' }).Count | Should -Be 1
        ($profiles | Where-Object { $_.Target -eq 'Public' -and $_.Detail -eq 'AllowInboundRules=False' }).Count | Should -Be 1
        ($profiles | Where-Object { $_.Detail -eq 'LogMaxSizeKilobytes=16384' }).Count | Should -Be 3

        $script:full.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $script:full.Execute.Summary.AppliedCount | Should -BeGreaterThan 0
    }

    It 'skips every item when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'
            return
        }
        @(Get-OpsMutationRecord -Path $script:full.ExecuteLog | Where-Object { $_.Command -ne 'netsh.exe' }).Count | Should -Be 0
        $script:full.Execute.Summary.SkippedCount | Should -BeGreaterThan 0
        $script:full.Execute.Summary.AppliedCount | Should -Be 0
    }
}

Describe 'Set-WindowsFirewallBaseline defaults' {
    BeforeAll {
        $fixture = New-FirewallFixture -Name 'defaults' -Rules $script:rules -Profiles $script:openProfiles
        $script:defaults = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptPath -Tag 'fw-defaults' -FixtureEnvironment $fixture -ExtraSetup $script:netshStub `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'defaults') }
    }

    It 'plans only the six profile properties for three profiles when no switch is given' {
        $script:defaults.Execute.ExitCode | Should -Be 0 -Because $script:defaults.Execute.Output
        $plan = Read-PlanJson -Summary $script:defaults.Execute.Summary
        $plan.Count | Should -Be 18
        @($plan | Where-Object { $_.Category -ne 'ProfileSetting' }).Count | Should -Be 0
        @($plan | Where-Object { $_.Setting -eq 'Public.AllowInboundRules' }).Count | Should -Be 0
    }

    It 'changes nothing under -WhatIf except the backup' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:defaults -IgnoreCommand 'netsh.exe'
    }

    It 'honours LogMaxSizeKilobytes' {
        $fixture = New-FirewallFixture -Name 'logsize' -Rules @() -Profiles $script:openProfiles
        $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath (Join-Path $script:workRoot 'logsize.log')) + $fixture + $script:netshStub) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'logsize'); LogMaxSizeKilobytes = 8192; WhatIf = $true }
        $run.ExitCode | Should -Be 0 -Because $run.Output
        $item = @(Read-PlanJson -Summary $run.Summary | Where-Object { $_.Setting -eq 'Private.LogMaxSizeKilobytes' })
        $item[0].DesiredValue | Should -Be '8192'
    }
}

Describe 'Set-WindowsFirewallBaseline when the profiles already match' {
    BeforeAll {
        $fixture = New-FirewallFixture -Name 'nochange' -Rules $script:rules -Profiles $script:targetProfiles
        $script:noChange = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptPath -Tag 'fw-nochange' -FixtureEnvironment $fixture -ExtraSetup $script:netshStub `
            -Argument @{
                ReportDirectory = (Join-Path $script:workRoot 'nochange')
                ScopeRuleDisplayName = @('No Such Rule')
                DisablePublicFeatureGroup = @('NoSuchGroup')
            }
    }

    It 'reports NoChange for every item and mutates nothing' {
        $script:noChange.Execute.ExitCode | Should -Be 0 -Because $script:noChange.Execute.Output
        $summary = $script:noChange.Execute.Summary
        $summary.AppliedCount | Should -Be 0
        $summary.FailedCount | Should -Be 0
        $summary.NoChangeCount | Should -Be @($summary.Items).Count
        @($summary.Items | Where-Object { $_.Setting -eq 'Public.DefaultInboundAction' })[0].Result | Should -Be 'NoChange'
        $summary.RollbackJsonPath | Should -BeNullOrEmpty
        @(Get-OpsMutationRecord -Path $script:noChange.ExecuteLog | Where-Object { $_.Command -ne 'netsh.exe' }).Count | Should -Be 0
    }

    It 'reports an unmatched DisplayName or group in the plan instead of ignoring it' {
        $plan = Read-PlanJson -Summary $script:noChange.Execute.Summary
        @($plan | Where-Object { $_.Setting -eq 'displayname:No Such Rule' -and $_.Action -like 'No change*' }).Count | Should -Be 1
        @($plan | Where-Object { $_.Setting -eq 'group:NoSuchGroup' -and $_.Action -like 'No change*' }).Count | Should -Be 1
    }
}

Describe 'Set-WindowsFirewallBaseline backup failure' {
    It 'stops an executing run before any change when the export fails, or warns when no change can follow' {
        $fixture = New-FirewallFixture -Name 'fail' -Rules $script:rules -Profiles $script:openProfiles
        $log = Join-Path $script:workRoot 'fw-fail.log'
        $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $fixture + $script:netshFailStub) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'fail'); Confirm = $false }
        $run.Output | Should -Match 'Firewall backup failed'
        @(Get-OpsMutationRecord -Path $log | Where-Object { $_.Command -ne 'netsh.exe' }).Count | Should -Be 0
        if ($script:isElevated) {
            $run.ExitCode | Should -Not -Be 0
        } else {
            # Not elevated: every item is skipped, so the run completes without a backup.
            $run.ExitCode | Should -Be 0 -Because "$($run.Output)"
            $run.Summary.BackupPath | Should -BeNullOrEmpty
            @($run.Summary.Items | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count | Should -Be 0
        }
    }

    It 'completes a -WhatIf run without a backup when the export fails' {
        $fixture = New-FirewallFixture -Name 'failwhatif' -Rules $script:rules -Profiles $script:openProfiles
        $log = Join-Path $script:workRoot 'fw-failwhatif.log'
        $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $fixture + $script:netshFailStub) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'failwhatif'); WhatIf = $true }
        $run.ExitCode | Should -Be 0 -Because "$($run.Output)"
        $run.Output | Should -Match 'Firewall backup failed'
        $run.Summary.BackupPath | Should -BeNullOrEmpty
        @(Get-OpsMutationRecord -Path $log | Where-Object { $_.Command -ne 'netsh.exe' }).Count | Should -Be 0
    }
}

Describe 'Set-WindowsFirewallBaseline -Rollback' {
    BeforeAll {
        $fixture = New-FirewallFixture -Name 'rollback' -Rules $script:rules -Profiles $script:targetProfiles
        $dir = Join-Path $script:workRoot 'rollback'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [pscustomobject]@{
            Timestamp = '20260101_000000'
            ChangedSettings = @(
                [pscustomobject]@{ Category = 'StaleProgramRule'; Setting = 'fw-stale'; Target = 'fw-stale'; Property = 'Enabled'
                    RequiresAdmin = $true; PriorValue = 'True'; AppliedValue = 'False' },
                [pscustomobject]@{ Category = 'ProfileSetting'; Setting = 'Public.DefaultInboundAction'; Target = 'Public'
                    Property = 'DefaultInboundAction'; RequiresAdmin = $true; PriorValue = 'Allow'; AppliedValue = 'Block' },
                [pscustomobject]@{ Category = 'ScopeRule'; Setting = 'fw-scope'; Target = 'fw-scope'; Property = ''
                    RequiresAdmin = $true; PriorValue = 'Profile=Public,Private;RemoteAddress=Any'
                    AppliedValue = 'Profile=Private;RemoteAddress=LocalSubnet'
                    PriorProfile = 'Public,Private'; PriorRemoteAddress = 'Any'
                    AppliedProfile = 'Private'; AppliedRemoteAddress = 'LocalSubnet' }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir 'firewall-baseline-rollback-20260101_000000.json')

        $script:rollback = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptPath -Tag 'fw-rollback' -FixtureEnvironment $fixture -ExtraSetup $script:netshStub `
            -Argument @{ ReportDirectory = $dir; Rollback = $true }
    }

    It 'runs in both modes, the second run not mistaking the first run''s rollback plan for the rollback file' {
        $script:rollback.WhatIf.ExitCode | Should -Be 0 -Because $script:rollback.WhatIf.Output
        $script:rollback.Execute.ExitCode | Should -Be 0 -Because $script:rollback.Execute.Output
    }

    It 'changes nothing under -WhatIf except the backup' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:rollback -IgnoreCommand 'netsh.exe'
    }

    It 'plans the reverse of each recorded change, last change first' {
        $plan = Read-PlanJson -Summary $script:rollback.Execute.Summary
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('fw-scope', 'Public.DefaultInboundAction', 'fw-stale')
        $plan[0].DesiredProfile | Should -Be 'Public,Private'
        $plan[0].DesiredRemoteAddress | Should -Be 'Any'
        $plan[1].DesiredValue | Should -Be 'Allow'
        $plan[2].DesiredValue | Should -Be 'True'
    }

    It 're-enables the disabled rule and restores the prior values when executing' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $mutations = @(Get-OpsMutationRecord -Path $script:rollback.ExecuteLog)
        @($mutations | Where-Object { $_.Command -eq 'Enable-NetFirewallRule' } | ForEach-Object { $_.Target }) | Should -Be @('fw-stale')
        @($mutations | Where-Object { $_.Command -eq 'Disable-NetFirewallRule' }).Count | Should -Be 0
        @($mutations | Where-Object { $_.Command -eq 'Set-NetFirewallProfile' })[0].Detail | Should -Be 'DefaultInboundAction=Allow'
        $scope = @($mutations | Where-Object { $_.Command -eq 'Set-NetFirewallRule' })
        $scope[0].Target | Should -Be 'fw-scope'
        $scope[0].Detail | Should -Be 'Profile=Public,Private;RemoteAddress=Any'
    }

    It 'fails clearly when there is no rollback file' {
        $log = Join-Path $script:workRoot 'fw-rollback-none.log'
        $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $script:netshStub) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'rollback-none'); Rollback = $true; Confirm = $false }
        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'Nothing to roll back'
    }
}
