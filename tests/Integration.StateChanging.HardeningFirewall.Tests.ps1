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

Describe 'Set-WindowsFirewallBaseline with an unreadable rule address' {
    It 'treats a rule whose RemoteAddress is empty as unreadable and plans no change for it' {
        $rules = @(@{ Name = 'fw-emptyaddr'; DisplayName = 'Empty Address App'; Program = $script:livePath; Profile = 'Public, Private'; RemoteAddress = '' })
        $fixture = New-FirewallFixture -Name 'emptyaddr' -Rules $rules -Profiles $script:targetProfiles
        $pair = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptPath -Tag 'fw-emptyaddr' -FixtureEnvironment $fixture -ExtraSetup $script:netshStub `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'emptyaddr'); ScopeRuleDisplayName = @('Empty Address App') }
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $item = @(Read-PlanJson -Summary $pair.WhatIf.Summary | Where-Object Setting -eq 'fw-emptyaddr')
        $item.Count | Should -Be 1
        $item[0].CurrentRemoteAddress | Should -Be 'unknown'
        $item[0].Action | Should -BeLike 'Cannot read Profile/RemoteAddress*not changed'
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

Describe 'Set-WindowsFirewallBaseline rollback safety' {
    BeforeAll {
        $script:fwDirCounter = 0
        $script:fwScriptFullPath = Join-Path (Get-RepositoryRoot) $script:scriptPath
        $script:fwFixture = New-FirewallFixture -Name 'safety' -Rules $script:rules -Profiles $script:targetProfiles

        function Get-LiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:fwScriptFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        function New-SafetyDir {
            $script:fwDirCounter++
            $dir = Join-Path $script:workRoot "fwSafety$($script:fwDirCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        function New-ProfileEntry {
            param($Category = 'ProfileSetting', $Target = 'Public', $Property = 'DefaultInboundAction', $Prior = 'Allow', $Applied = 'Block')
            $entry = [ordered]@{ Category = $Category; Setting = "$Target.$Property"; Target = $Target }
            if ($null -ne $Property) { $entry.Property = $Property }
            $entry.RequiresAdmin = $true
            $entry.PriorValue = $Prior
            $entry.AppliedValue = $Applied
            [pscustomobject]$entry
        }

        function New-RuleEntry {
            param($Category = 'StaleProgramRule', $Target = 'fw-stale', $Prior = 'True')
            [pscustomobject]@{ Category = $Category; Setting = $Target; Target = $Target; Property = 'Enabled'; RequiresAdmin = $true; PriorValue = $Prior; AppliedValue = 'False' }
        }

        function New-ScopeEntry {
            param($Target = 'fw-scope', $PriorProfile = 'Public,Private', $PriorRemoteAddress = 'Any')
            [pscustomobject]@{ Category = 'ScopeRule'; Setting = $Target; Target = $Target; Property = ''; RequiresAdmin = $true
                PriorValue = 'Profile=Public,Private;RemoteAddress=Any'; AppliedValue = 'Profile=Private;RemoteAddress=LocalSubnet'
                PriorProfile = $PriorProfile; PriorRemoteAddress = $PriorRemoteAddress; AppliedProfile = 'Private'; AppliedRemoteAddress = 'LocalSubnet' }
        }

        function Write-FwRollbackFile {
            param([string]$Dir, [string]$Name, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-FwRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute, [string]$Fixture = $script:fwFixture)
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
                -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $Fixture + $script:netshStub) -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Assert-FwRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-FwRollback -Dir $Dir -Tag "fwRefused$($script:fwDirCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'firewall-baseline-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'firewall-baseline-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because "$Because must be refused before the firewall backup or any change"
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the categories, profiles and properties the forward plan uses, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'unknown category'; Entry = (New-ProfileEntry -Category 'DeleteAllRules') },
            @{ Name = 'unknown profile'; Entry = (New-ProfileEntry -Target 'Evil') },
            @{ Name = 'unknown property'; Entry = (New-ProfileEntry -Property 'DefaultInboundActionX') },
            @{ Name = 'property the forward plan never sets'; Entry = (New-ProfileEntry -Property 'LogFileName' -Prior 'C:\evil.log') },
            @{ Name = 'property missing'; Entry = (New-ProfileEntry -Property $null) },
            @{ Name = 'rule entry with empty Target'; Entry = (New-RuleEntry -Target '') }
        )
        foreach ($case in $cases) {
            $dir = New-SafetyDir
            $name = 'firewall-baseline-rollback-20260101_000000.json'
            $null = Write-FwRollbackFile -Dir $dir -Name $name -Entry @((New-ProfileEntry), $case.Entry)
            Assert-FwRefused -Dir $dir -FileName $name -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-SafetyDir
        $null = Write-FwRollbackFile -Dir $dir -Name 'firewall-baseline-rollback-20260101_000000.json' `
            -Entry @((New-ProfileEntry), (New-ProfileEntry), (New-ProfileEntry -Target 'Evil'))
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 2 '
        $r.Run.Output | Should -Match 'Evil'
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $name = 'firewall-baseline-rollback-20260101_000000.json'
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "ProfileSetting" } }'
            'ChangedSettings a string'  = '{ "ChangedSettings": "all" }'
            'ChangedSettings one valid entry, not in an array' = '{ "ChangedSettings": { "Category": "ProfileSetting", "Setting": "Public.Enabled", "Target": "Public", "Property": "Enabled", "PriorValue": "True" } }'
            'top level is an array'     = '[ { "Category": "ProfileSetting" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "Public" ] }'
            'entry lacks PriorValue'    = '{ "ChangedSettings": [ { "Category": "ProfileSetting", "Setting": "Public.Enabled", "Target": "Public", "Property": "Enabled" } ] }'
            'ScopeRule lacks PriorProfile' = '{ "ChangedSettings": [ { "Category": "ScopeRule", "Setting": "r", "Target": "r", "PriorValue": "x", "PriorRemoteAddress": "Any" } ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-SafetyDir
            Set-Content -LiteralPath (Join-Path $dir $name) -Value $bodies[$label] -Encoding utf8
            Assert-FwRefused -Dir $dir -FileName $name -Because $label
        }
    }

    It 'refuses a value of the wrong type or outside the allowed words' {
        $name = 'firewall-baseline-rollback-20260101_000000.json'
        $cases = @(
            @{ Name = 'Enabled prior maybe'; Entry = (New-ProfileEntry -Property 'Enabled' -Prior 'maybe') },
            @{ Name = 'Enabled prior unknown'; Entry = (New-ProfileEntry -Property 'Enabled' -Prior 'unknown') },
            @{ Name = 'inbound action prior True'; Entry = (New-ProfileEntry -Property 'DefaultInboundAction' -Prior 'True') },
            @{ Name = 'log size abc'; Entry = (New-ProfileEntry -Property 'LogMaxSizeKilobytes' -Prior 'abc') },
            @{ Name = 'log size out of range'; Entry = (New-ProfileEntry -Property 'LogMaxSizeKilobytes' -Prior '99999') },
            @{ Name = 'log size zero'; Entry = (New-ProfileEntry -Property 'LogMaxSizeKilobytes' -Prior 0) },
            @{ Name = 'profile prior is an array'; Entry = (New-ProfileEntry -Prior @('Allow', 'Block')) },
            @{ Name = 'profile prior is null'; Entry = (New-ProfileEntry -Prior $null) },
            @{ Name = 'rule prior abc'; Entry = (New-RuleEntry -Prior 'abc') },
            @{ Name = 'feature rule prior unknown'; Entry = (New-RuleEntry -Category 'PublicFeatureRule' -Target 'fw-feature' -Prior 'unknown') },
            @{ Name = 'scope PriorProfile empty'; Entry = (New-ScopeEntry -PriorProfile '') },
            @{ Name = 'scope PriorRemoteAddress unknown'; Entry = (New-ScopeEntry -PriorRemoteAddress 'unknown') },
            @{ Name = 'scope PriorRemoteAddress an array'; Entry = (New-ScopeEntry -PriorRemoteAddress @('a', 'b')) }
        )
        foreach ($case in $cases) {
            $dir = New-SafetyDir
            $null = Write-FwRollbackFile -Dir $dir -Name $name -Entry @($case.Entry)
            Assert-FwRefused -Dir $dir -FileName $name -Because $case.Name
        }
    }

    It 'accepts every profile setting the forward plan can produce, so the validator cannot drift from it' {
        $log = Join-Path $script:workRoot 'fwDriftApply.log'
        $fixture = New-FirewallFixture -Name 'drift' -Rules @() -Profiles $script:openProfiles
        $apply = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $fixture + $script:netshStub) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'fwDriftPlan'); BlockAllInboundOnPublic = $true; WhatIf = $true }
        $apply.ExitCode | Should -Be 0 -Because $apply.Output
        $forward = @(Read-PlanJson -Summary $apply.Summary | Where-Object { $_.Category -eq 'ProfileSetting' })
        $forward.Count | Should -Be 19
        $entries = @($forward | ForEach-Object {
                New-ProfileEntry -Target $_.Target -Property $_.Property -Prior "$($_.CurrentValue)" -Applied "$($_.DesiredValue)"
            })
        $dir = New-SafetyDir
        $null = Write-FwRollbackFile -Dir $dir -Name 'firewall-baseline-rollback-20260101_000000.json' -Entry $entries
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwDriftRollback'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items).Count | Should -Be 19
    }

    It 'does not pick a consumed file: the older unconsumed file is planned instead' {
        $dir = New-SafetyDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'firewall-baseline-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-FwRollbackFile -Dir $dir -Name 'firewall-baseline-rollback-20260101_000000.json' `
            -Entry @((New-ProfileEntry -Target 'Private' -Property 'NotifyOnListen' -Prior 'True' -Applied 'False'))
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        $plan = Read-PlanJson -Summary $r.Run.Summary
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('Private.NotifyOnListen')
        $plan[0].DesiredValue | Should -Be 'True'
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-SafetyDir
        $name = 'firewall-baseline-rollback-20260101_000000.json'
        $file = Write-FwRollbackFile -Dir $dir -Name $name -Entry @((New-ProfileEntry))
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwUnelevatedExec' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $name
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf' {
        $dir = New-SafetyDir
        $name = 'firewall-baseline-rollback-20260101_000000.json'
        $file = Write-FwRollbackFile -Dir $dir -Name $name -Entry @((New-ProfileEntry))
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwWhatIfKeeps'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $name
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0

        # With nothing to revert there is no item to preview, so only the -WhatIf rule itself keeps the file.
        $dir2 = New-SafetyDir
        $name2 = 'firewall-baseline-rollback-20260101_000000.json'
        $file2 = Write-FwRollbackFile -Dir $dir2 -Name $name2 -Entry @()
        $r2 = Invoke-FwRollback -Dir $dir2 -Tag 'fwWhatIfKeeps2'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        Test-Path -LiteralPath $file2 | Should -BeTrue
        $r2.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
    }

    It 'consumes the file after an executing rollback with nothing left to revert' {
        $dir = New-SafetyDir
        $name = 'firewall-baseline-rollback-20260101_000000.json'
        $file = Write-FwRollbackFile -Dir $dir -Name $name -Entry @()
        $r = Invoke-FwRollback -Dir $dir -Tag 'fwConsumeEmpty' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'firewall-baseline-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        $again = Invoke-FwRollback -Dir $dir -Tag 'fwConsumeEmpty2' -Execute
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
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

    It 'validates one entry in a pure function lifted from the script, against the tables it is given' {
        $text = Get-LiftedFunctionText -Name 'Get-RollbackEntryProblem'
        $check = [scriptblock]::Create("param(`$Entry, `$Names, `$Properties, `$Categories)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -ProfileNames `$Names -ProfileProperties `$Properties -Categories `$Categories")
        $names = @('Public')
        $properties = @([pscustomobject]@{ Property = 'Enabled'; Kind = 'Bool' }, [pscustomobject]@{ Property = 'LogMaxSizeKilobytes'; Kind = 'Int' })
        $categories = @('ProfileSetting', 'StaleProgramRule', 'ScopeRule')

        & $check (New-ProfileEntry -Property 'Enabled' -Prior 'True') $names $properties $categories | Should -BeNullOrEmpty
        & $check (New-ProfileEntry -Property 'Enabled' -Prior $false) $names $properties $categories | Should -BeNullOrEmpty
        & $check (New-ProfileEntry -Property 'LogMaxSizeKilobytes' -Prior '4096') $names $properties $categories | Should -BeNullOrEmpty
        & $check (New-RuleEntry) $names $properties $categories | Should -BeNullOrEmpty
        & $check (New-ScopeEntry) $names $properties $categories | Should -BeNullOrEmpty
        & $check (New-ProfileEntry -Target 'Domain' -Property 'Enabled' -Prior 'True') $names $properties $categories | Should -Not -BeNullOrEmpty
        & $check (New-ProfileEntry -Property 'DefaultInboundAction' -Prior 'Allow') $names $properties $categories | Should -Not -BeNullOrEmpty -Because 'the property is not in the table it was given'
        & $check (New-RuleEntry -Category 'PublicFeatureRule') $names $properties $categories | Should -Not -BeNullOrEmpty -Because 'the category is not in the list it was given'
        & $check (New-RuleEntry -Prior 'unknown') $names $properties $categories | Should -Not -BeNullOrEmpty
    }

    It 'rolls back newest first and consumes each file as it goes' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $dir = New-SafetyDir
        $log1 = Join-Path $script:workRoot 'fwLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'fwLifoApply2.log'
        # Apply 1 pins the profiles (open profiles in the fixture). Apply 2, a second later, disables the
        # stale rule on a machine whose profiles already match.
        $openFixture = New-FirewallFixture -Name 'lifoOpen' -Rules $script:rules -Profiles $script:openProfiles
        $apply1 = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + $openFixture + $script:netshStub) `
            -Argument @{ ReportDirectory = $dir; Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $apply2 = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + $script:fwFixture + $script:netshStub) `
            -Argument @{ ReportDirectory = $dir; DisableStaleProgramRules = $true; Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-FwRollback -Dir $dir -Tag 'fwLifoRollback1' -Execute
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        $rb1.Run.Summary.RollbackConsumedPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $rb1.Run.Summary.RollbackConsumedPath | Should -BeTrue
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $rb1.Run.Summary.RollbackConsumedPath | Should -Match 'rollback-\d{8}_\d{6}\.consumed-\d{8}_\d{6}\.json$'
        $m1 = @(Get-OpsMutationRecord -Path $rb1.Log | Where-Object { $_.Command -ne 'netsh.exe' })
        @($m1 | Where-Object { $_.Command -eq 'Enable-NetFirewallRule' } | ForEach-Object { $_.Target }) | Should -Be @('fw-stale')
        @($m1 | Where-Object { $_.Command -eq 'Set-NetFirewallProfile' }).Count | Should -Be 0

        $rb2 = Invoke-FwRollback -Dir $dir -Tag 'fwLifoRollback2' -Execute
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply1.Summary.RollbackJsonPath | Should -BeFalse
        $m2 = @(Get-OpsMutationRecord -Path $rb2.Log | Where-Object { $_.Command -ne 'netsh.exe' })
        @($m2 | Where-Object { $_.Command -eq 'Set-NetFirewallProfile' }).Count | Should -BeGreaterThan 0
        @($m2 | Where-Object { $_.Command -eq 'Enable-NetFirewallRule' }).Count | Should -Be 0

        $rb3 = Invoke-FwRollback -Dir $dir -Tag 'fwLifoRollback3' -Execute
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
    }
}
