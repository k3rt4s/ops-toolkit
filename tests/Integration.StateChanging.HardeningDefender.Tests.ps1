# Runs Set-WindowsDefenderHardening.ps1 end to end against a pretend Defender, once with
# -WhatIf and once executing, and checks which Defender changes it decides to make.
#
# Defender is reached through the fake module in tests\Fixtures\FakeSystemModules\Defender.psm1,
# staged ahead of the real one on PSModulePath, so no run here can change a real Defender
# setting. The fake reports whatever OPSTOOLKIT_TEST_MP_* variables say; the plan assertions
# read the plan JSON the script writes, which an unelevated session still produces.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-defhard-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:relativePath = 'scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1'

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Fixture text for the child process: an empty exclusion list plus the given Defender state.
    function Get-DefenderFixtureText {
        param([hashtable]$State = @{})
        $lines = @(
            "`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''"
            "`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''"
        )
        foreach ($key in $State.Keys) { $lines += "`$env:OPSTOOLKIT_TEST_MP_$key = '$($State[$key])'" }
        $lines -join "`r`n"
    }

    function Invoke-DefenderPair {
        param([string]$Tag, [hashtable]$Argument = @{}, [hashtable]$State = @{})
        $Argument.ReportDirectory = Join-Path $script:workRoot $Tag
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Argument $Argument -Tag $Tag `
            -FixtureEnvironment (Get-DefenderFixtureText -State $State)
    }

    function Get-PlanItem {
        param($Run)
        @(Get-Content -LiteralPath $Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
    }

    # Every ASR rule, set to the given action, in the fake's 'guid=action;guid=action' form.
    $script:allAsrIds = @(
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        '3b576869-a4ec-4529-8536-b80a7769e899', '26190899-1602-49e8-8b27-eb1d0a1ce869',
        'd3e037e1-3eb8-44c8-a917-57927947596d', '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
        'd1e49aac-8f56-4280-b9ba-993a6d77406c', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        'e6db77e5-3df2-4cf1-b95a-636979351e5b', '56a863a9-875e-4185-98a7-b882c64b5ce5',
        'c1db55ab-c21a-4637-bb3f-a12568109d35', '01443614-cd74-433a-b99e-2ecdc07bfc25'
    )
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsDefenderHardening on a machine with nothing configured' {
    BeforeAll {
        $script:clean = Invoke-DefenderPair -Tag 'clean'
        $script:cleanItems = Get-PlanItem -Run $script:clean.Execute
    }

    It 'runs to completion in both modes' {
        $script:clean.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:clean.WhatIf.Output)"
        $script:clean.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:clean.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:clean
    }

    It 'plans all 14 ASR rules in Audit mode (action 2) by default' {
        $asr = @($script:cleanItems | Where-Object Category -eq 'AsrRule')
        $asr.Count | Should -Be 14
        @($asr | Where-Object { $_.DesiredValue -ne 2 }).Count | Should -Be 0
        @($asr | Where-Object { $_.Action -notlike 'Set ASR rule*' }).Count | Should -Be 0
        foreach ($id in $script:allAsrIds) { @($asr | Where-Object Setting -eq $id).Count | Should -Be 1 }
    }

    It 'plans audit-only Controlled Folder Access and network protection, and the cloud settings' {
        ($script:cleanItems | Where-Object Setting -eq 'EnableControlledFolderAccess').DesiredValue | Should -Be 2
        ($script:cleanItems | Where-Object Setting -eq 'EnableNetworkProtection').DesiredValue | Should -Be 2
        ($script:cleanItems | Where-Object Setting -eq 'PUAProtection').DesiredValue | Should -Be 1
        ($script:cleanItems | Where-Object Setting -eq 'MAPSReporting').DesiredValue | Should -Be 2
        ($script:cleanItems | Where-Object Setting -eq 'SubmitSamplesConsent').DesiredValue | Should -Be 1
        ($script:cleanItems | Where-Object Setting -eq 'CloudBlockLevel').DesiredValue | Should -Be 2
        ($script:cleanItems | Where-Object Setting -eq 'CloudExtendedTimeout').DesiredValue | Should -Be 50
    }

    It 'lists Tamper Protection, Smart App Control, signature age and the AV provider as report only' {
        foreach ($setting in 'IsTamperProtected', 'VerifiedAndReputablePolicyState', 'AntivirusSignatureAge', 'AMRunningMode') {
            $item = @($script:cleanItems | Where-Object Setting -eq $setting)
            $item.Count | Should -Be 1 -Because "$setting should be reported"
            $item[0].Action | Should -BeLike 'Report only*'
        }
    }

    It 'never plans an exclusion' {
        @($script:cleanItems | Where-Object { $_.Setting -match 'Exclusion' -or $_.Action -match 'xclusion' }).Count | Should -Be 0
    }

    It 'adds each ASR rule with action 2 and writes a rollback file when executing elevated' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $records = @(Get-OpsMutationRecord -Path $script:clean.ExecuteLog)
        $adds = @($records | Where-Object { $_.Command -eq 'Add-MpPreference' })
        $adds.Count | Should -Be 14
        foreach ($id in $script:allAsrIds) {
            $match = @($adds | Where-Object Target -eq $id)
            $match.Count | Should -Be 1
            $match[0].Detail | Should -Match 'AttackSurfaceReductionRules_Actions=2'
        }
        @($records | Where-Object { $_.Command -eq 'Remove-MpPreference' }).Count | Should -Be 0
        $sets = @($records | Where-Object { $_.Command -eq 'Set-MpPreference' } | ForEach-Object { $_.Detail }) -join ' '
        $sets | Should -Match 'EnableControlledFolderAccess=2'
        $sets | Should -Match 'EnableNetworkProtection=2'
        $sets | Should -Match 'PUAProtection=1'
        $sets | Should -Match 'CloudExtendedTimeout=50'
        $script:clean.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
    }

    It 'skips every change instead of applying it when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        @(Get-OpsMutationRecord -Path $script:clean.ExecuteLog).Count | Should -Be 0
        $script:clean.Execute.Summary.AppliedCount | Should -Be 0
        $script:clean.Execute.Summary.SkippedCount | Should -BeGreaterThan 0
    }
}

Describe 'Set-WindowsDefenderHardening opt-in switches' {
    BeforeAll {
        $script:block = Invoke-DefenderPair -Tag 'block' -Argument @{
            AsrMode = 'Block'
            AsrRuleId = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A')
            ControlledFolderAccess = 'Enabled'
            ControlledFolderAllowedApplication = @('C:\tools\example\python.exe')
            NetworkProtection = 'Enabled'
        }
        $script:blockItems = Get-PlanItem -Run $script:block.Execute
    }

    It 'runs to completion and changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:block
        $script:block.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:block.Execute.Output)"
    }

    It 'plans only the requested ASR rules, in Block mode (action 1)' {
        $asr = @($script:blockItems | Where-Object Category -eq 'AsrRule')
        $asr.Count | Should -Be 2
        @($asr | Where-Object { $_.DesiredValue -ne 1 }).Count | Should -Be 0
        @($asr | ForEach-Object { $_.Setting } | Sort-Object) -join ',' |
            Should -Be '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,d4f940ab-401b-4efc-aadc-ad5f3c50688a'
    }

    It 'plans Controlled Folder Access and network protection as Enabled (1) and the allowed application' {
        ($script:blockItems | Where-Object Setting -eq 'EnableControlledFolderAccess').DesiredValue | Should -Be 1
        ($script:blockItems | Where-Object Setting -eq 'EnableNetworkProtection').DesiredValue | Should -Be 1
        $app = @($script:blockItems | Where-Object Category -eq 'CfaAllowedApplication')
        $app.Count | Should -Be 1
        $app[0].Setting | Should -Be 'C:\tools\example\python.exe'
        $app[0].Action | Should -BeLike 'Allow*'
    }

    It 'plans the allowed applications before the Controlled Folder Access mode item' {
        $names = @($script:blockItems | ForEach-Object { $_.Setting })
        $modeIndex = [array]::IndexOf($names, 'EnableControlledFolderAccess')
        $appIndex = [array]::IndexOf($names, 'C:\tools\example\python.exe')
        $appIndex | Should -BeGreaterOrEqual 0
        $modeIndex | Should -BeGreaterThan $appIndex -Because 'Block mode must not be set before the allow-list is in place'
    }

    It 'records the Block action and the allowed application when executing elevated' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $records = @(Get-OpsMutationRecord -Path $script:block.ExecuteLog)
        @($records | Where-Object { $_.Detail -match 'AttackSurfaceReductionRules_Actions=1' }).Count | Should -Be 2
        @($records | Where-Object { $_.Target -eq 'C:\tools\example\python.exe' }).Count | Should -Be 1
    }

    It 'refuses a rule ID outside the built-in list' {
        $bad = Invoke-DefenderPair -Tag 'badrule' -Argument @{ AsrRuleId = @('00000000-0000-0000-0000-000000000000') }
        $bad.WhatIf.ExitCode | Should -Not -Be 0
        $bad.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $bad.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WindowsDefenderHardening when Defender already meets the target' {
    BeforeAll {
        $asrState = (($script:allAsrIds | ForEach-Object { "$_=2" }) -join ';')
        $script:met = Invoke-DefenderPair -Tag 'met' -State @{
            ASR = $asrState; CFA = 2; NETPROT = 2; PUA = 1; MAPS = 2; SAMPLES = 1; CLOUDBLOCK = 2; CLOUDTIMEOUT = 50
        }
        $script:metItems = Get-PlanItem -Run $script:met.Execute

        # Stronger than the audit-only target: one rule in Block, CFA and network protection Enabled.
        $strongAsr = (($script:allAsrIds | ForEach-Object { if ($_ -like 'd4f940ab*') { "$_=1" } else { "$_=2" } }) -join ';')
        $script:strong = Invoke-DefenderPair -Tag 'strong' -State @{
            ASR = $strongAsr; CFA = 1; NETPROT = 1; PUA = 1; MAPS = 2; SAMPLES = 3; CLOUDBLOCK = 4; CLOUDTIMEOUT = 50
        }
        $script:strongItems = Get-PlanItem -Run $script:strong.Execute
    }

    It 'plans no change and records no mutation' {
        $script:met.Execute.ExitCode | Should -Be 0 -Because $script:met.Execute.Output
        @($script:metItems | Where-Object { $_.Action -like 'No change*' }).Count | Should -Be 21
        @($script:metItems | Where-Object { $_.Action -like 'Set*' }).Count | Should -Be 0
        $script:met.Execute.Summary.NoChangeCount | Should -Be 21
        $script:met.Execute.Summary.AppliedCount | Should -Be 0
        @(Get-OpsMutationRecord -Path $script:met.ExecuteLog).Count | Should -Be 0
        $script:met.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
    }

    It 'never weakens a stronger setting to reach the audit-only target' {
        $script:strong.Execute.ExitCode | Should -Be 0 -Because $script:strong.Execute.Output
        @($script:strongItems | Where-Object { $_.Action -like 'Set*' }).Count | Should -Be 0
        ($script:strongItems | Where-Object Setting -eq 'd4f940ab-401b-4efc-aadc-ad5f3c50688a').Action | Should -BeLike 'No change*'
        ($script:strongItems | Where-Object Setting -eq 'EnableControlledFolderAccess').Action | Should -BeLike 'No change*'
        ($script:strongItems | Where-Object Setting -eq 'EnableNetworkProtection').Action | Should -BeLike 'No change*'
        ($script:strongItems | Where-Object Setting -eq 'SubmitSamplesConsent').Action | Should -BeLike 'No change*'
        ($script:strongItems | Where-Object Setting -eq 'CloudBlockLevel').Action | Should -BeLike 'No change*'
        @(Get-OpsMutationRecord -Path $script:strong.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WindowsDefenderHardening when Defender is not the active antivirus or is unreadable' {
    It 'plans nothing but report-only items when a third-party antivirus is active' {
        $run = Invoke-DefenderPair -Tag 'passive' -State @{ RUNMODE = 'Passive mode' }
        $run.Execute.ExitCode | Should -Be 0 -Because $run.Execute.Output
        $items = Get-PlanItem -Run $run.Execute
        @($items | Where-Object { $_.Action -notlike 'Report only*' }).Count | Should -Be 0
        @($items | Where-Object Category -eq 'AsrRule').Count | Should -Be 0
        ($items | Where-Object Setting -eq 'AMRunningMode').Action | Should -Match 'third-party'
        $run.Execute.Summary.ThirdPartyAvActive | Should -BeTrue
        @(Get-OpsMutationRecord -Path $run.ExecuteLog).Count | Should -Be 0
    }

    It 'plans no change, and does not call it compliant, when Defender cannot be read' {
        $run = Invoke-DefenderPair -Tag 'unreadable' -State @{ UNREADABLE = '1' }
        $run.Execute.ExitCode | Should -Be 0 -Because $run.Execute.Output
        $items = Get-PlanItem -Run $run.Execute
        @($items | Where-Object Category -eq 'AsrRule').Count | Should -Be 0
        @($items | Where-Object { $_.Action -like 'No change*' }).Count | Should -Be 0
        @($items | Where-Object { $_.Action -notlike 'Report only*' }).Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $run.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WindowsDefenderHardening -Rollback' {
    BeforeAll {
        $script:rbDirectory = Join-Path $script:workRoot 'rollback'
        New-Item -ItemType Directory -Path $script:rbDirectory -Force | Out-Null
        # A rule that was in Audit mode before the run, one that was absent, a setting, and an
        # allowed application the run added.
        [pscustomobject]@{
            Timestamp = '20260101_000000'
            AsrMode = 'Audit'
            ChangedSettings = @(
                [pscustomobject]@{ Category = 'AsrRule'; Setting = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; RequiresAdmin = $true; PriorValue = 2; AppliedValue = 1 }
                [pscustomobject]@{ Category = 'AsrRule'; Setting = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; RequiresAdmin = $true; PriorValue = 'absent'; AppliedValue = 2 }
                [pscustomobject]@{ Category = 'PuaProtection'; Setting = 'PUAProtection'; RequiresAdmin = $true; PriorValue = 0; AppliedValue = 1 }
                [pscustomobject]@{ Category = 'CfaAllowedApplication'; Setting = 'C:\tools\example\python.exe'; RequiresAdmin = $true; PriorValue = 'absent'; AppliedValue = 'present' }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $script:rbDirectory 'defender-hardening-rollback-20260101_000000.json') -Encoding utf8

        $script:rb = Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:relativePath -Argument @{ ReportDirectory = $script:rbDirectory; Rollback = $true } `
            -Tag 'rollback' -FixtureEnvironment (Get-DefenderFixtureText)
        $script:rbItems = Get-PlanItem -Run $script:rb.Execute
    }

    It 'runs to completion and changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:rb
        $script:rb.Execute.ExitCode | Should -Be 0 -Because "the rollback run failed: $($script:rb.Execute.Output)"
    }

    It 'plans to restore each prior value, including absent' {
        ($script:rbItems | Where-Object Setting -eq 'd4f940ab-401b-4efc-aadc-ad5f3c50688a').DesiredValue | Should -Be 2
        ($script:rbItems | Where-Object Setting -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2').DesiredValue | Should -Be 'absent'
        ($script:rbItems | Where-Object Setting -eq 'PUAProtection').DesiredValue | Should -Be 0
        ($script:rbItems | Where-Object Category -eq 'CfaAllowedApplication').DesiredValue | Should -Be 'absent'
    }

    It 'restores the prior action, removes added rules and applications when executing elevated' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $records = @(Get-OpsMutationRecord -Path $script:rb.ExecuteLog)
        $restore = @($records | Where-Object { $_.Command -eq 'Add-MpPreference' -and $_.Target -eq 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' })
        $restore.Count | Should -Be 1
        $restore[0].Detail | Should -Match 'AttackSurfaceReductionRules_Actions=2'
        @($records | Where-Object { $_.Command -eq 'Remove-MpPreference' -and $_.Target -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }).Count | Should -Be 1
        @($records | Where-Object { $_.Command -eq 'Remove-MpPreference' -and $_.Target -eq 'C:\tools\example\python.exe' }).Count | Should -Be 1
        @($records | Where-Object { $_.Command -eq 'Set-MpPreference' -and $_.Detail -match 'PUAProtection=0' }).Count | Should -Be 1
    }
}

Describe 'Set-WindowsDefenderHardening rollback safety' {
    BeforeAll {
        $script:rbDirCounter = 0
        $script:defScriptFullPath = Join-Path (Get-RepositoryRoot) $script:relativePath
        $script:rbName = 'defender-hardening-rollback-20260101_000000.json'

        function Get-LiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:defScriptFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        # A copy of the script that reports itself elevated, so the executing half of a rollback can
        # be exercised in an unelevated session. Every Defender command still goes to the staged fake
        # module, so nothing real is changed. FailPua also makes the PUA restore throw.
        function New-ScriptCopy {
            param([string]$Name, [switch]$FailPua)
            $text = Get-Content -LiteralPath $script:defScriptFullPath -Raw
            $elevated = '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
            $text.Contains($elevated) | Should -BeTrue -Because 'the elevation check this copy replaces must still exist'
            $patched = $text.Replace($elevated, '$true')
            if ($FailPua) {
                $restore = "'PuaProtection' { Set-MpPreference -PUAProtection ([int]`$Item.DesiredValue) -ErrorAction Stop }"
                $patched.Contains($restore) | Should -BeTrue -Because 'the PUA restore this copy replaces must still exist'
                $patched = $patched.Replace($restore, "'PuaProtection' { throw 'injected failure' }")
            }
            $copy = Join-Path $script:workRoot "$Name.ps1"
            Set-Content -LiteralPath $copy -Value $patched -Encoding utf8
            [System.IO.Path]::GetRelativePath((Get-RepositoryRoot), $copy)
        }

        function New-RollbackDir {
            $script:rbDirCounter++
            $dir = Join-Path $script:workRoot "defSafety$($script:rbDirCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        function New-DefEntry {
            param($Category = 'PuaProtection', $Setting = 'PUAProtection', $Prior = 0, $Applied = 1, $RequiresAdmin = $true)
            [pscustomobject]@{ Category = $Category; Setting = $Setting; RequiresAdmin = $RequiresAdmin; PriorValue = $Prior; AppliedValue = $Applied }
        }

        function Write-DefRollbackFile {
            param([string]$Dir, [string]$Name = $script:rbName, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; AsrMode = 'Audit'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-DefRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute, [string]$Relative = $script:relativePath)
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $setup = (Get-WindowsMutationStubText -MutationLogPath $log) + (Get-DefenderFixtureText)
            $run = Invoke-ScriptUnderTest -RelativePath $Relative -ModulePath $script:systemModulePath -Setup $setup -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Assert-DefRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-DefRollback -Dir $Dir -Tag "defRefused$($script:rbDirCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'defender-hardening-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'defender-hardening-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because $Because
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the controls the forward plan sets, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'unknown category'; Entry = (New-DefEntry -Category 'DisableRealtime' -Setting 'DisableRealtimeMonitoring') },
            @{ Name = 'known category, unknown setting'; Entry = (New-DefEntry -Setting 'DisableRealtimeMonitoring') },
            @{ Name = 'setting of another category'; Entry = (New-DefEntry -Category 'PuaProtection' -Setting 'MAPSReporting') },
            @{ Name = 'ASR rule outside the built-in list'; Entry = (New-DefEntry -Category 'AsrRule' -Setting '00000000-0000-0000-0000-000000000000' -Prior 'absent' -Applied 2) },
            @{ Name = 'report-only category'; Entry = (New-DefEntry -Category 'TamperProtection' -Setting 'IsTamperProtected' -Prior 'True' -Applied 'True') },
            @{ Name = 'applied value the forward plan never sets'; Entry = (New-DefEntry -Prior 1 -Applied 0) },
            @{ Name = 'prior value that outranks the applied one'; Entry = (New-DefEntry -Category 'CloudBlockLevel' -Setting 'CloudBlockLevel' -Prior 4 -Applied 2) },
            @{ Name = 'prior value that is not a value the setting holds'; Entry = (New-DefEntry -Prior 7 -Applied 1) },
            @{ Name = 'absent prior on a plain setting'; Entry = (New-DefEntry -Prior 'absent' -Applied 1) },
            @{ Name = 'RequiresAdmin false'; Entry = (New-DefEntry -RequiresAdmin $false) }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $null = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry), $case.Entry)
            Assert-DefRefused -Dir $dir -FileName $script:rbName -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-RollbackDir
        $null = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry), (New-DefEntry -Setting 'DisableRealtimeMonitoring'))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 1 '
        $r.Run.Output | Should -Match 'DisableRealtimeMonitoring'
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $good = '{ "Category": "PuaProtection", "Setting": "PUAProtection", "RequiresAdmin": true, "PriorValue": 0, "AppliedValue": 1 }'
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "PuaProtection" } }'
            'ChangedSettings a string'  = '{ "ChangedSettings": "PUAProtection" }'
            'ChangedSettings one valid entry, not in an array' = "{ `"ChangedSettings`": $good }"
            'top level is an array'     = '[ { "Category": "PuaProtection" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "PUAProtection" ] }'
            'entry lacks AppliedValue'  = '{ "ChangedSettings": [ { "Category": "PuaProtection", "Setting": "PUAProtection", "RequiresAdmin": true, "PriorValue": 0 } ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-RollbackDir
            Set-Content -LiteralPath (Join-Path $dir $script:rbName) -Value $bodies[$label] -Encoding utf8
            Assert-DefRefused -Dir $dir -FileName $script:rbName -Because $label
        }
    }

    It 'refuses a value of the wrong type' {
        $cases = @(
            @{ Name = 'PriorValue abc'; Entry = (New-DefEntry -Prior 'abc') },
            @{ Name = 'PriorValue unknown'; Entry = (New-DefEntry -Prior 'unknown') },
            @{ Name = 'PriorValue numeric string'; Entry = (New-DefEntry -Prior '0') },
            @{ Name = 'PriorValue boolean'; Entry = (New-DefEntry -Prior $false) },
            @{ Name = 'PriorValue array'; Entry = (New-DefEntry -Prior @(0, 1)) },
            @{ Name = 'PriorValue null'; Entry = (New-DefEntry -Prior $null) },
            @{ Name = 'PriorValue fraction'; Entry = (New-DefEntry -Prior 0.5) },
            @{ Name = 'PriorValue out of range'; Entry = (New-DefEntry -Prior 99999999999) },
            @{ Name = 'ASR PriorValue present'; Entry = (New-DefEntry -Category 'AsrRule' -Setting 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' -Prior 'present' -Applied 2) },
            @{ Name = 'AppliedValue abc'; Entry = (New-DefEntry -Applied 'abc') },
            @{ Name = 'AppliedValue unknown'; Entry = (New-DefEntry -Applied 'unknown') },
            @{ Name = 'AppliedValue numeric string'; Entry = (New-DefEntry -Applied '1') },
            @{ Name = 'allowed application PriorValue number'; Entry = (New-DefEntry -Category 'CfaAllowedApplication' -Setting 'C:\tools\x.exe' -Prior 0 -Applied 'present') },
            @{ Name = 'allowed application AppliedValue absent'; Entry = (New-DefEntry -Category 'CfaAllowedApplication' -Setting 'C:\tools\x.exe' -Prior 'absent' -Applied 'absent') },
            @{ Name = 'allowed application empty path'; Entry = (New-DefEntry -Category 'CfaAllowedApplication' -Setting '' -Prior 'absent' -Applied 'present') }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $null = Write-DefRollbackFile -Dir $dir -Entry @($case.Entry)
            Assert-DefRefused -Dir $dir -FileName $script:rbName -Because $case.Name
        }
    }

    It 'does not pick a consumed file: the older unconsumed file is planned instead' {
        $dir = New-RollbackDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'defender-hardening-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry -Category 'CloudProtection' -Setting 'MAPSReporting' -Prior 0 -Applied 2))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        $plan = @(Get-PlanItem -Run $r.Run)
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('MAPSReporting')
    }

    It 'picks the newest file by name, not by write time' {
        $dir = New-RollbackDir
        $newer = Write-DefRollbackFile -Dir $dir -Name 'defender-hardening-rollback-20260301_000000.json' -Entry @((New-DefEntry))
        $older = Write-DefRollbackFile -Dir $dir -Name 'defender-hardening-rollback-20260101_000000.json' -Entry @((New-DefEntry -Category 'CloudProtection' -Setting 'MAPSReporting' -Prior 0 -Applied 2))
        (Get-Item -LiteralPath $newer).LastWriteTime = (Get-Date).AddDays(-30)
        (Get-Item -LiteralPath $older).LastWriteTime = (Get-Date)
        $r = Invoke-DefRollback -Dir $dir -Tag 'defByName'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $newer)
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-RollbackDir
        $file = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defUnelevatedExec' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:rbName
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf, even from a session that reports itself elevated' {
        $elevated = New-ScriptCopy -Name 'def-elevated-whatif'
        $dir = New-RollbackDir
        $file = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defWhatIfKeeps' -Relative $elevated
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
        $elevated = New-ScriptCopy -Name 'def-elevated-consume'
        $dir = New-RollbackDir
        $file = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry), (New-DefEntry -Category 'CloudProtection' -Setting 'MAPSReporting' -Prior 1 -Applied 2))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defConsume' -Execute -Relative $elevated
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('Reverted', 'Reverted')
        @(Get-OpsMutationRecord -Path $r.Log | Where-Object { $_.Command -eq 'Set-MpPreference' }).Count | Should -Be 2
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'defender-hardening-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:rbName
        $again = Invoke-DefRollback -Dir $dir -Tag 'defConsume2' -Execute -Relative $elevated
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
    }

    It 'leaves the file unconsumed when an executing rollback fails on an item' {
        $failing = New-ScriptCopy -Name 'def-elevated-fail' -FailPua
        $dir = New-RollbackDir
        $file = Write-DefRollbackFile -Dir $dir -Entry @((New-DefEntry -Category 'CloudProtection' -Setting 'MAPSReporting' -Prior 1 -Applied 2), (New-DefEntry))
        $r = Invoke-DefRollback -Dir $dir -Tag 'defPartial' -Execute -Relative $failing
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
        $text = (Get-LiftedFunctionText -Name 'Test-RollbackNumber') + "`n" + (Get-LiftedFunctionText -Name 'Get-RollbackEntryProblem')
        $check = [scriptblock]::Create("param(`$Entry, `$Controls)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -Controls `$Controls")
        $controls = @(
            [pscustomobject]@{ Category = 'Ranked'; Settings = @('R'); Kind = 'Value'; Desired = @(2); Rank = @{ 0 = 0; 1 = 1; 2 = 2 }; AllowAbsent = $true }
            [pscustomobject]@{ Category = 'Plain'; Settings = @('P'); Kind = 'Value'; Desired = @(50); Rank = $null; AllowAbsent = $false }
            [pscustomobject]@{ Category = 'Members'; Settings = $null; Kind = 'List'; Desired = @(); Rank = $null; AllowAbsent = $true }
        )
        function New-Probe { param($Category = 'Ranked', $Setting = 'R', $Prior = 1, $Applied = 2, $Admin = $true) [pscustomobject]@{ Category = $Category; Setting = $Setting; RequiresAdmin = $Admin; PriorValue = $Prior; AppliedValue = $Applied } }

        & $check (New-Probe) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Prior 'absent') $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'Plain' -Setting 'P' -Prior 10 -Applied 50) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Category 'Members' -Setting 'C:\any\path.exe' -Prior 'absent' -Applied 'present') $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Setting 'X') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Other') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Prior 2) $controls | Should -Not -BeNullOrEmpty -Because 'a forward run only raises a setting'
        & $check (New-Probe -Prior 9) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Prior 'unknown') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Applied 1) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Admin $false) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Plain' -Setting 'P' -Prior 'absent' -Applied 50) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Plain' -Setting 'P' -Prior 50 -Applied 50) $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Category 'Members' -Setting '' -Prior 'absent' -Applied 'present') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Prior 1) @() | Should -Not -BeNullOrEmpty -Because 'a table without the entry allows nothing'
        $twice = @($controls[0], $controls[0])
        & $check (New-Probe) $twice | Should -Not -BeNullOrEmpty -Because 'a category that matches two rows is ambiguous, so nothing is allowed'
    }

    It 'accepts every control the forward plan can produce, so the validator cannot drift from it' {
        $variants = @(
            @{ Tag = 'driftBlock'; Argument = @{ AsrMode = 'Block'; ControlledFolderAccess = 'Enabled'; NetworkProtection = 'Enabled'; ControlledFolderAllowedApplication = @('C:\tools\example\python.exe') } },
            @{ Tag = 'driftAudit'; Argument = @{} }
        )
        foreach ($variant in $variants) {
            $plan = Invoke-DefenderPair -Tag $variant.Tag -Argument $variant.Argument
            $plan.WhatIf.ExitCode | Should -Be 0 -Because $plan.WhatIf.Output
            $forward = @(Get-PlanItem -Run $plan.WhatIf | Where-Object { $_.Action -like 'Set*' -or $_.Action -like 'Allow*' })
            $forward.Count | Should -BeGreaterThan 8
            $entries = @($forward | ForEach-Object {
                    if ($_.Category -eq 'CfaAllowedApplication') {
                        New-DefEntry -Category $_.Category -Setting $_.Setting -Prior 'absent' -Applied 'present'
                    } elseif ($_.Category -eq 'AsrRule') {
                        New-DefEntry -Category $_.Category -Setting $_.Setting -Prior 'absent' -Applied $_.DesiredValue
                    } else {
                        New-DefEntry -Category $_.Category -Setting $_.Setting -Prior 0 -Applied $_.DesiredValue
                    }
                })
            $dir = New-RollbackDir
            $null = Write-DefRollbackFile -Dir $dir -Entry $entries
            $r = Invoke-DefRollback -Dir $dir -Tag "$($variant.Tag)Rollback"
            $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
            @($r.Run.Summary.Items).Count | Should -Be $forward.Count
        }
    }

    It 'rolls back newest first and consumes each file as it goes' {
        $elevated = New-ScriptCopy -Name 'def-elevated-lifo'
        $dir = New-RollbackDir
        $applied = @{ ASR = (($script:allAsrIds | ForEach-Object { "$_=2" }) -join ';'); CFA = 2; NETPROT = 2; PUA = 1; MAPS = 2; SAMPLES = 1; CLOUDBLOCK = 2; CLOUDTIMEOUT = 50 }
        # Apply 1 sets the audit defaults on a clean machine. Apply 2 (a second later) raises the ASR
        # rules and Controlled Folder Access on a machine that already has apply 1 in place.
        $log1 = Join-Path $script:workRoot 'defLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'defLifoApply2.log'
        $apply1 = Invoke-ScriptUnderTest -RelativePath $elevated -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + (Get-DefenderFixtureText)) `
            -Argument @{ ReportDirectory = $dir; Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $apply2 = Invoke-ScriptUnderTest -RelativePath $elevated -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + (Get-DefenderFixtureText -State $applied)) `
            -Argument @{ ReportDirectory = $dir; AsrMode = 'Block'; ControlledFolderAccess = 'Enabled'; Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-DefRollback -Dir $dir -Tag 'defLifoRollback1' -Execute -Relative $elevated
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        $rb1.Run.Summary.RollbackConsumedPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $rb1.Run.Summary.RollbackConsumedPath | Should -BeTrue
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $rb1.Run.Summary.RollbackConsumedPath | Should -Match 'rollback-\d{8}_\d{6}\.consumed-\d{8}_\d{6}\.json$'
        $details1 = @(Get-OpsMutationRecord -Path $rb1.Log | ForEach-Object { $_.Detail }) -join ' '
        $details1 | Should -Match 'EnableControlledFolderAccess=2'
        $details1 | Should -Not -Match 'PUAProtection'

        $rb2 = Invoke-DefRollback -Dir $dir -Tag 'defLifoRollback2' -Execute -Relative $elevated
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply1.Summary.RollbackJsonPath | Should -BeFalse
        $records2 = @(Get-OpsMutationRecord -Path $rb2.Log)
        @($records2 | Where-Object { $_.Command -eq 'Remove-MpPreference' }).Count | Should -Be 14
        @($records2 | Where-Object { $_.Command -eq 'Set-MpPreference' -and $_.Detail -match 'PUAProtection=0' }).Count | Should -Be 1

        $rb3 = Invoke-DefRollback -Dir $dir -Tag 'defLifoRollback3' -Execute -Relative $elevated
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
    }
}
