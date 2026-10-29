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
        # A rule that was in Block mode before the run, one that was absent, a setting, and an
        # allowed application the run added.
        [pscustomobject]@{
            Timestamp = '20260101_000000'
            AsrMode = 'Audit'
            ChangedSettings = @(
                [pscustomobject]@{ Category = 'AsrRule'; Setting = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; RequiresAdmin = $true; PriorValue = 1; AppliedValue = 2 }
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
        ($script:rbItems | Where-Object Setting -eq 'd4f940ab-401b-4efc-aadc-ad5f3c50688a').DesiredValue | Should -Be 1
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
        $restore[0].Detail | Should -Match 'AttackSurfaceReductionRules_Actions=1'
        @($records | Where-Object { $_.Command -eq 'Remove-MpPreference' -and $_.Target -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }).Count | Should -Be 1
        @($records | Where-Object { $_.Command -eq 'Remove-MpPreference' -and $_.Target -eq 'C:\tools\example\python.exe' }).Count | Should -Be 1
        @($records | Where-Object { $_.Command -eq 'Set-MpPreference' -and $_.Detail -match 'PUAProtection=0' }).Count | Should -Be 1
    }
}
