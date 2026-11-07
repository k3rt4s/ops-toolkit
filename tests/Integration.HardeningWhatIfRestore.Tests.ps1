# Proves Set-WindowsDefenderHardening.ps1 and Set-WdacAuditPolicy.ps1 give the -WhatIf preference back
# after the block that clears it to load a system module.
#
# Both scripts set $script:WhatIfPreference = $false around Import-Module so ConfigDefender and ConfigCI
# load under `pwsh -File script -WhatIf`, and restore it in finally. If the restore broke, every later
# `-WhatIf:$WhatIfPreference` would be false and a preview would apply real changes. The ordinary suite
# cannot see that for items whose value was not read unelevated, which return 'Skipped: requires elevation
# (not read)' before ShouldProcess is reached (an item whose value was read does reach it under -WhatIf). Every run here starts pwsh -File directly (the runner-script route never reproduces the
# fault), with the fake Defender and ConfigCI modules staged ahead of the real ones and a stand-in
# CiTool, and always with -WhatIf, so no real Defender or code integrity setting can be touched.
#
# Two kinds of test:
# - Unelevated-capable: each fails if the restore is removed, with or without Administrator rights.
#   Defender is read through its rollback note, WDAC through a stopped preview that must still exit 0.
# - Elevated only: the plan items reach ShouldProcess and must all report Previewed, never Applied.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-whatifrestore-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:defScript = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1'
    $script:wdacScript = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1'

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Starts `pwsh -File <script> <args> -WhatIf` as its own process with the fakes staged. The caller
    # passes only argument values, and -WhatIf is always appended here, so no run can execute.
    function Invoke-DirectWhatIf {
        param([string]$Script, [string[]]$Argument, [hashtable]$Environment = @{}, [string]$Tag)
        $log = Join-Path $script:workRoot "$Tag.log"
        $mutationLog = Join-Path $script:workRoot "$Tag.mutations.log"
        $env = @{
            OPSTOOLKIT_TEST_MUTATION_LOG = $mutationLog
            OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''
            OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''
        }
        foreach ($key in $Environment.Keys) { $env[$key] = $Environment[$key] }
        $saved = @{ PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath') }
        foreach ($key in $env.Keys) { $saved[$key] = [Environment]::GetEnvironmentVariable($key) }
        $quoted = @($Argument | ForEach-Object { if ($_ -like '-*') { $_ } else { "`"$_`"" } })
        $exit = $null
        try {
            [Environment]::SetEnvironmentVariable('PSModulePath', "$script:systemModulePath$([IO.Path]::PathSeparator)$($saved['PSModulePath'])")
            foreach ($key in $env.Keys) { [Environment]::SetEnvironmentVariable($key, [string]$env[$key]) }
            $process = Start-Process -FilePath (Get-Process -Id $PID).Path -NoNewWindow -PassThru `
                -ArgumentList (@('-NoProfile', '-NonInteractive', '-File', "`"$Script`"") + $quoted + @('-WhatIf')) `
                -RedirectStandardOutput $log -RedirectStandardError "$log.err"
            if ($process.WaitForExit(180000)) { $exit = $process.ExitCode } else { Stop-Process -Id $process.Id -Force }
        } finally {
            foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key]) }
        }
        $text = (Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath "$log.err" -Raw -ErrorAction SilentlyContinue)
        [pscustomobject]@{ ExitCode = $exit; Text = [string]$text; MutationLog = $mutationLog }
    }

    function Read-StateItem {
        param([string]$ReportDirectory, [string]$Filter)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter $Filter -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $file) { return @() }
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json)
    }

    # A CiTool stand-in: answers --list-policies from OPSTOOLKIT_TEST_CITOOL_POLICIES and logs every call.
    function New-FakeCiTool {
        param([string]$Name)
        $path = Join-Path $script:workRoot "$Name.cmd"
        @(
            '@echo off'
            '>> "%OPSTOOLKIT_TEST_CITOOL_LOG%" echo %*'
            'if "%1"=="--list-policies" goto list'
            'echo {"OperationResult":0}'
            'exit /b 0'
            ':list'
            'echo %OPSTOOLKIT_TEST_CITOOL_POLICIES%'
            'exit /b 0'
        ) | Set-Content -LiteralPath $path -Encoding ascii
        $path
    }

    $script:systemPolicy = '{"Policies":[{"PolicyID":"5951a96a-e0b5-4d3d-8fb8-3e5b61030784","BasePolicyID":"5951a96a-e0b5-4d3d-8fb8-3e5b61030784","FriendlyName":"Microsoft Windows Driver Policy","IsSystemPolicy":true,"IsSignedPolicy":true,"IsEnforced":true}],"OperationResult":0}'
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsDefenderHardening gives the -WhatIf preference back after loading the Defender module' {
    It 'keeps a -Rollback -WhatIf run a preview: the rollback note names -WhatIf, the file is kept and nothing is recorded' {
        # Runs in or out of elevation. The rollback plan's one item is a change, so it is Skipped (not
        # elevated) or Previewed (elevated); either way the script must then see $WhatIfPreference true and
        # say '-WhatIf changes nothing'. With the restore gone it reads false, says the item 'failed or was
        # skipped' unelevated, and an elevated run reverts the setting and consumes the file.
        $dir = Join-Path $script:workRoot 'def-rollback'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $rollbackFile = Join-Path $dir 'defender-hardening-rollback-20260101_000000.json'
        [pscustomobject]@{
            Timestamp = '20260101_000000'; AsrMode = 'Audit'
            ChangedSettings = @([pscustomobject]@{ Category = 'PuaProtection'; Setting = 'PUAProtection'; RequiresAdmin = $true; PriorValue = 0; AppliedValue = 1 })
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackFile -Encoding utf8

        $run = Invoke-DirectWhatIf -Script $script:defScript -Tag 'def-rollback' -Argument @('-ReportDirectory', $dir, '-Rollback')
        $run.ExitCode | Should -Be 0 -Because $run.Text

        $state = Read-StateItem -ReportDirectory $dir -Filter 'defender-hardening-rollback-state-*.json'
        $state.Count | Should -Be 1 -Because 'the run must reach its state report, or the checks below prove nothing'
        $state[0].Result | Should -Not -Be 'Reverted'
        Test-Path -LiteralPath $rollbackFile | Should -BeTrue -Because 'a -WhatIf rollback leaves its file unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        # Formatted output wraps; compare with whitespace removed.
        ($run.Text -replace '\s', '') | Should -Match ([regex]::Escape('unconsumed:-WhatIfchangesnothing'))
        @(Get-Content -LiteralPath $run.MutationLog -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'previews every plan item and applies none on a forward -WhatIf run (elevated only)' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session: unelevated, every change is Skipped before ShouldProcess is called, so only the rollback test above covers the restore'
            return
        }
        $dir = Join-Path $script:workRoot 'def-forward'
        $run = Invoke-DirectWhatIf -Script $script:defScript -Tag 'def-forward' -Argument @('-ReportDirectory', $dir)
        $run.ExitCode | Should -Be 0 -Because $run.Text
        $state = Read-StateItem -ReportDirectory $dir -Filter 'defender-hardening-apply-state-*.json'
        $changes = @($state | Where-Object { $_.RequiresAdmin -eq $true })
        $changes.Count | Should -BeGreaterThan 14 -Because 'the clean fixture plans all 14 ASR rules and the other settings'
        @($changes | Where-Object { $_.Result -ne 'Previewed' }).Count | Should -Be 0 -Because ((@($changes | ForEach-Object { "$($_.Setting)=$($_.Result)" }) -join '; '))
        @($state | Where-Object { $_.Result -in 'Applied', 'Reverted' }).Count | Should -Be 0
        @(Get-Content -LiteralPath $run.MutationLog -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'a preview records no Defender mutation'
        @(Get-ChildItem -LiteralPath $dir -Filter '*-rollback-*.json' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'a preview writes no rollback record'
    }
}

Describe 'Set-WdacAuditPolicy gives the -WhatIf preference back after loading ConfigCI' {
    BeforeAll {
        $script:wdacExampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.3.0</VersionEx>
  <PolicyID>{E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A}</PolicyID>
  <BasePolicyID>{E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
</SiPolicy>
'@
    }

    It 'still exits 0 when a precondition fails, because the script sees -WhatIf as true at the end of the run' {
        # Runs in or out of elevation. The example directory is empty, so the BasePolicyFile precondition
        # fails and sets the stop reason. A live run throws on that ("did not complete"); a preview exits
        # 0. With the restore gone the script reads $WhatIfPreference as false after the ConfigCI import
        # and throws, so this fails on exit code alone.
        $examples = Join-Path $script:workRoot 'wdac-empty-examples'
        New-Item -ItemType Directory -Path $examples -Force | Out-Null
        $reports = Join-Path $script:workRoot 'wdac-stopped'
        $ciLog = Join-Path $script:workRoot 'wdac-stopped-citool.log'
        $fakeCiTool = New-FakeCiTool -Name 'wdac-stopped-citool'
        $run = Invoke-DirectWhatIf -Script $script:wdacScript -Tag 'wdac-stopped' `
            -Argument @('-ReportDirectory', $reports, '-ExamplePolicyDirectory', $examples, '-CiToolPath', $fakeCiTool) `
            -Environment @{ OPSTOOLKIT_TEST_CITOOL_LOG = $ciLog; OPSTOOLKIT_TEST_CITOOL_POLICIES = $script:systemPolicy }
        $run.ExitCode | Should -Be 0 -Because $run.Text
        ($run.Text -replace '\s', '') | Should -Not -Match 'didnotcomplete'

        $state = Read-StateItem -ReportDirectory $reports -Filter 'wdac-audit-apply-state-*.json'
        $state.Count | Should -BeGreaterThan 0 -Because 'the run must reach its state report, or the exit code proves nothing'
        ($state | Where-Object { $_.Category -eq 'Precondition' -and $_.Setting -eq 'ConfigCI' }).Result | Should -Be 'Met' -Because 'ConfigCI must have loaded for the restore path to run'
        ($state | Where-Object { $_.Category -eq 'Precondition' -and $_.Setting -eq 'BasePolicyFile' }).Result | Should -Match '^Failed'
        @($state | Where-Object { $_.Result -in 'Applied', 'Reverted' }).Count | Should -Be 0
        $calls = @(Get-Content -LiteralPath $ciLog -ErrorAction SilentlyContinue)
        @($calls | Where-Object { $_ -match '--update-policy|--remove-policy' }).Count | Should -Be 0
    }

    It 'previews the deployment and runs no CiTool change on a forward -WhatIf run (elevated only)' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session: unelevated, the deployment is Skipped before ShouldProcess is called, so only the stopped-preview test above covers the restore'
            return
        }
        $examples = Join-Path $script:workRoot 'wdac-examples'
        New-Item -ItemType Directory -Path $examples -Force | Out-Null
        $script:wdacExampleXml | Set-Content -LiteralPath (Join-Path $examples 'AllowMicrosoft.xml') -Encoding utf8
        $script:wdacExampleXml | Set-Content -LiteralPath (Join-Path $examples 'DefaultWindows_Audit.xml') -Encoding utf8
        $reports = Join-Path $script:workRoot 'wdac-forward'
        $ciLog = Join-Path $script:workRoot 'wdac-forward-citool.log'
        $fakeCiTool = New-FakeCiTool -Name 'wdac-forward-citool'
        $run = Invoke-DirectWhatIf -Script $script:wdacScript -Tag 'wdac-forward' `
            -Argument @('-ReportDirectory', $reports, '-ExamplePolicyDirectory', $examples, '-CiToolPath', $fakeCiTool) `
            -Environment @{ OPSTOOLKIT_TEST_CITOOL_LOG = $ciLog; OPSTOOLKIT_TEST_CITOOL_POLICIES = $script:systemPolicy }
        $run.ExitCode | Should -Be 0 -Because $run.Text
        $state = Read-StateItem -ReportDirectory $reports -Filter 'wdac-audit-apply-state-*.json'
        ($state | Where-Object { $_.Category -eq 'DeployAuditPolicy' }).Result | Should -Be 'Previewed'
        @($state | Where-Object { $_.Result -in 'Applied', 'Reverted' }).Count | Should -Be 0
        $calls = @(Get-Content -LiteralPath $ciLog -ErrorAction SilentlyContinue)
        @($calls | Where-Object { $_ -match '--list-policies' }).Count | Should -BeGreaterThan 0 -Because 'the stand-in CiTool must be the one that ran'
        @($calls | Where-Object { $_ -match '--update-policy|--remove-policy' }).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $reports -Filter '*-rollback-*.json' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
}
