#Requires -Modules Pester

# A -Rollback run writes '<prefix>-rollback-plan-<ts>.json' and '<prefix>-rollback-state-<ts>.json'
# next to the real '<prefix>-rollback-<ts>.json'. A finder that matches '<prefix>-rollback-*.json'
# and takes the newest picks up the plan or state file after any rollback preview, so the next
# -Rollback reads the wrong record. Each case seeds a real rollback record, previews a rollback
# once to create those files, and requires the second preview to still plan from the record.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-rbsel-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    function Invoke-RollbackPreviewTwice {
        param([string]$RelativePath, [string]$Prefix, [string]$Tag, [object]$Record, [hashtable]$ExtraArgument = @{})
        $dir = Join-Path $script:workRoot $Tag
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $seed = Join-Path $dir "$Prefix-rollback-20200101_000000.json"
        $Record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $seed -Encoding utf8
        (Get-Item -LiteralPath $seed).LastWriteTime = [datetime]'2020-01-01'

        $runs = foreach ($n in 1, 2) {
            $log = Join-Path $script:workRoot "$Tag-$n.log"
            $argument = @{ ReportDirectory = $dir; Rollback = $true; WhatIf = $true } + $ExtraArgument
            Invoke-ScriptUnderTest -RelativePath $RelativePath -ModulePath $script:systemModulePath `
                -Setup (Get-WindowsMutationStubText -MutationLogPath $log) `
                -Argument $argument
            # Distinct timestamps, so the second run's files do not overwrite the first's.
            Start-Sleep -Milliseconds 1100
        }
        @($runs)
    }

    function Get-PlannedSetting {
        param($Run)
        @(Get-Content -LiteralPath $Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json) | ForEach-Object { "$($_.Setting)" }
    }
}

AfterAll {
    if ($script:workRoot -and (Test-Path -LiteralPath $script:workRoot)) {
        Remove-Item -LiteralPath $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Rollback record selection after a rollback preview' {
    It 'Set-WorkstationLockPosture plans the second rollback from the rollback record' {
        $runs = Invoke-RollbackPreviewTwice -Tag 'lock' -Prefix 'lock-posture' `
            -RelativePath 'scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1' `
            -Record @{ ChangedSettings = @(@{ Category = 'ScreenSaver'; Setting = 'RollbackSelectionProbe'; RequiresAdmin = $false; AppliedValue = '1380'; PriorValue = '600' }) }
        $runs[1].ExitCode | Should -Be 0 -Because "$($runs[1].Output)"
        Get-PlannedSetting $runs[1] | Should -Contain 'RollbackSelectionProbe'
    }

    It 'Set-BrowserCredentialPosture plans the second rollback from the rollback record' {
        $runs = Invoke-RollbackPreviewTwice -Tag 'browser' -Prefix 'browser-credential-posture' `
            -RelativePath 'scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1' `
            -Record @{ ChangedSettings = @(@{ Category = 'Policy'; Setting = 'RollbackSelectionProbe'; RequiresAdmin = $true
                        RegPath = 'HKLM:\SOFTWARE\OpsToolkitTest'; RegName = 'Probe'; RegKind = 'DWord'; AppliedValue = '1'; PriorValue = $null }) }
        $runs[1].ExitCode | Should -Be 0 -Because "$($runs[1].Output)"
        Get-PlannedSetting $runs[1] | Should -Contain 'RollbackSelectionProbe'
    }

    It 'Set-WorkstationPerformance plans the second rollback from the rollback record' {
        $probe = Join-Path $script:workRoot 'RollbackSelectionProbe'
        $runs = Invoke-RollbackPreviewTwice -Tag 'perf' -Prefix 'performance' `
            -RelativePath 'scripts\it-operations\performance\Set-WorkstationPerformance.ps1' `
            -Record @{ PreviousActiveSchemeGuid = $null; AddedDefenderPaths = @($probe); AddedDefenderProcesses = @() } `
            -ExtraArgument @{ DefenderPathExclusion = @($probe) }
        $runs[1].ExitCode | Should -Be 0 -Because "$($runs[1].Output)"
        Get-PlannedSetting $runs[1] | Should -Contain $probe
    }
}
