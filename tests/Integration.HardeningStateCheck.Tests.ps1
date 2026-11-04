#Requires -Modules Pester

# Test-WindowsHardeningState.ps1: how it turns each hardening script's result into a state, and
# that an item it could not read is never counted as compliant.
#
# Three layers. The mapping functions are extracted from the script by AST and called directly.
# The whole script then runs in a child process from a temporary copy of the repository tree whose
# Set- scripts are small fakes that write a state file chosen by the test, so every Result string
# the real scripts can produce is exercised without touching the machine. Last, the real script
# reads a fixture BitLocker volume through the staged fake BitLocker module.
#
# What this proves: the mapping, the counting, the exit code, and that no key protector reaches a
# report. It does not prove what the real Set- scripts return on a real machine; that is covered by
# their own tests and by running the checker.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1' `
        -FunctionName 'Get-HardeningStateVerdict', 'Get-WdacDeployVerdict', 'Get-LegacyRowState'

    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-hstate-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:pwshPath = (Get-Process -Id $PID).Path
    $script:runCounter = 0

    # A temporary copy of the tree the script resolves its modules and Set- scripts against, with a
    # fake in place of each Set- script. The fake writes whatever state file the test points it at.
    $script:fakeRoot = Join-Path $script:workRoot 'tree'
    $script:fakeFolder = Join-Path $script:fakeRoot 'scripts\it-operations\windows-hardening'
    New-Item -ItemType Directory -Path $script:fakeFolder -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:fakeRoot 'modules') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path (Get-RepositoryRoot) 'modules\OpsToolkit.Reporting') `
        -Destination (Join-Path $script:fakeRoot 'modules') -Recurse -Force
    Copy-Item -LiteralPath (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1') `
        -Destination $script:fakeFolder -Force
    $script:fakeChecker = Join-Path $script:fakeFolder 'Test-WindowsHardeningState.ps1'

    $stateTemplate = @'
[CmdletBinding(SupportsShouldProcess = $true)]
param([Parameter(Mandatory = $true)][string]$ReportDirectory)
$ErrorActionPreference = 'Stop'
if ($env:OPSTOOLKIT_TEST_FAKE_EXIT) { exit ([int]$env:OPSTOOLKIT_TEST_FAKE_EXIT) }
if ($env:OPSTOOLKIT_TEST_FAKE_MODULEPATH_FILE) { Set-Content -LiteralPath $env:OPSTOOLKIT_TEST_FAKE_MODULEPATH_FILE -Value $env:PSModulePath -WhatIf:$false }
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Copy-Item -LiteralPath $env:OPSTOOLKIT_TEST_FAKE_STATE_FILE -Destination (Join-Path $ReportDirectory "__PREFIX__-apply-state-$stamp.json") -WhatIf:$false
'@
    $script:fakePrefix = [ordered]@{
        'Set-WindowsDefenderHardening.ps1' = 'defender-hardening'
        'Set-WindowsCredentialProtection.ps1' = 'credential-protection'
        'Set-WindowsFirewallBaseline.ps1' = 'firewall-baseline'
        'Set-WdacAuditPolicy.ps1' = 'wdac-audit'
    }
    foreach ($file in $script:fakePrefix.Keys) {
        Set-Content -LiteralPath (Join-Path $script:fakeFolder $file) -Value $stateTemplate.Replace('__PREFIX__', $script:fakePrefix[$file]) -Encoding ascii
    }

    # An older-schema fake. It must be given -SkipRegistryBackup, as the real one is.
    Set-Content -LiteralPath (Join-Path $script:fakeFolder 'Set-Windows11PrivacyHardening.ps1') -Encoding ascii -Value @'
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$ReportDirectory,
    [Parameter(Mandatory = $true)][switch]$SkipRegistryBackup
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if ($env:OPSTOOLKIT_TEST_FAKE_LEGACY_CSV) {
    Copy-Item -LiteralPath $env:OPSTOOLKIT_TEST_FAKE_LEGACY_CSV -Destination (Join-Path $ReportDirectory "fake-privacy-plan-$stamp.csv") -WhatIf:$false
    return
}
@(
    [pscustomobject]@{ Action = 'NoChange'; Category = 'Telemetry'; ItemType = 'Registry'; Target = 'HKLM\A\One'; CurrentValue = '0'; DesiredValue = '0'; DesiredState = 'off'; Reason = 'already' }
    [pscustomobject]@{ Action = 'SetValue'; Category = 'Telemetry'; ItemType = 'Registry'; Target = 'HKLM\A\Two'; CurrentValue = '1'; DesiredValue = '0'; DesiredState = 'off'; Reason = 'wrong' }
    [pscustomobject]@{ Action = 'CreateValue'; Category = 'Telemetry'; ItemType = 'Registry'; Target = 'HKLM\A\Three'; CurrentValue = ''; DesiredValue = '0'; DesiredState = 'off'; Reason = 'missing' }
    [pscustomobject]@{ Action = 'Skipped'; Category = 'Telemetry'; ItemType = 'Service'; Target = 'svc'; CurrentValue = ''; DesiredValue = ''; DesiredState = ''; Reason = 'n/a' }
) | Export-Csv -LiteralPath (Join-Path $ReportDirectory "fake-privacy-plan-$stamp.csv") -NoTypeInformation -Encoding utf8 -WhatIf:$false
'@

    function New-StateItem {
        param(
            [string]$Category = 'Setting', [string]$Setting = 'S', [string]$Result, [string]$Action = 'Set it',
            [string]$CurrentValue = '0', [string]$DesiredValue = '1'
        )
        [pscustomobject]@{
            Category = $Category; Setting = $Setting; RequiresAdmin = $true; CurrentValue = $CurrentValue
            DesiredValue = $DesiredValue; Action = $Action; Result = $Result
        }
    }

    # Runs the checker in a child process, with the given environment variables set for the child and
    # restored afterwards. Returns the exit code and what the run wrote.
    function Invoke-Checker {
        param(
            [string]$Script = $script:fakeChecker, [string[]]$Target, [hashtable]$Environment = @{},
            [string[]]$ComputerName, [switch]$FailOnDrift, [string[]]$ExtraArgument = @()
        )
        $script:runCounter++
        $out = Join-Path $script:workRoot "out-$script:runCounter"
        $log = Join-Path $script:workRoot "run-$script:runCounter.log"
        $arguments = @('-NoProfile', '-NonInteractive', '-File', "`"$Script`"", '-Target', ($Target -join ','), '-OutputDirectory', "`"$out`"")
        if ($ComputerName) { $arguments += @('-ComputerName', ($ComputerName -join ',')) }
        if ($FailOnDrift) { $arguments += '-FailOnDrift' }
        if ($ExtraArgument.Count) { $arguments += $ExtraArgument }

        $saved = @{}
        foreach ($key in $Environment.Keys) {
            $saved[$key] = [Environment]::GetEnvironmentVariable($key)
            [Environment]::SetEnvironmentVariable($key, $Environment[$key])
        }
        try {
            $process = Start-Process -FilePath $script:pwshPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $log -RedirectStandardError "$log.err"
        } finally {
            foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key]) }
        }

        $runDirectory = Get-ChildItem -LiteralPath $out -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        $summaryPath = if ($runDirectory) { Join-Path $runDirectory.FullName 'summary.json' } else { '' }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            OutputDirectory = $out
            RunDirectory = if ($runDirectory) { $runDirectory.FullName } else { '' }
            Summary = if ($summaryPath -and (Test-Path -LiteralPath $summaryPath)) { Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json } else { $null }
            Records = if ($runDirectory -and (Test-Path -LiteralPath (Join-Path $runDirectory.FullName 'hardening-compliance.csv'))) { @(Import-Csv -LiteralPath (Join-Path $runDirectory.FullName 'hardening-compliance.csv')) } else { @() }
            Results = if ($runDirectory -and (Test-Path -LiteralPath (Join-Path $runDirectory.FullName 'script-results.csv'))) { @(Import-Csv -LiteralPath (Join-Path $runDirectory.FullName 'script-results.csv')) } else { @() }
            Log = $log
        }
    }

    function Invoke-FakeChecker {
        param([string]$Target, [object[]]$Item, [hashtable]$Environment = @{}, [string[]]$ComputerName, [switch]$FailOnDrift)
        $stateFile = Join-Path $script:workRoot "state-$($script:runCounter + 1).json"
        ConvertTo-Json -InputObject @($Item) -Depth 4 | Set-Content -LiteralPath $stateFile -Encoding utf8
        $env = @{ OPSTOOLKIT_TEST_FAKE_STATE_FILE = $stateFile }
        foreach ($key in $Environment.Keys) { $env[$key] = $Environment[$key] }
        Invoke-Checker -Target $Target -Environment $env -ComputerName $ComputerName -FailOnDrift:$FailOnDrift
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Get-HardeningStateVerdict' {
    It 'maps result <Result> (category <Category>, action <Action>, current <Current>) to <State>' -ForEach @(
        @{ Result = 'NoChange'; Category = 'Setting'; Action = 'No change'; Current = '1'; State = 'Compliant' }
        @{ Result = 'Previewed'; Category = 'Setting'; Action = 'Set it'; Current = '0'; State = 'Drifted' }
        @{ Result = 'Skipped: requires elevation'; Category = 'Setting'; Action = 'Set it'; Current = '0'; State = 'Drifted' }
        @{ Result = 'Skipped: requires elevation'; Category = 'Feature'; Action = 'Unreadable: feature state'; Current = 'unknown'; State = 'Unread' }
        @{ Result = 'Skipped: requires elevation'; Category = 'Setting'; Action = 'Set it'; Current = 'unknown'; State = 'Unread' }
        @{ Result = 'Skipped: current value unreadable'; Category = 'Setting'; Action = 'Cannot assess x'; Current = 'unknown'; State = 'Unread' }
        @{ Result = 'Skipped: requires elevation (not read)'; Category = 'Setting'; Action = 'Set it'; Current = ''; State = 'Unread' }
        @{ Result = 'Skipped: prior state unreadable'; Category = 'Setting'; Action = 'Set it'; Current = 'unknown'; State = 'Unread' }
        @{ Result = 'Skipped: current session is remote'; Category = 'Setting'; Action = 'Skipped: current session is remote'; Current = ''; State = 'Unread' }
        @{ Result = 'Failed: access denied'; Category = 'Setting'; Action = 'Set it'; Current = '0'; State = 'Failed' }
        @{ Result = 'ReportOnly'; Category = 'Report'; Action = 'Report only: x'; Current = 'On'; State = 'ReportOnly' }
        @{ Result = 'NoChange'; Category = 'Report'; Action = 'No change (report only: x)'; Current = 'Off'; State = 'ReportOnly' }
        @{ Result = 'Met'; Category = 'Setting'; Action = 'x'; Current = 'True'; State = 'Precondition' }
        @{ Result = 'Failed: not available'; Category = 'Precondition'; Action = 'Precondition: x'; Current = 'False'; State = 'Precondition' }
        @{ Result = ''; Category = 'Setting'; Action = 'Set it'; Current = '0'; State = 'Unread' }
        @{ Result = 'SomethingNew'; Category = 'Setting'; Action = 'Set it'; Current = '0'; State = 'Unread' }
    ) {
        $item = New-StateItem -Category $Category -Result $Result -Action $Action -CurrentValue $Current
        (Get-HardeningStateVerdict -Item $item).State | Should -Be $State
    }

    It 'never calls a skipped or undetermined result compliant' {
        foreach ($result in @(
                'Skipped: current value unreadable', 'Skipped: requires elevation (not read)', 'Skipped: current state unreadable',
                'Skipped: prior state unreadable', 'Skipped: could not be read', 'Skipped: precondition failed (x)', '', 'Unknown')) {
            $item = New-StateItem -Result $result
            (Get-HardeningStateVerdict -Item $item).State | Should -Not -Be 'Compliant' -Because "result '$result' was never read as the desired value"
            (Get-HardeningStateVerdict -Item $item).State | Should -Be 'Unread' -Because "result '$result' is undetermined"
        }
    }
}

Describe 'Get-WdacDeployVerdict' {
    BeforeAll {
        function New-WdacPrecondition {
            param([string]$Active = 'Met', [string]$ConfigCI = 'Met', [string]$BasePolicyFile = 'Met', [string]$CiTool = 'Met')
            @{ NoActiveAuditPolicy = $Active; ConfigCI = $ConfigCI; BasePolicyFile = $BasePolicyFile; CiTool = $CiTool; Elevated = 'Skipped: requires elevation' }
        }
        $script:wdacActive = "Failed: a policy named 'ops-toolkit WDAC audit' is already active (policy ID {abc}); run this script with -Rollback first"
        $script:wdacDeploy = New-StateItem -Category 'DeployAuditPolicy' -Setting 'ops-toolkit WDAC audit' -Result 'Skipped: requires elevation' -CurrentValue 'not deployed'
    }

    It 'is compliant when the toolkit audit policy is already active' {
        $generic = Get-HardeningStateVerdict -Item $script:wdacDeploy
        (Get-WdacDeployVerdict -Generic $generic -PreconditionResult (New-WdacPrecondition -Active $script:wdacActive)).State | Should -Be 'Compliant'
    }

    It 'is drifted when the list was read and the policy is not active' {
        $generic = Get-HardeningStateVerdict -Item $script:wdacDeploy
        (Get-WdacDeployVerdict -Generic $generic -PreconditionResult (New-WdacPrecondition -Active 'Met')).State | Should -Be 'Drifted'
    }

    It 'is unread when the active policy list could not be read' {
        $generic = Get-HardeningStateVerdict -Item $script:wdacDeploy
        foreach ($active in 'Skipped: requires elevation', 'Failed: active policies could not be read: x') {
            (Get-WdacDeployVerdict -Generic $generic -PreconditionResult (New-WdacPrecondition -Active $active)).State | Should -Be 'Unread'
        }
    }

    It 'is unread, never compliant, when the policy could not be built' {
        $generic = Get-HardeningStateVerdict -Item $script:wdacDeploy
        foreach ($condition in @(
                (New-WdacPrecondition -Active 'Met' -ConfigCI 'Failed: ConfigCI missing'),
                (New-WdacPrecondition -Active 'Met' -BasePolicyFile 'Failed: building the audit policy failed: x'),
                (New-WdacPrecondition -Active $script:wdacActive -BasePolicyFile 'Failed: example policy missing'))) {
            (Get-WdacDeployVerdict -Generic $generic -PreconditionResult $condition).State | Should -Be 'Unread'
        }
    }
}

Describe 'Test-WindowsHardeningState run against fake hardening scripts' {
    Context 'a mixed result set' {
        BeforeAll {
            $script:mixedModulePathFile = Join-Path $script:workRoot 'modulepath.txt'
            $items = @(
                New-StateItem -Setting 'ok' -Result 'NoChange' -Action 'No change'
                New-StateItem -Setting 'wrong' -Result 'Previewed'
                New-StateItem -Setting 'wrongNoAdmin' -Result 'Skipped: requires elevation'
                New-StateItem -Setting 'unreadable' -Result 'Skipped: current value unreadable' -Action 'Cannot assess unreadable' -CurrentValue 'unknown'
                New-StateItem -Setting 'failed' -Result 'Failed: boom'
                New-StateItem -Category 'Report' -Setting 'info' -Result 'ReportOnly' -Action 'Report only: info'
                New-StateItem -Category 'Precondition' -Setting 'Elevated' -Result 'Skipped: requires elevation' -Action 'Precondition: session is elevated'
            )
            $script:mixed = Invoke-FakeChecker -Target 'Defender' -Item $items -Environment @{
                PSModulePath = "$script:systemModulePath;$env:PSModulePath"
                OPSTOOLKIT_TEST_FAKE_MODULEPATH_FILE = $script:mixedModulePathFile
            }
        }

        It 'finishes and reports the target as checked' {
            $script:mixed.ExitCode | Should -Be 0 -Because (Get-Content -LiteralPath "$($script:mixed.Log).err" -Raw -ErrorAction SilentlyContinue)
            $script:mixed.Results[0].Status | Should -Be 'Checked'
        }

        It 'passes fixture environment variables and PSModulePath to the child process' {
            Test-Path -LiteralPath $script:mixedModulePathFile | Should -BeTrue
            (Get-Content -LiteralPath $script:mixedModulePathFile -Raw) | Should -Match ([regex]::Escape($script:systemModulePath))
            @($script:mixed.Records).Count | Should -Be 7 -Because 'the child read OPSTOOLKIT_TEST_FAKE_STATE_FILE from the inherited environment'
        }

        It 'gives each row its state' {
            $byItem = @{}
            foreach ($r in $script:mixed.Records) { $byItem[$r.Item] = $r.State }
            $byItem['ok'] | Should -Be 'Compliant'
            $byItem['wrong'] | Should -Be 'Drifted'
            $byItem['wrongNoAdmin'] | Should -Be 'Drifted'
            $byItem['unreadable'] | Should -Be 'Unread'
            $byItem['failed'] | Should -Be 'Failed'
            $byItem['info'] | Should -Be 'ReportOnly'
            $byItem['Elevated'] | Should -Be 'Precondition'
        }

        It 'never counts an unreadable row as compliant' {
            $script:mixed.Summary.CompliantCount | Should -Be 1
            @($script:mixed.Records | Where-Object { $_.State -eq 'Compliant' } | ForEach-Object { $_.Item }) | Should -Be @('ok')
        }

        It 'counts Failed toward the target drift count and the summary drift total' {
            $script:mixed.Results[0].DriftCount | Should -Be 3 -Because 'two Drifted rows and one Failed row'
            $script:mixed.Results[0].FailedCount | Should -Be 1
            $script:mixed.Summary.TotalDrift | Should -Be 3
        }

        It 'reports unread rows in the target row and the summary, apart from drift' {
            $script:mixed.Results[0].UnreadCount | Should -Be 1
            $script:mixed.Summary.UnreadCount | Should -Be 1
            @($script:mixed.Summary.UnreadTargets) | Should -Contain 'Defender:1'
            $script:mixed.Summary.Passed | Should -BeFalse
        }

        It 'leaves report-only and precondition rows out of the items checked' {
            $script:mixed.Summary.ItemsChecked | Should -Be 4 -Because 'Compliant, two Drifted and Failed'
            $script:mixed.Summary.ReportOnlyCount | Should -Be 1
        }

        It 'keeps the summary fields the evidence pack reads' {
            foreach ($name in 'TotalDrift', 'ItemsChecked', 'CompliantCount', 'Passed', 'UncheckedTargets', 'DriftedCount', 'NotConfiguredCount') {
                $script:mixed.Summary.PSObject.Properties.Name | Should -Contain $name
            }
        }
    }

    Context 'the older schema' {
        BeforeAll {
            $script:legacy = Invoke-Checker -Target 'Privacy'
        }

        It 'still maps the plan Action column and passes -SkipRegistryBackup' {
            $script:legacy.ExitCode | Should -Be 0
            $byItem = @{}
            foreach ($r in $script:legacy.Records) { $byItem[$r.Item] = $r.State }
            $byItem['HKLM\A\One'] | Should -Be 'Compliant'
            $byItem['HKLM\A\Two'] | Should -Be 'Drifted'
            $byItem['HKLM\A\Three'] | Should -Be 'NotConfigured'
            $byItem['svc'] | Should -Be 'Unread' -Because 'a Skipped legacy row is undetermined, not a state of its own'
        }

        It 'keeps the older drift count: Drifted plus NotConfigured' {
            $script:legacy.Results[0].DriftCount | Should -Be 2
            $script:legacy.Summary.TotalDrift | Should -Be 2
        }

        It 'counts the unclassified legacy row as unread and not as drift' {
            $script:legacy.Summary.UnreadCount | Should -Be 1
            $script:legacy.Summary.TotalDrift | Should -Be 2
            @($script:legacy.Summary.UnreadTargets) | Should -Contain 'Privacy:1'
            $script:legacy.Summary.ItemsChecked | Should -Be 3 -Because 'the unread row is outside the items checked'
        }
    }

    Context 'an older-schema plan with no drift and one row the checker cannot classify' {
        BeforeAll {
            $csv = Join-Path $script:workRoot 'legacy-undetermined.csv'
            @(
                [pscustomobject]@{ Action = 'NoChange'; Category = 'Telemetry'; ItemType = 'Registry'; Target = 'HKLM\A\One'; CurrentValue = '0'; DesiredValue = '0'; DesiredState = 'off'; Reason = 'already' }
                [pscustomobject]@{ Action = 'DisableService'; Category = 'Service'; ItemType = 'Service'; Target = 'DiagTrack'; CurrentValue = 'Running; startup type evaluated during apply'; DesiredValue = 'Stopped; Disabled'; DesiredState = 'Disabled'; Reason = 'telemetry' }
                [pscustomobject]@{ Action = 'DisableScheduledTask'; Category = 'ScheduledTask'; ItemType = 'ScheduledTask'; Target = '\T\Off'; CurrentValue = 'Disabled'; DesiredValue = 'Disabled'; DesiredState = 'Disabled'; Reason = 'telemetry' }
            ) | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding utf8
            $script:legacyUndetermined = Invoke-Checker -Target 'Privacy' -Environment @{ OPSTOOLKIT_TEST_FAKE_LEGACY_CSV = $csv } -FailOnDrift
        }

        It 'never passes: the unclassified row is Unread, so Passed stays false and -FailOnDrift exits 1' {
            $run = $script:legacyUndetermined
            $run.Summary.TotalDrift | Should -Be 0
            $run.Summary.UnreadCount | Should -Be 1
            $run.Summary.Passed | Should -BeFalse
            $run.ExitCode | Should -Be 1
        }

        It 'classifies the scheduled-task row that carries enough to compare, and counts only the other as unread' {
            $byItem = @{}
            foreach ($r in $script:legacyUndetermined.Records) { $byItem[$r.Item] = $r.State }
            $byItem['DiagTrack'] | Should -Be 'Unread'
            $byItem['\T\Off'] | Should -Be 'Compliant'
            $script:legacyUndetermined.Summary.CompliantCount | Should -Be 2
        }
    }

    Context '-Target as one comma-joined value, the form the evidence pack sends' {
        It 'accepts several newer targets in one value and checks each' {
            $run = Invoke-FakeChecker -Target 'Defender,Firewall' -Item @(New-StateItem -Result 'NoChange')
            $run.ExitCode | Should -Be 0
            @($run.Results | ForEach-Object { $_.Target } | Sort-Object -Unique) | Should -Be @('Defender', 'Firewall')
            $run.Summary.UnreadCount | Should -Be 0
            $run.Summary.Passed | Should -BeTrue
        }

        It 'still rejects a name that is not a target' {
            $run = Invoke-Checker -Target 'Defender,NotATarget'
            $run.ExitCode | Should -Not -Be 0
            $run.Summary | Should -BeNullOrEmpty
        }
    }

    Context 'a child script that fails' {
        It 'reports PlanFailed and never compliant when the new-schema script exits non-zero' {
            $run = Invoke-FakeChecker -Target 'CredentialProtection' -Item @(New-StateItem -Result 'NoChange') -Environment @{ OPSTOOLKIT_TEST_FAKE_EXIT = '3' }
            $run.Results[0].Status | Should -Be 'PlanFailed'
            $run.Summary.CompliantCount | Should -Be 0
            @($run.Records).Count | Should -Be 0
            @($run.Summary.UncheckedTargets) | Should -Contain 'CredentialProtection:PlanFailed'
            $run.Summary.Passed | Should -BeFalse
        }

        It 'exits 1 with -FailOnDrift when a target could not be checked' {
            $run = Invoke-FakeChecker -Target 'CredentialProtection' -Item @(New-StateItem -Result 'NoChange') -Environment @{ OPSTOOLKIT_TEST_FAKE_EXIT = '3' } -FailOnDrift
            $run.ExitCode | Should -Be 1
        }

        It 'reports a target whose script is missing instead of omitting it' {
            $run = Invoke-Checker -Target 'AuditLogging'
            $run.Results[0].Status | Should -Be 'ScriptMissing'
            @($run.Summary.UncheckedTargets) | Should -Contain 'AuditLogging:ScriptMissing'
        }
    }

    Context '-FailOnDrift' {
        It 'exits 1 when a new-schema target has a drifted row' {
            $run = Invoke-FakeChecker -Target 'Firewall' -FailOnDrift -Item @(
                New-StateItem -Setting 'a' -Result 'NoChange'
                New-StateItem -Setting 'b' -Result 'Previewed')
            $run.ExitCode | Should -Be 1
            $run.Summary.Passed | Should -BeFalse
        }

        It 'exits 1 when a new-schema target has a failed row' {
            $run = Invoke-FakeChecker -Target 'Firewall' -FailOnDrift -Item @(
                New-StateItem -Setting 'a' -Result 'NoChange'
                New-StateItem -Setting 'b' -Result 'Failed: x')
            $run.ExitCode | Should -Be 1
        }

        It 'exits 0 with only compliant and report-only rows' {
            $run = Invoke-FakeChecker -Target 'Firewall' -FailOnDrift -Item @(
                New-StateItem -Setting 'a' -Result 'NoChange'
                New-StateItem -Category 'Report' -Setting 'r' -Result 'ReportOnly' -Action 'Report only: r')
            $run.ExitCode | Should -Be 0
            $run.Summary.Passed | Should -BeTrue
        }

        It 'exits 1 when the only other row is unread, because undetermined is never a pass' {
            $run = Invoke-FakeChecker -Target 'Firewall' -FailOnDrift -Item @(
                New-StateItem -Setting 'a' -Result 'NoChange'
                New-StateItem -Category 'Report' -Setting 'r' -Result 'ReportOnly' -Action 'Report only: r'
                New-StateItem -Setting 'u' -Result 'Skipped: prior state unreadable' -CurrentValue 'unknown')
            $run.ExitCode | Should -Be 1
            $run.Summary.TotalDrift | Should -Be 0
            $run.Summary.UnreadCount | Should -Be 1
            $run.Summary.Passed | Should -BeFalse
            (Get-Content -LiteralPath $run.Log -Raw) | Should -Match 'could not be read and are NOT counted as compliant'
        }
    }

    Context 'WdacAudit end to end' {
        It 'is compliant when the audit policy is active' {
            $run = Invoke-FakeChecker -Target 'WdacAudit' -Item @(
                New-StateItem -Category 'Precondition' -Setting 'ConfigCI' -Result 'Met'
                New-StateItem -Category 'Precondition' -Setting 'NoActiveAuditPolicy' -Result "Failed: a policy named 'ops-toolkit WDAC audit' is already active (policy ID {x}); run this script with -Rollback first"
                New-StateItem -Category 'DeployAuditPolicy' -Setting 'ops-toolkit WDAC audit' -Result 'Skipped: requires elevation' -CurrentValue 'not deployed')
            $deploy = $run.Records | Where-Object { $_.Category -eq 'DeployAuditPolicy' }
            $deploy.State | Should -Be 'Compliant'
        }

        It 'is unread when the policy list could not be read and the base policy failed' {
            $run = Invoke-FakeChecker -Target 'WdacAudit' -Item @(
                New-StateItem -Category 'Precondition' -Setting 'ConfigCI' -Result 'Failed: the ConfigCI cmdlets are not available'
                New-StateItem -Category 'Precondition' -Setting 'NoActiveAuditPolicy' -Result 'Skipped: requires elevation'
                New-StateItem -Category 'DeployAuditPolicy' -Setting 'ops-toolkit WDAC audit' -Result 'Skipped: requires elevation' -CurrentValue 'not deployed')
            ($run.Records | Where-Object { $_.Category -eq 'DeployAuditPolicy' }).State | Should -Be 'Unread'
            $run.Summary.CompliantCount | Should -Be 0
        }
    }

    Context 'a remote machine' {
        It 'does not read new-schema items remotely and says so' {
            $run = Invoke-FakeChecker -Target 'Defender' -ComputerName 'REMOTE-HOST-NOT-HERE' -Item @(New-StateItem -Result 'NoChange')
            $run.ExitCode | Should -Be 0
            @($run.Records)[0].State | Should -Be 'NotCheckedRemotely'
            @($run.Records)[0].CurrentValue | Should -BeNullOrEmpty
            $run.Summary.CompliantCount | Should -Be 0
            $run.Summary.NotCheckedRemotelyCount | Should -Be 1
            $run.Summary.ItemsChecked | Should -Be 0 -Because 'an item that was not checked is not an item checked'
            $run.Summary.Passed | Should -BeFalse
        }

        It 'does not read BitLocker remotely and says so' {
            $run = Invoke-Checker -Script (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1') `
                -Target 'BitLocker' -ComputerName 'REMOTE-HOST-NOT-HERE'
            @($run.Records)[0].State | Should -Be 'NotCheckedRemotely'
        }
    }
}

Describe 'Test-WindowsHardeningState BitLocker target' {
    BeforeAll {
        $script:realChecker = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1'
        $script:protectorId = '{DEADBEEF-1111-4222-8333-ABCDEF012345}'
        $script:recoveryId = '{FEEDFACE-9999-4888-8777-0123456789AB}'

        function Invoke-BitLockerChecker {
            param([string]$VolumeJson, [switch]$ReadError, [switch]$FailOnDrift)
            $environment = @{
                PSModulePath = "$script:systemModulePath;$env:PSModulePath"
                SystemDrive = 'Q:'
                OPSTOOLKIT_TEST_BL_VOLUMES_JSON = $VolumeJson
                OPSTOOLKIT_TEST_BL_READERROR = $(if ($ReadError) { '1' } else { $null })
            }
            Invoke-Checker -Script $script:realChecker -Target 'BitLocker' -Environment $environment -FailOnDrift:$FailOnDrift
        }

        function Get-RunText {
            param($Run)
            $files = @(Get-ChildItem -LiteralPath $Run.OutputDirectory -Recurse -File) + @(Get-Item -LiteralPath $Run.Log, "$($Run.Log).err")
            ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        }

        $protected = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyEncrypted","ProtectionStatus":"On","EncryptionMethod":"XtsAes256","KeyProtector":[{"KeyProtectorType":"Tpm","KeyProtectorId":"' + $script:protectorId + '"},{"KeyProtectorType":"RecoveryPassword","KeyProtectorId":"' + $script:recoveryId + '"}]}]'
        $decrypted = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyDecrypted","ProtectionStatus":"Off","EncryptionMethod":"None","KeyProtector":[]}]'
        $inProgress = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"EncryptionInProgress","ProtectionStatus":"Off","EncryptionMethod":"XtsAes256","KeyProtector":[]}]'

        function New-VolumeJson {
            param([string]$Status, [string]$Protection)
            '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"' + $Status + '","ProtectionStatus":"' + $Protection + '","EncryptionMethod":"XtsAes256","KeyProtector":[]}]'
        }
        $script:blProtected = Invoke-BitLockerChecker -VolumeJson $protected
        $script:blDecrypted = Invoke-BitLockerChecker -VolumeJson $decrypted
        $script:blDecryptedGate = Invoke-BitLockerChecker -VolumeJson $decrypted -FailOnDrift
        $script:blInProgress = Invoke-BitLockerChecker -VolumeJson $inProgress
        $script:blReadError = Invoke-BitLockerChecker -VolumeJson $protected -ReadError
        $script:blReadErrorGate = Invoke-BitLockerChecker -VolumeJson $protected -ReadError -FailOnDrift
        $script:blNoVolume = Invoke-BitLockerChecker -VolumeJson ''
    }

    It 'is compliant for a protected OS volume' {
        $script:blProtected.ExitCode | Should -Be 0 -Because (Get-Content -LiteralPath "$($script:blProtected.Log).err" -Raw -ErrorAction SilentlyContinue)
        @($script:blProtected.Records)[0].State | Should -Be 'Compliant'
        @($script:blProtected.Records)[0].Item | Should -Be 'Q:'
        $script:blProtected.Summary.CompliantCount | Should -Be 1
    }

    It 'is drifted, with the missing half named, for <Status> with protection <Protection>' -ForEach @(
        @{ Status = 'FullyEncrypted'; Protection = 'Off'; Reason = 'protection is Off' }
        @{ Status = 'EncryptionInProgress'; Protection = 'On'; Reason = 'not fully encrypted' }
        @{ Status = 'EncryptionInProgress'; Protection = 'Off'; Reason = 'protection is Off' }
        @{ Status = 'DecryptionInProgress'; Protection = 'On'; Reason = 'not fully encrypted' }
    ) {
        $run = Invoke-BitLockerChecker -VolumeJson (New-VolumeJson -Status $Status -Protection $Protection) -FailOnDrift
        @($run.Records).Count | Should -Be 1
        @($run.Records)[0].State | Should -Be 'Drifted'
        @($run.Records)[0].Reason | Should -Match $Reason
        $run.Summary.CompliantCount | Should -Be 0
        $run.Summary.TotalDrift | Should -Be 1
        $run.ExitCode | Should -Be 1
    }

    It 'is unread, never compliant, when the protection status is not On or Off' -ForEach @('Unknown', '') {
        $run = Invoke-BitLockerChecker -VolumeJson (New-VolumeJson -Status 'FullyEncrypted' -Protection $_)
        @($run.Records).Count | Should -Be 1
        @($run.Records)[0].State | Should -Be 'Unread'
        $run.Summary.CompliantCount | Should -Be 0
    }

    It 'is only compliant for FullyEncrypted with protection On' {
        @($script:blProtected.Records)[0].State | Should -Be 'Compliant'
        $script:blProtected.Summary.CompliantCount | Should -Be 1
    }

    It 'is drifted, not compliant, while encryption is in progress with protection off' {
        @($script:blInProgress.Records)[0].State | Should -Be 'Drifted'
    }

    It 'is not configured for a decrypted OS volume, and that fails -FailOnDrift' {
        @($script:blDecrypted.Records)[0].State | Should -Be 'NotConfigured'
        $script:blDecrypted.Summary.CompliantCount | Should -Be 0
        $script:blDecryptedGate.ExitCode | Should -Be 1
    }

    It 'is unread, not compliant, when the volume read throws' {
        @($script:blReadError.Records)[0].State | Should -Be 'Unread'
        @($script:blReadError.Records)[0].Reason | Should -Match 'Get-BitLockerVolume failed'
        $script:blReadError.Summary.CompliantCount | Should -Be 0
        $script:blReadError.Summary.UnreadCount | Should -Be 1
        $script:blReadError.Summary.ItemsChecked | Should -Be 0
    }

    It 'is unread when the read returns no volume' {
        @($script:blNoVolume.Records)[0].State | Should -Be 'Unread'
        $script:blNoVolume.Summary.CompliantCount | Should -Be 0
    }

    It 'fails -FailOnDrift for an unread volume rather than passing it' {
        $script:blReadErrorGate.ExitCode | Should -Be 1
        $script:blReadErrorGate.Summary.Passed | Should -BeFalse
    }

    It 'writes no key protector id into any report or log' {
        $text = Get-RunText -Run $script:blProtected
        $text | Should -Not -Match ([regex]::Escape('DEADBEEF-1111-4222-8333-ABCDEF012345'))
        $text | Should -Not -Match ([regex]::Escape('FEEDFACE-9999-4888-8777-0123456789AB'))
        $text | Should -Not -Match 'RecoveryPassword'
        $text | Should -Match 'FullyEncrypted' -Because 'the report must still carry the status it was built from'
    }
}

Describe 'Test-WindowsHardeningState Defender target against the real script' {
    # The checker runs Set-WindowsDefenderHardening.ps1 -WhatIf in a child pwsh. Under -WhatIf the
    # Defender module's own Set-Alias calls were suppressed, every value read unknown, and the target
    # came back with no verdict. The fake Defender module fails at import the same way.
    BeforeAll {
        $script:realChecker = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1'
        $script:defRun = Invoke-Checker -Script $script:realChecker -Target 'Defender' -Environment @{
            PSModulePath = "$script:systemModulePath;$env:PSModulePath"
            OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''
            OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''
            OPSTOOLKIT_TEST_MP_PUA = '1'
            OPSTOOLKIT_TEST_MP_MAPS = '0'
        }
    }

    It 'checks the target and reads Defender settings' {
        $script:defRun.ExitCode | Should -Be 0 -Because (Get-Content -LiteralPath "$($script:defRun.Log).err" -Raw -ErrorAction SilentlyContinue)
        @($script:defRun.Results).Count | Should -Be 1
        @($script:defRun.Results)[0].Status | Should -Be 'Checked'
        @($script:defRun.Records).Count | Should -BeGreaterThan 14
        @($script:defRun.Records | Where-Object Category -eq 'DefenderPreference').Count | Should -Be 0
    }

    It 'carries the current values the fixture planted, not unknown' {
        $pua = @($script:defRun.Records | Where-Object Item -eq 'PUAProtection')
        $pua.Count | Should -Be 1
        $pua[0].CurrentValue | Should -Be '1'
        $pua[0].State | Should -Be 'Compliant'
        $maps = @($script:defRun.Records | Where-Object Item -eq 'MAPSReporting')
        $maps.Count | Should -Be 1
        $maps[0].CurrentValue | Should -Be '0'
        $maps[0].State | Should -Be 'Drifted'
    }

    It 'plans all 18 ASR rules as drifted on a machine with none configured' {
        $asr = @($script:defRun.Records | Where-Object Category -eq 'AsrRule')
        $asr.Count | Should -Be 18
        @($asr | Where-Object State -ne 'Drifted').Count | Should -Be 0
    }
}

Describe 'Test-WindowsHardeningState Credential Guard' {
    BeforeAll {
        $script:realChecker = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1'
        function Invoke-CredentialGuardChecker {
            param([string]$SnapshotJson, [switch]$FailOnDrift)
            $snapshot = ''
            if ($SnapshotJson) {
                $snapshot = Join-Path $script:workRoot "dg-$([guid]::NewGuid().ToString('N')).json"
                Set-Content -LiteralPath $snapshot -Value $SnapshotJson -Encoding utf8
            } else {
                $snapshot = Join-Path $script:workRoot 'dg-missing.json'
            }
            Invoke-Checker -Script $script:realChecker -Target 'CredentialProtection' -FailOnDrift:$FailOnDrift `
                -ExtraArgument @('-DeviceGuardSnapshotPath', "`"$snapshot`"") `
                -Environment @{ PSModulePath = "$script:systemModulePath;$env:PSModulePath" }
        }
        function Get-GuardRecord { param($Run) @($Run.Records | Where-Object Category -eq 'CredentialGuard') }

        $script:cgConfiguredNotRunning = Invoke-CredentialGuardChecker -SnapshotJson '{"SecurityServicesConfigured":[1],"SecurityServicesRunning":[]}' -FailOnDrift
        $script:cgRunning = Invoke-CredentialGuardChecker -SnapshotJson '{"SecurityServicesConfigured":[1,2],"SecurityServicesRunning":[1,2]}' -FailOnDrift
        $script:cgNone = Invoke-CredentialGuardChecker -SnapshotJson '{"SecurityServicesConfigured":[],"SecurityServicesRunning":[]}' -FailOnDrift
        $script:cgOnlyHvci = Invoke-CredentialGuardChecker -SnapshotJson '{"SecurityServicesConfigured":[1,2],"SecurityServicesRunning":[2]}'
        $script:cgNoProps = Invoke-CredentialGuardChecker -SnapshotJson '{"Other":1}'
        $script:cgUnreadable = Invoke-CredentialGuardChecker -SnapshotJson ''
    }

    It 'reports configured but not running as drifted, never compliant, and fails -FailOnDrift' {
        $record = Get-GuardRecord -Run $script:cgConfiguredNotRunning
        $record.Count | Should -Be 1
        $record[0].State | Should -Be 'Drifted'
        $record[0].Reason | Should -Match 'configured but not running'
        $record[0].CurrentValue | Should -Be 'SecurityServicesConfigured=1;SecurityServicesRunning='
        # Drift attributable to this record, not to whatever else the machine's LSA settings show.
        @($script:cgConfiguredNotRunning.Records | Where-Object { $_.Category -eq 'CredentialGuard' -and $_.State -eq 'Drifted' }).Count | Should -Be 1
        $script:cgConfiguredNotRunning.Summary.TotalDrift | Should -Be ($script:cgRunning.Summary.TotalDrift + 1)
        $script:cgConfiguredNotRunning.Summary.Passed | Should -BeFalse
    }

    It 'treats configured with only memory integrity running as drifted too' {
        (Get-GuardRecord -Run $script:cgOnlyHvci)[0].State | Should -Be 'Drifted'
    }

    It 'is compliant only when Credential Guard is running' {
        $record = Get-GuardRecord -Run $script:cgRunning
        $record.Count | Should -Be 1
        $record[0].State | Should -Be 'Compliant'
    }

    It 'reports neither configured nor running as ReportOnly and counts no drift for it' {
        $record = Get-GuardRecord -Run $script:cgNone
        $record.Count | Should -Be 1
        $record[0].State | Should -Be 'ReportOnly'
        $record[0].Reason | Should -Match 'opt-in'
        # Same drift, same verdict and same exit as the run where Credential Guard is running, whatever
        # else this machine's own settings contribute: the record adds nothing to the drift total.
        $script:cgNone.Summary.TotalDrift | Should -Be $script:cgRunning.Summary.TotalDrift
        $script:cgNone.Summary.NotConfiguredCount | Should -Be $script:cgRunning.Summary.NotConfiguredCount
        $script:cgNone.Summary.Passed | Should -Be $script:cgRunning.Summary.Passed
        $script:cgNone.ExitCode | Should -Be $script:cgRunning.ExitCode
        $script:cgNone.Summary.ReportOnlyCount | Should -Be ($script:cgRunning.Summary.ReportOnlyCount + 1)
    }

    It 'is unread, not compliant, when the lists are missing or the source cannot be read' {
        foreach ($run in $script:cgNoProps, $script:cgUnreadable) {
            $record = Get-GuardRecord -Run $run
            $record.Count | Should -Be 1
            $record[0].State | Should -Be 'Unread'
        }
    }
}

Describe 'Get-LegacyRowState' {
    # A local row of the older plan the checker cannot classify is Unread: not drift (it is not known to be
    # wrong) and never a pass. A row that carries enough to compare is classified instead.
    BeforeAll {
        function New-LegacyRow { param([string]$Action, [string]$Current = '', [string]$Desired = '')
            [pscustomobject]@{ Action = $Action; CurrentValue = $Current; DesiredValue = $Desired } }
    }

    It 'maps the registry actions as before' {
        (Get-LegacyRowState -Item (New-LegacyRow 'NoChange')).State | Should -Be 'Compliant'
        (Get-LegacyRowState -Item (New-LegacyRow 'CreateValue')).State | Should -Be 'NotConfigured'
        (Get-LegacyRowState -Item (New-LegacyRow 'SetValue')).State | Should -Be 'Drifted'
        (Get-LegacyRowState -Item (New-LegacyRow 'DeleteValue')).State | Should -Be 'Drifted'
    }

    It 'maps a Skipped row, a service row, a Missing row, an unknown action and no action to Unread' {
        foreach ($action in 'Skipped', 'DisableService', 'EnableService', 'Missing', 'SomethingNew', '') {
            $state = (Get-LegacyRowState -Item (New-LegacyRow $action 'Running; startup type evaluated during apply' 'Stopped; Disabled')).State
            $state | Should -Be 'Unread' -Because "action '$action' cannot be classified"
        }
    }

    It 'compares a scheduled-task row against its desired state' {
        (Get-LegacyRowState -Item (New-LegacyRow 'DisableScheduledTask' 'Ready' 'Disabled')).State | Should -Be 'Drifted'
        (Get-LegacyRowState -Item (New-LegacyRow 'DisableScheduledTask' 'Disabled' 'Disabled')).State | Should -Be 'Compliant'
        (Get-LegacyRowState -Item (New-LegacyRow 'EnableScheduledTask' 'Disabled' 'Enabled')).State | Should -Be 'Drifted'
        (Get-LegacyRowState -Item (New-LegacyRow 'EnableScheduledTask' 'Ready' 'Enabled')).State | Should -Be 'Compliant'
    }

    It 'keeps a scheduled-task row whose state could not be compared Unread' {
        (Get-LegacyRowState -Item (New-LegacyRow 'DisableScheduledTask' 'Unknown' 'Disabled')).State | Should -Be 'Unread'
        (Get-LegacyRowState -Item (New-LegacyRow 'DisableScheduledTask' '' 'Disabled')).State | Should -Be 'Unread'
        (Get-LegacyRowState -Item (New-LegacyRow 'EnableScheduledTask' 'Ready' '')).State | Should -Be 'Unread'
    }
}

Describe 'Test-WindowsHardeningState default targets' {
    # The checker's own default stays SchannelTls and Privacy so a bare run keeps its old scope. The
    # evidence pack names every target itself and reads UnreadCount and Passed, so the newer targets are
    # opt-in here but no longer invisible to CFG-01.
    It 'defaults to SchannelTls and Privacy only' {
        $path = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Target' }
        $default = @($param.DefaultValue.SafeGetValue())
        $default | Should -Be @('SchannelTls', 'Privacy')
    }
}
