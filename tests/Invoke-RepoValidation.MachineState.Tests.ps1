#Requires -Modules Pester

# The machine-state guard in Invoke-RepoValidation.ps1.
#
# This spec exists because the guard's own pass is worthless unless the guard has been
# shown to fail. It was written after a test run disabled four real scheduled tasks and
# added three real Defender path exclusions while every test reported green, so the
# whole point of the gate is to notice that, and the whole point of this spec is to
# prove the gate can.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ScriptFunction -RelativePath 'Invoke-RepoValidation.ps1' `
        -FunctionName @('Get-MachineStateSnapshot', 'Compare-MachineStateSnapshot', 'Get-PesterResultSummary')
}

Describe 'Get-PesterResultSummary' {
    It 'reports an unexecuted test as NotRun instead of a failure' {
        $resultPath = Join-Path ([System.IO.Path]::GetTempPath()) "ops-pester-result-$([guid]::NewGuid().ToString('N')).xml"
        try {
            @'
<?xml version="1.0" encoding="utf-8"?>
<test-results total="3" errors="0" failures="1" not-run="0" skipped="1">
  <test-suite>
    <results>
      <test-case name="passed" success="True" result="Success" executed="True" />
      <test-case name="failed" success="False" result="Failure" executed="True">
        <failure><message>expected failure</message></failure>
      </test-case>
      <test-case name="timed-out" success="False" result="Ignored" executed="False" />
    </results>
  </test-suite>
</test-results>
'@ | Set-Content -LiteralPath $resultPath -Encoding utf8

            $summary = Get-PesterResultSummary -Path $resultPath
            $summary.TotalCount | Should -Be 3
            $summary.FailedCount | Should -Be 1
            $summary.NotRunCount | Should -Be 1
            @($summary.FailedTests).Name | Should -Contain 'failed'
            @($summary.FailedTests).Name | Should -Not -Contain 'timed-out'
            @($summary.NotRunTests).Name | Should -Contain 'timed-out'
        } finally {
            Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Compare-MachineStateSnapshot' {
    It 'reports nothing when the machine is unchanged' {
        $before = @{ DefenderExclusionPath = 'C:\Code|C:\Code_data'; ScheduledTasks = 'Consolidator=Ready' }
        @(Compare-MachineStateSnapshot -Before $before -After $before.Clone()).Count | Should -Be 0
    }

    It 'catches an added Defender exclusion' {
        # The exact shape of the incident: an antivirus exclusion appearing during a
        # test run, on a machine nobody was watching.
        $before = @{ DefenderExclusionPath = 'C:\Code|C:\Code_data' }
        $after = @{ DefenderExclusionPath = 'C:\Code|C:\Code_data|C:\Users\x\AppData\Local\Temp\ops-win-1\excluded' }

        $drift = @(Compare-MachineStateSnapshot -Before $before -After $after)
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'DefenderExclusionPath'
        # The message has to carry both values, or whoever reads it still has to go
        # and find out what actually changed.
        $drift[0] | Should -Match 'ops-win-1'
        $drift[0] | Should -Match 'Before:'
    }

    It 'catches a scheduled task that changed state' {
        $before = @{ ScheduledTasks = 'Consolidator=Ready|DmClient=Ready' }
        $after = @{ ScheduledTasks = 'Consolidator=Disabled|DmClient=Ready' }

        $drift = @(Compare-MachineStateSnapshot -Before $before -After $after)
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'ScheduledTasks'
    }

    It 'reports every changed probe, not just the first' {
        # A run that reaches two subsystems should name both. Stopping at the first
        # would understate the blast radius of exactly the failure this catches.
        $before = @{ DefenderExclusionPath = 'a'; ScheduledTasks = 'b'; Printers = 'c' }
        $after = @{ DefenderExclusionPath = 'a2'; ScheduledTasks = 'b2'; Printers = 'c' }

        @(Compare-MachineStateSnapshot -Before $before -After $after).Count | Should -Be 2
    }

    It 'treats a probe that stopped reporting as drift' {
        # A probe vanishing is not evidence of no change, it is the absence of
        # evidence, and this repository does not fold that into a pass.
        $drift = @(Compare-MachineStateSnapshot -Before @{ Printers = 'HP' } -After @{})
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'probe missing'
    }

    It 'catches a changed Defender attack surface reduction action' {
        # Same rule id, action 1 (block) to 0 (disabled): the rule is still listed, so
        # only comparing the id=action pair notices.
        $before = @{ DefenderAsrRules = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a=1|3b576869-a4ec-4529-8536-b80a7769e899=1' }
        $after = @{ DefenderAsrRules = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a=0|3b576869-a4ec-4529-8536-b80a7769e899=1' }

        $drift = @(Compare-MachineStateSnapshot -Before $before -After $after)
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'DefenderAsrRules'
        $drift[0] | Should -Match 'd4f940ab-401b-4efc-aadc-ad5f3c50688a=0'
    }

    It 'catches a changed firewall default' {
        $before = @{ FirewallProfiles = 'Domain:True/Block/Allow/True|Private:True/Block/Allow/True|Public:True/Block/Allow/False' }
        $after = @{ FirewallProfiles = 'Domain:True/Block/Allow/True|Private:True/Allow/Allow/True|Public:True/Block/Allow/False' }

        $drift = @(Compare-MachineStateSnapshot -Before $before -After $after)
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'FirewallProfiles'
        $drift[0] | Should -Match 'Private:True/Allow'
    }

    It 'does not call an unreadable probe drift while it stays unreadable' {
        # Not elevated before and after: the same honest "unreadable" on both sides is
        # not a change, and it must not be reported as one or folded into a pass of
        # some other value.
        $unreadable = 'unreadable: Access is denied.'
        $before = @{ BitLockerOsVolume = $unreadable; AuditPolicy = $unreadable; DefenderAsrRules = 'none' }
        @(Compare-MachineStateSnapshot -Before $before -After $before.Clone()).Count | Should -Be 0
    }

    It 'calls a probe that went from readable to unreadable drift' {
        $drift = @(Compare-MachineStateSnapshot -Before @{ BitLockerOsVolume = 'ProtectionStatus=On;VolumeStatus=FullyEncrypted' } `
                -After @{ BitLockerOsVolume = 'unreadable: Access is denied.' })
        $drift.Count | Should -Be 1
        $drift[0] | Should -Match 'BitLockerOsVolume'
    }
}

Describe 'Get-MachineStateSnapshot' {
    BeforeAll {
        $script:snapshot = Get-MachineStateSnapshot -ScriptRoot (Join-Path (Get-RepositoryRoot) 'scripts')
    }

    It 'covers every subsystem the scripts in this repository can change' {
        # If a script starts changing something not on this list, the guard goes blind
        # to it. That is how the incident happened, so the list is asserted rather than
        # assumed.
        $probes = @(
            'DefenderExclusionPath', 'DefenderExclusionProcess', 'ScheduledTasks', 'Printers', 'PSDrives',
            'DefenderAsrRules', 'DefenderControlledFolderAccess', 'DefenderNetworkProtection', 'DefenderPuaProtection',
            'FirewallProfiles', 'FirewallDisabledRuleCount', 'BitLockerOsVolume', 'CodeIntegrityPolicies',
            'Smb1Protocol', 'LsaAndCredentialRegistry', 'AuditPolicy', 'LocalAccountLockout'
        )
        foreach ($probe in $probes) {
            $script:snapshot.ContainsKey($probe) | Should -BeTrue -Because "$probe must be watched"
        }
    }

    It 'returns a stable value when nothing has changed between two calls' {
        $second = Get-MachineStateSnapshot -ScriptRoot (Join-Path (Get-RepositoryRoot) 'scripts')
        @(Compare-MachineStateSnapshot -Before $script:snapshot -After $second).Count |
            Should -Be 0 -Because 'a snapshot that varies on its own would make the gate cry wolf'
    }

    It 'records why a probe could not be read rather than reporting it as empty' {
        # An unreadable setting comparing equal to an unreadable setting is honest. An
        # unreadable setting comparing equal to "none" hides a real change.
        foreach ($value in $script:snapshot.Values) {
            $value | Should -Not -BeNullOrEmpty -Because 'an empty probe value is indistinguishable from a cleared setting'
        }
    }

    It 'watches the scheduled tasks the hardening script actually names' {
        # Parsed from the scripts rather than hard-coded, so a task added to a script
        # is watched without anyone remembering to update the guard.
        $script:snapshot.ScheduledTasks | Should -Match 'Consolidator'
    }
}
