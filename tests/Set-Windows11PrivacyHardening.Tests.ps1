#Requires -Modules Pester

# Unit coverage over which Store-app AppPrivacy values the privacy plan includes.
#
# Force-denying every Store app background access and device sync stops syncing Store
# apps such as iCloud for Windows from finishing setup, so the two values are opt-in.
# Rollback has to plan them regardless of the switch: a machine hardened before they
# became opt-in carries them, and a rollback that skipped them would leave it broken.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ScriptFunction -RelativePath 'scripts\it-operations\windows-hardening\Set-Windows11PrivacyHardening.ps1'

    $script:optIn = @('LetAppsRunInBackground', 'LetAppsSyncWithDevices')

    function Get-PlannedAppPrivacyName {
        param([hashtable]$Switch = @{})
        @(Get-Windows11PrivacyHardeningPlan -DiagnosticDataLevel Required -SkipCurrentUserSettings @Switch |
                Where-Object { $_.Category -eq 'AppPrivacy' } |
                ForEach-Object { $_.ValueName })
    }
}

Describe 'Get-Windows11PrivacyHardeningPlan Store-app AppPrivacy values' {
    It 'leaves background access and device sync out by default' {
        $names = Get-PlannedAppPrivacyName
        foreach ($name in $script:optIn) {
            $names | Should -Not -Contain $name
        }
        # The other AppPrivacy denials are unaffected by the opt-in.
        $names | Should -Contain 'LetAppsAccessLocation'
    }

    It 'force-denies both when -DenyStoreAppBackgroundAccess is passed' {
        $plan = @(Get-Windows11PrivacyHardeningPlan -DiagnosticDataLevel Required -SkipCurrentUserSettings -DenyStoreAppBackgroundAccess |
                Where-Object { $script:optIn -contains $_.ValueName })
        $plan.Count | Should -Be 2
        foreach ($item in $plan) {
            $item.DesiredValue | Should -Be 2
            $item.DesiredState | Should -Be 'ForceDenied'
        }
    }

    It 'plans removal of both on -Rollback even without the switch' {
        $plan = @(Get-Windows11PrivacyHardeningPlan -DiagnosticDataLevel Required -SkipCurrentUserSettings -Rollback |
                Where-Object { $script:optIn -contains $_.ValueName })
        $plan.Count | Should -Be 2
        foreach ($item in $plan) {
            $item.DesiredValue | Should -Be '<delete>'
            $item.DesiredState | Should -Be 'NotConfigured'
        }
    }
}
