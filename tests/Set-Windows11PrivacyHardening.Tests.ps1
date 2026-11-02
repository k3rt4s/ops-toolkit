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

Describe 'Invoke-HardeningPlan per-item failure handling' {
    BeforeAll {
        $script:moduleName = 'UnderTest_Set-Windows11PrivacyHardening'

        function New-RegistryPlanItem {
            param([string]$Name)
            [pscustomobject]@{
                ItemType = 'Registry'; Category = 'Test'; Target = "HKLM:\SOFTWARE\OpsToolkitNoSuchKey\$Name!$Name"
                RegistryPath = 'HKLM:\SOFTWARE\OpsToolkitNoSuchKey\Test'; ValueName = $Name; PropertyType = 'DWord'
                DesiredValue = 1; DesiredState = 'Disabled'; Action = 'CreateValue'; Reason = 'test'
            }
        }
    }

    BeforeEach {
        # Nothing here touches the registry: the key check and both writes are mocked inside the module.
        Mock -ModuleName $script:moduleName Test-Path { $true }
        Mock -ModuleName $script:moduleName New-Item { }
        Mock -ModuleName $script:moduleName New-ItemProperty {
            if ($Name -eq 'EnableFeeds') { throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.') }
        }
        $script:plan = @('First', 'EnableFeeds', 'Third', 'Fourth' | ForEach-Object { New-RegistryPlanItem -Name $_ })
    }

    It 'records the refused item as Failed with its message and still runs every later item' {
        $result = Invoke-HardeningPlan -Plan $script:plan -Preview $false 3>$null

        Should -Invoke -ModuleName $script:moduleName New-ItemProperty -Exactly -Times 4
        $result.ChangedCount | Should -Be 3
        $result.FailedCount | Should -Be 1
        $result.Statuses.Count | Should -Be 4
        $result.Statuses[$script:plan[1].Target] | Should -Be 'Failed: Attempted to perform an unauthorized operation.'
        foreach ($i in 0, 2, 3) { $result.Statuses[$script:plan[$i].Target] | Should -Be 'Changed' }
    }

    It 'carries the Failed result into the state list rows' {
        $result = Invoke-HardeningPlan -Plan $script:plan -Preview $false 3>$null
        $rows = @(Get-RunStateList -Plan $script:plan -Statuses $result.Statuses)

        $rows.Count | Should -Be 4
        @($rows | Where-Object { $_.Result -like 'Failed:*' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Result -eq 'Changed' }).Count | Should -Be 3
        $rows[1].Reason | Should -Be 'test'
    }

    It 'leaves a failed item out of the list of items reported as disabled or restored' {
        $result = Invoke-HardeningPlan -Plan $script:plan -Preview $false 3>$null
        $rows = @(Get-RunStateList -Plan $script:plan -Statuses $result.Statuses)
        $ok = @(Get-SucceededStateList -StateList $rows)

        $ok.Count | Should -Be 3
        @($ok | Where-Object { $_.Target -eq $script:plan[1].Target }).Count | Should -Be 0
        @($ok | Where-Object { $_.Result -like 'Failed:*' }).Count | Should -Be 0
    }

    It 'reports no failure and writes nothing on a preview' {
        $result = Invoke-HardeningPlan -Plan $script:plan -Preview $true
        Should -Invoke -ModuleName $script:moduleName New-ItemProperty -Exactly -Times 0
        $result.FailedCount | Should -Be 0
        @($result.Statuses.Values | Sort-Object -Unique) | Should -Be @('Previewed')
    }
}
