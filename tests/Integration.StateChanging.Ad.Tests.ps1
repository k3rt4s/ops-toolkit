#Requires -Modules Pester

# The Active Directory scripts that change the directory. These are the
# highest-consequence code in the repository and had no coverage at all.
#
# Every script here is run twice against the same fixture: once with -WhatIf, which
# must produce a correct plan and attempt no change, and once executing, which must
# attempt exactly the changes the plan described. The second run is what gives the
# first one meaning. "-WhatIf attempted nothing" is unfalsifiable on its own, because
# a script that silently does nothing at all also attempts nothing, and that is a
# failure this repository has shipped before.
#
# Nothing is ever really changed. The write cmdlets in the fake ActiveDirectory module
# record the attempt to a log and return.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:adModulePath = Use-FakeActiveDirectory
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-adchange-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    function Get-MutationRecord {
        <#
        .SYNOPSIS
        Read the directory changes a run attempted, as objects.
        #>
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }
}

AfterAll {
    foreach ($p in $script:adModulePath, $script:workRoot) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Disable-AdStaleComputerAccountsAndMoveToOu' {
    BeforeAll {
        # PC-STALE is inactive and enabled, so it is the one account that should move.
        # PC-FRESH logged on yesterday. PC-OFF is already disabled and must be left
        # alone unless -IncludeDisabledComputers is passed. PC-NEVER has never logged
        # on, which is not the same fact as being inactive and is opted into
        # separately, because a never-used account is often a new build.
        # Every property the script names in its Properties list is present, and
        # nothing else is. A fixture carrying extra properties would hide a script
        # reading something it never asked the directory for, which under strict mode
        # is a crash in production and a pass here.
        $script:staleFixture = @'
$global:FakeAdData = @{
    Computers = @(
        [pscustomobject]@{ Name = 'PC-STALE'; SamAccountName = 'PC-STALE$'
            DistinguishedName = 'CN=PC-STALE,OU=Workstations,DC=test,DC=local'
            Enabled = $true; LastLogonDate = (Get-Date).AddDays(-400)
            OperatingSystem = 'Windows 10 Pro'; Created = (Get-Date).AddDays(-900)
            whenChanged = (Get-Date).AddDays(-400); Description = '' }
        [pscustomobject]@{ Name = 'PC-FRESH'; SamAccountName = 'PC-FRESH$'
            DistinguishedName = 'CN=PC-FRESH,OU=Workstations,DC=test,DC=local'
            Enabled = $true; LastLogonDate = (Get-Date).AddDays(-1)
            OperatingSystem = 'Windows 11 Pro'; Created = (Get-Date).AddDays(-900)
            whenChanged = (Get-Date).AddDays(-1); Description = '' }
        [pscustomobject]@{ Name = 'PC-OFF'; SamAccountName = 'PC-OFF$'
            DistinguishedName = 'CN=PC-OFF,OU=Workstations,DC=test,DC=local'
            Enabled = $false; LastLogonDate = (Get-Date).AddDays(-500)
            OperatingSystem = 'Windows 10 Pro'; Created = (Get-Date).AddDays(-900)
            whenChanged = (Get-Date).AddDays(-500); Description = '' }
        [pscustomobject]@{ Name = 'PC-NEVER'; SamAccountName = 'PC-NEVER$'
            DistinguishedName = 'CN=PC-NEVER,OU=Workstations,DC=test,DC=local'
            Enabled = $true; LastLogonDate = $null
            OperatingSystem = 'Windows 11 Pro'; Created = (Get-Date).AddDays(-800)
            whenChanged = (Get-Date).AddDays(-800); Description = '' }
    )
}
'@

        $script:targetOu = 'OU=Disabled,DC=test,DC=local'

        $script:whatIfLog = Join-Path $script:workRoot 'stale-whatif.log'
        $script:whatIfRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:whatIfLog)'`n$($script:staleFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'stale-whatif')
            TargetOu        = $script:targetOu
            InactiveDays    = 90
            Action          = 'DisableAndMove'
            WhatIf          = $true
        }

        $script:executeLog = Join-Path $script:workRoot 'stale-execute.log'
        $script:executeRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:executeLog)'`n$($script:staleFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'stale-execute')
            TargetOu        = $script:targetOu
            InactiveDays    = 90
            Action          = 'DisableAndMove'
            Confirm         = $false
        }
    }

    It 'runs to completion in both modes' {
        $script:whatIfRun.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:whatIfRun.Output)"
        $script:executeRun.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:executeRun.Output)"
    }

    It 'plans a change only for the account that is actually stale' {
        # Three, not four: the default filter is `Enabled -eq $true`, so PC-OFF is
        # never returned by the directory at all. The count matters more than it looks.
        # Planning three changes here would mean disabling every workstation in the OU,
        # including one that logged on yesterday.
        $script:whatIfRun.Summary.ComputerCount | Should -Be 3
        $script:whatIfRun.Summary.PlannedChangeCount | Should -Be 1

        $plan = @(Import-Csv $script:whatIfRun.Summary.PlanCsvPath)
        $planned = @($plan | Where-Object { $_.Action -in @('Disable', 'Move', 'DisableAndMove') })
        $planned.Count | Should -Be 1
        $planned[0].Name | Should -Be 'PC-STALE'
    }

    It 'leaves the fresh and never-used accounts out of the plan' {
        $plan = @(Import-Csv $script:whatIfRun.Summary.PlanCsvPath)
        $plan[0].PSObject.Properties.Name | Should -Contain 'Action'
        foreach ($name in @('PC-FRESH', 'PC-NEVER')) {
            $row = $plan | Where-Object { $_.Name -eq $name }
            $row | Should -Not -BeNullOrEmpty -Because "$name should appear in the plan as a no-change row"
            $row.Action | Should -Not -BeIn @('Disable', 'Move', 'DisableAndMove') -Because "$name is not stale"
        }

        # Never logged on is not the same fact as inactive, and is opted into
        # separately, because a never-used account is often a machine built last week.
        ($plan | Where-Object { $_.Name -eq 'PC-NEVER' }).Action | Should -Be 'Skipped'

        # The disabled account was filtered out by the directory, not merely skipped.
        $plan | Where-Object { $_.Name -eq 'PC-OFF' } | Should -BeNullOrEmpty
    }

    It 'attempts no directory change under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:whatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf attempted: $($mutations | ConvertTo-Json -Compress)"
        $script:whatIfRun.Summary.ChangedCount | Should -Be 0
        $script:whatIfRun.Summary.PreviewedCount | Should -Be 1
    }

    It 'attempts exactly the planned change when executing' {
        # Without this the -WhatIf assertion above proves nothing: a script that had
        # stopped working entirely would satisfy it perfectly.
        $mutations = Get-MutationRecord -Path $script:executeLog
        $mutations.Count | Should -Be 2
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'Disable-ADAccount'
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'Move-ADObject'
        foreach ($mutation in $mutations) {
            $mutation.Identity | Should -Be 'CN=PC-STALE,OU=Workstations,DC=test,DC=local'
        }
        ($mutations | Where-Object { $_.Command -eq 'Move-ADObject' }).TargetPath | Should -Be $script:targetOu
        $script:executeRun.Summary.ChangedCount | Should -Be 1
    }

    It 'writes a rollback input naming what it changed' {
        # A change with no recorded way back is the part that turns a mistake into an
        # incident.
        Test-Path $script:executeRun.Summary.RollbackInputPath | Should -BeTrue
        $rollback = @(Import-Csv $script:executeRun.Summary.RollbackInputPath)
        $rollback.Count | Should -Be 1
        $rollback[0].Name | Should -Be 'PC-STALE'
        $rollback[0].OriginalDistinguishedName | Should -Be 'CN=PC-STALE,OU=Workstations,DC=test,DC=local'
    }

    It 'writes an empty rollback input after a -WhatIf run rather than omitting it' {
        # Absent and empty must be distinguishable: absent could mean the run died.
        Test-Path $script:whatIfRun.Summary.RollbackInputPath | Should -BeTrue
        @(Import-Csv $script:whatIfRun.Summary.RollbackInputPath).Count | Should -Be 0
    }

    It 'reverses a real change when the rollback input is fed back in' {
        $rollbackLog = Join-Path $script:workRoot 'stale-rollback.log'
        $rollbackRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$rollbackLog'`n$($script:staleFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory   = (Join-Path $script:workRoot 'stale-rollback')
            Rollback          = $true
            RollbackStatePath = $script:executeRun.Summary.RollbackInputPath
            Confirm           = $false
        }

        $rollbackRun.ExitCode | Should -Be 0 -Because "the rollback run failed: $($rollbackRun.Output)"
        $rollbackRun.Summary.Mode | Should -Be 'Rollback'
        $rollbackRun.Summary.RolledBackCount | Should -Be 1

        # Moved back to the original parent and re-enabled, because it was enabled
        # before. Rolling back to "disabled" would be a second outage.
        $mutations = Get-MutationRecord -Path $rollbackLog
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'Move-ADObject'
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'Enable-ADAccount'
        ($mutations | Where-Object { $_.Command -eq 'Move-ADObject' }).TargetPath |
            Should -Be 'OU=Workstations,DC=test,DC=local'
    }

    It 'changes nothing at all under ReportOnly' {
        $reportLog = Join-Path $script:workRoot 'stale-reportonly.log'
        $reportRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$reportLog'`n$($script:staleFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'stale-reportonly')
            TargetOu        = $script:targetOu
            Action          = 'ReportOnly'
            Confirm         = $false
        }

        $reportRun.ExitCode | Should -Be 0 -Because "the ReportOnly run failed: $($reportRun.Output)"
        @(Get-MutationRecord -Path $reportLog).Count | Should -Be 0
        $reportRun.Summary.ChangedCount | Should -Be 0
        # It still has to find the stale account, or ReportOnly is just a broken run.
        $reportRun.Summary.ComputerCount | Should -Be 3
        @(Import-Csv $reportRun.Summary.PlanCsvPath | Where-Object { $_.Action -eq 'ReportOnly' }).Count |
            Should -Be 1
    }
}
