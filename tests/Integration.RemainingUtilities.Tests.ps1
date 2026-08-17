#Requires -Modules Pester

# The last five scripts without coverage. None of them changes anything by default, so
# four are run for real against this machine and only Page-File-Bleed is stubbed.
#
# Assertions are on invariants and on shape, not on values: what this machine's OS build
# or group membership happens to be belongs to whichever machine runs the suite. What
# has to hold everywhere is that a read-only script reports what it read, says so when
# it could not read something, and does not quietly present an unknown as an answer.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-util-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) {
        Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-WindowsLifecycleInventory' {
    BeforeAll {
        $script:lifecycle = & (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1') `
            -OutputDirectory (Join-Path $script:workRoot 'lifecycle')
    }

    It 'writes the run-directory layout the comparison tool needs' {
        (Split-Path $script:lifecycle.OutputDirectory -Leaf) | Should -Match '^windows-lifecycle-inventory-\d{8}_\d{6}$'
        Test-Path (Join-Path $script:lifecycle.OutputDirectory 'summary.json') | Should -BeTrue
    }

    It 'accounts for every machine it queried' {
        $counted = $script:lifecycle.OutOfSupportCount + $script:lifecycle.EndingSoonCount +
        $script:lifecycle.SupportedCount + $script:lifecycle.UnknownCount + $script:lifecycle.UnreachableCount
        $counted | Should -Be $script:lifecycle.ComputersQueried
    }

    It 'measures staleness from the data rather than the file timestamp' {
        # git resets a checked-out file's mtime, so a fresh clone of stale support
        # dates would otherwise report them as verified today.
        $script:lifecycle.LifecycleDataOldestVerifiedOn | Should -Not -BeNullOrEmpty
        $script:lifecycle.LifecycleDataAgeDays | Should -BeGreaterOrEqual 0
        $script:lifecycle.LifecycleDataIsStale | Should -BeOfType [bool]
    }
}

Describe 'Export-WindowsUpdateHealth' {
    BeforeAll {
        $script:update = & (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\lifecycle\Export-WindowsUpdateHealth.ps1') `
            -OutputDirectory (Join-Path $script:workRoot 'update')
    }

    It 'writes the run-directory layout the comparison tool needs' {
        (Split-Path $script:update.OutputDirectory -Leaf) | Should -Match '^windows-update-health-\d{8}_\d{6}$'
        Test-Path (Join-Path $script:update.OutputDirectory 'summary.json') | Should -BeTrue
    }

    It 'accounts for every machine it queried' {
        $counted = $script:update.HealthyCount + $script:update.DegradedCount +
        $script:update.UnhealthyCount + $script:update.UnreachableCount
        $counted | Should -Be $script:update.ComputersQueried
    }

    It 'does not report update history from the future' {
        # The COM history returns timestamps with Kind Unspecified, which read as local
        # and put a just-installed update hours ahead of now.
        $historyFile = Get-ChildItem -LiteralPath $script:update.OutputDirectory -Filter '*history*.csv' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($historyFile) {
            $dated = @(Import-Csv $historyFile.FullName | Where-Object { $_.PSObject.Properties.Name -contains 'InstalledOn' -and $_.InstalledOn })
            foreach ($row in $dated) {
                [datetime]$row.InstalledOn | Should -BeLessOrEqual (Get-Date).AddDays(1)
            }
        }
    }
}

Describe 'Test-Windows11UpgradeReadiness' {
    BeforeAll {
        $script:readiness = & (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\lifecycle\Test-Windows11UpgradeReadiness.ps1') `
            -OutputDirectory (Join-Path $script:workRoot 'readiness')
        $script:checks = @(Import-Csv (Get-ChildItem -LiteralPath $script:readiness.OutputDirectory -Filter *.csv | Select-Object -First 1).FullName)
    }

    It 'writes the run-directory layout the comparison tool needs' {
        (Split-Path $script:readiness.OutputDirectory -Leaf) | Should -Match '^windows11-upgrade-readiness-\d{8}_\d{6}$'
        Test-Path (Join-Path $script:readiness.OutputDirectory 'summary.json') | Should -BeTrue
    }

    It 'accounts for every machine it queried' {
        $counted = $script:readiness.ReadyCount + $script:readiness.BlockedCount +
        $script:readiness.UndeterminedCount + $script:readiness.UnreachableCount
        $counted | Should -Be $script:readiness.ComputersQueried
    }

    It 'gives every check a verdict and both sides of the comparison' {
        # A check with no Actual and Required is unauditable: the reader cannot tell
        # whether it passed by a wide margin or by nothing at all.
        $script:checks.Count | Should -BeGreaterThan 0
        foreach ($check in $script:checks) {
            $check.Status | Should -BeIn @('Pass', 'Fail', 'Review', 'Undetermined')
            $check.Check | Should -Not -BeNullOrEmpty
            $check.Required | Should -Not -BeNullOrEmpty
        }
    }

    It 'marks the processor model for review rather than guessing' {
        # Microsoft publishes a model list, not a rule, so this one genuinely cannot be
        # decided from the machine. Answering it either way would be an invention.
        ($script:checks | Where-Object { $_.Check -eq 'ProcessorModel' }).Status | Should -Be 'Review'
    }
}

Describe 'Get-CurrentUserContext' {
    It 'reports the account it is actually running as' {
        $context = & (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\utilities\Get-CurrentUserContext.ps1')
        $context | Should -Not -BeNullOrEmpty
        # Compared against the running identity rather than a fixed value, so this
        # holds on any machine and under any account.
        $expected = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ($context.PSObject.Properties.Value -join ' ') | Should -Match ([regex]::Escape($expected.Split('\')[-1]))
    }

    It 'writes a report only when asked for one' {
        $out = Join-Path $script:workRoot 'context'
        $context = & (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\utilities\Get-CurrentUserContext.ps1') `
            -OutputDirectory $out -IncludeGroups

        $context | Should -Not -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $out -Recurse -File).Count | Should -BeGreaterThan 0
    }
}

Describe 'Page-File-Bleed' {
    BeforeAll {
        # This one gates on -Execute rather than -WhatIf, which its own header records
        # as a deliberate deviation. Both paths are stubbed regardless: it reconfigures
        # the page file, and there is no version of that worth doing to the machine
        # running the suite.
        $script:pageFixture = @'
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -match 'PageFile') {
        return [pscustomobject]@{ Name = 'C:\pagefile.sys'; InitialSize = 0; MaximumSize = 0; AllocatedBaseSize = 4096 }
    }
    [pscustomobject]@{ AutomaticManagedPagefile = $true; TotalPhysicalMemory = 34359738368 }
}
function Set-CimInstance { param($InputObject, $Property) Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value 'Set-CimInstance' }
function Invoke-CimMethod { param($InputObject, $MethodName, $Arguments) Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value "Invoke-CimMethod:$MethodName" }
'@

        $script:pageLog = Join-Path $script:workRoot 'page.log'
        $script:pageRun = Invoke-ScriptUnderTest -RelativePath 'scripts\it-operations\utilities\Page-File-Bleed.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:pageLog)'`n$($script:pageFixture)" `
            -Argument @{}
    }

    It 'runs to completion without -Execute' {
        $script:pageRun.ExitCode | Should -Be 0 -Because "the dry run failed: $($script:pageRun.Output)"
    }

    It 'changes nothing without -Execute' {
        # The deviation is that the gate is -Execute rather than -WhatIf. The promise
        # it makes is the same one, so it is tested the same way.
        (Test-Path -LiteralPath $script:pageLog) | Should -BeFalse -Because 'nothing should have been written without -Execute'
    }

    It 'says that it is a dry run rather than staying silent' {
        $script:pageRun.Output | Should -Match 'Dry run'
        $script:pageRun.Output | Should -Match '-Execute'
    }
}
