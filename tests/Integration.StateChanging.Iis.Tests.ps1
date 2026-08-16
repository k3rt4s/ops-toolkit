#Requires -Modules Pester

# The four IIS scripts that write configuration. None had coverage, and none could
# previously be run here at all: they call Import-Module WebAdministration
# -ErrorAction Stop and this machine has no IIS.
#
# Same shape as the Active Directory state-changing specs. Each script runs with
# -WhatIf, which must write no configuration, and again executing, which must write
# exactly what the preview described.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:iisModulePath = Use-FakeWebAdministration
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-iis-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    # Two sites. Default already carries the header at the wanted value, so it must be
    # left alone; Intranet carries a stale value and must be updated. A script that
    # rewrites both looks identical in a summary count to one that works.
    # X-Content-Type-Options is set on Default Web Site at exactly the value the
    # recommended preset uses, which is the only way to reach the preset's skip path.
    # X-Frame-Options is not part of the preset, so it exercises the single-header
    # scripts without interfering with the preset run.
    $script:sites = 'Default Web Site;Intranet'
    $script:existingHeaders = @{
        'Default Web Site' = @(
            @{ name = 'X-Frame-Options'; value = 'SAMEORIGIN' }
            @{ name = 'X-Content-Type-Options'; value = 'nosniff' }
        )
        'Intranet'         = @(@{ name = 'X-Frame-Options'; value = 'ALLOW-FROM https://old' })
    } | ConvertTo-Json -Depth 5 -Compress

    function New-IisSetup {
        <#
        .SYNOPSIS
        Build the setup text that points the fake IIS module at this fixture.
        #>
        param([string]$MutationLog, [string]$Headers, [string]$LogFields)

        $lines = @(
            "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$MutationLog'"
            "`$env:OPSTOOLKIT_TEST_IIS_SITES = '$($script:sites)'"
        )
        if ($Headers) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_HEADERS = '$Headers'" }
        if ($LogFields) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_LOGFIELDS = '$LogFields'" }
        $lines -join "`n"
    }

    function Get-MutationRecord {
        <#
        .SYNOPSIS
        Read the configuration writes a run attempted, as objects.
        #>
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }
}

AfterAll {
    foreach ($p in $script:iisModulePath, $script:workRoot) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-IisSiteCustomHeader' {
    BeforeAll {
        $script:oneWhatIfLog = Join-Path $script:workRoot 'one-whatif.log'
        $script:oneWhatIf = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteCustomHeader.ps1' `
            -Setup (New-IisSetup -MutationLog $script:oneWhatIfLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ SiteName = 'Intranet'; HeaderName = 'X-Frame-Options'; HeaderValue = 'DENY'; WhatIf = $true }

        $script:oneExecuteLog = Join-Path $script:workRoot 'one-execute.log'
        $script:oneExecute = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteCustomHeader.ps1' `
            -Setup (New-IisSetup -MutationLog $script:oneExecuteLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ SiteName = 'Intranet'; HeaderName = 'X-Frame-Options'; HeaderValue = 'DENY'; Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:oneWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:oneWhatIf.Output)"
        $script:oneExecute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:oneExecute.Output)"
    }

    It 'writes no configuration under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:oneWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($mutations | ConvertTo-Json -Compress)"
    }

    It 'updates the existing header in place rather than adding a duplicate' {
        # Add on a header the site already has is how a site ends up serving two
        # X-Frame-Options values, which browsers resolve unpredictably.
        $mutations = Get-MutationRecord -Path $script:oneExecuteLog
        $mutations.Count | Should -Be 1
        $mutations[0].Command | Should -Be 'Set-WebConfigurationProperty'
        $mutations[0].Site | Should -Be 'Intranet'
        $mutations[0].Value | Should -Be 'DENY'
    }

    It 'adds the header when the site does not already have it' {
        $log = Join-Path $script:workRoot 'one-add.log'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteCustomHeader.ps1' `
            -Setup (New-IisSetup -MutationLog $log -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ SiteName = 'Intranet'; HeaderName = 'X-Content-Type-Options'; HeaderValue = 'nosniff'; Confirm = $false }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        $mutations = Get-MutationRecord -Path $log
        $mutations.Count | Should -Be 1
        $mutations[0].Command | Should -Be 'Add-WebConfigurationProperty'
        $mutations[0].Value | Should -Match 'nosniff'
    }
}

Describe 'Set-IisSiteCustomHeaderForAllSites' {
    BeforeAll {
        $script:allWhatIfLog = Join-Path $script:workRoot 'all-whatif.log'
        $script:allWhatIf = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1' `
            -Setup (New-IisSetup -MutationLog $script:allWhatIfLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ HeaderName = 'X-Frame-Options'; HeaderValue = 'SAMEORIGIN'; WhatIf = $true }

        $script:allExecuteLog = Join-Path $script:workRoot 'all-execute.log'
        $script:allExecute = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1' `
            -Setup (New-IisSetup -MutationLog $script:allExecuteLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ HeaderName = 'X-Frame-Options'; HeaderValue = 'SAMEORIGIN'; Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:allWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:allWhatIf.Output)"
        $script:allExecute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:allExecute.Output)"
    }

    It 'walks every site on the server' {
        @($script:allWhatIf.Summary.Results).Count | Should -Be 2
        @($script:allWhatIf.Summary.Results | ForEach-Object { $_.SiteName }) |
            Should -Be @('Default Web Site', 'Intranet')
    }

    It 'writes no configuration under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:allWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($mutations | ConvertTo-Json -Compress)"
    }

    It 'touches only the site whose value is actually wrong' {
        # Default Web Site already serves SAMEORIGIN. Rewriting it would be a
        # configuration write, an apppool-level change record, and a diff in someone's
        # change control, all to set a value to itself.
        $mutations = Get-MutationRecord -Path $script:allExecuteLog
        $mutations.Count | Should -Be 1
        $mutations[0].Site | Should -Be 'Intranet'

        $script:allExecute.Summary.ChangedCount | Should -Be 1
        $script:allExecute.Summary.SkippedCount | Should -Be 1
        ($script:allExecute.Summary.Results | Where-Object { $_.SiteName -eq 'Default Web Site' }).Reason |
            Should -Be 'Already set'
    }
}

Describe 'Set-IisRecommendedSecurityHeaders' {
    BeforeAll {
        $script:presetWhatIfLog = Join-Path $script:workRoot 'preset-whatif.log'
        $script:presetWhatIf = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisRecommendedSecurityHeaders.ps1' `
            -Setup (New-IisSetup -MutationLog $script:presetWhatIfLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ WhatIf = $true }

        $script:presetExecuteLog = Join-Path $script:workRoot 'preset-execute.log'
        $script:presetExecute = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisRecommendedSecurityHeaders.ps1' `
            -Setup (New-IisSetup -MutationLog $script:presetExecuteLog -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:presetWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:presetWhatIf.Output)"
        $script:presetExecute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:presetExecute.Output)"
    }

    It 'writes no configuration under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:presetWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($mutations | ConvertTo-Json -Compress)"
        $script:presetWhatIf.Summary.ChangedCount | Should -Be 0
    }

    It 'applies the preset to both sites and reports what it did' {
        $mutations = Get-MutationRecord -Path $script:presetExecuteLog
        $mutations.Count | Should -BeGreaterThan 0
        @($mutations | ForEach-Object { $_.Site } | Sort-Object -Unique) |
            Should -Be @('Default Web Site', 'Intranet')
        $script:presetExecute.Summary.ChangedCount | Should -Be $mutations.Count
    }

    It 'leaves a header already at the preset value alone' {
        # Default Web Site already serves X-Content-Type-Options nosniff, which is
        # exactly what the preset wants, so it must be skipped rather than rewritten.
        # Intranet does not have it and must get it.
        $script:presetExecute.Summary.SkippedCount | Should -BeGreaterThan 0

        $nosniffWrites = @(Get-MutationRecord -Path $script:presetExecuteLog |
                Where-Object { $_.Value -match 'nosniff' })
        @($nosniffWrites | ForEach-Object { $_.Site } | Sort-Object -Unique) | Should -Be @('Intranet')
    }

    It 'writes a backup report before removing anything' {
        # -RemoveExisting deletes headers that are already there. Without a record of
        # what was removed there is no way back, so the report is written even on a
        # preview run.
        $log = Join-Path $script:workRoot 'preset-remove.log'
        $reportPath = Join-Path $script:workRoot 'header-backup.csv'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisRecommendedSecurityHeaders.ps1' `
            -Setup (New-IisSetup -MutationLog $log -Headers $script:existingHeaders) `
            -ModulePath $script:iisModulePath `
            -Argument @{ RemoveExisting = $true; BackupReportPath = $reportPath; WhatIf = $true }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        Test-Path $reportPath | Should -BeTrue -Because 'the backup report is the only record of what -RemoveExisting would delete'

        $backup = @(Import-Csv $reportPath)
        $backup.Count | Should -BeGreaterThan 0
        @($backup | ForEach-Object { $_.SiteName } | Sort-Object -Unique) |
            Should -Be @('Default Web Site', 'Intranet')

        # And still nothing removed, because this was a preview.
        @(Get-MutationRecord -Path $log | Where-Object { $_.Command -eq 'Remove-WebConfigurationProperty' }).Count |
            Should -Be 0
    }
}

Describe 'Set-IisSiteDefaultCustomLogFields' {
    BeforeAll {
        # The script's default field list is exactly one entry, X-Forwarded-For from
        # the request header, so each of the three paths is reached by varying what the
        # server already has rather than by varying the requested fields.
        $script:logCorrect = @(
            @{ logFieldName = 'X-Forwarded-For'; sourceName = 'X-Forwarded-For'; sourceType = 'RequestHeader' }
        ) | ConvertTo-Json -Depth 5 -Compress

        $script:logWrongSource = @(
            @{ logFieldName = 'X-Forwarded-For'; sourceName = 'X-Forwarded-For'; sourceType = 'ServerVariable' }
        ) | ConvertTo-Json -Depth 5 -Compress

        $script:logWhatIfLog = Join-Path $script:workRoot 'log-whatif.log'
        $script:logWhatIf = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1' `
            -Setup (New-IisSetup -MutationLog $script:logWhatIfLog -LogFields $script:logWrongSource) `
            -ModulePath $script:iisModulePath `
            -Argument @{ WhatIf = $true }

        $script:logSkipLog = Join-Path $script:workRoot 'log-skip.log'
        $script:logSkip = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1' `
            -Setup (New-IisSetup -MutationLog $script:logSkipLog -LogFields $script:logCorrect) `
            -ModulePath $script:iisModulePath `
            -Argument @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:logWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:logWhatIf.Output)"
        $script:logSkip.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:logSkip.Output)"
    }

    It 'writes no configuration under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:logWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($mutations | ConvertTo-Json -Compress)"
        $script:logWhatIf.Summary.ChangedCount | Should -Be 0
    }

    It 'leaves a field that is already correct alone' {
        # Re-adding a field the server already has is how a log line gains a second
        # column with the same name, after which every downstream parser disagrees
        # about which one it is reading.
        @(Get-MutationRecord -Path $script:logSkipLog).Count | Should -Be 0
        $script:logSkip.Summary.SkippedCount | Should -Be 1
        $script:logSkip.Summary.ChangedCount | Should -Be 0
    }

    It 'updates a field whose source is wrong rather than adding a second one' {
        $log = Join-Path $script:workRoot 'log-update.log'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1' `
            -Setup (New-IisSetup -MutationLog $log -LogFields $script:logWrongSource) `
            -ModulePath $script:iisModulePath `
            -Argument @{ Confirm = $false }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        $mutations = Get-MutationRecord -Path $log
        @($mutations | Where-Object { $_.Command -eq 'Add-WebConfigurationProperty' }).Count | Should -Be 0
        @($mutations | Where-Object { $_.Command -eq 'Set-WebConfigurationProperty' }).Count | Should -Be 2
        @($mutations | ForEach-Object { $_.Value }) | Should -Contain 'RequestHeader'
        $run.Summary.ChangedCount | Should -Be 1
    }

    It 'adds the field when the server has none' {
        $log = Join-Path $script:workRoot 'log-add.log'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1' `
            -Setup (New-IisSetup -MutationLog $log) `
            -ModulePath $script:iisModulePath `
            -Argument @{ Confirm = $false }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        $mutations = Get-MutationRecord -Path $log
        $mutations.Count | Should -Be 1
        $mutations[0].Command | Should -Be 'Add-WebConfigurationProperty'
        $mutations[0].Value | Should -Match 'X-Forwarded-For'
    }
}
