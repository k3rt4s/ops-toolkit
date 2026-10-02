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
    # X-Content-Type-Options and X-Frame-Options are both part of the recommended
    # preset. Default Web Site carries them at exactly the preset values (nosniff and
    # SAMEORIGIN), which is the only way to reach the preset's skip path. Intranet
    # carries no X-Content-Type-Options, so the preset adds it, and a stale
    # X-Frame-Options, so the preset updates it in place: both the add and the update
    # path are reached deliberately. The single-header scripts reuse the same
    # X-Frame-Options fixture.
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
        param([string]$MutationLog, [string]$Headers, [string]$LogFields, [string]$RemoveServerHeader, [string]$Hsts)

        $lines = @(
            "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$MutationLog'"
            "`$env:OPSTOOLKIT_TEST_IIS_SITES = '$($script:sites)'"
        )
        if ($Headers) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_HEADERS = '$Headers'" }
        if ($LogFields) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_LOGFIELDS = '$LogFields'" }
        if ($RemoveServerHeader) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_REMOVESERVERHEADER = '$RemoveServerHeader'" }
        if ($Hsts) { $lines += "`$env:OPSTOOLKIT_TEST_IIS_HSTS = '$Hsts'" }
        $lines -join "`n"
    }

    function Invoke-IisCase {
        <#
        .SYNOPSIS
        Run one IIS script against the fixture and return the run with the writes it attempted.
        #>
        param(
            [string]$Script,
            [string]$Name,
            [hashtable]$Argument = @{},
            [hashtable]$RawArgument = @{},
            [string]$Headers = $script:existingHeaders,
            [string]$RemoveServerHeader,
            [string]$Hsts
        )

        $log = Join-Path $script:workRoot "$Name.log"
        $run = Invoke-ScriptUnderTest -RelativePath "scripts\iis\$Script.ps1" `
            -Setup (New-IisSetup -MutationLog $log -Headers $Headers -RemoveServerHeader $RemoveServerHeader -Hsts $Hsts) `
            -ModulePath $script:iisModulePath -Argument $Argument -RawArgument $RawArgument
        [pscustomobject]@{ Run = $run; Mutations = @(Get-MutationRecord -Path $log) }
    }

    function Get-WrittenHeaderName {
        <#
        .SYNOPSIS
        Name the custom header a Set or Add mutation record wrote, or nothing for any other write.
        #>
        param($Mutation)

        if ($Mutation.Filter -ne 'system.webServer/httpProtocol/customHeaders' -and $Mutation.Filter -notmatch "customHeaders/add\[@name=") { return }
        if ($Mutation.Command -eq 'Add-WebConfigurationProperty') { return ($Mutation.Value -replace '^name=([^,]+),.*$', '$1') }
        if ($Mutation.Command -eq 'Set-WebConfigurationProperty') { return ($Mutation.Filter -replace "^.*add\[@name='([^']+)'\]$", '$1') }
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
        # Nothing is removed in this fixture (no X-Powered-By), so every mutation is a
        # Set or Add and ChangedCount equals the mutation count. Default Web Site: 9
        # preset headers minus the 2 already at the preset value = 7 adds, plus the
        # Server header = 8. Intranet: 8 adds, 1 update, Server header = 10.
        $mutations = Get-MutationRecord -Path $script:presetExecuteLog
        $mutations.Count | Should -Be 18
        $script:presetExecute.Summary.ChangedCount | Should -Be $mutations.Count
        $script:presetExecute.Summary.SkippedCount | Should -Be 2
        $script:presetExecute.Summary.RemovedCount | Should -Be 0
        $script:presetExecute.Summary.NotRunCount | Should -Be 0
        @($mutations | ForEach-Object { $_.Site } | Sort-Object -Unique) |
            Should -Be @('Default Web Site', 'Intranet')
    }

    It 'reaches the update path on Intranet and the skip path on Default Web Site for X-Frame-Options' {
        $xfo = @($script:presetExecute.Summary.Results | Where-Object { $_.HeaderName -eq 'X-Frame-Options' })
        $xfo.Count | Should -Be 2
        ($xfo | Where-Object { $_.SiteName -eq 'Default Web Site' }).Action | Should -Be 'None'
        ($xfo | Where-Object { $_.SiteName -eq 'Intranet' }).Action | Should -Be 'Update'
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

Describe 'Set-IisRecommendedSecurityHeaders preset contents' {
    BeforeAll {
        $script:presetScript = 'Set-IisRecommendedSecurityHeaders'
        $script:presetNames = @(
            'Content-Security-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
            'Permissions-Policy', 'Referrer-Policy', 'Strict-Transport-Security',
            'X-Content-Type-Options', 'X-Frame-Options', 'X-Permitted-Cross-Domain-Policies'
        )
        $script:defRun = Invoke-IisCase -Script $script:presetScript -Name 'def-exec' -Argument @{ Confirm = $false }
    }

    It 'runs to completion' {
        $script:defRun.Run.ExitCode | Should -Be 0 -Because "the run failed: $($script:defRun.Run.Output)"
    }

    It 'writes the nine preset headers and nothing else' {
        # Default Web Site already has two of the nine at the preset value; Intranet has none correct.
        $written = @($script:defRun.Mutations | ForEach-Object { [pscustomobject]@{ Site = $_.Site; Header = (Get-WrittenHeaderName $_) } } |
                Where-Object { $_.Header })
        $written.Count | Should -Be 16

        @($written | Where-Object { $_.Site -eq 'Intranet' } | ForEach-Object { $_.Header } | Sort-Object) |
            Should -Be @($script:presetNames | Sort-Object)
        @($written | Where-Object { $_.Site -eq 'Default Web Site' } | ForEach-Object { $_.Header } | Sort-Object) |
            Should -Be @($script:presetNames | Where-Object { $_ -notin 'X-Content-Type-Options', 'X-Frame-Options' } | Sort-Object)
    }

    It 'sends neither Pragma nor Cache-Control by default' {
        $names = @($script:defRun.Mutations | ForEach-Object { Get-WrittenHeaderName $_ } | Where-Object { $_ })
        $names.Count | Should -Be 16
        $names | Should -Not -Contain 'Pragma'
        $names | Should -Not -Contain 'Cache-Control'
    }

    It 'writes the documented value for each header added to Intranet' {
        $expected = @{
            'Content-Security-Policy'           = "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
            'Referrer-Policy'                   = 'strict-origin-when-cross-origin'
            'Permissions-Policy'                = 'geolocation=(), microphone=(), camera=()'
            'Cross-Origin-Opener-Policy'        = 'same-origin'
            'Cross-Origin-Resource-Policy'      = 'same-site'
            'X-Permitted-Cross-Domain-Policies' = 'none'
            'X-Content-Type-Options'            = 'nosniff'
            'Strict-Transport-Security'         = 'max-age=31536000'
        }
        $adds = @($script:defRun.Mutations | Where-Object { $_.Site -eq 'Intranet' -and $_.Command -eq 'Add-WebConfigurationProperty' })
        $adds.Count | Should -Be 8
        foreach ($name in $expected.Keys) {
            @($adds | Where-Object { $_.Value -eq "name=$name,value=$($expected[$name])" }).Count |
                Should -Be 1 -Because "$name should be added with '$($expected[$name])'"
        }
    }

    It 'updates the stale X-Frame-Options on Intranet to SAMEORIGIN in place' {
        $set = @($script:defRun.Mutations | Where-Object { $_.Command -eq 'Set-WebConfigurationProperty' -and $_.Name -eq 'value' })
        $set.Count | Should -Be 1
        $set[0].Site | Should -Be 'Intranet'
        $set[0].Filter | Should -Match "add\[@name='X-Frame-Options'\]"
        $set[0].Value | Should -Be 'SAMEORIGIN'
    }
}

Describe 'Set-IisRecommendedSecurityHeaders -IncludeNoStore' {
    BeforeAll {
        $script:noStoreWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nostore-whatif' -Argument @{ IncludeNoStore = $true; WhatIf = $true }
        $script:noStoreExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nostore-exec' -Argument @{ IncludeNoStore = $true; Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:noStoreWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:noStoreWhatIf.Run.Output)"
        $script:noStoreExec.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:noStoreExec.Run.Output)"
    }

    It 'writes no configuration under -WhatIf' {
        $script:noStoreWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:noStoreWhatIf.Mutations | ConvertTo-Json -Compress)"
        $script:noStoreWhatIf.Run.Summary.ChangedCount | Should -Be 0
    }

    It 'adds Cache-Control no-store to every site, and still no Pragma' {
        $script:noStoreExec.Mutations.Count | Should -Be 20
        $cache = @($script:noStoreExec.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq 'Cache-Control' })
        $cache.Count | Should -Be 2
        @($cache | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -Be @('name=Cache-Control,value=no-store')
        @($script:noStoreExec.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq 'Pragma' }).Count | Should -Be 0
    }
}

Describe 'Set-IisRecommendedSecurityHeaders -CspReportOnly' {
    BeforeAll {
        $script:cspWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'csp-whatif' -Argument @{ CspReportOnly = $true; WhatIf = $true }
        $script:cspExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'csp-exec' -Argument @{ CspReportOnly = $true; Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:cspWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:cspWhatIf.Run.Output)"
        $script:cspExec.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:cspExec.Run.Output)"
    }

    It 'writes no configuration under -WhatIf' {
        $script:cspWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:cspWhatIf.Mutations | ConvertTo-Json -Compress)"
        $script:cspWhatIf.Run.Summary.CspReportOnly | Should -BeTrue
    }

    It 'writes the Report-Only header name on both sites and never the enforcing one' {
        $script:cspExec.Mutations.Count | Should -Be 18
        $names = @($script:cspExec.Mutations | ForEach-Object { Get-WrittenHeaderName $_ } | Where-Object { $_ })
        @($names | Where-Object { $_ -eq 'Content-Security-Policy-Report-Only' }).Count | Should -Be 2
        @($names | Where-Object { $_ -eq 'Content-Security-Policy' }).Count | Should -Be 0
        $script:cspExec.Run.Summary.CspReportOnly | Should -BeTrue
    }
}

Describe 'Set-IisRecommendedSecurityHeaders -CspReportUri' {
    BeforeAll {
        $script:reportUri = 'https://reports.example.com/csp'
        $script:ruWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'ru-whatif' -Argument @{ CspReportUri = $script:reportUri; WhatIf = $true }
        $script:ruExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'ru-exec' -Argument @{ CspReportUri = $script:reportUri; Confirm = $false }
        $script:ruReportOnly = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'ru-ro' -Argument @{ CspReportUri = $script:reportUri; CspReportOnly = $true; Confirm = $false }

        function Get-WrittenValue {
            param($Case, [string]$Header)
            @($Case.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq $Header } |
                    ForEach-Object { $_.Value -replace "^name=$([regex]::Escape($Header)),value=", '' } | Sort-Object -Unique)
        }
    }

    It 'runs to completion in every mode' {
        foreach ($case in $script:ruWhatIf, $script:ruExec, $script:ruReportOnly) {
            $case.Run.ExitCode | Should -Be 0 -Because "the run failed: $($case.Run.Output)"
        }
        $script:ruExec.Run.Summary.CspReportUri | Should -Be $script:reportUri
    }

    It 'writes no configuration under -WhatIf' {
        $script:ruWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:ruWhatIf.Mutations | ConvertTo-Json -Compress)"
    }

    It 'adds Reporting-Endpoints and both reporting directives to the enforced policy' {
        # Ten preset headers per site, two already correct on Default Web Site, plus the Server header on each.
        $script:ruExec.Mutations.Count | Should -Be 20
        Get-WrittenValue -Case $script:ruExec -Header 'Reporting-Endpoints' |
            Should -Be @('csp-endpoint="https://reports.example.com/csp"')
        Get-WrittenValue -Case $script:ruExec -Header 'Content-Security-Policy' |
            Should -Be @("default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; report-uri https://reports.example.com/csp; report-to csp-endpoint")
    }

    It 'puts the reporting directives on the Report-Only policy under -CspReportOnly' {
        Get-WrittenValue -Case $script:ruReportOnly -Header 'Content-Security-Policy-Report-Only' |
            Should -Match 'report-to csp-endpoint$'
        @(Get-WrittenValue -Case $script:ruReportOnly -Header 'Content-Security-Policy').Count | Should -Be 0
        @(Get-WrittenValue -Case $script:ruReportOnly -Header 'Reporting-Endpoints').Count | Should -Be 1
    }

    It 'rejects <Uri> with no reads or writes' -ForEach @(
        @{ Uri = 'http://reports.example.com/csp' }
        @{ Uri = '/csp-reports' }
        @{ Uri = 'https://reports.example.com/a;script-src *' }
        @{ Uri = 'https://reports.example.com/a,b' }
    ) {
        $case = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name ('ru-bad-' + [guid]::NewGuid().ToString('N')) `
            -Argument @{ CspReportUri = $Uri; Confirm = $false }

        $case.Run.ExitCode | Should -Not -Be 0
        $case.Mutations.Count | Should -Be 0 -Because "writes happened: $($case.Mutations | ConvertTo-Json -Compress)"
        $case.Run.Output | Should -Match 'must be an absolute https'
    }
}

Describe 'Set-IisRecommendedSecurityHeaders -CoopAllowPopups' {
    BeforeAll {
        $script:coopExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'coop-exec' -Argument @{ CoopAllowPopups = $true; Confirm = $false }
    }

    It 'sends same-origin-allow-popups on both sites and never same-origin' {
        $script:coopExec.Run.ExitCode | Should -Be 0 -Because "the run failed: $($script:coopExec.Run.Output)"
        $coop = @($script:coopExec.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq 'Cross-Origin-Opener-Policy' })
        $coop.Count | Should -Be 2
        @($coop | ForEach-Object { $_.Value } | Sort-Object -Unique) |
            Should -Be @('name=Cross-Origin-Opener-Policy,value=same-origin-allow-popups')
        $script:coopExec.Run.Summary.CoopAllowPopups | Should -BeTrue
    }
}

Describe 'Set-IisRecommendedSecurityHeaders HSTS options' {
    BeforeAll {
        $script:stsDefault = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'sts-default' -Argument @{ Confirm = $false }
        $script:stsWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'sts-whatif' -Argument @{ HstsIncludeSubDomains = $true; HstsMaxAgeSeconds = '600'; WhatIf = $true }
        $script:stsExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'sts-exec' -Argument @{ HstsIncludeSubDomains = $true; HstsMaxAgeSeconds = '600'; Confirm = $false }
    }

    It 'runs to completion' {
        $script:stsDefault.Run.ExitCode | Should -Be 0 -Because "the default run failed: $($script:stsDefault.Run.Output)"
        $script:stsWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:stsWhatIf.Run.Output)"
        $script:stsExec.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:stsExec.Run.Output)"
    }

    It 'sends HSTS without includeSubDomains by default' {
        $sts = @($script:stsDefault.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq 'Strict-Transport-Security' })
        $sts.Count | Should -Be 2
        @($sts | ForEach-Object { $_.Value } | Sort-Object -Unique) |
            Should -Be @('name=Strict-Transport-Security,value=max-age=31536000')
    }

    It 'writes no configuration under -WhatIf' {
        $script:stsWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:stsWhatIf.Mutations | ConvertTo-Json -Compress)"
    }

    It 'adds includeSubDomains and the requested max-age under the switches' {
        $script:stsExec.Mutations.Count | Should -Be 18
        $sts = @($script:stsExec.Mutations | Where-Object { (Get-WrittenHeaderName $_) -eq 'Strict-Transport-Security' })
        $sts.Count | Should -Be 2
        @($sts | ForEach-Object { $_.Value } | Sort-Object -Unique) |
            Should -Be @('name=Strict-Transport-Security,value=max-age=600; includeSubDomains')
    }
}

Describe 'Set-IisRecommendedSecurityHeaders Server header removal' {
    BeforeAll {
        $script:srvOneSet = '{"Default Web Site":true,"Intranet":false}'
        $script:srvAllSet = '{"Default Web Site":true,"Intranet":true}'
        $script:srvWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-whatif' -RemoveServerHeader $script:srvOneSet -Argument @{ WhatIf = $true }
        $script:srvDefault = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-default' -Argument @{ Confirm = $false }
        $script:srvPartial = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-partial' -RemoveServerHeader $script:srvOneSet -Argument @{ Confirm = $false }
        $script:srvAll = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-all' -RemoveServerHeader $script:srvAllSet -Argument @{ Confirm = $false }
        $script:srvUnsupportedWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-unsup-whatif' -RemoveServerHeader 'unsupported' -Argument @{ WhatIf = $true }
        $script:srvUnsupported = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-unsup' -RemoveServerHeader 'unsupported' -Argument @{ Confirm = $false }
        $script:srvKeep = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-keep' -RemoveServerHeader 'unsupported' -Argument @{ KeepServerHeader = $true; Confirm = $false }
        $script:srvKeepWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'srv-keep-whatif' -Argument @{ KeepServerHeader = $true; WhatIf = $true }

        function Get-ServerWrite {
            param($Case)
            @($Case.Mutations | Where-Object { $_.Name -eq 'removeServerHeader' })
        }
    }

    It 'runs to completion in every mode, an unsupported server included' {
        foreach ($case in 'srvWhatIf', 'srvDefault', 'srvPartial', 'srvAll', 'srvUnsupportedWhatIf', 'srvUnsupported', 'srvKeep', 'srvKeepWhatIf') {
            $run = (Get-Variable -Name $case -Scope Script -ValueOnly).Run
            $run.ExitCode | Should -Be 0 -Because "$case failed: $($run.Output)"
        }
    }

    It 'writes removeServerHeader once per site' {
        $writes = Get-ServerWrite -Case $script:srvDefault
        $writes.Count | Should -Be 2
        @($writes | ForEach-Object { $_.Site } | Sort-Object) | Should -Be @('Default Web Site', 'Intranet')
        @($writes | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -Be @('True')
        @($writes | ForEach-Object { $_.Filter } | Sort-Object -Unique) | Should -Be @('system.webServer/security/requestFiltering')
        $script:srvDefault.Run.Summary.ServerHeaderRemoval | Should -BeTrue
    }

    It 'writes nothing for a site that already removes the Server header' {
        $writes = Get-ServerWrite -Case $script:srvPartial
        $writes.Count | Should -Be 1
        $writes[0].Site | Should -Be 'Intranet'

        $row = $script:srvPartial.Run.Summary.Results | Where-Object { $_.SiteName -eq 'Default Web Site' -and $_.HeaderName -eq 'Server' }
        $row.Action | Should -Be 'None'
        $row.Reason | Should -Be 'Already set'
        $script:srvPartial.Run.Summary.NotRunCount | Should -Be 0
    }

    It 'writes no Server header change at all when every site already has it' {
        (Get-ServerWrite -Case $script:srvAll).Count | Should -Be 0
        $script:srvAll.Mutations.Count | Should -Be 16
    }

    It 'previews the Server header change without writing it' {
        $script:srvWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:srvWhatIf.Mutations | ConvertTo-Json -Compress)"
        $row = $script:srvWhatIf.Run.Summary.Results | Where-Object { $_.SiteName -eq 'Intranet' -and $_.HeaderName -eq 'Server' }
        $row.Changed | Should -BeFalse
        $row.Reason | Should -Be 'Previewed'
    }

    It 'reports an unsupported server as NotRun, not skipped or changed, and carries on' {
        foreach ($case in $script:srvUnsupported, $script:srvUnsupportedWhatIf) {
            $case.Run.Summary.NotRunCount | Should -Be 2
            (Get-ServerWrite -Case $case).Count | Should -Be 0
            $rows = @($case.Run.Summary.Results | Where-Object { $_.HeaderName -eq 'Server' })
            $rows.Count | Should -Be 2
            @($rows | ForEach-Object { $_.Action } | Sort-Object -Unique) | Should -Be @('NotRun')
            @($rows | ForEach-Object { $_.Changed } | Sort-Object -Unique) | Should -Be @($false)
            @($rows | ForEach-Object { $_.Reason } | Sort-Object -Unique) |
                Should -Be @('removeServerHeader not supported (needs Windows Server or Windows 10 version 1709 or later)')
        }

        # The header work still happens: 16 header writes, none counted for the Server header.
        $script:srvUnsupported.Mutations.Count | Should -Be 16
        $script:srvUnsupported.Run.Summary.ChangedCount | Should -Be 16
        $script:srvUnsupported.Run.Summary.SkippedCount | Should -Be 2
        $script:srvUnsupportedWhatIf.Mutations.Count | Should -Be 0
    }

    It 'does not read or write the Server header under -KeepServerHeader' {
        # The fixture says unsupported; a script that still read it would report NotRun.
        $script:srvKeep.Run.Summary.NotRunCount | Should -Be 0
        $script:srvKeep.Run.Summary.ServerHeaderRemoval | Should -BeFalse
        (Get-ServerWrite -Case $script:srvKeep).Count | Should -Be 0
        @($script:srvKeep.Run.Summary.Results | Where-Object { $_.HeaderName -eq 'Server' }).Count | Should -Be 0
        $script:srvKeep.Mutations.Count | Should -Be 16

        $script:srvKeepWhatIf.Mutations.Count | Should -Be 0
    }
}

Describe 'Set-IisRecommendedSecurityHeaders -UseNativeHsts' {
    BeforeAll {
        $script:headersWithSts = @{
            'Default Web Site' = @(
                @{ name = 'X-Frame-Options'; value = 'SAMEORIGIN' }
                @{ name = 'X-Content-Type-Options'; value = 'nosniff' }
                @{ name = 'Strict-Transport-Security'; value = 'max-age=300' }
            )
            'Intranet'         = @(
                @{ name = 'X-Frame-Options'; value = 'ALLOW-FROM https://old' }
                @{ name = 'Strict-Transport-Security'; value = 'max-age=300' }
            )
        } | ConvertTo-Json -Depth 5 -Compress

        $script:hstsMixed = '{"Default Web Site":{"enabled":true,"max-age":31536000,"includeSubDomains":false},"Intranet":{"enabled":false,"max-age":0,"includeSubDomains":false}}'
        $script:hstsOneUnsupported = '{"Default Web Site":{"enabled":false,"max-age":0,"includeSubDomains":false},"Intranet":"unsupported"}'

        $script:natArgs = @{ UseNativeHsts = $true; HstsIncludeSubDomains = $true }
        $script:natWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-whatif' -Headers $script:headersWithSts -Hsts $script:hstsMixed -Argument ($script:natArgs + @{ WhatIf = $true })
        $script:natExec = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-exec' -Headers $script:headersWithSts -Hsts $script:hstsMixed -Argument ($script:natArgs + @{ Confirm = $false })
        $script:natUnsupportedAll = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-unsup-all' -Headers $script:headersWithSts -Hsts 'unsupported' -Argument ($script:natArgs + @{ Confirm = $false })
        $script:natUnsupportedOne = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-unsup-one' -Headers $script:headersWithSts -Hsts $script:hstsOneUnsupported -Argument ($script:natArgs + @{ Confirm = $false })
        $script:natUnsupportedOneWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-unsup-one-whatif' -Headers $script:headersWithSts -Hsts $script:hstsOneUnsupported -Argument ($script:natArgs + @{ WhatIf = $true })
        $script:natRedirect = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-redirect' -Headers $script:headersWithSts -Hsts $script:hstsMixed -Argument ($script:natArgs + @{ RedirectHttpToHttps = $true; Confirm = $false })
        $script:natRedirectWhatIf = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'nat-redirect-whatif' -Headers $script:headersWithSts -Hsts $script:hstsMixed -Argument ($script:natArgs + @{ RedirectHttpToHttps = $true; WhatIf = $true })

        function Get-HstsWrite {
            param($Case, [string]$Site)
            @($Case.Mutations | Where-Object { $_.Filter -match '/hsts$' -and $_.Site -eq $Site })
        }
    }

    It 'runs to completion in both modes' {
        $script:natWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:natWhatIf.Run.Output)"
        $script:natExec.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:natExec.Run.Output)"
        $script:natExec.Run.Summary.UseNativeHsts | Should -BeTrue
    }

    It 'writes no configuration under -WhatIf, and previews the custom header removal' {
        $script:natWhatIf.Mutations.Count | Should -Be 0 -Because "-WhatIf wrote: $($script:natWhatIf.Mutations | ConvertTo-Json -Compress)"
        $script:natWhatIf.Run.Summary.ChangedCount | Should -Be 0
        $script:natWhatIf.Run.Summary.RemovedCount | Should -Be 0

        $removals = @($script:natWhatIf.Run.Summary.Results | Where-Object { $_.Action -eq 'Remove' })
        $removals.Count | Should -Be 2
        @($removals | ForEach-Object { $_.Reason } | Sort-Object -Unique) | Should -Be @('Previewed')
    }

    It 'writes only the hsts attributes that differ, per site' {
        # Default Web Site already has enabled and the one-year max-age, so only includeSubDomains differs.
        $default = Get-HstsWrite -Case $script:natExec -Site 'Default Web Site'
        $default.Count | Should -Be 1
        $default[0].Name | Should -Be 'includeSubDomains'
        $default[0].Value | Should -Be 'True'
        $default[0].Command | Should -Be 'Set-WebConfigurationProperty'

        $intranet = Get-HstsWrite -Case $script:natExec -Site 'Intranet'
        $intranet.Count | Should -Be 3
        $byName = @{}
        foreach ($m in $intranet) { $byName[$m.Name] = $m.Value }
        $byName['enabled'] | Should -Be 'True'
        $byName['max-age'] | Should -Be '31536000'
        $byName['includeSubDomains'] | Should -Be 'True'
    }

    It 'removes the existing custom Strict-Transport-Security header from each site and writes no new one' {
        $removals = @($script:natExec.Mutations | Where-Object { $_.Command -eq 'Remove-WebConfigurationProperty' })
        $removals.Count | Should -Be 2
        @($removals | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -Be @('name=Strict-Transport-Security')
        @($removals | ForEach-Object { $_.Site } | Sort-Object) | Should -Be @('Default Web Site', 'Intranet')
        $script:natExec.Run.Summary.RemovedCount | Should -Be 2

        $names = @($script:natExec.Mutations | ForEach-Object { Get-WrittenHeaderName $_ } | Where-Object { $_ })
        $names | Should -Not -Contain 'Strict-Transport-Security'
        $removalRows = @($script:natExec.Run.Summary.Results | Where-Object { $_.Action -eq 'Remove' })
        @($removalRows | ForEach-Object { $_.Reason } | Sort-Object -Unique) | Should -Be @('Replaced by native HSTS')
    }

    It 'counts every write and never touches redirectHttpToHttps' {
        # Default: 6 header adds + Server + 1 hsts = 8. Intranet: 8 header writes + Server + 3 hsts = 12.
        # Plus 2 removals of the custom header.
        $script:natExec.Run.Summary.ChangedCount | Should -Be 20
        $script:natExec.Mutations.Count | Should -Be 22
        @($script:natExec.Mutations | Where-Object { $_.Name -eq 'redirectHttpToHttps' }).Count | Should -Be 0
    }

    It 'turns on redirectHttpToHttps once per site under -RedirectHttpToHttps, and previews it under -WhatIf' {
        $script:natRedirect.Run.ExitCode | Should -Be 0 -Because "the run failed: $($script:natRedirect.Run.Output)"
        $writes = @($script:natRedirect.Mutations | Where-Object { $_.Name -eq 'redirectHttpToHttps' })
        $writes.Count | Should -Be 2
        @($writes | ForEach-Object { $_.Site } | Sort-Object) | Should -Be @('Default Web Site', 'Intranet')
        @($writes | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -Be @('True')
        $script:natRedirect.Run.Summary.RedirectHttpToHttps | Should -BeTrue

        $script:natRedirectWhatIf.Run.ExitCode | Should -Be 0
        $script:natRedirectWhatIf.Mutations.Count | Should -Be 0
    }

    It 'throws before any write when a site does not support native HSTS' {
        # Default Web Site would be written first, so zero writes proves the preflight ran first.
        foreach ($case in $script:natUnsupportedAll, $script:natUnsupportedOne, $script:natUnsupportedOneWhatIf) {
            $case.Run.ExitCode | Should -Not -Be 0
            $case.Mutations.Count | Should -Be 0 -Because "writes happened: $($case.Mutations | ConvertTo-Json -Compress)"
            $case.Run.Output | Should -Match 'Native HSTS needs IIS 10'
        }
    }
}

Describe 'Set-IisRecommendedSecurityHeaders conflicting parameters' {
    BeforeAll {
        $script:customOnly = "@{ 'X-Content-Type-Options' = 'nosniff' }"
        $script:customSts = "@{ 'strict-transport-security' = 'max-age=300' }"
    }

    It 'rejects <Name> with no reads or writes' -ForEach @(
        @{ Name = '-Headers with -CspReportOnly'; Argument = @{ CspReportOnly = $true }; Headers = 'customOnly'; Fragment = 'replaces the preset' }
        @{ Name = '-Headers with -IncludeNoStore'; Argument = @{ IncludeNoStore = $true }; Headers = 'customOnly'; Fragment = 'replaces the preset' }
        @{ Name = '-Headers with STS and -UseNativeHsts'; Argument = @{ UseNativeHsts = $true }; Headers = 'customSts'; Fragment = 'already contains' }
        @{ Name = '-Headers with STS and -HstsIncludeSubDomains'; Argument = @{ HstsIncludeSubDomains = $true }; Headers = 'customSts'; Fragment = 'already contains' }
        @{ Name = '-Headers with STS and -HstsMaxAgeSeconds'; Argument = @{ HstsMaxAgeSeconds = '600' }; Headers = 'customSts'; Fragment = 'already contains' }
        @{ Name = '-HstsIncludeSubDomains with -Headers lacking STS'; Argument = @{ HstsIncludeSubDomains = $true }; Headers = 'customOnly'; Fragment = 'do nothing here' }
        @{ Name = '-HstsMaxAgeSeconds with -Headers lacking STS'; Argument = @{ HstsMaxAgeSeconds = '600' }; Headers = 'customOnly'; Fragment = 'do nothing here' }
        @{ Name = '-Headers with -CspReportUri'; Argument = @{ CspReportUri = 'https://reports.example.com/csp' }; Headers = 'customOnly'; Fragment = 'replaces the preset' }
        @{ Name = '-Headers with -CoopAllowPopups'; Argument = @{ CoopAllowPopups = $true }; Headers = 'customOnly'; Fragment = 'replaces the preset' }
        @{ Name = '-RedirectHttpToHttps without -UseNativeHsts'; Argument = @{ RedirectHttpToHttps = $true }; Headers = ''; Fragment = 'needs -UseNativeHsts' }
    ) {
        $raw = if ($Headers) { @{ Headers = (Get-Variable -Name $Headers -Scope Script -ValueOnly) } } else { @{} }
        $case = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name ('conflict-' + [guid]::NewGuid().ToString('N')) `
            -Argument ($Argument + @{ Confirm = $false }) -RawArgument $raw

        $case.Run.ExitCode | Should -Not -Be 0
        $case.Mutations.Count | Should -Be 0 -Because "writes happened: $($case.Mutations | ConvertTo-Json -Compress)"
        $case.Run.Output | Should -Match $Fragment
    }

    It 'accepts -HstsMaxAgeSeconds with -Headers lacking STS when -UseNativeHsts supplies HSTS' {
        $case = Invoke-IisCase -Script 'Set-IisRecommendedSecurityHeaders' -Name 'conflict-ok' `
            -Argument @{ UseNativeHsts = $true; HstsMaxAgeSeconds = '600'; Confirm = $false } `
            -RawArgument @{ Headers = $script:customOnly }

        $case.Run.ExitCode | Should -Be 0 -Because "the run failed: $($case.Run.Output)"
        # XCTO added to Intranet (1), Server header on both sites (2), hsts enabled and
        # max-age on both sites (4); includeSubDomains already matches the false default.
        $case.Run.Summary.ChangedCount | Should -Be 7
        $names = @($case.Mutations | ForEach-Object { Get-WrittenHeaderName $_ } | Where-Object { $_ })
        $names | Should -Be @('X-Content-Type-Options')
    }
}

Describe 'Header input validation in all three scripts' {
    BeforeAll {
        # Raw arguments are emitted into the runner verbatim, which is the only way to
        # pass a quote or a CR/LF through Invoke-ScriptUnderTest's quoting.
        $script:quoteName = '"X''Y"'
        $script:crlfValue = '"a`r`nb"'
    }

    It 'rejects a header name containing a single quote in <Script>' -ForEach @(
        @{ Script = 'Set-IisSiteCustomHeader'; Argument = @{ SiteName = 'Intranet'; HeaderValue = 'v' }; Raw = 'single' }
        @{ Script = 'Set-IisSiteCustomHeaderForAllSites'; Argument = @{ HeaderValue = 'v' }; Raw = 'single' }
        @{ Script = 'Set-IisRecommendedSecurityHeaders'; Argument = @{}; Raw = 'preset' }
    ) {
        $raw = if ($Raw -eq 'single') { @{ HeaderName = $script:quoteName } } else { @{ Headers = '@{ "X''Y" = ''v'' }' } }
        $case = Invoke-IisCase -Script $Script -Name ('quote-' + [guid]::NewGuid().ToString('N')) `
            -Argument ($Argument + @{ Confirm = $false }) -RawArgument $raw

        $case.Run.ExitCode | Should -Not -Be 0
        $case.Mutations.Count | Should -Be 0 -Because "writes happened: $($case.Mutations | ConvertTo-Json -Compress)"
    }

    It 'rejects a header value containing CR/LF in <Script>' -ForEach @(
        @{ Script = 'Set-IisSiteCustomHeader'; Argument = @{ SiteName = 'Intranet'; HeaderName = 'X-Test' }; Raw = 'single' }
        @{ Script = 'Set-IisSiteCustomHeaderForAllSites'; Argument = @{ HeaderName = 'X-Test' }; Raw = 'single' }
        @{ Script = 'Set-IisRecommendedSecurityHeaders'; Argument = @{}; Raw = 'preset' }
    ) {
        $raw = if ($Raw -eq 'single') { @{ HeaderValue = $script:crlfValue } } else { @{ Headers = '@{ ''X-Test'' = "a`r`nb" }' } }
        $case = Invoke-IisCase -Script $Script -Name ('crlf-' + [guid]::NewGuid().ToString('N')) `
            -Argument ($Argument + @{ Confirm = $false }) -RawArgument $raw

        $case.Run.ExitCode | Should -Not -Be 0
        $case.Mutations.Count | Should -Be 0 -Because "writes happened: $($case.Mutations | ConvertTo-Json -Compress)"
        $case.Run.Output | Should -Match 'control characters'
        $case.Run.Output | Should -Match 'X-Test'
    }

    It 'still accepts a horizontal tab inside a header value' {
        $case = Invoke-IisCase -Script 'Set-IisSiteCustomHeader' -Name 'tab-ok' `
            -Argument @{ SiteName = 'Intranet'; HeaderName = 'X-Test'; Confirm = $false } `
            -RawArgument @{ HeaderValue = '"a`tb"' }

        $case.Run.ExitCode | Should -Be 0 -Because "the run failed: $($case.Run.Output)"
        $case.Mutations.Count | Should -Be 1
        $case.Mutations[0].Command | Should -Be 'Add-WebConfigurationProperty'
    }
}
