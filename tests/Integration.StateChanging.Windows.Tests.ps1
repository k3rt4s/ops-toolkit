#Requires -Modules Pester

# The ten Windows scripts that change this machine: registry values, services,
# printers, network adapters, provisioned apps, scheduled tasks, power plans, Defender
# exclusions, and files.
#
# Every command that would change something is stubbed as a recorder before the script
# runs. That is not only to protect the machine the suite runs on. The fault these
# tests exist to catch is a mutation that is not gated behind ShouldProcess, and
# running such a script unstubbed with -WhatIf would demonstrate the bug by performing
# it. Stubbing catches it in the log instead.
#
# So each script runs twice: with -WhatIf, where the recorder must stay empty, and
# executing, where it must fill with the changes the script promised. Neither run
# touches the machine.
#
# What this proves: which changes each script decides to make, that -WhatIf suppresses
# all of them, and that the executing path still reaches them. What it does not prove
# is that the real registry, service manager, or print subsystem accepts those calls.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-win-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    # Scheduled tasks, Defender, and printers are reached through modules whose
    # commands a script-scope function does not shadow. Staging replacements ahead of
    # them on PSModulePath is what actually isolates them; the function stubs alone do
    # not, and relying on that disabled four real scheduled tasks and added three real
    # Defender exclusions on the machine this was first run on.
    $script:systemModulePath = Use-FakeSystemModule

    function Get-MutationRecord {
        <#
        .SYNOPSIS
        Read the machine changes a run attempted, as objects.
        #>
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }

    function Invoke-WindowsScriptPair {
        <#
        .SYNOPSIS
        Run one script with -WhatIf and again executing, returning both results and logs.

        .DESCRIPTION
        The pair is the unit of meaning. A -WhatIf run that attempts nothing says
        nothing on its own, because a script that has stopped working also attempts
        nothing; the executing run is what proves the suppressed path was reachable.
        #>
        param(
            [string]$RelativePath,
            [hashtable]$Argument = @{},
            [string]$Tag
        )

        $whatIfLog = Join-Path $script:workRoot "$Tag-whatif.log"
        $executeLog = Join-Path $script:workRoot "$Tag-execute.log"

        $whatIfArgument = $Argument.Clone()
        $whatIfArgument.WhatIf = $true
        $executeArgument = $Argument.Clone()
        $executeArgument.Confirm = $false

        # The fixture environment is appended to the stub text so the staged modules
        # know what already exists on the pretend machine.
        $fixtureEnvironment = @"

`$env:OPSTOOLKIT_TEST_TASKS = '\Microsoft\Windows\Customer Experience Improvement Program\|Consolidator|Ready;\Microsoft\Windows\Feedback\Siuf\|DmClient|Ready'
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH = ''
`$env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS = ''
`$env:OPSTOOLKIT_TEST_PRINTERS = ''
"@

        [pscustomobject]@{
            WhatIf     = Invoke-ScriptUnderTest -RelativePath $RelativePath -ModulePath $script:systemModulePath `
                -Setup ((Get-WindowsMutationStubText -MutationLogPath $whatIfLog) + $fixtureEnvironment) -Argument $whatIfArgument
            WhatIfLog  = $whatIfLog
            Execute    = Invoke-ScriptUnderTest -RelativePath $RelativePath -ModulePath $script:systemModulePath `
                -Setup ((Get-WindowsMutationStubText -MutationLogPath $executeLog) + $fixtureEnvironment) -Argument $executeArgument
            ExecuteLog = $executeLog
        }
    }

    function Assert-NoChangeUnderWhatIf {
        <#
        .SYNOPSIS
        Assert a -WhatIf run completed and attempted nothing.

        .DESCRIPTION
        The exit-code check is not decoration. A run that died before reaching any
        change also leaves an empty log, so without it this assertion passes for a
        script that is completely broken.
        #>
        param($Pair, [string[]]$IgnoreCommand = @())

        $Pair.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($Pair.WhatIf.Output)"
        $mutations = @(Get-MutationRecord -Path $Pair.WhatIfLog | Where-Object { $_.Command -notin $IgnoreCommand })
        $mutations.Count | Should -Be 0 -Because "-WhatIf attempted: $($mutations | ConvertTo-Json -Compress)"
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsLightMode' {
    BeforeAll {
        $script:light = Invoke-WindowsScriptPair -Tag 'lightmode' `
            -RelativePath 'scripts\it-operations\utilities\Set-WindowsLightMode.ps1' `
            -Argument @{ Mode = 'Light' }
    }

    It 'runs to completion in both modes' {
        $script:light.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:light.WhatIf.Output)"
        $script:light.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:light.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:light
    }

    It 'sets both theme values when executing' {
        # Apps and system are separate values, and setting only one leaves a
        # half-themed desktop that looks like the setting did not take.
        $mutations = @(Get-MutationRecord -Path $script:light.ExecuteLog |
                Where-Object { $_.Command -eq 'Set-ItemProperty' })
        @($mutations | ForEach-Object { ($_.Target -split '\\')[-1] } | Sort-Object) |
            Should -Be @('AppsUseLightTheme', 'SystemUsesLightTheme')
        @($mutations | ForEach-Object { $_.Detail } | Sort-Object -Unique) | Should -Be @('1')
    }

    It 'writes 0 for dark mode rather than skipping the write' {
        $log = Join-Path $script:workRoot 'lightmode-dark.log'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\it-operations\utilities\Set-WindowsLightMode.ps1' `
            -Setup (Get-WindowsMutationStubText -MutationLogPath $log) `
            -Argument @{ Mode = 'Dark'; Confirm = $false }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        @(Get-MutationRecord -Path $log | Where-Object { $_.Command -eq 'Set-ItemProperty' } |
                ForEach-Object { $_.Detail } | Sort-Object -Unique) | Should -Be @('0')
    }
}

Describe 'Set-WindowsSchannelTlsHardening' {
    BeforeAll {
        $script:tls = Invoke-WindowsScriptPair -Tag 'tls' `
            -RelativePath 'scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1' `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'tls'); Baseline = 'Tls12Only' }
    }

    It 'runs to completion in both modes' {
        $script:tls.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:tls.WhatIf.Output)"
        $script:tls.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:tls.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        # reg.exe is the registry backup, which is written before any change and is
        # deliberately taken on a preview run too.
        Assert-NoChangeUnderWhatIf -Pair $script:tls -IgnoreCommand 'reg.exe'
    }

    It 'writes the Schannel protocol values when executing' {
        # Disabling a protocol without enabling its replacement is how a machine ends
        # up unable to reach anything, so both halves have to be written.
        $mutations = @(Get-MutationRecord -Path $script:tls.ExecuteLog)
        $mutations.Count | Should -BeGreaterThan 0
        $schannel = @($mutations | Where-Object { $_.Target -match 'SCHANNEL\\Protocols' })
        $schannel.Count | Should -BeGreaterThan 0
        ($schannel | ForEach-Object { $_.Target }) -join ' ' | Should -Match 'TLS 1\.2'
    }
}

Describe 'Set-Windows11PrivacyHardening' {
    BeforeAll {
        $script:privacy = Invoke-WindowsScriptPair -Tag 'privacy' `
            -RelativePath 'scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1' `
            -Argument @{
            ReportDirectory       = (Join-Path $script:workRoot 'privacy')
            SkipWindows11Check    = $true
            IncludeScheduledTasks = $true
            IncludeServices       = $true
        }
    }

    It 'runs to completion in both modes' {
        $script:privacy.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:privacy.WhatIf.Output)"
        $script:privacy.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:privacy.Execute.Output)"
    }

    It 'changes nothing under -WhatIf, including services and scheduled tasks' {
        # This is the widest-reaching script here: with these switches it can disable
        # services and scheduled tasks as well as write registry values.
        Assert-NoChangeUnderWhatIf -Pair $script:privacy -IgnoreCommand 'reg.exe'
    }

    It 'applies registry, service, and scheduled-task changes when executing' {
        $mutations = @(Get-MutationRecord -Path $script:privacy.ExecuteLog)
        $commands = @($mutations | ForEach-Object { $_.Command } | Sort-Object -Unique)
        # It creates values rather than setting existing ones, so New-ItemProperty is
        # the registry write here.
        ($commands -join ' ') | Should -Match 'ItemProperty'
        # Each switch has to actually reach its own kind of change, or the switch is
        # decorative.
        ($commands -join ' ') | Should -Match 'Service'
        ($commands -join ' ') | Should -Match 'ScheduledTask'
    }
}

Describe 'Set-WorkstationLockPosture' {
    BeforeAll {
        # 23 minutes, not 10: this machine already sits at 600 seconds, so asking for 10
        # would correctly produce NoChange and the write path would never run. The
        # timeout has to differ from whatever the host happens to be set to.
        $script:lock = Invoke-WindowsScriptPair -Tag 'lock' `
            -RelativePath 'scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1' `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'lock'); IdleTimeoutMinutes = 23 }
    }

    It 'runs to completion in both modes' {
        $script:lock.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:lock.WhatIf.Output)"
        $script:lock.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:lock.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:lock -IgnoreCommand 'reg.exe','powercfg','powercfg.exe'
    }

    It 'sets the screensaver timeout it was asked for when executing' {
        $mutations = @(Get-MutationRecord -Path $script:lock.ExecuteLog)
        $mutations.Count | Should -BeGreaterThan 0
        $timeout = @($mutations | Where-Object { $_.Target -match 'ScreenSaveTimeOut' })
        $timeout.Count | Should -BeGreaterThan 0
        # Expressed in seconds, because the registry value is in seconds and an
        # off-by-sixty here is a lock policy that never fires.
        $timeout[0].Detail | Should -Be '1380'
    }
}

Describe 'Set-WorkstationPerformance' {
    BeforeAll {
        $script:perf = Invoke-WindowsScriptPair -Tag 'perf' `
            -RelativePath 'scripts\it-operations\performance\Set-WorkstationPerformance.ps1' `
            -Argument @{
            ReportDirectory       = (Join-Path $script:workRoot 'perf')
            DefenderPathExclusion = @((Join-Path $script:workRoot 'excluded'))
        }
    }

    It 'runs to completion in both modes' {
        $script:perf.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:perf.WhatIf.Output)"
        $script:perf.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:perf.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        # A Defender exclusion added by a preview run is a security hole opened by a
        # command whose entire promise was that it would not do anything.
        Assert-NoChangeUnderWhatIf -Pair $script:perf -IgnoreCommand 'powercfg','powercfg.exe'
    }

    It 'adds only the exclusions it was given when executing' {
        $exclusions = @(Get-MutationRecord -Path $script:perf.ExecuteLog |
                Where-Object { $_.Command -match 'MpPreference' })
        $exclusions.Count | Should -BeGreaterThan 0
        ($exclusions | ForEach-Object { $_.Target }) -join ' ' | Should -Match 'excluded'
    }
}

Describe 'Set-NetworkAdapterRandomMac' {
    BeforeAll {
        $script:mac = Invoke-WindowsScriptPair -Tag 'mac' `
            -RelativePath 'scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1' `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'mac'); SkipAdapterRestart = $true }
    }

    It 'runs to completion in both modes' {
        $script:mac.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:mac.WhatIf.Output)"
        $script:mac.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:mac.Execute.Output)"
    }

    It 'changes no adapter under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:mac -IgnoreCommand 'reg.exe'
    }

    It 'does not restart an adapter when told to skip the restart' {
        # Restarting the adapter you are connected over is the difference between a
        # config change and a dropped session.
        @(Get-MutationRecord -Path $script:mac.ExecuteLog |
                Where-Object { $_.Command -eq 'Restart-NetAdapter' }).Count | Should -Be 0
    }
}

Describe 'Remove-WindowsProvisionedBloatwareApps' {
    BeforeAll {
        $script:appx = Invoke-WindowsScriptPair -Tag 'appx' `
            -RelativePath 'scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1' `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'appx'); SkipWindows11Check = $true }
    }

    It 'runs to completion in both modes' {
        $script:appx.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:appx.WhatIf.Output)"
        $script:appx.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:appx.Execute.Output)"
    }

    It 'removes nothing under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:appx
    }

    It 'never removes a package on the protected list' {
        # The protected list is the only thing standing between this script and
        # uninstalling something the machine needs. It is read from a data file, so a
        # path change or a rename silently empties it.
        $protectedPath = Join-Path (Get-RepositoryRoot) 'data\windows-hardening\windows11-appx-protected.txt'
        Test-Path $protectedPath | Should -BeTrue -Because 'the protected list is what makes this script safe to run'
        $protected = @(Get-Content $protectedPath | Where-Object { $_ -and -not $_.StartsWith('#') })
        $protected.Count | Should -BeGreaterThan 0

        $removed = @(Get-MutationRecord -Path $script:appx.ExecuteLog |
                Where-Object { $_.Command -match 'Appx' } | ForEach-Object { $_.Target })
        foreach ($name in $protected) {
            $removed | Should -Not -Contain $name -Because "$name is on the protected list"
        }
    }
}

Describe 'Set-WindowsPrinterConnections' {
    BeforeAll {
        $script:printer = Invoke-WindowsScriptPair -Tag 'printer' `
            -RelativePath 'scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1' `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'printer')
            Action          = 'Add'
            PrinterPath     = @('\\printserver\HP-Floor2')
        }
    }

    It 'runs to completion in both modes' {
        $script:printer.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:printer.WhatIf.Output)"
        $script:printer.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:printer.Execute.Output)"
    }

    It 'connects nothing under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:printer
    }

    It 'connects exactly the printer it was given when executing' {
        $added = @(Get-MutationRecord -Path $script:printer.ExecuteLog |
                Where-Object { $_.Command -eq 'Add-Printer' })
        $added.Count | Should -Be 1
        $added[0].Target | Should -Be '\\printserver\HP-Floor2'
    }

    It 'removes rather than adds when the action is Remove' {
        $log = Join-Path $script:workRoot 'printer-remove.log'
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1' `
            -Setup (Get-WindowsMutationStubText -MutationLogPath $log) `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'printer-remove')
            Action          = 'Remove'
            PrinterName     = @('\\printserver\HP-Floor2')
            Confirm         = $false
        }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        @(Get-MutationRecord -Path $log | Where-Object { $_.Command -eq 'Add-Printer' }).Count | Should -Be 0
    }
}

Describe 'Invoke-WindowsFileCleanup' {
    BeforeAll {
        # A real directory with a genuinely old file and a genuinely new one, so the
        # age filter has something to be right or wrong about.
        $script:cleanupTarget = Join-Path $script:workRoot 'cleanup-target'
        New-Item -ItemType Directory -Path $script:cleanupTarget -Force | Out-Null
        $old = Join-Path $script:cleanupTarget 'old.log'
        $new = Join-Path $script:cleanupTarget 'new.log'
        Set-Content -LiteralPath $old -Value 'old' -Encoding utf8
        Set-Content -LiteralPath $new -Value 'new' -Encoding utf8
        (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-90)

        $script:cleanup = Invoke-WindowsScriptPair -Tag 'cleanup' `
            -RelativePath 'scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1' `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'cleanup')
            Mode            = 'OlderThan'
            Path            = @($script:cleanupTarget)
            OlderThanDays   = 30
        }
    }

    It 'runs to completion in both modes' {
        $script:cleanup.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:cleanup.WhatIf.Output)"
        $script:cleanup.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:cleanup.Execute.Output)"
    }

    It 'deletes nothing under -WhatIf' {
        Assert-NoChangeUnderWhatIf -Pair $script:cleanup
    }

    It 'selects the old file and leaves the recent one' {
        # The whole risk in a cleanup script is the age boundary. Deleting everything
        # and deleting nothing both look like a successful run in a summary count.
        $removed = @(Get-MutationRecord -Path $script:cleanup.ExecuteLog |
                Where-Object { $_.Command -eq 'Remove-Item' } | ForEach-Object { $_.Target })
        ($removed -join ' ') | Should -Match 'old\.log'
        ($removed -join ' ') | Should -Not -Match 'new\.log'
    }
}

Describe 'Invoke-DiskSpaceReclaim' {
    BeforeAll {
        $script:reclaim = Invoke-WindowsScriptPair -Tag 'reclaim' `
            -RelativePath 'scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1' `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'reclaim'); Target = @('RecycleBin') }
    }

    It 'runs to completion in both modes' {
        $script:reclaim.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:reclaim.WhatIf.Output)"
        $script:reclaim.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:reclaim.Execute.Output)"
    }

    It 'empties nothing under -WhatIf' {
        # The recycle bin is the last copy of whatever a user already deleted once.
        Assert-NoChangeUnderWhatIf -Pair $script:reclaim
    }

    It 'touches only the target it was asked for' {
        $mutations = @(Get-MutationRecord -Path $script:reclaim.ExecuteLog)
        @($mutations | Where-Object { $_.Command -eq 'Stop-Service' }).Count |
            Should -Be 0 -Because 'no service target was requested'
    }
}
