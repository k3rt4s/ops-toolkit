#Requires -Modules Pester

# BitLocker enablement on the OS volume and the WDAC audit-mode policy, plus the read-only
# audit-event exporter.
#
# Every command that would change the machine is a recorder: the BitLocker, TrustedPlatformModule,
# SecureBoot and ConfigCI cmdlets come from staged fake modules, and CiTool.exe is a function stub.
# Each changing script runs twice, with -WhatIf where the recorder must stay empty and executing
# where it must fill with the changes the script promised.
#
# The suite is normally not elevated. Both scripts skip their change step without elevation, so the
# assertions on the executing half that need it are skipped, and the plan and state JSON that an
# unelevated run still writes are asserted instead.
#
# What this proves: the order of the BitLocker steps, that a recovery password is never written to a
# report, that a bad key directory changes nothing, and that WDAC deploys only an audit policy. It does
# not prove the real BitLocker, ConfigCI or CiTool accept the calls.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-blwdac-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $script:blScript = 'scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1'
    $script:wdacScript = 'scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1'
    $script:eventScript = 'scripts\it-operations\windows-hardening\Export-WdacAuditEvent.ps1'

    # A unique, recognisable fake recovery password. If it appears in any report or console
    # output the script leaked it.
    $script:fakePassword = '918273-645546-372819-182736-455463-728190-918273-645546'

    # The tests run the script with SystemDrive pointed at a drive that does not exist, so a
    # recovery key directory under the temp folder (normally on C:) is "off the OS volume".
    $script:blGoodEnv = @"
`$env:SystemDrive = 'Q:'
`$env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyDecrypted","ProtectionStatus":"Off","EncryptionMethod":"None","KeyProtector":[]}]'
`$env:OPSTOOLKIT_TEST_TPM_PRESENT = '1'
`$env:OPSTOOLKIT_TEST_TPM_READY = '1'
`$env:OPSTOOLKIT_TEST_SECUREBOOT = 'true'
`$env:OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD = '$($script:fakePassword)'
`$env:OPSTOOLKIT_TEST_BL_PROTECTORID = '{AAAAAAAA-0000-4000-8000-000000000001}'
"@

    $script:uncShadow = @'
function Test-Path {
    param($Path, $LiteralPath, $PathType)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    if ($p.StartsWith('\\')) { return $true }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Resolve-Path {
    param($Path, $LiteralPath)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    if ($p.StartsWith('\\')) { return [pscustomobject]@{ Path = $p; ProviderPath = $p } }
    Microsoft.PowerShell.Management\Resolve-Path @PSBoundParameters
}
'@

    # A thrown message is wrapped and decorated by the host, so flatten it before matching a phrase.
    function Get-FlatText {
        param([string]$Text)
        $plain = $Text -replace ([char]27 + '\[[0-9;]*m'), ''
        $plain -replace '\s*\|\s*', ' ' -replace '\s+', ' '
    }

    function New-WorkDirectory {
        param([string]$Name)
        $path = Join-Path $script:workRoot $Name
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $path
    }

    function Invoke-Pair {
        param([string]$RelativePath, [hashtable]$Argument, [string]$Tag, [string]$FixtureEnvironment, [string]$ExtraSetup = '')
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $RelativePath -Argument $Argument -Tag $Tag -FixtureEnvironment ($FixtureEnvironment + "`n") -ExtraSetup $ExtraSetup
    }

    function Get-StateItem {
        param([string]$ReportDirectory, [string]$Mode = 'apply', [string]$Setting)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter "*-$Mode-state-*.json" -File | Sort-Object LastWriteTime | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Setting -eq $Setting }
    }

    function Get-AllReportText {
        param([string[]]$Directory)
        $text = foreach ($d in $Directory) {
            foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue)) {
                # The key file itself legitimately holds the password; reports must not.
                if ($f.Name -like 'BitLocker-Recovery-*') { continue }
                Get-Content -LiteralPath $f.FullName -Raw
            }
        }
        $text -join "`n"
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Enable-BitLockerOsVolume' {
    BeforeAll {
        $script:blKeys = New-WorkDirectory 'bl-keys'
        $script:blReports = New-WorkDirectory 'bl-reports'
        $script:bl = Invoke-Pair -Tag 'bl' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $script:blReports; RecoveryKeyDirectory = $script:blKeys } `
            -FixtureEnvironment $script:blGoodEnv
    }

    It 'runs to completion in both modes' {
        $script:bl.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:bl.WhatIf.Output)"
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'an unelevated live run fails by design; see the next two tests'
            return
        }
        $script:bl.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:bl.Execute.Output)"
    }

    It 'fails a live run, with the reason, instead of exiting 0 when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        $script:bl.Execute.ExitCode | Should -Not -Be 0
        $script:bl.Execute.Output | Should -Match 'session is not elevated'
        (Get-StateItem -ReportDirectory $script:blReports -Mode 'apply' -Setting 'Elevated').Result | Should -Be 'Failed: session is not elevated'
        @(Get-OpsMutationRecord -Path $script:bl.ExecuteLog | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
    }

    It 'only skips the elevation precondition, and exits 0, under -WhatIf when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        $script:bl.WhatIf.ExitCode | Should -Be 0
        # The summary's own items, not the state file: both runs can share one timestamped file name.
        (@($script:bl.WhatIf.Summary.Items) | Where-Object Setting -eq 'Elevated').Result | Should -Be 'Skipped: requires elevation'
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:bl
    }

    It 'plans every precondition and the ordered enable' {
        $plan = @(Get-Content -LiteralPath $script:bl.WhatIf.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        ($plan | Where-Object Category -eq 'Precondition' | ForEach-Object { $_.Setting }) |
            Should -Be @('RecoveryKeyDirectory', 'KeyDirectoryWritable', 'Elevated', 'Tpm', 'SecureBoot', 'OsVolumeNotProtected')
        $enable = @($plan | Where-Object Category -eq 'EnableOsVolume')
        $enable.Count | Should -Be 1
        $enable[0].Setting | Should -Be 'Q:'
        $enable[0].Action | Should -Match 'recovery password protector'
        $enable[0].Action | Should -Match 'XtsAes256'
        $enable[0].RequiresReboot | Should -BeTrue
    }

    It 'meets the TPM, Secure Boot and volume preconditions from the fixture' {
        (Get-StateItem -ReportDirectory $script:blReports -Mode 'apply' -Setting 'OsVolumeNotProtected').Result | Should -Be 'Met'
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'Get-Tpm and Confirm-SecureBootUEFI are read only when elevated'
            return
        }
        foreach ($name in 'Tpm', 'SecureBoot') {
            (Get-StateItem -ReportDirectory $script:blReports -Mode 'apply' -Setting $name).Result | Should -Be 'Met'
        }
    }

    It 'reports the TPM and Secure Boot as unread, not failed or met, when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        # The fixture TPM and Secure Boot cmdlets would answer unelevated; the script must not ask them.
        foreach ($name in 'Tpm', 'SecureBoot') {
            (Get-StateItem -ReportDirectory $script:blReports -Mode 'apply' -Setting $name).Result | Should -Be 'Skipped: requires elevation (not read)'
        }
    }

    It 'adds the recovery protector before enabling BitLocker, with the key file written first' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $m = @(Get-OpsMutationRecord -Path $script:bl.ExecuteLog)
        $names = @($m | ForEach-Object { $_.Command })
        $add = [array]::IndexOf($names, 'Add-BitLockerKeyProtector')
        $enable = [array]::IndexOf($names, 'Enable-BitLocker')
        $add | Should -BeGreaterOrEqual 0
        $enable | Should -BeGreaterThan $add
        $m[$add].Detail | Should -Be 'RecoveryPassword'
        $m[$enable].Detail | Should -Match 'XtsAes256;tpm=True;usedspace=True'

        $keyFile = @(Get-ChildItem -LiteralPath $script:blKeys -Filter 'BitLocker-Recovery-*-AAAAAAAA-0000-4000-8000-000000000001.txt')
        $keyFile.Count | Should -Be 1
        (Get-Content -LiteralPath $keyFile[0].FullName -Raw) | Should -Match ([regex]::Escape($script:fakePassword))
        $script:bl.Execute.Summary.RebootRequired | Should -BeTrue
        $script:bl.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
    }

    It 'skips the change step when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        # The live-run write probe is deleted through the recorded Remove-Item; no BitLocker call may appear.
        @(Get-OpsMutationRecord -Path $script:bl.ExecuteLog | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $script:blReports -Mode 'apply' -Setting 'Q:').Result | Should -Be 'Skipped: requires elevation'
    }

    It 'never writes the recovery password to a report or the console' {
        $text = Get-AllReportText -Directory @($script:blReports)
        $text | Should -Not -Match ([regex]::Escape($script:fakePassword))
        $script:bl.Execute.Output | Should -Not -Match ([regex]::Escape($script:fakePassword))
        $script:bl.WhatIf.Output | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }
}

Describe 'Enable-BitLockerOsVolume refusals' {
    It 'refuses a recovery key directory on the OS volume and records nothing, even executing' {
        $keys = New-WorkDirectory 'bl-sysdrive-keys'
        $reports = Join-Path $script:workRoot 'bl-sysdrive-reports'
        $drive = [System.IO.Path]::GetPathRoot($keys).TrimEnd('\')
        $env = $script:blGoodEnv -replace "SystemDrive = 'Q:'", "SystemDrive = '$drive'"
        $pair = Invoke-Pair -Tag 'bl-sysdrive' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $pair.WhatIf.ExitCode | Should -Not -Be 0
        $pair.Execute.ExitCode | Should -Not -Be 0
        $pair.Execute.Output | Should -Match 'operating-system volume'
        @(Get-OpsMutationRecord -Path $pair.WhatIfLog).Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'refuses a recovery key directory that does not exist and records nothing' {
        $reports = Join-Path $script:workRoot 'bl-missing-reports'
        $pair = Invoke-Pair -Tag 'bl-missing' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = (Join-Path $script:workRoot 'does-not-exist') } `
            -FixtureEnvironment $script:blGoodEnv
        $pair.Execute.ExitCode | Should -Not -Be 0
        $pair.Execute.Output | Should -Match 'does not exist'
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
    }

    # UNC paths cannot be made real in a test, so Test-Path and Resolve-Path answer for them and pass
    # everything else to the real cmdlets. Resolve-Path on a reachable share returns the UNC path as ProviderPath.
    It 'refuses a UNC path that points back at this computer (<Unc>) and records nothing' -ForEach @(
        @{ Unc = '\\localhost\c$\keys' }
        @{ Unc = '\\127.0.0.1\c$\keys' }
        @{ Unc = "\\$($env:COMPUTERNAME.ToLowerInvariant())\c$\keys" }
        @{ Unc = '\\.\C:\keys' }
        @{ Unc = '\\?\C:\keys' }
    ) {
        $reports = Join-Path $script:workRoot "bl-unc-$([guid]::NewGuid().ToString('N'))"
        $extra = $script:uncShadow
        $pair = Invoke-Pair -Tag 'bl-unc-local' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $Unc } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $extra
        $pair.WhatIf.ExitCode | Should -Not -Be 0
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-FlatText $pair.Execute.Output) | Should -Match 'Refusing: RecoveryKeyDirectory .* is on this computer'
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'accepts a UNC path on another host' {
        $reports = New-WorkDirectory 'bl-unc-other-reports'
        $pair = Invoke-Pair -Tag 'bl-unc-other' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = '\\fileserver01\recovery\keys' } `
            -FixtureEnvironment $script:blGoodEnv -ExtraSetup $script:uncShadow
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $pair.WhatIf.Summary.RecoveryKeyDirectory | Should -Be '\\fileserver01\recovery\keys'
    }

    It 'refuses a substituted drive whose target is on the operating-system volume' {
        $keys = New-WorkDirectory 'bl-subst-keys'
        $reports = Join-Path $script:workRoot 'bl-subst-reports'
        $drive = [System.IO.Path]::GetPathRoot($keys).TrimEnd('\')
        # subst with no arguments lists 'D:\: => C:\keys'. The real temp drive is made a SUBST of the pretend system drive Q:.
        $extra = "function subst { '$drive\: => Q:\keys' }"
        $pair = Invoke-Pair -Tag 'bl-subst' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $extra
        $pair.WhatIf.ExitCode | Should -Not -Be 0
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-FlatText $pair.Execute.Output) | Should -Match 'substituted for .Q:\\keys.*operating-system volume'
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'refuses a mapped drive that points at this computer' {
        $keys = New-WorkDirectory 'bl-mapped-keys'
        $reports = Join-Path $script:workRoot 'bl-mapped-reports'
        $extra = "function Get-CimInstance { param(`$ClassName, `$Filter, `$ErrorAction) [pscustomobject]@{ DeviceID = 'X:'; DriveType = 4; ProviderName = '\\localhost\c`$' } }"
        $pair = Invoke-Pair -Tag 'bl-mapped' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $extra
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-FlatText $pair.Execute.Output) | Should -Match 'mapped to .\\\\localhost\\c\$.*is on this computer'
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'refuses a drive it cannot look up instead of passing it' -ForEach @(
        @{ Name = 'garbled subst output'; Extra = "function subst { 'not a subst line' }" }
        @{ Name = 'a failing drive query'; Extra = "function Get-CimInstance { param(`$ClassName, `$Filter, `$ErrorAction) throw 'cim down' }" }
    ) {
        $keys = New-WorkDirectory 'bl-unknown-keys'
        $reports = Join-Path $script:workRoot "bl-unknown-$([guid]::NewGuid().ToString('N'))"
        $pair = Invoke-Pair -Tag 'bl-unknown' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $Extra
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-FlatText $pair.Execute.Output) | Should -Match 'cannot be verified as off the operating-system volume'
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'accepts a plain local drive that is neither substituted nor a network drive' {
        $keys = New-WorkDirectory 'bl-plain-keys'
        $reports = New-WorkDirectory 'bl-plain-reports'
        $drive = [System.IO.Path]::GetPathRoot($keys).TrimEnd('\')
        # Another letter is substituted and this one is a fixed disk (DriveType 3); neither touches the key directory.
        $extra = "function subst { 'Y:\: => Z:\other' }`n" +
            "function Get-CimInstance { param(`$ClassName, `$Filter, `$ErrorAction) [pscustomobject]@{ DeviceID = '$drive'; DriveType = 3; ProviderName = `$null } }"
        $pair = Invoke-Pair -Tag 'bl-plain' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $extra
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $pair.WhatIf.Summary.RecoveryKeyDirectory | Should -Be $keys
    }

    It 'stops before any change when the TPM is not ready' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'the TPM is read only when elevated'
            return
        }
        $keys = New-WorkDirectory 'bl-notpm-keys'
        $reports = New-WorkDirectory 'bl-notpm-reports'
        $env = $script:blGoodEnv -replace "TPM_READY = '1'", "TPM_READY = '0'"
        $pair = Invoke-Pair -Tag 'bl-notpm' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $pair.WhatIf.ExitCode | Should -Be 0
        $pair.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -match 'BitLocker' }).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'Tpm').Result | Should -Match '^Failed: TPM is not present and ready'
    }

    It 'treats an unreadable Secure Boot state as a stop with the reason, not a pass' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'Secure Boot is read only when elevated'
            return
        }
        $keys = New-WorkDirectory 'bl-sb-keys'
        $reports = New-WorkDirectory 'bl-sb-reports'
        $env = $script:blGoodEnv -replace "SECUREBOOT = 'true'", "SECUREBOOT = 'error'"
        $pair = Invoke-Pair -Tag 'bl-sb' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $pair.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -match 'BitLocker' }).Count | Should -Be 0
        $result = (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'SecureBoot').Result
        $result | Should -Match '^Failed: Secure Boot state could not be read'
    }

    It 'treats a Secure Boot state of off as a stop' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'Secure Boot is read only when elevated'
            return
        }
        $keys = New-WorkDirectory 'bl-sboff-keys'
        $reports = New-WorkDirectory 'bl-sboff-reports'
        $env = $script:blGoodEnv -replace "SECUREBOOT = 'true'", "SECUREBOOT = 'false'"
        $pair = Invoke-Pair -Tag 'bl-sboff' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'SecureBoot').Result | Should -Match '^Failed: Secure Boot is not enabled'
    }

    It 'treats an unreadable OS volume as a stop, not a pass' {
        $keys = New-WorkDirectory 'bl-unread-keys'
        $reports = New-WorkDirectory 'bl-unread-reports'
        $env = $script:blGoodEnv + "`n`$env:OPSTOOLKIT_TEST_BL_READERROR = '1'"
        $pair = Invoke-Pair -Tag 'bl-unread' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $result = (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'OsVolumeNotProtected').Result
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -match 'BitLocker' }).Count | Should -Be 0
        if (-not $script:isElevated) {
            # Unelevated, the failed read is the elevation gap, so it is unread rather than a stop.
            $result | Should -Be 'Skipped: requires elevation (not read)'
            return
        }
        $pair.Execute.ExitCode | Should -Not -Be 0
        $result | Should -Match '^Failed: OS volume state could not be read'
    }
}

Describe 'Enable-BitLockerOsVolume already protected' {
    BeforeAll {
        $keys = New-WorkDirectory 'bl-done-keys'
        $script:doneReports = New-WorkDirectory 'bl-done-reports'
        # No TPM in the fixture on purpose: an already-protected volume is NoChange for the whole run.
        $env = @"
`$env:SystemDrive = 'Q:'
`$env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyEncrypted","ProtectionStatus":"On","EncryptionMethod":"XtsAes256","KeyProtector":[{"KeyProtectorType":"Tpm","KeyProtectorId":"{BBBBBBBB-0000-4000-8000-000000000002}"}]}]'
"@
        $script:done = Invoke-Pair -Tag 'bl-done' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $script:doneReports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
    }

    It 'exits 0 in both modes and records nothing' {
        $script:done.WhatIf.ExitCode | Should -Be 0 -Because $script:done.WhatIf.Output
        $script:done.Execute.ExitCode | Should -Be 0 -Because $script:done.Execute.Output
        @(Get-OpsMutationRecord -Path $script:done.ExecuteLog).Count | Should -Be 0
    }

    It 'reports the enable step as NoChange' {
        (Get-StateItem -ReportDirectory $script:doneReports -Mode 'apply' -Setting 'Q:').Result | Should -Be 'NoChange'
        $script:done.Execute.Summary.NoChangeCount | Should -BeGreaterThan 0
        $script:done.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
    }

    It 'treats a decrypted volume with a TPM protector (enable pending restart) as done, adding no second protector' {
        $keys = New-WorkDirectory 'bl-pending-keys'
        $reports = New-WorkDirectory 'bl-pending-reports'
        $env = $script:blGoodEnv -replace '"KeyProtector":\[\]', '"KeyProtector":[{"KeyProtectorType":"Tpm","KeyProtectorId":"{CCCCCCCC-0000-4000-8000-000000000003}"},{"KeyProtectorType":"RecoveryPassword","KeyProtectorId":"{DDDDDDDD-0000-4000-8000-000000000004}"}]'
        $pair = Invoke-Pair -Tag 'bl-pending' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $env
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        $enable = Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'Q:'
        $enable.Result | Should -Be 'NoChange'
        $enable.CurrentValue | Should -Match 'enable pending restart'
    }
}

Describe 'Enable-BitLockerOsVolume key file failures' {
    It 'removes the recovery protector and never enables BitLocker when the key file cannot be written' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $keys = New-WorkDirectory 'bl-nowrite-keys'
        $reports = New-WorkDirectory 'bl-nowrite-reports'
        $stub = @'
function Set-Content {
    [CmdletBinding()]
    param($Path, $LiteralPath, $Value, $Encoding, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)
    if ("$LiteralPath$Path" -like '*BitLocker-Recovery-*') { throw 'Access to the path is denied (fixture).' }
    $forward = @{ Value = $Value }
    if ($LiteralPath) { $forward.LiteralPath = $LiteralPath } else { $forward.Path = $Path }
    if ($Encoding) { $forward.Encoding = $Encoding }
    Microsoft.PowerShell.Management\Set-Content @forward -WhatIf:$false
}
'@
        $pair = Invoke-Pair -Tag 'bl-nowrite' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $stub
        $pair.Execute.ExitCode | Should -Not -Be 0
        $names = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | ForEach-Object { $_.Command })
        $names | Should -Contain 'Add-BitLockerKeyProtector'
        $names | Should -Contain 'Remove-BitLockerKeyProtector'
        $names | Should -Not -Contain 'Enable-BitLocker'
        (Get-AllReportText -Directory @($reports)) | Should -Not -Match ([regex]::Escape($script:fakePassword))
        $pair.Execute.Output | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }

    It 'removes the recovery protector and never enables BitLocker when the read-back lacks the password' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $keys = New-WorkDirectory 'bl-badread-keys'
        $reports = New-WorkDirectory 'bl-badread-reports'
        $stub = @'
function Get-Content {
    [CmdletBinding()]
    param($Path, $LiteralPath, [switch]$Raw)
    if ("$LiteralPath$Path" -like '*BitLocker-Recovery-*') { return 'truncated' }
    $forward = @{}
    if ($LiteralPath) { $forward.LiteralPath = $LiteralPath } else { $forward.Path = $Path }
    if ($Raw) { $forward.Raw = $true }
    Microsoft.PowerShell.Management\Get-Content @forward
}
'@
        $pair = Invoke-Pair -Tag 'bl-badread' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; RecoveryKeyDirectory = $keys } -FixtureEnvironment $script:blGoodEnv -ExtraSetup $stub
        $pair.Execute.ExitCode | Should -Not -Be 0
        $names = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | ForEach-Object { $_.Command })
        $names | Should -Contain 'Remove-BitLockerKeyProtector'
        $names | Should -Not -Contain 'Enable-BitLocker'
    }
}

Describe 'Enable-BitLockerOsVolume rollback' {
    BeforeAll {
        $script:blRbReports = New-WorkDirectory 'bl-rb-reports'
        [pscustomobject]@{
            Timestamp = '20260101_000000'; ComputerName = 'TESTPC'; MountPoint = 'Q:'
            ProtectorId = '{AAAAAAAA-0000-4000-8000-000000000001}'; KeyFilePath = 'E:\keys\BitLocker-Recovery-TESTPC-x.txt'
            ScriptEnabledBitLocker = $true; EncryptionMethod = 'XtsAes256'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:blRbReports 'bitlocker-enable-rollback-20260101_000000.json') -Encoding utf8
        $script:blRb = Invoke-Pair -Tag 'bl-rb' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $script:blRbReports; Rollback = $true } -FixtureEnvironment $script:blGoodEnv
    }

    It 'previews the decryption without recording a change, and the second run still finds the real rollback file' {
        # The -WhatIf run writes a rollback-plan file first; the executing run must not pick that.
        $script:blRb.WhatIf.ExitCode | Should -Be 0 -Because $script:blRb.WhatIf.Output
        $script:blRb.Execute.ExitCode | Should -Be 0 -Because $script:blRb.Execute.Output
        Assert-OpsNoChangeUnderWhatIf -Pair $script:blRb
        $plan = @(Get-Content -LiteralPath $script:blRb.WhatIf.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        $disable = @($plan | Where-Object Category -eq 'DisableOsVolume')
        $disable.Count | Should -Be 1
        $disable[0].Setting | Should -Be 'Q:'
        $disable[0].Action | Should -Match 'takes hours'
    }

    It 'disables BitLocker on the recorded volume when executing' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $m = @(Get-OpsMutationRecord -Path $script:blRb.ExecuteLog | Where-Object { $_.Command -eq 'Disable-BitLocker' })
        $m.Count | Should -Be 1
        $m[0].Target | Should -Be 'Q:'
    }

    It 'refuses to disable when the rollback file does not show this script enabled it' {
        $reports = New-WorkDirectory 'bl-rb2-reports'
        [pscustomobject]@{ MountPoint = 'Q:'; ScriptEnabledBitLocker = $false } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $reports 'bitlocker-enable-rollback-20260101_000000.json') -Encoding utf8
        $pair = Invoke-Pair -Tag 'bl-rb2' -RelativePath $script:blScript `
            -Argument @{ ReportDirectory = $reports; Rollback = $true } -FixtureEnvironment $script:blGoodEnv
        $pair.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WdacAuditPolicy' {
    BeforeAll {
        $script:exampleDir = New-WorkDirectory 'wdac-examples'
        $exampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.3.0</VersionEx>
  <PolicyID>{E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A}</PolicyID>
  <BasePolicyID>{E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
</SiPolicy>
'@
        # The enforced example has no audit rule; the script must force it on.
        $exampleXml | Set-Content -LiteralPath (Join-Path $script:exampleDir 'AllowMicrosoft.xml') -Encoding utf8
        $exampleXml.Replace('<Rule><Option>Enabled:UMCI</Option></Rule>', '<Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule>') |
            Set-Content -LiteralPath (Join-Path $script:exampleDir 'DefaultWindows_Audit.xml') -Encoding utf8

        $script:ciStub = @'
function CiTool.exe {
    $a = $args -join ' '
    if ($a -like '--list-policies*') { $env:OPSTOOLKIT_TEST_CITOOL_POLICIES; return }
    Write-OpsTestMutation -Command 'CiTool.exe' -Target $a -Detail ''
    '{"OperationResult":0}'
}
'@
        $script:systemPolicy = '{"PolicyID":"5951a96a-e0b5-4d3d-8fb8-3e5b61030784","BasePolicyID":"5951a96a-e0b5-4d3d-8fb8-3e5b61030784","FriendlyName":"Microsoft Windows Driver Policy","Version":2814749767106560,"VersionString":"10.0.0.0","IsSystemPolicy":true,"IsSignedPolicy":true,"IsOnDisk":true,"IsEnforced":true,"IsAuthorized":true}'
        $script:wdacEnv = @"
`$env:OPSTOOLKIT_TEST_CITOOL_POLICIES = '{"Policies":[$($script:systemPolicy)],"OperationResult":0}'
"@
        $script:wdacReports = Join-Path $script:workRoot 'wdac-reports'
        $script:wdac = Invoke-Pair -Tag 'wdac' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $script:wdacReports; ExamplePolicyDirectory = $script:exampleDir } `
            -FixtureEnvironment $script:wdacEnv -ExtraSetup $script:ciStub
    }

    It 'runs to completion in both modes' {
        $script:wdac.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:wdac.WhatIf.Output)"
        $script:wdac.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:wdac.Execute.Output)"
    }

    It 'deploys nothing under -WhatIf (authoring the policy files is plan work and is allowed)' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:wdac -IgnoreCommand 'Set-CIPolicyIdInfo', 'Set-RuleOption', 'ConvertFrom-CIPolicy'
        @(Get-OpsMutationRecord -Path $script:wdac.WhatIfLog | Where-Object { $_.Command -eq 'CiTool.exe' }).Count | Should -Be 0
    }

    It 'builds an audit-mode policy with a new ID and the toolkit name, even under -WhatIf' {
        $summary = $script:wdac.WhatIf.Summary
        Test-Path -LiteralPath $summary.PolicyBinaryPath | Should -BeTrue
        $xml = [xml](Get-Content -LiteralPath $summary.PolicyXmlPath -Raw)
        $summary.PolicyId | Should -Not -Be '{E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A}'
        # Both runs can land in the same second and share one file name; the later run owns it then.
        $owner = if ($script:wdac.Execute.Summary.PolicyXmlPath -eq $summary.PolicyXmlPath) { $script:wdac.Execute.Summary } else { $summary }
        $xml.SiPolicy.PolicyID | Should -Be $owner.PolicyId
        (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Contain 'Enabled:Audit Mode'
        $names = @(Get-OpsMutationRecord -Path $script:wdac.WhatIfLog | Where-Object { $_.Command -eq 'Set-CIPolicyIdInfo' })
        $names[0].Detail | Should -Match 'name=ops-toolkit WDAC audit;reset=True'
        $plan = @(Get-Content -LiteralPath $summary.PlanJsonPath -Raw | ConvertFrom-Json)
        $deploy = @($plan | Where-Object Category -eq 'DeployAuditPolicy')
        $deploy.Count | Should -Be 1
        $deploy[0].Action | Should -Match '--update-policy'
        $deploy[0].Action | Should -Match ([regex]::Escape($owner.PolicyBinaryPath))
    }

    It 'forces Audit Mode on when the base example is an enforced policy' {
        $reports = Join-Path $script:workRoot 'wdac-allowms-reports'
        $pair = Invoke-Pair -Tag 'wdac-allowms' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $reports; ExamplePolicyDirectory = $script:exampleDir; BasePolicy = 'AllowMicrosoft' } `
            -FixtureEnvironment $script:wdacEnv -ExtraSetup $script:ciStub
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $xml = [xml](Get-Content -LiteralPath $pair.WhatIf.Summary.PolicyXmlPath -Raw)
        (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Contain 'Enabled:Audit Mode'
        $opt = @(Get-OpsMutationRecord -Path $pair.WhatIfLog | Where-Object { $_.Command -eq 'Set-RuleOption' })
        $opt[0].Detail | Should -Match 'option=3'
    }

    It 'forces the unsigned-policy option on when the base example lacks it, since the policy is deployed unsigned' {
        $dir = New-WorkDirectory 'wdac-unsigned-added-examples'
        (Get-Content -LiteralPath (Join-Path $script:exampleDir 'DefaultWindows_Audit.xml') -Raw).Replace('<Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>', '') |
            Set-Content -LiteralPath (Join-Path $dir 'DefaultWindows_Audit.xml') -Encoding utf8
        $reports = Join-Path $script:workRoot 'wdac-unsigned-added-reports'
        $pair = Invoke-Pair -Tag 'wdac-unsigned-added' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $reports; ExamplePolicyDirectory = $dir } `
            -FixtureEnvironment $script:wdacEnv -ExtraSetup $script:ciStub
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $xml = [xml](Get-Content -LiteralPath $pair.WhatIf.Summary.PolicyXmlPath -Raw)
        (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Contain 'Enabled:Unsigned System Integrity Policy'
        $opt = @(Get-OpsMutationRecord -Path $pair.WhatIfLog | Where-Object { $_.Command -eq 'Set-RuleOption' })
        @($opt | Where-Object { $_.Detail -match 'option=6' }).Count | Should -Be 1
    }

    It 'still refuses when the unsigned-policy option is not present after Set-RuleOption, since the policy is deployed unsigned' {
        $dir = New-WorkDirectory 'wdac-signed-examples'
        (Get-Content -LiteralPath (Join-Path $script:exampleDir 'DefaultWindows_Audit.xml') -Raw).Replace('<Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>', '') |
            Set-Content -LiteralPath (Join-Path $dir 'DefaultWindows_Audit.xml') -Encoding utf8
        $reports = Join-Path $script:workRoot 'wdac-signed-reports'
        # A Set-RuleOption that silently does not add option 6 (the real cmdlet could fail to) must still be caught by the check.
        $ignoreOption6 = "`n`$env:OPSTOOLKIT_TEST_CI_IGNORE_OPTION = '6'"
        $pair = Invoke-Pair -Tag 'wdac-signed' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $reports; ExamplePolicyDirectory = $dir } `
            -FixtureEnvironment ($script:wdacEnv + $ignoreOption6) -ExtraSetup $script:ciStub
        # A -WhatIf run only previews and exits 0; the refusal is in its state report.
        $pair.Execute.ExitCode | Should -Not -Be 0
        (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'BasePolicyFile').Result |
            Should -Match '^Failed: building the audit policy failed: .*Unsigned System Integrity Policy'
        $pair.Execute.Summary.PolicyBinaryPath | Should -BeNullOrEmpty
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' }).Count | Should -Be 0
    }

    It 'has no enforce switch' {
        $cmd = Get-Command (Get-RepositoryScriptPath -RelativePath $script:wdacScript)
        @($cmd.Parameters.Keys | Where-Object { $_ -match 'enforc' }).Count | Should -Be 0
    }

    It 'reports the enforced policies and Smart App Control without changing them' {
        $plan = @(Get-Content -LiteralPath $script:wdac.WhatIf.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        ($plan | Where-Object Setting -eq 'EnforcedPolicies').CurrentValue | Should -Match 'total=1;enforced=1;enforced non-system=0'
        ($plan | Where-Object Setting -eq 'SmartAppControl').Action | Should -Match '^No change'
    }

    It 'deploys with CiTool --update-policy and the .cip path when executing' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $ci = @(Get-OpsMutationRecord -Path $script:wdac.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' })
        $ci.Count | Should -Be 1
        $ci[0].Target | Should -Be ('--update-policy ' + $script:wdac.Execute.Summary.PolicyBinaryPath + ' --json')
        $rollback = Get-Content -LiteralPath $script:wdac.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        $rollback.PolicyId | Should -Be $script:wdac.Execute.Summary.PolicyId
    }

    It 'skips the deployment when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        @(Get-OpsMutationRecord -Path $script:wdac.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' }).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $script:wdacReports -Mode 'apply' -Setting 'ops-toolkit WDAC audit').Result | Should -Be 'Skipped: requires elevation'
    }

    It 'refuses when a policy with the same name is already active' {
        $reports = Join-Path $script:workRoot 'wdac-dup-reports'
        $dup = '{"PolicyID":"11111111-2222-4333-8444-555555555555","BasePolicyID":"11111111-2222-4333-8444-555555555555","FriendlyName":"ops-toolkit WDAC audit","IsSystemPolicy":false,"IsEnforced":false}'
        $env = "`$env:OPSTOOLKIT_TEST_CITOOL_POLICIES = '{`"Policies`":[$dup],`"OperationResult`":0}'"
        $pair = Invoke-Pair -Tag 'wdac-dup' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $reports; ExamplePolicyDirectory = $script:exampleDir } `
            -FixtureEnvironment $env -ExtraSetup $script:ciStub
        $pair.WhatIf.ExitCode | Should -Be 0
        $pair.Execute.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' }).Count | Should -Be 0
        $r = (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'NoActiveAuditPolicy').Result
        $r | Should -Match 'already active'
        $r | Should -Match '-Rollback'
    }

    It 'does not treat an unreadable policy list as a pass' {
        $reports = Join-Path $script:workRoot 'wdac-unread-reports'
        $env = "`$env:OPSTOOLKIT_TEST_CITOOL_POLICIES = '{`"OperationResult`":-2147024891}'"
        $pair = Invoke-Pair -Tag 'wdac-unread' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $reports; ExamplePolicyDirectory = $script:exampleDir } `
            -FixtureEnvironment $env -ExtraSetup $script:ciStub
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' }).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $reports -Mode 'apply' -Setting 'NoActiveAuditPolicy').Result | Should -Match '^(Skipped: requires elevation|Failed: active policies could not be read)'
    }
}

Describe 'Set-WdacAuditPolicy rollback' {
    BeforeAll {
        $script:plantedId = '{22222222-3333-4444-8555-666666666666}'
        $script:wdacRbReports = New-WorkDirectory 'wdac-rb-reports'
        [pscustomobject]@{
            Timestamp = '20260101_000000'; PolicyName = 'ops-toolkit WDAC audit'; PolicyId = $script:plantedId
            CipPath = 'x.cip'; XmlPath = 'x.xml'; BasePolicy = 'DefaultWindows'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:wdacRbReports 'wdac-audit-rollback-20260101_000000.json') -Encoding utf8
        $script:ciStub2 = @'
function CiTool.exe {
    $a = $args -join ' '
    if ($a -like '--list-policies*') { $env:OPSTOOLKIT_TEST_CITOOL_POLICIES; return }
    Write-OpsTestMutation -Command 'CiTool.exe' -Target $a -Detail ''
    '{"OperationResult":0}'
}
'@
    }

    It 'removes the planted policy ID when executing, and previews it under -WhatIf' {
        $env = "`$env:OPSTOOLKIT_TEST_CITOOL_POLICIES = '{`"Policies`":[{`"PolicyID`":`"22222222-3333-4444-8555-666666666666`",`"FriendlyName`":`"ops-toolkit WDAC audit`",`"IsEnforced`":false,`"IsSystemPolicy`":false}],`"OperationResult`":0}'"
        $pair = Invoke-Pair -Tag 'wdac-rb' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $script:wdacRbReports; Rollback = $true } -FixtureEnvironment $env -ExtraSetup $script:ciStub2
        $pair.WhatIf.ExitCode | Should -Be 0 -Because $pair.WhatIf.Output
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        Assert-OpsNoChangeUnderWhatIf -Pair $pair
        $plan = @(Get-Content -LiteralPath $pair.WhatIf.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        $remove = @($plan | Where-Object Category -eq 'RemoveAuditPolicy')
        $remove.Count | Should -Be 1
        $remove[0].Setting | Should -Be $script:plantedId
        $remove[0].CurrentValue | Should -Be 'active'
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session to record the --remove-policy call'
            return
        }
        $ci = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'CiTool.exe' })
        $ci.Count | Should -Be 1
        $ci[0].Target | Should -Be "--remove-policy $($script:plantedId) --json"
    }

    It 'is NoChange when the planted policy is no longer active' {
        $env = "`$env:OPSTOOLKIT_TEST_CITOOL_POLICIES = '{`"Policies`":[],`"OperationResult`":0}'"
        $pair = Invoke-Pair -Tag 'wdac-rb-gone' -RelativePath $script:wdacScript `
            -Argument @{ ReportDirectory = $script:wdacRbReports; Rollback = $true } -FixtureEnvironment $env -ExtraSetup $script:ciStub2
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        $pair.Execute.Summary.NoChangeCount | Should -Be 1
    }
}

Describe 'Export-WdacAuditEvent' {
    BeforeAll {
        $script:eventSetup = @'
function New-FakeCiEvent {
    param([int]$Id, [datetime]$Time, [hashtable]$Data)
    $inner = ($Data.GetEnumerator() | ForEach-Object { '<Data Name="' + $_.Key + '">' + $_.Value + '</Data>' }) -join ''
    $xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>' + $Id + '</EventID></System><EventData>' + $inner + '</EventData></Event>'
    $o = [pscustomobject]@{ Id = $Id; TimeCreated = $Time; MachineName = 'TESTPC'; Xml = $xml }
    $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml } -PassThru
}

function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, $LogName, $MaxEvents)
    Set-Content -LiteralPath $env:OPSTOOLKIT_TEST_WINEVENT_QUERY -Value (($FilterHashtable.Id -join ',') + '|' + $FilterHashtable.LogName + '|' + $FilterHashtable.StartTime.ToString('o')) -Encoding ascii
    if ($env:OPSTOOLKIT_TEST_WINEVENT_MODE -eq 'none') { throw 'No events were found that match the specified selection criteria.' }
    if ($env:OPSTOOLKIT_TEST_WINEVENT_MODE -eq 'error') { throw 'The specified channel could not be found.' }
    $t = Get-Date
    New-FakeCiEvent -Id 3076 -Time $t.AddHours(-3) -Data @{ 'File Name' = 'C:\tools\a.exe'; 'Process Name' = 'C:\Windows\explorer.exe'; PolicyName = 'ops-toolkit WDAC audit' }
    New-FakeCiEvent -Id 3076 -Time $t.AddHours(-2) -Data @{ 'File Name' = 'C:\tools\a.exe'; 'Process Name' = 'C:\Windows\explorer.exe'; PolicyName = 'ops-toolkit WDAC audit' }
    New-FakeCiEvent -Id 3089 -Time $t.AddHours(-2) -Data @{ 'File Name' = 'C:\tools\a.exe'; PublisherName = 'Contoso Ltd'; IssuerName = 'Contoso CA' }
    New-FakeCiEvent -Id 3076 -Time $t.AddHours(-1) -Data @{ 'File Name' = 'C:\tmp\unsigned.dll'; 'Process Name' = 'C:\tools\a.exe'; PolicyName = 'ops-toolkit WDAC audit' }
}
'@
    }

    It 'groups audit events by file and by publisher' {
        $query = Join-Path $script:workRoot 'ev-query-1.txt'
        $setup = "`$env:OPSTOOLKIT_TEST_WINEVENT_QUERY = '$query'`n" + $script:eventSetup
        $run = Invoke-ScriptUnderTest -RelativePath $script:eventScript -Setup $setup `
            -Argument @{ OutputDirectory = (Join-Path $script:workRoot 'ev-out-1'); Days = 14 }
        $run.ExitCode | Should -Be 0 -Because $run.Output
        $s = $run.Summary
        $s.Status | Should -Be 'Events'
        $s.AuditWouldBlockCount | Should -Be 3
        $s.DistinctFileCount | Should -Be 2
        (Split-Path $s.OutputDirectory -Leaf) | Should -Match '^wdac-audit-events-\d{8}_\d{6}$'
        Test-Path (Join-Path $s.OutputDirectory 'summary.json') | Should -BeTrue

        $byFile = @(Import-Csv (Join-Path $s.OutputDirectory 'wdac-audit-by-file.csv'))
        $a = $byFile | Where-Object FilePath -eq 'C:\tools\a.exe'
        $a.AuditWouldBlockCount | Should -Be '2'
        $a.Publisher | Should -Be 'Contoso Ltd'
        ($byFile | Where-Object FilePath -eq 'C:\tmp\unsigned.dll').Publisher | Should -BeNullOrEmpty
        $byPublisher = @(Import-Csv (Join-Path $s.OutputDirectory 'wdac-audit-by-publisher.csv'))
        $byPublisher.Count | Should -Be 1
        $byPublisher[0].Publisher | Should -Be 'Contoso Ltd'
    }

    It 'queries events 3076 and 3089 in the Code Integrity log over the requested window' {
        $query = Join-Path $script:workRoot 'ev-query-1.txt'
        $parts = (Get-Content -LiteralPath $query -Raw).Trim() -split '\|'
        ($parts[0] -split ',') | Should -Contain '3076'
        ($parts[0] -split ',') | Should -Contain '3089'
        $parts[1] | Should -Be 'Microsoft-Windows-CodeIntegrity/Operational'
        $days = ((Get-Date) - [datetime]::Parse($parts[2])).TotalDays
        $days | Should -BeGreaterThan 13.9
        $days | Should -BeLessThan 14.1
    }

    It 'writes empty reports and says NoEvents when the log has none' {
        $setup = "`$env:OPSTOOLKIT_TEST_WINEVENT_QUERY = '$(Join-Path $script:workRoot 'ev-query-2.txt')'`n`$env:OPSTOOLKIT_TEST_WINEVENT_MODE = 'none'`n" + $script:eventSetup
        $run = Invoke-ScriptUnderTest -RelativePath $script:eventScript -Setup $setup `
            -Argument @{ OutputDirectory = (Join-Path $script:workRoot 'ev-out-2') }
        $run.ExitCode | Should -Be 0 -Because $run.Output
        $run.Summary.Status | Should -Be 'NoEvents'
        Test-Path (Join-Path $run.Summary.OutputDirectory 'wdac-audit-by-file.csv') | Should -BeTrue
    }

    It 'reports an unreadable log as Unreadable, not as no events' {
        $setup = "`$env:OPSTOOLKIT_TEST_WINEVENT_QUERY = '$(Join-Path $script:workRoot 'ev-query-3.txt')'`n`$env:OPSTOOLKIT_TEST_WINEVENT_MODE = 'error'`n" + $script:eventSetup
        $run = Invoke-ScriptUnderTest -RelativePath $script:eventScript -Setup $setup `
            -Argument @{ OutputDirectory = (Join-Path $script:workRoot 'ev-out-3') }
        $run.ExitCode | Should -Be 0 -Because $run.Output
        $run.Summary.Status | Should -Be 'Unreadable'
        $run.Summary.ReadError | Should -Match 'channel could not be found'
    }
}
