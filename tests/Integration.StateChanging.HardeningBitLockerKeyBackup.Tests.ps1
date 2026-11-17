#Requires -Modules Pester

# Enable-BitLockerOsVolume: where the recovery key goes when -RecoveryKeyDirectory is not given.
#
# The destination comes from the parameter, else the BitLockerKeyBackup section of the organisation
# settings file (Folder, EntraId, ActiveDirectory), else the run is refused before anything changes.
# Every command that would change the machine is a recorder from the staged fake BitLocker module;
# OPSTOOLKIT_TEST_ORGSETTINGS_PATH points the settings read at a temp file, never the real
# ProgramData one, and the pretend host comes from HostContextFixture, never the real dsregcmd.exe.
#
# The script runs from a temporary copy in which Test-IsAdministrator answers true, so the executing
# half is exercised without an elevated session. Each state-changing path has a -WhatIf run where
# the recorder must stay empty and an executing run where it must fill with the promised calls.
#
# What this proves: the order (protector, key backup, then encryption), that a failed or unconfigured
# backup never reaches Enable-BitLocker, and that no report or console text holds the key value. It
# does not prove the real BackupToAAD-BitLockerKeyProtector or Backup-BitLockerKeyProtector accept
# these parameters, or that a real Entra or domain join reads the way the stand-in reads.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'HostContextFixture.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-blkey-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:hostFixture = Use-FakeHostContext -Directory $script:workRoot
    $script:repoRoot = Split-Path -Parent $PSScriptRoot

    $realPath = Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1'
    $copyRoot = Join-Path $script:workRoot 'elevated-copy'
    $copyDir = Join-Path $copyRoot 'scripts\it-operations\windows-hardening'
    New-Item -ItemType Directory -Path $copyDir -Force | Out-Null
    foreach ($m in 'OpsToolkit.Reporting', 'OpsToolkit.Hardening') {
        Copy-Item -LiteralPath (Join-Path $script:repoRoot "modules\$m") -Destination (Join-Path $copyRoot "modules\$m") -Recurse
    }
    $original = Get-Content -LiteralPath $realPath -Raw
    $patched = [regex]::Replace($original, '(?s)function Test-IsAdministrator \{.*?\r?\n\}', 'function Test-IsAdministrator { $true }')
    if ($patched -eq $original) { throw 'The elevated copy could not be made: Test-IsAdministrator was not found in the script.' }
    $copyPath = Join-Path $copyDir 'Enable-BitLockerOsVolume.ps1'
    Set-Content -LiteralPath $copyPath -Value $patched -Encoding utf8
    $script:elevRelative = [System.IO.Path]::GetRelativePath($script:repoRoot, $copyPath)

    # A unique, recognisable fake recovery password. If it appears in a report or the console, the script leaked it.
    $script:fakePassword = '918273-645546-372819-182736-455463-728190-918273-645546'
    $script:protectorId = '{AAAAAAAA-0000-4000-8000-000000000001}'

    function New-WorkDirectory {
        param([string]$Name)
        $path = Join-Path $script:workRoot $Name
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $path
    }

    # Writes a settings file whose BitLockerKeyBackup section is the given hashtable, or the raw text when -Raw is given.
    function New-SettingsFile {
        param([string]$Name, [hashtable]$KeyBackup, [string]$Raw)
        $path = Join-Path $script:workRoot "$Name.settings.json"
        $text = if ($Raw) { $Raw } else { [ordered]@{ SchemaVersion = 1; BitLockerKeyBackup = $KeyBackup } | ConvertTo-Json -Depth 4 }
        Set-Content -LiteralPath $path -Value $text -Encoding utf8
        $path
    }

    # One run of the script against the unencrypted fixture volume Q:. -Settings is a settings file path (default:
    # one that does not exist), -HostKind a HostContextFixture kind, -Volume overrides the fixture volume JSON.
    function Invoke-KeyRun {
        param(
            [string]$Tag, [string]$Settings, [string]$HostKind = 'Physical', [string]$KeyDirectory,
            [switch]$WhatIf, [string]$Extra = '', [string]$VolumeJson
        )
        if (-not $Settings) { $Settings = Join-Path $script:workRoot 'no-such-settings.json' }
        if (-not $VolumeJson) { $VolumeJson = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyDecrypted","ProtectionStatus":"Off","EncryptionMethod":"None","KeyProtector":[]}]' }
        $reports = New-WorkDirectory "$Tag-reports"
        $log = Join-Path $script:workRoot "$Tag.log"
        $environment = @"
`$env:SystemDrive = 'Q:'
`$env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON = '$VolumeJson'
`$env:OPSTOOLKIT_TEST_TPM_PRESENT = '1'
`$env:OPSTOOLKIT_TEST_TPM_READY = '1'
`$env:OPSTOOLKIT_TEST_SECUREBOOT = 'true'
`$env:OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD = '$($script:fakePassword)'
`$env:OPSTOOLKIT_TEST_BL_PROTECTORID = '$($script:protectorId)'
`$env:OPSTOOLKIT_TEST_ORGSETTINGS_PATH = '$Settings'
$(Get-FakeHostSetupText -Fixture $script:hostFixture -Kind $HostKind)
$Extra
"@
        $argument = @{ ReportDirectory = $reports }
        if ($KeyDirectory) { $argument.RecoveryKeyDirectory = $KeyDirectory }
        if ($WhatIf) { $argument.WhatIf = $true } else { $argument.Confirm = $false }
        $run = Invoke-ScriptUnderTest -RelativePath $script:elevRelative -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + "`n" + $environment) -Argument $argument
        [pscustomobject]@{ Run = $run; Log = $log; Reports = $reports; Keys = $KeyDirectory }
    }

    function Get-Names {
        param($Result)
        @(Get-OpsMutationRecord -Path $Result.Log | ForEach-Object { $_.Command })
    }

    function Get-StateRow {
        param([string]$ReportDirectory, [string]$Setting)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter '*-apply-state-*.json' -File | Sort-Object Name | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Setting -eq $Setting }
    }

    function Get-PlanRow {
        param([string]$ReportDirectory)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter '*-apply-plan-*.json' -File | Sort-Object Name | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json)
    }

    # Every report and the console text, with the key files themselves excluded (they legitimately hold the password).
    function Get-LeakText {
        param($Result)
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($f in @(Get-ChildItem -LiteralPath $Result.Reports -Recurse -File -ErrorAction SilentlyContinue)) { $parts.Add((Get-Content -LiteralPath $f.FullName -Raw)) }
        if (Test-Path -LiteralPath $Result.Log) { $parts.Add((Get-Content -LiteralPath $Result.Log -Raw)) }
        $parts.Add([string]$Result.Run.Output)
        $parts -join "`n"
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Enable-BitLockerOsVolume key destination: Folder from the settings' {
    BeforeAll {
        $script:fKeys = New-WorkDirectory 'folder-keys'
        $script:fSettings = New-SettingsFile -Name 'folder' -KeyBackup @{ Type = 'Folder'; FolderPath = $script:fKeys }
        # The preview gets its own folder, because the live run below writes a key file into fKeys.
        $script:fWhatIfKeys = New-WorkDirectory 'folder-whatif-keys'
        $script:fWhatIfSettings = New-SettingsFile -Name 'folder-whatif' -KeyBackup @{ Type = 'Folder'; FolderPath = $script:fWhatIfKeys }
        $script:fWhatIf = Invoke-KeyRun -Tag 'folder-whatif' -Settings $script:fWhatIfSettings -WhatIf
        $script:fRun = Invoke-KeyRun -Tag 'folder-live' -Settings $script:fSettings
    }

    It 'changes nothing under -WhatIf and plans the folder rows' {
        $script:fWhatIf.Run.ExitCode | Should -Be 0 -Because $script:fWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:fWhatIf.Log).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:fWhatIfKeys -Filter 'BitLocker-Recovery-*' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'a -WhatIf run must not write a key file'
        $plan = Get-PlanRow -ReportDirectory $script:fWhatIf.Reports
        ($plan | Where-Object Category -eq 'Precondition' | ForEach-Object { $_.Setting }) |
            Should -Be @('RecoveryKeyDirectory', 'KeyDirectoryWritable', 'Elevated', 'Tpm', 'SecureBoot', 'OsVolumeNotProtected')
    }

    It 'writes the key file to the settings folder, then enables, and reports where the key went' {
        $script:fRun.Run.ExitCode | Should -Be 0 -Because $script:fRun.Run.Output
        $names = Get-Names $script:fRun
        [array]::IndexOf($names, 'Enable-BitLocker') | Should -BeGreaterThan ([array]::IndexOf($names, 'Add-BitLockerKeyProtector'))
        $names | Should -Not -Contain 'BackupToAAD-BitLockerKeyProtector'
        $keyFile = @(Get-ChildItem -LiteralPath $script:fKeys -Filter 'BitLocker-Recovery-*-AAAAAAAA-0000-4000-8000-000000000001.txt')
        $keyFile.Count | Should -Be 1
        $s = $script:fRun.Run.Summary
        $s.KeyBackupDestination | Should -Be 'Folder'
        $s.KeyBackupSource | Should -Be 'Settings'
        $s.KeyBackupLocation | Should -Be (Resolve-Path -LiteralPath $script:fKeys).ProviderPath
        @($s.KeyBackupProtectorIds) | Should -Contain $script:protectorId
        $s.KeyBackupNote | Should -BeNullOrEmpty
    }

    It 'never writes the key value to a report or the console' {
        (Get-LeakText $script:fRun) | Should -Not -Match ([regex]::Escape($script:fakePassword))
        (Get-LeakText $script:fWhatIf) | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }

    It 'refuses a settings folder on the operating-system volume and changes nothing' {
        $bad = New-SettingsFile -Name 'folder-os' -KeyBackup @{ Type = 'Folder'; FolderPath = 'Q:\keys' }
        $r = Invoke-KeyRun -Tag 'folder-os' -Settings $bad
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'Refusing'
        @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
    }
}

Describe 'Enable-BitLockerOsVolume key destination: Entra ID' {
    BeforeAll {
        $script:eSettings = New-SettingsFile -Name 'entra' -KeyBackup @{ Type = 'EntraId' }
        $script:eWhatIf = Invoke-KeyRun -Tag 'entra-whatif' -Settings $script:eSettings -HostKind EntraJoined -WhatIf
        $script:eRun = Invoke-KeyRun -Tag 'entra-live' -Settings $script:eSettings -HostKind EntraJoined
        $script:eFail = Invoke-KeyRun -Tag 'entra-fail' -Settings $script:eSettings -HostKind EntraJoined -Extra "`$env:OPSTOOLKIT_TEST_BL_BACKUP_FAIL = '1'"
        $script:eWork = Invoke-KeyRun -Tag 'entra-workgroup' -Settings $script:eSettings -HostKind Physical
        $script:eUnread = Invoke-KeyRun -Tag 'entra-unread' -Settings $script:eSettings -HostKind JoinUnread
    }

    It 'changes nothing under -WhatIf and plans a Key backup precondition instead of the directory rows' {
        $script:eWhatIf.Run.ExitCode | Should -Be 0 -Because $script:eWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:eWhatIf.Log).Count | Should -Be 0
        $plan = Get-PlanRow -ReportDirectory $script:eWhatIf.Reports
        ($plan | Where-Object Category -eq 'Precondition' | ForEach-Object { $_.Setting }) |
            Should -Be @('KeyBackup', 'Elevated', 'Tpm', 'SecureBoot', 'OsVolumeNotProtected')
        ($plan | Where-Object Setting -eq 'Q:').Action | Should -Match 'back it up to Entra ID'
    }

    It 'adds the protector, escrows it to Entra ID, and only then enables BitLocker' {
        $script:eRun.Run.ExitCode | Should -Be 0 -Because $script:eRun.Run.Output
        $m = @(Get-OpsMutationRecord -Path $script:eRun.Log)
        $names = @($m | ForEach-Object { $_.Command })
        $add = [array]::IndexOf($names, 'Add-BitLockerKeyProtector')
        $backup = [array]::IndexOf($names, 'BackupToAAD-BitLockerKeyProtector')
        $enable = [array]::IndexOf($names, 'Enable-BitLocker')
        $add | Should -BeGreaterOrEqual 0
        $backup | Should -BeGreaterThan $add
        $enable | Should -BeGreaterThan $backup
        $m[$backup].Detail | Should -Be $script:protectorId
        $s = $script:eRun.Run.Summary
        $s.KeyBackupDestination | Should -Be 'EntraId'
        $s.KeyBackupLocation | Should -Be 'Entra ID'
        @($s.KeyBackupProtectorIds) | Should -Contain $script:protectorId
        (Get-StateRow -ReportDirectory $script:eRun.Reports -Setting 'KeyBackup').Result | Should -Be 'Met'
        (Get-StateRow -ReportDirectory $script:eRun.Reports -Setting 'Q:').Detail | Should -Match 'KeyBackup=EntraId'
        (Get-LeakText $script:eRun) | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }

    It 'never starts encryption after a failed backup, and removes the protector it added' {
        $script:eFail.Run.ExitCode | Should -Not -Be 0
        $names = Get-Names $script:eFail
        $names | Should -Contain 'BackupToAAD-BitLockerKeyProtector'
        $names | Should -Contain 'Remove-BitLockerKeyProtector'
        $names | Should -Not -Contain 'Enable-BitLocker'
        (Get-StateRow -ReportDirectory $script:eFail.Reports -Setting 'Q:').Result | Should -Match '^Failed:.*BitLocker was not enabled'
        @(Get-ChildItem -LiteralPath $script:eFail.Reports -Filter '*-rollback-*.json' -ErrorAction SilentlyContinue).Count | Should -Be 0
        (Get-LeakText $script:eFail) | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }

    It 'refuses an Entra destination on a host that is not Entra joined, and when the join is unread' {
        foreach ($r in $script:eWork, $script:eUnread) {
            $r.Run.ExitCode | Should -Not -Be 0
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
            (Get-StateRow -ReportDirectory $r.Reports -Setting 'KeyBackup').Result | Should -Match '^Failed: Key backup: Entra ID needs'
        }
    }
}

Describe 'Enable-BitLockerOsVolume key destination: Active Directory' {
    BeforeAll {
        $script:aSettings = New-SettingsFile -Name 'ad' -KeyBackup @{ Type = 'ActiveDirectory' }
        $script:aWhatIf = Invoke-KeyRun -Tag 'ad-whatif' -Settings $script:aSettings -HostKind Domain -WhatIf
        $script:aRun = Invoke-KeyRun -Tag 'ad-live' -Settings $script:aSettings -HostKind Domain
        $script:aFail = Invoke-KeyRun -Tag 'ad-fail' -Settings $script:aSettings -HostKind Domain -Extra "`$env:OPSTOOLKIT_TEST_BL_BACKUP_FAIL = '1'"
        $script:aEntra = Invoke-KeyRun -Tag 'ad-entra-host' -Settings $script:aSettings -HostKind EntraJoined
        $script:aPlain = Invoke-KeyRun -Tag 'ad-workgroup' -Settings $script:aSettings -HostKind Physical
    }

    It 'changes nothing under -WhatIf' {
        $script:aWhatIf.Run.ExitCode | Should -Be 0 -Because $script:aWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:aWhatIf.Log).Count | Should -Be 0
    }

    It 'escrows to Active Directory before enabling on a domain joined host' {
        $script:aRun.Run.ExitCode | Should -Be 0 -Because $script:aRun.Run.Output
        $names = Get-Names $script:aRun
        $backup = [array]::IndexOf($names, 'Backup-BitLockerKeyProtector')
        $backup | Should -BeGreaterThan ([array]::IndexOf($names, 'Add-BitLockerKeyProtector'))
        [array]::IndexOf($names, 'Enable-BitLocker') | Should -BeGreaterThan $backup
        $names | Should -Not -Contain 'BackupToAAD-BitLockerKeyProtector'
        $script:aRun.Run.Summary.KeyBackupLocation | Should -Be 'Active Directory'
    }

    It 'never starts encryption after a failed Active Directory backup' {
        $script:aFail.Run.ExitCode | Should -Not -Be 0
        $names = Get-Names $script:aFail
        $names | Should -Contain 'Remove-BitLockerKeyProtector'
        $names | Should -Not -Contain 'Enable-BitLocker'
    }

    It 'meets the precondition only on a domain joined host, not on a workgroup or Entra-only host' {
        foreach ($r in $script:aPlain, $script:aEntra) {
            $r.Run.ExitCode | Should -Not -Be 0
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
            (Get-StateRow -ReportDirectory $r.Reports -Setting 'KeyBackup').Result | Should -Match '^Failed: Key backup: Active Directory needs a domain joined host'
        }
    }
}

Describe 'Enable-BitLockerOsVolume key destination: not configured' {
    BeforeAll {
        $script:nSettingsInvalid = New-SettingsFile -Name 'invalid' -Raw '{ not json'
        $script:nSettingsOther = New-SettingsFile -Name 'only-events' -Raw '{"SchemaVersion":1,"EventDestination":{"Type":"AzureMonitorAgent"}}'
        $script:nMissing = Invoke-KeyRun -Tag 'none-live'
        $script:nMissingWhatIf = Invoke-KeyRun -Tag 'none-whatif' -WhatIf
        $script:nInvalid = Invoke-KeyRun -Tag 'none-invalid' -Settings $script:nSettingsInvalid
        $script:nOther = Invoke-KeyRun -Tag 'none-other' -Settings $script:nSettingsOther
    }

    It 'refuses a live run before any change, naming the missing key backup' {
        $script:nMissing.Run.ExitCode | Should -Not -Be 0
        $script:nMissing.Run.Output | Should -Match 'Key backup: not configured'
        @(Get-OpsMutationRecord -Path $script:nMissing.Log).Count | Should -Be 0
        $row = Get-StateRow -ReportDirectory $script:nMissing.Reports -Setting 'KeyBackup'
        $row.Category | Should -Be 'Precondition'
        $row.Result | Should -Match '^Failed: Key backup: not configured'
        (Get-PlanRow -ReportDirectory $script:nMissing.Reports | Where-Object Setting -eq 'KeyBackup').Action | Should -Match 'Key backup: not configured'
        (Get-StateRow -ReportDirectory $script:nMissing.Reports -Setting 'Q:').Result | Should -Match '^Skipped: precondition failed'
        @(Get-ChildItem -LiteralPath $script:nMissing.Reports -Filter '*-rollback-*.json' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'only previews under -WhatIf: exit 0, nothing changed, the row still reads Failed' {
        $script:nMissingWhatIf.Run.ExitCode | Should -Be 0 -Because $script:nMissingWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:nMissingWhatIf.Log).Count | Should -Be 0
        (Get-StateRow -ReportDirectory $script:nMissingWhatIf.Reports -Setting 'KeyBackup').Result | Should -Match '^Failed: Key backup: not configured'
    }

    It 'treats an invalid settings file, and a file with no key backup section, as not configured' {
        foreach ($r in $script:nInvalid, $script:nOther) {
            $r.Run.ExitCode | Should -Not -Be 0
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
            (Get-StateRow -ReportDirectory $r.Reports -Setting 'KeyBackup').Result | Should -Match '^Failed: Key backup: not configured'
        }
    }
}

Describe 'Enable-BitLockerOsVolume key destination: the parameter wins' {
    BeforeAll {
        $script:pKeys = New-WorkDirectory 'param-keys'
        $script:pOther = New-WorkDirectory 'param-settings-folder'
        $script:pFolder = New-SettingsFile -Name 'param-folder' -KeyBackup @{ Type = 'Folder'; FolderPath = $script:pOther }
        $script:pEntra = New-SettingsFile -Name 'param-entra' -KeyBackup @{ Type = 'EntraId' }
        $script:pRun = Invoke-KeyRun -Tag 'param-folder' -Settings $script:pFolder -KeyDirectory $script:pKeys
        $script:pRunEntra = Invoke-KeyRun -Tag 'param-entra' -Settings $script:pEntra -KeyDirectory (New-WorkDirectory 'param-keys-entra') -HostKind EntraJoined
    }

    It 'uses the parameter folder, ignores a settings Folder, and says so in the summary' {
        $script:pRun.Run.ExitCode | Should -Be 0 -Because $script:pRun.Run.Output
        @(Get-ChildItem -LiteralPath $script:pKeys -Filter 'BitLocker-Recovery-*').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:pOther -Filter 'BitLocker-Recovery-*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        $s = $script:pRun.Run.Summary
        $s.KeyBackupSource | Should -Be 'Parameter'
        $s.KeyBackupNote | Should -Match 'was ignored'
        $s.KeyBackupNote | Should -Match ([regex]::Escape($script:pOther))
    }

    It 'does not call an escrow cmdlet when the parameter is given alongside an Entra setting' {
        $script:pRunEntra.Run.ExitCode | Should -Be 0 -Because $script:pRunEntra.Run.Output
        (Get-Names $script:pRunEntra) | Should -Not -Contain 'BackupToAAD-BitLockerKeyProtector'
        $script:pRunEntra.Run.Summary.KeyBackupDestination | Should -Be 'Folder'
        $script:pRunEntra.Run.Summary.KeyBackupNote | Should -BeNullOrEmpty
    }
}

Describe 'Enable-BitLockerOsVolume key destination: an already encrypted volume with a recovery protector' {
    BeforeAll {
        $protector = '[{"KeyProtectorType":"RecoveryPassword","KeyProtectorId":"{DDDDDDDD-0000-4000-8000-000000000004}","RecoveryPassword":"' + $script:fakePassword + '"}]'
        $volume = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"FullyEncrypted","ProtectionStatus":"On","EncryptionMethod":"XtsAes256","KeyProtector":' + $protector + '}]'
        $settings = New-SettingsFile -Name 'enc-entra' -KeyBackup @{ Type = 'EntraId' }
        $script:xWhatIf = Invoke-KeyRun -Tag 'enc-whatif' -Settings $settings -HostKind EntraJoined -VolumeJson $volume -WhatIf
        $script:xRun = Invoke-KeyRun -Tag 'enc-live' -Settings $settings -HostKind EntraJoined -VolumeJson $volume
        $script:xNone = Invoke-KeyRun -Tag 'enc-none' -VolumeJson $volume
    }

    It 'changes nothing under -WhatIf' {
        $script:xWhatIf.Run.ExitCode | Should -Be 0 -Because $script:xWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:xWhatIf.Log).Count | Should -Be 0
    }

    It 'escrows the existing protector without adding one or touching encryption' {
        $script:xRun.Run.ExitCode | Should -Be 0 -Because $script:xRun.Run.Output
        $m = @(Get-OpsMutationRecord -Path $script:xRun.Log)
        @($m | ForEach-Object { $_.Command }) | Should -Be @('BackupToAAD-BitLockerKeyProtector')
        $m[0].Detail | Should -Be '{DDDDDDDD-0000-4000-8000-000000000004}'
        (Get-LeakText $script:xRun) | Should -Not -Match ([regex]::Escape($script:fakePassword))
    }

    It 'refuses when there is a recovery protector to back up but no destination' {
        $script:xNone.Run.ExitCode | Should -Not -Be 0
        @(Get-OpsMutationRecord -Path $script:xNone.Log).Count | Should -Be 0
    }
}
