#Requires -Modules Pester

# Enable-BitLockerOsVolume: the opt-in TPM plus startup PIN protector, and the refusal to plan an enable on a
# volume that is mid-decryption.
#
# Every command that would change the machine is a recorder or a fixture. The BitLocker, TPM and Secure Boot
# cmdlets come from the staged fake modules. The FVE policy key is a small stateful fake registry kept in a JSON
# file (it models the real hazard that New-Item -Force on an existing key replaces it), and the Win32_ComputerSystem
# read answers from an environment variable.
#
# The script is run from a temporary copy whose only difference is that Test-IsAdministrator answers true. The
# suite is normally not elevated and an unelevated live run stops before any change, so without the copy the
# apply, undo and rollback paths could not be exercised at all. The copy is rebuilt from the real file on every
# run, so a change to the script is always what is under test.
#
# What this proves: the PIN reaches Enable-BitLocker as a SecureString and appears in no file the run writes, the
# policy values are written before the enable and restored on a failure or a rollback, an existing policy key is
# never replaced, a virtual machine or an unreadable model is refused, and a decrypting volume stops the run with
# nothing changed. It does not prove the real Enable-BitLocker accepts the call or that the policy value names and
# numbers are the ones Windows reads; those are unverified on a live machine.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-blpin-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
    $script:repoRoot = Split-Path -Parent $PSScriptRoot

    $script:realRelative = 'scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1'
    $script:realPath = Get-RepositoryScriptPath -RelativePath $script:realRelative

    # A temporary tree with the script and the reporting module it imports, Test-IsAdministrator answering true.
    $copyRoot = Join-Path $script:workRoot 'elevated-copy'
    $copyDir = Join-Path $copyRoot 'scripts\it-operations\windows-hardening'
    New-Item -ItemType Directory -Path $copyDir -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $script:repoRoot 'modules\OpsToolkit.Reporting') -Destination (Join-Path $copyRoot 'modules\OpsToolkit.Reporting') -Recurse
    Copy-Item -LiteralPath (Join-Path $script:repoRoot 'modules\OpsToolkit.Hardening') -Destination (Join-Path $copyRoot 'modules\OpsToolkit.Hardening') -Recurse
    $original = Get-Content -LiteralPath $script:realPath -Raw
    $patched = [regex]::Replace($original, '(?s)function Test-IsAdministrator \{.*?\r?\n\}', 'function Test-IsAdministrator { $true }')
    if ($patched -eq $original) { throw 'The elevated copy could not be made: Test-IsAdministrator was not found in the script.' }
    $copyPath = Join-Path $copyDir 'Enable-BitLockerOsVolume.ps1'
    Set-Content -LiteralPath $copyPath -Value $patched -Encoding utf8
    $script:elevRelative = [System.IO.Path]::GetRelativePath($script:repoRoot, $copyPath)

    # Unique, recognisable secrets. If either appears in a file or the console, the script leaked it.
    $script:pin = '48151623'
    $script:fakePassword = '918273-645546-372819-182736-455463-728190-918273-645546'
    $script:fveKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $script:fveNames = @('UseAdvancedStartup', 'EnableBDEWithNoTPM', 'UseTPM', 'UseTPMPIN', 'UseTPMKey', 'UseTPMKeyPIN')

    # A stateful stand-in for the FVE policy key, in the file named by OPSTOOLKIT_TEST_FVE_STATE. It records every
    # write through the harness recorder, refuses a write to a missing key like the real provider, and makes
    # New-Item -Force on an existing key replace it, which is the hazard the script's Test-Path guard exists for.
    $script:fveShadow = @'

function Get-FveKeyName { 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' }
function Read-FakeFve { Microsoft.PowerShell.Management\Get-Content -LiteralPath $env:OPSTOOLKIT_TEST_FVE_STATE -Raw | ConvertFrom-Json }
function Save-FakeFve {
    param($State)
    $State | ConvertTo-Json -Depth 4 | Microsoft.PowerShell.Management\Set-Content -LiteralPath $env:OPSTOOLKIT_TEST_FVE_STATE -Encoding utf8 -WhatIf:$false
}
function Get-FakeTarget { param($Path, $LiteralPath) if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path } }
function Get-ItemProperty {
    param($Path, $LiteralPath, $Name, $ErrorAction)
    $t = Get-FakeTarget $Path $LiteralPath
    if ($t -ne (Get-FveKeyName)) { return Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters }
    $s = Read-FakeFve
    if (-not $s.exists) { throw [System.Management.Automation.ItemNotFoundException]::new("Cannot find path '$t' because it does not exist.") }
    # The registry provider returns DWords as Int32; JSON hands back Int64, so convert.
    $ints = [ordered]@{}
    foreach ($p in $s.values.PSObject.Properties) { $ints[$p.Name] = [int]$p.Value }
    [pscustomobject]$ints
}
function Test-Path {
    param($Path, $LiteralPath, $PathType, $ErrorAction)
    $t = Get-FakeTarget $Path $LiteralPath
    if ($t -ne (Get-FveKeyName)) { return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters }
    [bool](Read-FakeFve).exists
}
function Set-ItemProperty {
    param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
    Write-OpsTestMutation -Command 'Set-ItemProperty' -Target "$Path\$Name" -Detail ([string]$Value)
    if ("$Path" -eq (Get-FveKeyName)) {
        $s = Read-FakeFve
        if (-not $s.exists) { throw "Cannot find path '$Path' because it does not exist." }
        $s.values | Add-Member -NotePropertyName $Name -NotePropertyValue ([int]$Value) -Force
        Save-FakeFve $s
    }
}
function Remove-ItemProperty {
    param($Path, $Name, [switch]$Force, $ErrorAction)
    Write-OpsTestMutation -Command 'Remove-ItemProperty' -Target "$Path\$Name" -Detail ''
    if ("$Path" -eq (Get-FveKeyName)) {
        $s = Read-FakeFve
        if (-not $s.values.PSObject.Properties[$Name]) { throw "Property $Name does not exist at $Path." }
        $s.values.PSObject.Properties.Remove($Name)
        Save-FakeFve $s
    }
}
function New-Item {
    param($Path, $ItemType, $Value, [switch]$Force, $ErrorAction, $LiteralPath)
    $t = Get-FakeTarget $Path $LiteralPath
    if ($t -eq (Get-FveKeyName)) {
        Write-OpsTestMutation -Command 'New-Item' -Target $t -Detail 'registry key'
        $s = Read-FakeFve
        if ($s.exists -and $Force) { $s.values = [pscustomobject]@{} }
        $s.exists = $true
        Save-FakeFve $s
        return
    }
    if ($t -match '^(HKLM|HKCU|HKCR|HKU|Registry::)') { Write-OpsTestMutation -Command 'New-Item' -Target $t -Detail 'registry key'; return }
    $forward = @{ Path = $t; Force = $true; WhatIf = $false }
    if ($ItemType) { $forward.ItemType = $ItemType }
    Microsoft.PowerShell.Management\New-Item @forward
}
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_ComputerSystem') {
        if ($env:OPSTOOLKIT_TEST_CS -eq 'error') { throw 'CIM is down (fixture).' }
        if ($env:OPSTOOLKIT_TEST_CS -eq 'blank') { return [pscustomobject]@{ Manufacturer = ''; Model = '' } }
        $p = @($env:OPSTOOLKIT_TEST_CS -split '\|', 2)
        return [pscustomobject]@{ Manufacturer = $p[0]; Model = $p[1] }
    }
    CimCmdlets\Get-CimInstance @PSBoundParameters
}
'@

    function New-FveStateFile {
        param([string]$Name, [bool]$Exists, [hashtable]$Values = @{})
        $path = Join-Path $script:workRoot "$Name.fve.json"
        [pscustomobject]@{ exists = $Exists; values = [pscustomobject]$Values } | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $path -Encoding utf8
        $path
    }

    function Read-FveStateFile {
        param([string]$Path)
        $s = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $h = [ordered]@{}
        foreach ($p in ($s.values.PSObject.Properties | Sort-Object Name)) { $h[$p.Name] = [int]$p.Value }
        [pscustomobject]@{ Exists = [bool]$s.exists; Values = ($h | ConvertTo-Json -Compress) }
    }

    function Get-PinEnv {
        param(
            [string]$Status = 'FullyDecrypted', [string]$Protection = 'Off', [string]$KeyProtectorJson = '[]',
            [string]$FveState, [string]$Machine = 'Dell Inc.|Latitude 7440', [string]$Pin = $script:pin, [string]$Extra = ''
        )
        $volume = '[{"MountPoint":"Q:","VolumeType":"OperatingSystem","VolumeStatus":"' + $Status + '","ProtectionStatus":"' + $Protection + '","EncryptionMethod":"None","KeyProtector":' + $KeyProtectorJson + '}]'
        @"
`$env:SystemDrive = 'Q:'
`$env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON = '$volume'
`$env:OPSTOOLKIT_TEST_TPM_PRESENT = '1'
`$env:OPSTOOLKIT_TEST_TPM_READY = '1'
`$env:OPSTOOLKIT_TEST_SECUREBOOT = 'true'
`$env:OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD = '$($script:fakePassword)'
`$env:OPSTOOLKIT_TEST_BL_PROTECTORID = '{AAAAAAAA-0000-4000-8000-000000000001}'
`$env:OPSTOOLKIT_TEST_FVE_STATE = '$FveState'
`$env:OPSTOOLKIT_TEST_CS = '$Machine'
`$env:OPSTOOLKIT_TEST_PIN = '$Pin'
`$env:OPSTOOLKIT_TEST_ORGSETTINGS_PATH = '$(Join-Path $script:workRoot 'no-such-settings.json')'
$Extra
"@
    }

    function New-WorkDirectory {
        param([string]$Name)
        $path = Join-Path $script:workRoot $Name
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $path
    }

    # One run of the script. The PIN is built inside the child as a SecureString, the only form the script accepts.
    function Invoke-PinRun {
        param(
            [string]$Tag, [string]$Environment, [string]$ReportDirectory, [string]$KeyDirectory,
            [switch]$WhatIf, [switch]$Rollback, [switch]$NoPin, [switch]$PinWithoutSwitch,
            [string]$ScriptRelative = $script:elevRelative
        )
        $log = Join-Path $script:workRoot "$Tag.log"
        $argument = @{ ReportDirectory = $ReportDirectory }
        if ($KeyDirectory) { $argument.RecoveryKeyDirectory = $KeyDirectory }
        if ($Rollback) { $argument.Rollback = $true }
        if ($WhatIf) { $argument.WhatIf = $true } else { $argument.Confirm = $false }
        $raw = @{}
        $secure = '(ConvertTo-SecureString $env:OPSTOOLKIT_TEST_PIN -AsPlainText -Force)'
        if (-not $NoPin) {
            if (-not $PinWithoutSwitch) { $raw.UseTpmAndPin = '$true' }
            $raw.StartupPin = $secure
        }
        $run = Invoke-ScriptUnderTest -RelativePath $ScriptRelative -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + "`n" + $Environment + "`n" + $script:fveShadow) `
            -Argument $argument -RawArgument $raw
        [pscustomobject]@{ Run = $run; Log = $log; Reports = $ReportDirectory; Keys = $KeyDirectory }
    }

    function Get-StateRow {
        param([string]$ReportDirectory, [string]$Setting, [string]$Mode = 'apply')
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter "*-$Mode-state-*.json" -File | Sort-Object Name | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Setting -eq $Setting }
    }

    function Get-PlanRow {
        param([string]$ReportDirectory, [string]$Mode = 'apply')
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter "*-$Mode-plan-*.json" -File | Sort-Object Name | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json)
    }

    # Every place the PIN could be written: files under the directories, named files, and console text.
    function Find-TextLeak {
        param([string[]]$Directory = @(), [string[]]$File = @(), [string[]]$Text = @(), [string]$Needle)
        $hits = [System.Collections.Generic.List[string]]::new()
        $paths = @($File)
        foreach ($d in $Directory) { $paths += @(Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
        foreach ($p in $paths) {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $content = Get-Content -LiteralPath $p -Raw
            if ($content -and $content.Contains($Needle)) { $hits.Add($p) }
        }
        foreach ($t in $Text) { if ($t -and "$t".Contains($Needle)) { $hits.Add('(console or summary text)') } }
        @($hits)
    }

    $script:priorFve = @{ UseTPMPIN = 2; UseTPM = 0; Unrelated = 7 }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Enable-BitLockerOsVolume -UseTpmAndPin on a physical machine' {
    BeforeAll {
        $script:aKeys = New-WorkDirectory 'pin-a-keys'
        $script:aWhatIfReports = New-WorkDirectory 'pin-a-whatif-reports'
        $script:aReports = New-WorkDirectory 'pin-a-reports'
        $script:aWhatIfState = New-FveStateFile -Name 'pin-a-whatif' -Exists $true -Values $script:priorFve
        $script:aState = New-FveStateFile -Name 'pin-a' -Exists $true -Values $script:priorFve
        $script:aWhatIf = Invoke-PinRun -Tag 'pin-a-whatif' -WhatIf -ReportDirectory $script:aWhatIfReports -KeyDirectory $script:aKeys `
            -Environment (Get-PinEnv -FveState $script:aWhatIfState)
        $script:aExec = Invoke-PinRun -Tag 'pin-a-exec' -ReportDirectory $script:aReports -KeyDirectory $script:aKeys `
            -Environment (Get-PinEnv -FveState $script:aState)
        # Capture what the forward run left behind before the rollback run consumes the file and restores the policy.
        $script:aRollbackFileText = Get-Content -LiteralPath $script:aExec.Run.Summary.RollbackJsonPath -Raw
        $script:aStateAfterForward = Read-FveStateFile -Path $script:aState
        # The rollback of that run, against the policy state it left behind.
        $script:aRollback = Invoke-PinRun -Tag 'pin-a-rollback' -NoPin -Rollback -ReportDirectory $script:aReports `
            -Environment (Get-PinEnv -FveState $script:aState)
    }

    It 'plans the PIN checks, then the six policy values with their prior values, then the enable, and changes nothing under -WhatIf' {
        $script:aWhatIf.Run.ExitCode | Should -Be 0 -Because $script:aWhatIf.Run.Output
        @(Get-OpsMutationRecord -Path $script:aWhatIf.Log | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
        $script:aWhatIf.Run.Summary.UseTpmAndPin | Should -BeTrue
        $plan = Get-PlanRow -ReportDirectory $script:aWhatIfReports
        ($plan | Where-Object Category -eq 'Precondition' | ForEach-Object { $_.Setting }) |
            Should -Be @('RecoveryKeyDirectory', 'KeyDirectoryWritable', 'Elevated', 'Tpm', 'SecureBoot', 'OsVolumeNotProtected', 'NotVirtualMachine', 'StartupPin')
        $fve = @($plan | Where-Object Category -eq 'FvePolicy')
        ($fve | ForEach-Object { $_.Setting }) | Should -Be $script:fveNames
        ($fve | ForEach-Object { $_.CurrentValue }) | Should -Be @('absent', 'absent', '0', '2', 'absent', 'absent')
        ($fve | ForEach-Object { $_.DesiredValue }) | Should -Be @('1', '0', '0', '1', '0', '0')
        $fve[2].Action | Should -Match '^No change' -Because 'UseTPM already holds its target'
        $enable = @($plan | Where-Object Category -eq 'EnableOsVolume')
        $enable.Count | Should -Be 1
        $enable[0].Action | Should -Match 'startup PIN'
        $categories = @($plan | ForEach-Object { [string]$_.Category })
        [array]::IndexOf($categories, 'EnableOsVolume') | Should -BeGreaterThan ([array]::LastIndexOf($categories, 'FvePolicy')) -Because 'policy is written before the enable'
    }

    It 'writes the policy first, then adds the recovery protector, then enables with a TPM and PIN protector carrying the SecureString' {
        $script:aExec.Run.ExitCode | Should -Be 0 -Because $script:aExec.Run.Output
        $m = @(Get-OpsMutationRecord -Path $script:aExec.Log)
        $names = @($m | ForEach-Object { $_.Command })
        $add = [array]::IndexOf($names, 'Add-BitLockerKeyProtector')
        $enable = [array]::IndexOf($names, 'Enable-BitLocker')
        $add | Should -BeGreaterOrEqual 0
        $enable | Should -BeGreaterThan $add
        $sets = @(0..($m.Count - 1) | Where-Object { $m[$_].Command -eq 'Set-ItemProperty' })
        $sets.Count | Should -Be 5 -Because 'UseTPM already holds its target'
        foreach ($i in $sets) { $i | Should -BeLessThan $add }
        (($sets | ForEach-Object { $m[$_].Target }) -join ';') | Should -Be (($script:fveNames | Where-Object { $_ -ne 'UseTPM' } | ForEach-Object { "$($script:fveKeyPath)\$_" }) -join ';')
        (($sets | ForEach-Object { $m[$_].Detail }) -join ';') | Should -Be '1;0;1;0;0'
        $m[$enable].Detail | Should -Be 'XtsAes256;tpm=False;usedspace=True;tpmpin=True;pin=SecureString;pinlen=8'
        $script:aExec.Run.Summary.RebootRequired | Should -BeTrue
    }

    It 'never replaces an existing policy key: no key is created and its other values survive' {
        @(Get-OpsMutationRecord -Path $script:aExec.Log | Where-Object { $_.Command -eq 'New-Item' }).Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $script:aExec.Log | Where-Object { $_.Command -eq 'Remove-ItemProperty' }).Count | Should -Be 0
        # The unrelated value is still there after the forward run, which a replaced key would have lost.
        $script:aStateAfterForward.Exists | Should -BeTrue
        $script:aStateAfterForward.Values | Should -Be '{"EnableBDEWithNoTPM":0,"Unrelated":7,"UseAdvancedStartup":1,"UseTPM":0,"UseTPMKey":0,"UseTPMKeyPIN":0,"UseTPMPIN":1}'
    }

    It 'records the prior value of each policy value written, with no path, in the rollback file' {
        $data = $script:aRollbackFileText | ConvertFrom-Json
        @($data.ChangedSettings).Count | Should -Be 6
        $data.ChangedSettings[0].Category | Should -Be 'EnableOsVolume'
        $policy = @($data.ChangedSettings | Where-Object Category -eq 'FvePolicy')
        $policy.Count | Should -Be 5
        foreach ($p in $policy) { (($p.PSObject.Properties | ForEach-Object { $_.Name }) -join ',') | Should -Be 'Category,Name,PriorValue' }
        $prior = @{}
        foreach ($p in $policy) { $prior[$p.Name] = $p.PriorValue }
        $prior['UseAdvancedStartup'] | Should -Be 'absent'
        $prior['EnableBDEWithNoTPM'] | Should -Be 'absent'
        $prior['UseTPMPIN'] | Should -Be '2'
        $prior['UseTPMKey'] | Should -Be 'absent'
        $prior['UseTPMKeyPIN'] | Should -Be 'absent'
        $prior.ContainsKey('UseTPM') | Should -BeFalse -Because 'UseTPM was not written'
        $script:aRollbackFileText | Should -Not -Match 'HKLM|Policies'
    }

    It 'rolls the policy back to the recorded prior values, leaving unrelated values alone' {
        $script:aRollback.Run.ExitCode | Should -Be 0 -Because $script:aRollback.Run.Output
        $m = @(Get-OpsMutationRecord -Path $script:aRollback.Log)
        @($m | Where-Object { $_.Command -eq 'Disable-BitLocker' }).Count | Should -Be 1
        @($m | Where-Object { $_.Command -eq 'Remove-ItemProperty' } | ForEach-Object { ($_.Target -split '\\')[-1] } | Sort-Object) |
            Should -Be @('EnableBDEWithNoTPM', 'UseAdvancedStartup', 'UseTPMKey', 'UseTPMKeyPIN')
        $restored = @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' })
        $restored.Count | Should -Be 1
        $restored[0].Target | Should -Be "$($script:fveKeyPath)\UseTPMPIN"
        $restored[0].Detail | Should -Be '2'
        $after = Read-FveStateFile -Path $script:aState
        $after.Exists | Should -BeTrue
        $after.Values | Should -Be '{"Unrelated":7,"UseTPM":0,"UseTPMPIN":2}'
        $script:aRollback.Run.Summary.RollbackConsumedPath | Should -Not -BeNullOrEmpty
    }

    It 'writes the PIN to no file, plan, state, rollback, key file, mutation log or console, and the leak check can fail' {
        $hits = Find-TextLeak -Directory @($script:aWhatIfReports, $script:aReports, $script:aKeys) `
            -File @($script:aWhatIf.Log, $script:aExec.Log, $script:aRollback.Log, $script:aWhatIfState, $script:aState) `
            -Text @($script:aWhatIf.Run.Output, $script:aExec.Run.Output, $script:aRollback.Run.Output, ($script:aWhatIf.Run.Summary | ConvertTo-Json -Depth 10), ($script:aExec.Run.Summary | ConvertTo-Json -Depth 10)) `
            -Needle $script:pin
        $hits | Should -BeNullOrEmpty -Because "the PIN was found in: $($hits -join ', ')"
        # The check itself: a planted copy is found, so an empty result above means the PIN really is absent.
        $decoyDir = New-WorkDirectory 'pin-decoy'
        Set-Content -LiteralPath (Join-Path $decoyDir 'plan.csv') -Value "Detail,PIN $($script:pin)" -Encoding ascii
        @(Find-TextLeak -Directory @($decoyDir) -Needle $script:pin).Count | Should -Be 1
        # The recovery password is still kept out of every report, as before.
        @(Find-TextLeak -Directory @($script:aWhatIfReports, $script:aReports) -Needle $script:fakePassword).Count | Should -Be 0
    }
}

Describe 'Enable-BitLockerOsVolume -UseTpmAndPin when the policy key does not exist' {
    BeforeAll {
        $keys = New-WorkDirectory 'pin-abs-keys'
        $script:absReports = New-WorkDirectory 'pin-abs-reports'
        $script:absState = New-FveStateFile -Name 'pin-abs' -Exists $false
        $script:abs = Invoke-PinRun -Tag 'pin-abs' -ReportDirectory $script:absReports -KeyDirectory $keys -Environment (Get-PinEnv -FveState $script:absState)
    }

    It 'creates the key once, writes all six values, and records every prior value as absent' {
        $script:abs.Run.ExitCode | Should -Be 0 -Because $script:abs.Run.Output
        $m = @(Get-OpsMutationRecord -Path $script:abs.Log)
        @($m | Where-Object { $_.Command -eq 'New-Item' }).Count | Should -Be 1
        @($m | Where-Object { $_.Command -eq 'Set-ItemProperty' }).Count | Should -Be 6
        $after = Read-FveStateFile -Path $script:absState
        $after.Exists | Should -BeTrue
        $after.Values | Should -Be '{"EnableBDEWithNoTPM":0,"UseAdvancedStartup":1,"UseTPM":0,"UseTPMKey":0,"UseTPMKeyPIN":0,"UseTPMPIN":1}'
        $data = Get-Content -LiteralPath $script:abs.Run.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        @($data.ChangedSettings | Where-Object Category -eq 'FvePolicy' | ForEach-Object { $_.PriorValue } | Select-Object -Unique) | Should -Be @('absent')
    }
}

Describe 'Enable-BitLockerOsVolume -UseTpmAndPin refuses a virtual machine' {
    BeforeAll {
        $script:vmPair = @{}
        $keys = New-WorkDirectory 'pin-vm-keys'
        foreach ($mode in 'whatif', 'exec') {
            $state = New-FveStateFile -Name "pin-vm-$mode" -Exists $true -Values $script:priorFve
            $script:vmPair[$mode] = Invoke-PinRun -Tag "pin-vm-$mode" -WhatIf:($mode -eq 'whatif') -ReportDirectory (New-WorkDirectory "pin-vm-$mode-reports") -KeyDirectory $keys `
                -Environment (Get-PinEnv -FveState $state -Machine 'Microsoft Corporation|Virtual Machine')
        }
        $script:vmDefault = Invoke-PinRun -Tag 'pin-vm-default' -WhatIf -NoPin -ReportDirectory (New-WorkDirectory 'pin-vm-default-reports') -KeyDirectory $keys `
            -Environment (Get-PinEnv -FveState (New-FveStateFile -Name 'pin-vm-default' -Exists $true) -Machine 'Microsoft Corporation|Virtual Machine')
    }

    It 'records the refusal as a failed precondition and exits 0 under -WhatIf' {
        $script:vmPair['whatif'].Run.ExitCode | Should -Be 0 -Because $script:vmPair['whatif'].Run.Output
        $row = Get-StateRow -ReportDirectory $script:vmPair['whatif'].Reports -Setting 'NotVirtualMachine'
        $row.Result | Should -Match '^Failed: this is a virtual machine \(Manufacturer=Microsoft Corporation;Model=Virtual Machine\)'
        $row.Result | Should -Match 'Azure Virtual Desktop'
    }

    It 'stops a live run after writing its reports, changing nothing' {
        $run = $script:vmPair['exec']
        $run.Run.ExitCode | Should -Not -Be 0
        $run.Run.Output | Should -Match 'virtual machine'
        (Get-StateRow -ReportDirectory $run.Reports -Setting 'NotVirtualMachine').Result | Should -Match '^Failed: this is a virtual machine'
        # Only the write probe's own cleanup may be recorded: no policy write, no protector, no enable.
        @(Get-OpsMutationRecord -Path $run.Log | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
        (Get-StateRow -ReportDirectory $run.Reports -Setting 'Q:').Result | Should -Match '^Skipped: precondition failed'
        (Get-StateRow -ReportDirectory $run.Reports -Setting 'UseTPMPIN').Result | Should -Match '^Skipped: precondition failed'
    }

    It 'refuses other hypervisor guests and an unreadable or blank model, never passing them' -ForEach @(
        @{ Name = 'VMware'; Machine = 'VMware, Inc.|VMware20,1'; Expect = '^Failed: this is a virtual machine' }
        @{ Name = 'QEMU'; Machine = 'QEMU|Standard PC (Q35 + ICH9, 2009)'; Expect = '^Failed: this is a virtual machine' }
        @{ Name = 'a failed read'; Machine = 'error'; Expect = '^Failed: could not tell whether this is a virtual machine' }
        @{ Name = 'a blank model and manufacturer'; Machine = 'blank'; Expect = '^Failed: could not tell whether this is a virtual machine' }
    ) {
        $keys = New-WorkDirectory 'pin-vm2-keys'
        $reports = New-WorkDirectory "pin-vm2-$([guid]::NewGuid().ToString('N'))"
        $state = New-FveStateFile -Name "pin-vm2-$([guid]::NewGuid().ToString('N'))" -Exists $true
        $run = Invoke-PinRun -Tag "pin-vm2-$([guid]::NewGuid().ToString('N'))" -ReportDirectory $reports -KeyDirectory $keys -Environment (Get-PinEnv -FveState $state -Machine $Machine)
        $run.Run.ExitCode | Should -Not -Be 0
        (Get-StateRow -ReportDirectory $reports -Setting 'NotVirtualMachine').Result | Should -Match $Expect
        @(Get-OpsMutationRecord -Path $run.Log | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
    }

    It 'leaves a run without -UseTpmAndPin untouched on a virtual machine' {
        $script:vmDefault.Run.ExitCode | Should -Be 0 -Because $script:vmDefault.Run.Output
        $plan = Get-PlanRow -ReportDirectory $script:vmDefault.Reports
        @($plan | Where-Object { $_.Setting -in @('NotVirtualMachine', 'StartupPin') -or $_.Category -eq 'FvePolicy' }).Count | Should -Be 0
        @($plan | Where-Object Category -eq 'EnableOsVolume')[0].Action | Should -Not -Match 'startup PIN'
        $script:vmDefault.Run.Summary.UseTpmAndPin | Should -BeFalse
    }
}

Describe 'Enable-BitLockerOsVolume -UseTpmAndPin refuses a PIN that breaks the rules' {
    It 'stops with nothing changed and a message that does not repeat the PIN' {
        $keys = New-WorkDirectory 'pin-bad-keys'
        $reports = New-WorkDirectory 'pin-bad-reports'
        $bad = '70913'
        $state = New-FveStateFile -Name 'pin-bad' -Exists $true -Values $script:priorFve
        $run = Invoke-PinRun -Tag 'pin-bad' -ReportDirectory $reports -KeyDirectory $keys -Environment (Get-PinEnv -FveState $state -Pin $bad)
        $run.Run.ExitCode | Should -Not -Be 0
        (Get-StateRow -ReportDirectory $reports -Setting 'StartupPin').Result | Should -Be 'Failed: the startup PIN must be 6 to 20 digits (0-9 only); the value is not recorded'
        @(Get-OpsMutationRecord -Path $run.Log | Where-Object { $_.Command -ne 'Remove-Item' }).Count | Should -Be 0
        (Read-FveStateFile -Path $state).Values | Should -Be '{"Unrelated":7,"UseTPM":0,"UseTPMPIN":2}'
        @(Find-TextLeak -Directory @($reports) -File @($run.Log) -Text @($run.Run.Output) -Needle $bad).Count | Should -Be 0
    }

    It 'accepts the switch only together with a PIN, and a PIN only together with the switch' {
        $reports = Join-Path $script:workRoot 'pin-noswitch-reports'
        $run = Invoke-PinRun -Tag 'pin-noswitch' -PinWithoutSwitch -ReportDirectory $reports -KeyDirectory (New-WorkDirectory 'pin-noswitch-keys') `
            -ScriptRelative $script:realRelative -Environment (Get-PinEnv -FveState (New-FveStateFile -Name 'pin-noswitch' -Exists $true))
        $run.Run.ExitCode | Should -Not -Be 0 -Because 'a PIN without -UseTpmAndPin must not be silently ignored'
        @(Get-OpsMutationRecord -Path $run.Log).Count | Should -Be 0
        Test-Path -LiteralPath $reports | Should -BeFalse
    }

    It 'declares the PIN as a SecureString, never a plain string' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:realPath, [ref]$tokens, [ref]$errors)
        $pinParam = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'StartupPin' })
        $pinParam.Count | Should -Be 1
        $pinParam[0].StaticType.FullName | Should -Be 'System.Security.SecureString'
    }
}

Describe 'Enable-BitLockerOsVolume undoes the policy when the enable fails' {
    BeforeAll {
        $keys = New-WorkDirectory 'pin-fail-keys'
        $script:failReports = New-WorkDirectory 'pin-fail-reports'
        $script:failState = New-FveStateFile -Name 'pin-fail' -Exists $true -Values $script:priorFve
        $script:fail = Invoke-PinRun -Tag 'pin-fail' -ReportDirectory $script:failReports -KeyDirectory $keys `
            -Environment (Get-PinEnv -FveState $script:failState -Extra "`$env:OPSTOOLKIT_TEST_BL_ENABLE_FAIL = '1'")
    }

    It 'restores every value it wrote, after the failed enable, and writes no rollback file' {
        $script:fail.Run.ExitCode | Should -Not -Be 0
        $script:fail.Run.Output | Should -Match 'BitLocker change did not complete: enable failed'
        $m = @(Get-OpsMutationRecord -Path $script:fail.Log)
        $names = @($m | ForEach-Object { $_.Command })
        $enable = [array]::IndexOf($names, 'Enable-BitLocker')
        $enable | Should -BeGreaterOrEqual 0
        $names | Should -Contain 'Remove-BitLockerKeyProtector'
        $afterEnable = @($m[($enable + 1)..($m.Count - 1)])
        @($afterEnable | Where-Object { $_.Command -eq 'Remove-ItemProperty' } | ForEach-Object { ($_.Target -split '\\')[-1] } | Sort-Object) |
            Should -Be @('EnableBDEWithNoTPM', 'UseAdvancedStartup', 'UseTPMKey', 'UseTPMKeyPIN')
        @($afterEnable | Where-Object { $_.Command -eq 'Set-ItemProperty' } | ForEach-Object { "$(($_.Target -split '\\')[-1])=$($_.Detail)" }) | Should -Be @('UseTPMPIN=2')
        (Read-FveStateFile -Path $script:failState).Values | Should -Be '{"Unrelated":7,"UseTPM":0,"UseTPMPIN":2}'
        (Get-StateRow -ReportDirectory $script:failReports -Setting 'Q:').Result | Should -Match 'FVE policy values written for the PIN were restored'
        @(Get-ChildItem -LiteralPath $script:failReports -Filter '*-rollback-*.json' -ErrorAction SilentlyContinue).Count | Should -Be 0
        @(Find-TextLeak -Directory @($script:failReports) -File @($script:fail.Log) -Text @($script:fail.Run.Output) -Needle $script:pin).Count | Should -Be 0
    }
}

Describe 'Enable-BitLockerOsVolume leaves an already protected volume alone with -UseTpmAndPin' {
    It 'plans no policy, PIN or protector change and says so in a report-only row' {
        $keys = New-WorkDirectory 'pin-done-keys'
        $reports = New-WorkDirectory 'pin-done-reports'
        $state = New-FveStateFile -Name 'pin-done' -Exists $true -Values $script:priorFve
        $protector = '[{"KeyProtectorType":"Tpm","KeyProtectorId":"{BBBBBBBB-0000-4000-8000-000000000002}"}]'
        $run = Invoke-PinRun -Tag 'pin-done' -WhatIf -ReportDirectory $reports -KeyDirectory $keys `
            -Environment (Get-PinEnv -FveState $state -Status 'FullyEncrypted' -Protection 'On' -KeyProtectorJson $protector)
        $run.Run.ExitCode | Should -Be 0 -Because $run.Run.Output
        $plan = Get-PlanRow -ReportDirectory $reports
        @($plan | Where-Object { $_.Category -eq 'FvePolicy' -or $_.Setting -in @('NotVirtualMachine') }).Count | Should -Be 0
        $note = @($plan | Where-Object { $_.Category -eq 'Report' -and $_.Setting -eq 'StartupPin' })
        $note.Count | Should -Be 1
        $note[0].Action | Should -Match '^No change \(report only: -UseTpmAndPin has no effect'
        (@($run.Run.Summary.Items) | Where-Object { $_.Category -eq 'Report' -and $_.Setting -eq 'StartupPin' }).Result | Should -Be 'NoChange'
    }
}

Describe 'Enable-BitLockerOsVolume on a volume that is mid-decryption' {
    BeforeAll {
        $script:recoveryProtector = '[{"KeyProtectorType":"RecoveryPassword","KeyProtectorId":"{DDDDDDDD-0000-4000-8000-000000000004}","RecoveryPassword":"' + $script:fakePassword + '"}]'
        $keys = New-WorkDirectory 'dec-keys'
        $script:decRuns = @{}
        foreach ($case in @(
                @{ Key = 'progress-whatif'; Status = 'DecryptionInProgress'; WhatIf = $true; Pin = $false }
                @{ Key = 'progress-exec'; Status = 'DecryptionInProgress'; WhatIf = $false; Pin = $false }
                @{ Key = 'paused-exec'; Status = 'DecryptionPaused'; WhatIf = $false; Pin = $false }
                @{ Key = 'progress-pin-exec'; Status = 'DecryptionInProgress'; WhatIf = $false; Pin = $true }
            )) {
            $state = New-FveStateFile -Name "dec-$($case.Key)" -Exists $true -Values $script:priorFve
            $script:decRuns[$case.Key] = Invoke-PinRun -Tag "dec-$($case.Key)" -WhatIf:$case.WhatIf -NoPin:(-not $case.Pin) `
                -ReportDirectory (New-WorkDirectory "dec-$($case.Key)-reports") -KeyDirectory $keys `
                -Environment (Get-PinEnv -FveState $state -Status $case.Status -Protection 'Off' -KeyProtectorJson $script:recoveryProtector)
        }
    }

    It 'previews the state under -WhatIf, plans no enable and no backup, and exits 0' {
        $run = $script:decRuns['progress-whatif']
        $run.Run.ExitCode | Should -Be 0 -Because $run.Run.Output
        $run.Run.Summary.OsVolumeStatus | Should -Be 'DecryptionInProgress'
        $plan = Get-PlanRow -ReportDirectory $run.Reports
        @($plan | Where-Object Category -eq 'BackupRecoveryProtector').Count | Should -Be 0
        $enable = @($plan | Where-Object Category -eq 'EnableOsVolume')
        $enable.Count | Should -Be 1
        $enable[0].Action | Should -Match '^No change \(OS volume Q: is being decrypted: DecryptionInProgress'
        @(Get-OpsMutationRecord -Path $run.Log).Count | Should -Be 0
    }

    It 'stops a live run with the state named and nothing changed (<Key>)' -ForEach @(
        @{ Key = 'progress-exec'; Status = 'DecryptionInProgress' }
        @{ Key = 'paused-exec'; Status = 'DecryptionPaused' }
    ) {
        $run = $script:decRuns[$Key]
        $run.Run.ExitCode | Should -Not -Be 0
        $run.Run.Output | Should -Match 'being decrypted'
        (Get-StateRow -ReportDirectory $run.Reports -Setting 'OsVolumeNotProtected').Result | Should -Match "^Failed: OS volume is being decrypted \($Status\); nothing was changed"
        foreach ($name in 'Tpm', 'SecureBoot', 'KeyDirectoryWritable') {
            (Get-StateRow -ReportDirectory $run.Reports -Setting $name).Result | Should -Be 'Skipped: not evaluated (OS volume is being decrypted)'
        }
        (Get-StateRow -ReportDirectory $run.Reports -Setting 'Q:').Result | Should -Be 'NoChange'
        # Not even the write probe: the log is empty.
        @(Get-OpsMutationRecord -Path $run.Log).Count | Should -Be 0
        @(Get-PlanRow -ReportDirectory $run.Reports | Where-Object Category -eq 'BackupRecoveryProtector').Count | Should -Be 0
        @(Find-TextLeak -Directory @($run.Reports) -Needle $script:fakePassword).Count | Should -Be 0
    }

    It 'plans no PIN check and no policy write when the volume is decrypting, even with -UseTpmAndPin' {
        $run = $script:decRuns['progress-pin-exec']
        $run.Run.ExitCode | Should -Not -Be 0
        $plan = Get-PlanRow -ReportDirectory $run.Reports
        @($plan | Where-Object { $_.Category -eq 'FvePolicy' -or $_.Setting -in @('NotVirtualMachine', 'StartupPin') }).Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $run.Log).Count | Should -Be 0
        @(Find-TextLeak -Directory @($run.Reports) -File @($run.Log) -Text @($run.Run.Output) -Needle $script:pin).Count | Should -Be 0
    }
}

Describe 'Enable-BitLockerOsVolume rollback refuses a malformed policy record' {
    It 'refuses, under -WhatIf, a policy record that carries a path or names another value (<Name>)' -ForEach @(
        @{ Name = 'an extra Path field'; Entry = '{ "Category": "FvePolicy", "Name": "UseTPMPIN", "PriorValue": "2", "Path": "HKLM:\\SOFTWARE\\Other" }' }
        @{ Name = 'a value this script never writes'; Entry = '{ "Category": "FvePolicy", "Name": "LocalAccountTokenFilterPolicy", "PriorValue": "0" }' }
        @{ Name = 'a prior value that is not absent, unknown or a number'; Entry = '{ "Category": "FvePolicy", "Name": "UseTPMPIN", "PriorValue": "..\\x" }' }
    ) {
        $reports = New-WorkDirectory "pin-forge-$([guid]::NewGuid().ToString('N'))"
        $enableEntry = '{ "Category": "EnableOsVolume", "MountPoint": "Q:", "ProtectorId": "{AAAAAAAA-0000-4000-8000-000000000001}", "ScriptEnabledBitLocker": true, "EncryptionMethod": "XtsAes256" }'
        $file = '{ "Timestamp": "20260101_000000", "ComputerName": "TESTPC", "MountPoint": "Q:", "ProtectorId": "{AAAAAAAA-0000-4000-8000-000000000001}", "ScriptEnabledBitLocker": true, "EncryptionMethod": "XtsAes256", "ChangedSettings": [ ' + $enableEntry + ', ' + $Entry + ' ] }'
        Set-Content -LiteralPath (Join-Path $reports 'bitlocker-enable-rollback-20260101_000000.json') -Value $file -Encoding utf8
        $state = New-FveStateFile -Name "pin-forge-$([guid]::NewGuid().ToString('N'))" -Exists $true -Values $script:priorFve
        $run = Invoke-PinRun -Tag "pin-forge-$([guid]::NewGuid().ToString('N'))" -WhatIf -NoPin -Rollback -ReportDirectory $reports -Environment (Get-PinEnv -FveState $state)
        $run.Run.ExitCode | Should -Not -Be 0
        $run.Run.Output | Should -Match 'refused'
        @(Get-OpsMutationRecord -Path $run.Log).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $reports -Filter '*-rollback-plan-*' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'a refused file plans nothing'
    }
}

Describe 'Enable-BitLockerOsVolume pure checks lifted from the script' {
    BeforeAll {
        function Get-LiftedText {
            param([string[]]$Name)
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:realPath, [ref]$tokens, [ref]$errors)
            foreach ($n in $Name) {
                $hit = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $n })
                $hit.Count | Should -Be 1 -Because "the script must define $n once at its top level"
                $hit[0].Extent.Text
            }
        }

        # Runs the three pure functions against tables in one child process and returns the results as objects.
        $functions = (Get-LiftedText -Name 'Get-StartupPinProblem', 'Test-IsVirtualMachineIdentity', 'Get-RollbackPolicyEntryProblem') -join "`n"
        $body = @"
Set-StrictMode -Version 3.0
$functions
`$full = -join ([char]0xFF11, [char]0xFF12, [char]0xFF13, [char]0xFF14, [char]0xFF15, [char]0xFF16)
`$pins = [ordered]@{
    'six digits' = '482916'; 'twenty digits' = '12345678901234567890'; 'leading zeros' = '000000'
    'five digits' = '12345'; 'twenty-one digits' = '123456789012345678901'; 'letters' = '12ab56'
    'a space' = '123 456'; 'full-width digits' = `$full; 'empty' = ''
}
`$pinResult = foreach (`$k in `$pins.Keys) {
    `$secure = if (`$pins[`$k] -eq '') { [System.Security.SecureString]::new() } else { ConvertTo-SecureString `$pins[`$k] -AsPlainText -Force }
    [pscustomobject]@{ Case = `$k; Problem = [string](Get-StartupPinProblem -Pin `$secure) }
}
`$nullPin = [pscustomobject]@{ Case = 'null'; Problem = [string](Get-StartupPinProblem -Pin `$null) }
`$machines = @(
    @('Microsoft Corporation', 'Virtual Machine', `$true), @('VMware, Inc.', 'VMware20,1', `$true), @('innotek GmbH', 'VirtualBox', `$true)
    @('QEMU', 'Standard PC (Q35 + ICH9, 2009)', `$true), @('Xen', 'HVM domU', `$true), @('Amazon EC2', 'm5.large', `$true)
    @('Google', 'Google Compute Engine', `$true), @('Dell Inc.', 'Latitude 7440', `$false), @('LENOVO', '21HD', `$false)
    @('Microsoft Corporation', 'Surface Laptop 5', `$false), @('HP', 'HP EliteBook 840 G9', `$false)
)
`$vmResult = foreach (`$m in `$machines) {
    [pscustomobject]@{ Case = "`$(`$m[0])|`$(`$m[1])"; Expected = [bool]`$m[2]; Actual = [bool](Test-IsVirtualMachineIdentity -Manufacturer `$m[0] -Model `$m[1]) }
}
`$names = @('UseAdvancedStartup', 'UseTPMPIN')
function New-Rec { param([hashtable]`$Override = @{}) `$h = [ordered]@{ Category = 'FvePolicy'; Name = 'UseTPMPIN'; PriorValue = '2' }; foreach (`$k in `$Override.Keys) { if (`$Override[`$k] -eq '__remove__') { `$h.Remove(`$k) } else { `$h[`$k] = `$Override[`$k] } }; [pscustomobject]`$h }
`$recs = [ordered]@{
    'valid' = (New-Rec); 'absent prior' = (New-Rec @{ PriorValue = 'absent' }); 'unknown prior' = (New-Rec @{ PriorValue = 'unknown' })
    'extra field' = (New-Rec @{ Path = 'HKLM:\x' }); 'other name' = (New-Rec @{ Name = 'Other' }); 'name case' = (New-Rec @{ Name = 'usetpmpin' })
    'bad prior' = (New-Rec @{ PriorValue = 'abc' }); 'numeric prior' = (New-Rec @{ PriorValue = 5 }); 'long prior' = (New-Rec @{ PriorValue = '1234567890' })
    'wrong category' = (New-Rec @{ Category = 'x' }); 'no name' = (New-Rec @{ Name = '__remove__' }); 'null' = `$null
}
`$recResult = foreach (`$k in `$recs.Keys) {
    [pscustomobject]@{ Case = `$k; Problem = [string](Get-RollbackPolicyEntryProblem -Entry `$recs[`$k] -ControlName `$names -PolicyCategory 'FvePolicy') }
}
[pscustomobject]@{ Pins = @(`$pinResult) + @(`$nullPin); Vms = @(`$vmResult); Records = @(`$recResult) } | ConvertTo-Json -Depth 5 -Compress
"@
        $file = Join-Path $script:workRoot 'pin-lifted.ps1'
        Set-Content -LiteralPath $file -Value $body -Encoding utf8
        $text = (& pwsh -NoProfile -File $file 2>&1 | Out-String)
        $script:lifted = $text.Trim() | Select-String -Pattern '^\{.*\}$' | Select-Object -Last 1
        if ($script:lifted) { $script:liftedData = $script:lifted.Line | ConvertFrom-Json } else { $script:liftedData = $null; $script:liftedText = $text }
    }

    It 'accepts only 6 to 20 ASCII digits as a PIN and says nothing about the value' {
        $script:liftedData | Should -Not -BeNullOrEmpty -Because $script:liftedText
        $byCase = @{}
        foreach ($r in $script:liftedData.Pins) { $byCase[$r.Case] = $r.Problem }
        foreach ($ok in 'six digits', 'twenty digits', 'leading zeros') { $byCase[$ok] | Should -BeNullOrEmpty -Because $ok }
        foreach ($bad in 'five digits', 'twenty-one digits', 'letters', 'a space', 'full-width digits') {
            $byCase[$bad] | Should -Be 'the startup PIN must be 6 to 20 digits (0-9 only); the value is not recorded' -Because $bad
        }
        $byCase['empty'] | Should -Be 'no startup PIN was supplied'
        $byCase['null'] | Should -Be 'no startup PIN was supplied'
    }

    It 'recognises hypervisor guests by model or manufacturer and not physical hardware' {
        foreach ($r in $script:liftedData.Vms) { $r.Actual | Should -Be $r.Expected -Because $r.Case }
    }

    It 'validates a policy rollback record against the value table' {
        $byCase = @{}
        foreach ($r in $script:liftedData.Records) { $byCase[$r.Case] = $r.Problem }
        foreach ($ok in 'valid', 'absent prior', 'unknown prior') { $byCase[$ok] | Should -BeNullOrEmpty -Because $ok }
        foreach ($bad in 'extra field', 'other name', 'name case', 'bad prior', 'numeric prior', 'long prior', 'wrong category', 'no name', 'null') {
            $byCase[$bad] | Should -Not -BeNullOrEmpty -Because $bad
        }
    }
}
