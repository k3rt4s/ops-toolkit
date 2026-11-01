#Requires -Modules Pester

# Set-WindowsRemoteAccessPosture.ps1 and Set-WindowsLocalAccountPolicy.ps1, each run as a pair:
# -WhatIf must record no mutation, and the executing run must record the specific changes the plan
# promises.
#
# Every command that would change the machine is a recorder: registry writes, services, and net.exe
# come from Get-WindowsMutationStubText plus the setup below, and local account changes come from the
# staged Microsoft.PowerShell.LocalAccounts fake module. Registry reads are real unless a test
# shadows Get-ItemProperty with a fixture table, which these tests do for every key the scripts
# read, so no assertion depends on the machine the suite runs on.
#
# The session is normally not elevated. The scripts then mark every admin item 'Skipped: requires
# elevation' and make no change, so assertions on the executing run's mutations are skipped, while
# the plan JSON (which an unelevated run still writes) is asserted in full.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-hardra-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # The not-remote assertions are meaningless if the machine running the suite is itself in a
    # Remote Desktop session, because the script reads the real session metric as well.
    Add-Type -Namespace 'OpsTest' -Name 'SessionNative' -ErrorAction SilentlyContinue -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex);'
    $script:hostIsRemote = ([string]$env:SESSIONNAME -match '^RDP-') -or ([OpsTest.SessionNative]::GetSystemMetrics(0x1000) -ne 0)

    $script:tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $script:rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $script:raPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    $script:tsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $script:uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $script:lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    # Setup text that shadows Get-ItemProperty: a path in the table answers from the table (a $null
    # entry means the key does not exist), any other path reads the real registry.
    function ConvertTo-RegistryFixtureText {
        param([hashtable]$Table)
        $entries = foreach ($path in $Table.Keys) {
            $values = $Table[$path]
            if ($null -eq $values) { "'$path' = `$null"; continue }
            $inner = ($values.Keys | ForEach-Object { "'$_' = $($values[$_])" }) -join '; '
            "'$path' = @{ $inner }"
        }
        @"

`$global:OpsFixtureRegistry = @{
$($entries -join "`n")
}
function Get-ItemProperty {
    [CmdletBinding()]
    param(`$Path, `$LiteralPath, `$Name)
    `$target = if (`$LiteralPath) { [string]`$LiteralPath } else { [string]`$Path }
    if (`$global:OpsFixtureRegistry.ContainsKey(`$target)) {
        `$values = `$global:OpsFixtureRegistry[`$target]
        if (`$null -eq `$values) { throw [System.Management.Automation.ItemNotFoundException]::new('fixture: key absent') }
        return [pscustomobject]`$values
    }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
"@
    }

    # net.exe: bare 'accounts' replays the fixture text, anything else is a change and is recorded.
    function Get-NetExeStubText {
        param([string[]]$Line)
        $quoted = ($Line | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
        @"

`$global:OpsNetAccounts = @($quoted)
function net.exe {
    if ((`$args -join ' ') -eq 'accounts') { `$global:OpsNetAccounts; return }
    Write-OpsTestMutation -Command 'net.exe' -Target (`$args -join ' ') -Detail ''
}
"@
    }

    $script:netDefault = @(
        'Force user logoff how long after time expires?:       Never'
        'Minimum password age (days):                          0'
        'Maximum password age (days):                          42'
        'Minimum password length:                              0'
        'Length of password history maintained:                None'
        'Lockout threshold:                                    Never'
        'Lockout duration (minutes):                           30'
        'Lockout observation window (minutes):                 30'
        'Computer role:                                        WORKSTATION'
        'The command completed successfully.'
    )
    $script:netCompliant = @($script:netDefault | ForEach-Object {
            $_ -replace 'Lockout threshold:\s+Never', 'Lockout threshold:                                    10' `
                -replace 'duration \(minutes\):\s+30', 'duration (minutes):                           15' `
                -replace 'window \(minutes\):\s+30', 'window (minutes):                 15'
        })

    function Get-LatestJson {
        param([string]$Directory, [string]$Pattern)
        $file = Get-ChildItem -LiteralPath $Directory -Filter $Pattern -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty -Because "no $Pattern under $Directory"
        , @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json)
    }

    function Get-PlanItem {
        param($Plan, [string]$Setting)
        @($Plan | Where-Object { $_.Setting -eq $Setting }) | Select-Object -First 1
    }

    function Invoke-Pair {
        param([string]$Script, [string]$Tag, [hashtable]$Argument, [string]$Fixture = '', [string]$Extra = '')
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath "scripts\it-operations\windows-hardening\$Script" -Argument $Argument -Tag $Tag `
            -FixtureEnvironment $Fixture -ExtraSetup $Extra
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsRemoteAccessPosture' {
    BeforeAll {
        $script:raScript = 'Set-WindowsRemoteAccessPosture.ps1'
        $script:raEnabled = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 0 }
            $script:rdpTcpPath = @{ UserAuthentication = 0 }
            $script:raPath = @{ fAllowToGetHelp = 1 }
            $script:tsPolicyPath = $null
        }
        $script:raCompliant = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 0 }
            $script:rdpTcpPath = @{ UserAuthentication = 1; SecurityLayer = 2 }
            $script:raPath = @{ fAllowToGetHelp = 0 }
            $script:tsPolicyPath = $null
        }
        $script:raDisabled = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 1 }
            $script:rdpTcpPath = @{ UserAuthentication = 0 }
            $script:raPath = @{ fAllowToGetHelp = 0 }
            $script:tsPolicyPath = $null
        }
        $script:winrmStub = @'

$global:OpsWinRm = [string]$env:OPSTOOLKIT_TEST_WINRM
function Get-Service {
    [CmdletBinding()]
    param($Name)
    if ($global:OpsWinRm -eq 'error') { throw 'fixture: service control manager unavailable' }
    if (-not $global:OpsWinRm -or $global:OpsWinRm -eq 'absent') { return }
    $parts = $global:OpsWinRm -split '/'
    [pscustomobject]@{ Name = 'WinRM'; StartType = $parts[0]; Status = $parts[1] }
}
'@

        $dir = Join-Path $script:workRoot 'ra-default'
        $script:raDefault = Invoke-Pair -Script $script:raScript -Tag 'ra-default' -Argument @{ ReportDirectory = $dir } `
            -Fixture $script:raEnabled -Extra $script:winrmStub
        $script:raDefaultDir = $dir
    }

    It 'runs to completion in both modes' {
        $script:raDefault.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:raDefault.WhatIf.Output)"
        $script:raDefault.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:raDefault.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:raDefault
    }

    It 'plans NLA, the TLS security layer and Remote Assistance off when Remote Desktop is enabled' {
        $plan = Get-LatestJson -Directory $script:raDefaultDir -Pattern 'remote-access-posture-apply-plan-*.json'
        $nla = Get-PlanItem -Plan $plan -Setting 'UserAuthentication'
        $nla.DesiredValue | Should -Be 1
        $nla.Action | Should -BeLike 'Set *'
        $nla.Path | Should -Be $script:rdpTcpPath
        (Get-PlanItem -Plan $plan -Setting 'SecurityLayer').DesiredValue | Should -Be 2
        (Get-PlanItem -Plan $plan -Setting 'SecurityLayer').CurrentValue | Should -Be 'absent'
        (Get-PlanItem -Plan $plan -Setting 'fAllowToGetHelp').DesiredValue | Should -Be 0
        $plan.Setting | Should -Not -Contain 'fDenyTSConnections'
        $plan.Setting | Should -Not -Contain 'WinRM'
    }

    It 'lists the report-only items and never applies them' {
        $report = @($script:raDefault.Execute.Summary.Items | Where-Object { $_.Kind -eq 'Report' })
        $report.Count | Should -Be 2
        @($report.Result | Sort-Object -Unique) | Should -Be @('ReportOnly')
        $script:raDefault.Execute.Summary.ReportOnlyCount | Should -Be 2
        $script:raDefault.Execute.Summary.RebootRequired | Should -BeFalse
    }

    It 'writes the planned values and a rollback file when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $writes = @(Get-OpsMutationRecord -Path $script:raDefault.ExecuteLog | Where-Object { $_.Command -eq 'Set-ItemProperty' })
        $writes.Count | Should -Be 3
        ($writes | Where-Object { $_.Target -like '*\UserAuthentication' }).Detail | Should -Be '1'
        ($writes | Where-Object { $_.Target -like '*\SecurityLayer' }).Detail | Should -Be '2'
        ($writes | Where-Object { $_.Target -like '*\fAllowToGetHelp' }).Detail | Should -Be '0'
        $script:raDefault.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $rollback = Get-Content -LiteralPath $script:raDefault.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        $prior = @($rollback.ChangedSettings | Where-Object { $_.Name -eq 'SecurityLayer' })[0]
        $prior.PriorValue | Should -Be 'absent'
    }

    It 'reports NoChange and makes no write when the fixture already matches' {
        $dir = Join-Path $script:workRoot 'ra-nochange'
        $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-nochange' -Argument @{ ReportDirectory = $dir } -Fixture $script:raCompliant
        Assert-OpsNoChangeUnderWhatIf -Pair $pair
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        $pair.Execute.Summary.AppliedCount | Should -Be 0
        $pair.Execute.Summary.NoChangeCount | Should -Be 3
        $pair.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
    }

    It 'leaves NLA alone when Remote Desktop is disabled' {
        $dir = Join-Path $script:workRoot 'ra-rdpoff'
        $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-rdpoff' -Argument @{ ReportDirectory = $dir } -Fixture $script:raDisabled
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        $plan = Get-LatestJson -Directory $dir -Pattern 'remote-access-posture-apply-plan-*.json'
        (Get-PlanItem -Plan $plan -Setting 'UserAuthentication').Action | Should -BeLike 'No change*'
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
    }

    It 'treats an unreadable Remote Desktop state as unconfirmed, not enabled' {
        $dir = Join-Path $script:workRoot 'ra-rdpunknown'
        # The Terminal Server key throws something other than not-found, as an access failure would.
        $fixture = $script:raEnabled + @'

$global:OpsFixtureRegistry.Remove('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server')
function Get-ItemProperty {
    [CmdletBinding()]
    param($Path, $LiteralPath, $Name)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($target -like '*\Terminal Server') { throw [System.UnauthorizedAccessException]::new('fixture: denied') }
    if ($global:OpsFixtureRegistry.ContainsKey($target)) {
        $values = $global:OpsFixtureRegistry[$target]
        if ($null -eq $values) { throw [System.Management.Automation.ItemNotFoundException]::new('fixture: key absent') }
        return [pscustomobject]$values
    }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
'@
        $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-rdpunknown' -Argument @{ ReportDirectory = $dir } -Fixture $fixture
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        $plan = Get-LatestJson -Directory $dir -Pattern 'remote-access-posture-apply-plan-*.json'
        (Get-PlanItem -Plan $plan -Setting 'UserAuthentication').Action | Should -BeLike 'Skipped:*'
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Target -like '*UserAuthentication' }).Count | Should -Be 0
    }

    Context '-DisableRemoteDesktop' {
        It 'is refused when the session is a Remote Desktop session' {
            $dir = Join-Path $script:workRoot 'ra-rdp-remote'
            $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-rdp-remote' -Argument @{ ReportDirectory = $dir; DisableRemoteDesktop = $true } `
                -Fixture $script:raEnabled -Extra "`n`$env:SESSIONNAME = 'RDP-Tcp#0'`n"
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            $plan = Get-LatestJson -Directory $dir -Pattern 'remote-access-posture-apply-plan-*.json'
            (Get-PlanItem -Plan $plan -Setting 'fDenyTSConnections').Action | Should -Be 'Skipped: current session is remote'
            $item = $pair.Execute.Summary.Items | Where-Object { $_.Setting -eq 'fDenyTSConnections' }
            $item.Result | Should -Be 'Skipped: current session is remote'
            # Elevated or not, a refused item is never written.
            @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Target -like '*fDenyTSConnections' }).Count | Should -Be 0
        }

        It 'sets fDenyTSConnections to 1 from a local session' {
            if ($script:hostIsRemote) { Set-ItResult -Skipped -Because 'the test host is itself in a remote session'; return }
            $dir = Join-Path $script:workRoot 'ra-rdp-local'
            $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-rdp-local' -Argument @{ ReportDirectory = $dir; DisableRemoteDesktop = $true } `
                -Fixture $script:raEnabled -Extra "`n`$env:SESSIONNAME = 'Console'`n"
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $plan = Get-LatestJson -Directory $dir -Pattern 'remote-access-posture-apply-plan-*.json'
            $deny = Get-PlanItem -Plan $plan -Setting 'fDenyTSConnections'
            $deny.DesiredValue | Should -Be 1
            $deny.CurrentValue | Should -Be 0
            $deny.Action | Should -BeLike 'Set *'
            (Get-PlanItem -Plan $plan -Setting 'UserAuthentication').Action | Should -BeLike 'No change*'
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $writes = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*\fDenyTSConnections' })
            $writes.Count | Should -Be 1
            $writes[0].Detail | Should -Be '1'
        }
    }

    Context '-DisableWinRM' {
        It 'disables then stops a running Manual WinRM service and records the prior state' {
            $dir = Join-Path $script:workRoot 'ra-winrm'
            $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-winrm' -Argument @{ ReportDirectory = $dir; DisableWinRM = $true } `
                -Fixture ($script:raCompliant + "`n`$env:OPSTOOLKIT_TEST_WINRM = 'Manual/Running'`n") -Extra $script:winrmStub
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            $plan = Get-LatestJson -Directory $dir -Pattern 'remote-access-posture-apply-plan-*.json'
            $svc = Get-PlanItem -Plan $plan -Setting 'WinRM'
            $svc.CurrentValue | Should -Be 'Manual/Running'
            $svc.Action | Should -BeLike 'Set WinRM*'
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $mutations = @(Get-OpsMutationRecord -Path $pair.ExecuteLog)
            @($mutations | ForEach-Object { $_.Command }) | Should -Be @('Set-Service', 'Stop-Service')
            $mutations[0].Detail | Should -Be 'Disabled'
            $rollback = Get-Content -LiteralPath $pair.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
            $entry = @($rollback.ChangedSettings)[0]
            $entry.PriorValue | Should -Be 'Manual/Running'
            $entry.PriorStatus | Should -Be 'Running'
        }

        It 'reports NoChange when WinRM is already Disabled and Stopped, and when it is absent' {
            foreach ($case in @(@{ Name = 'ra-winrm-off'; Value = 'Disabled/Stopped'; Current = 'Disabled/Stopped' }, @{ Name = 'ra-winrm-absent'; Value = 'absent'; Current = 'absent' })) {
                $dir = Join-Path $script:workRoot $case.Name
                $pair = Invoke-Pair -Script $script:raScript -Tag $case.Name -Argument @{ ReportDirectory = $dir; DisableWinRM = $true } `
                    -Fixture ($script:raCompliant + "`n`$env:OPSTOOLKIT_TEST_WINRM = '$($case.Value)'`n") -Extra $script:winrmStub
                $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
                $item = $pair.Execute.Summary.Items | Where-Object { $_.Setting -eq 'WinRM' }
                $item.Result | Should -Be 'NoChange'
                $item.CurrentValue | Should -Be $case.Current
                @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
            }
        }

        It 'skips, rather than passes, a service state that cannot be read' {
            $dir = Join-Path $script:workRoot 'ra-winrm-error'
            $pair = Invoke-Pair -Script $script:raScript -Tag 'ra-winrm-error' -Argument @{ ReportDirectory = $dir; DisableWinRM = $true } `
                -Fixture ($script:raCompliant + "`n`$env:OPSTOOLKIT_TEST_WINRM = 'error'`n") -Extra $script:winrmStub
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            $item = $pair.Execute.Summary.Items | Where-Object { $_.Setting -eq 'WinRM' }
            $item.CurrentValue | Should -Be 'unknown'
            $item.Result | Should -BeLike 'Skipped:*'
        }
    }

    Context '-Rollback' {
        BeforeAll {
            $script:raRbDir = Join-Path $script:workRoot 'ra-rollback'
            New-Item -ItemType Directory -Path $script:raRbDir -Force | Out-Null
            $entries = @(
                @{ Category = 'RdpSecurityLayer'; Setting = 'SecurityLayer'; Kind = 'Registry'; Path = $script:rdpTcpPath; Name = 'SecurityLayer'; ValueType = 'DWord'; PriorStatus = ''; PriorValue = 'absent'; AppliedValue = 2 }
                @{ Category = 'RemoteAssistance'; Setting = 'fAllowToGetHelp'; Kind = 'Registry'; Path = $script:raPath; Name = 'fAllowToGetHelp'; ValueType = 'DWord'; PriorStatus = ''; PriorValue = 1; AppliedValue = 0 }
                @{ Category = 'WinRmService'; Setting = 'WinRM'; Kind = 'Service'; Path = ''; Name = ''; ValueType = ''; PriorStatus = 'Running'; PriorValue = 'Manual/Running'; AppliedValue = 'Disabled/Stopped' }
            )
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = $entries } | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath (Join-Path $script:raRbDir 'remote-access-posture-rollback-20260101_000000.json') -Encoding utf8
            $script:raRb = Invoke-Pair -Script $script:raScript -Tag 'ra-rollback' -Argument @{ ReportDirectory = $script:raRbDir; Rollback = $true } `
                -Fixture $script:raCompliant
        }

        It 'plans the prior values from the planted file and changes nothing under -WhatIf' {
            Assert-OpsNoChangeUnderWhatIf -Pair $script:raRb
            $script:raRb.Execute.ExitCode | Should -Be 0 -Because $script:raRb.Execute.Output
            $plan = Get-LatestJson -Directory $script:raRbDir -Pattern 'remote-access-posture-rollback-plan-*.json'
            (Get-PlanItem -Plan $plan -Setting 'SecurityLayer').DesiredValue | Should -Be 'absent'
            (Get-PlanItem -Plan $plan -Setting 'fAllowToGetHelp').DesiredValue | Should -Be 1
            (Get-PlanItem -Plan $plan -Setting 'WinRM').DesiredValue | Should -Be 'Manual/Running'
        }

        It 'restores absent by removing the value, and restores the service startup type and status' {
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $m = @(Get-OpsMutationRecord -Path $script:raRb.ExecuteLog)
            @($m | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -like '*\SecurityLayer' }).Count | Should -Be 1
            ($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*\fAllowToGetHelp' }).Detail | Should -Be '1'
            ($m | Where-Object { $_.Command -eq 'Set-Service' }).Detail | Should -Be 'Manual'
            @($m | Where-Object { $_.Command -eq 'Start-Service' }).Count | Should -Be 1
        }

        It 'fails with a clear message when there is no rollback file' {
            $empty = Join-Path $script:workRoot 'ra-rollback-none'
            $run = Invoke-ScriptUnderTest -RelativePath 'scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1' `
                -ModulePath $script:systemModulePath -Setup (Get-WindowsMutationStubText -MutationLogPath (Join-Path $script:workRoot 'ra-none.log')) `
                -Argument @{ ReportDirectory = $empty; Rollback = $true; WhatIf = $true }
            $run.ExitCode | Should -Not -Be 0
            $run.Output | Should -Match 'No remote-access-posture-rollback'
        }
    }
}

Describe 'Set-WindowsLocalAccountPolicy' {
    BeforeAll {
        $script:laScript = 'Set-WindowsLocalAccountPolicy.ps1'
        $script:uacNonCompliant = @{
            $script:uacPath = @{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 0 }
            $script:lsaPath = @{ LimitBlankPasswordUse = 0 }
        }
        $script:uacCompliant = @{
            $script:uacPath = @{ EnableLUA = 1; ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
            $script:lsaPath = @{ LimitBlankPasswordUse = 1 }
        }
        $script:sidBase = 'S-1-5-21-111111111-222222222-333333333'
        $script:usersTwoAdmins = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:sidBase)-500|True;Guest|$($script:sidBase)-501|True;alice|$($script:sidBase)-1001|True'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:sidBase)-500|User;HOST\alice|$($script:sidBase)-1001|User'`n"
        $script:usersOnlyBuiltIn = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:sidBase)-500|True;Guest|$($script:sidBase)-501|True;alice|$($script:sidBase)-1001|True'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:sidBase)-500|User'`n"
        $script:usersAliceDisabled = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:sidBase)-500|True;Guest|$($script:sidBase)-501|False;alice|$($script:sidBase)-1001|False'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:sidBase)-500|User;HOST\alice|$($script:sidBase)-1001|User'`n"
        $script:usersGuestOff = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:sidBase)-500|True;Guest|$($script:sidBase)-501|False;alice|$($script:sidBase)-1001|True'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:sidBase)-500|User;HOST\alice|$($script:sidBase)-1001|User'`n"

        $fixture = (ConvertTo-RegistryFixtureText -Table $script:uacNonCompliant) + $script:usersTwoAdmins
        $dir = Join-Path $script:workRoot 'la-default'
        $script:laDefault = Invoke-Pair -Script $script:laScript -Tag 'la-default' -Argument @{ ReportDirectory = $dir } `
            -Fixture $fixture -Extra (Get-NetExeStubText -Line $script:netDefault)
        $script:laDefaultDir = $dir
    }

    It 'runs to completion in both modes' {
        $script:laDefault.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:laDefault.WhatIf.Output)"
        $script:laDefault.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:laDefault.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:laDefault
    }

    It 'plans the default lockout values with the window lowered before the duration' {
        $plan = Get-LatestJson -Directory $script:laDefaultDir -Pattern 'local-account-policy-apply-plan-*.json'
        $lockout = @($plan | Where-Object { $_.Category -eq 'Lockout' })
        # Current window 30, desired duration 15: lowering the duration first would leave window 30 above it.
        @($lockout.Setting) | Should -Be @('lockoutthreshold', 'lockoutwindow', 'lockoutduration')
        (Get-PlanItem -Plan $plan -Setting 'lockoutthreshold').DesiredValue | Should -Be 10
        (Get-PlanItem -Plan $plan -Setting 'lockoutthreshold').CurrentValue | Should -Be 0
        (Get-PlanItem -Plan $plan -Setting 'lockoutduration').DesiredValue | Should -Be 15
        (Get-PlanItem -Plan $plan -Setting 'lockoutwindow').DesiredValue | Should -Be 15
        (Get-PlanItem -Plan $plan -Setting 'lockoutwindow').CurrentValue | Should -Be 30
    }

    It 'plans Guest disabled by SID and the UAC and blank-password values, but not the opt-in account changes' {
        $plan = Get-LatestJson -Directory $script:laDefaultDir -Pattern 'local-account-policy-apply-plan-*.json'
        $guest = Get-PlanItem -Plan $plan -Setting 'Guest account'
        $guest.Sid | Should -Be "$($script:sidBase)-501"
        $guest.Action | Should -Be 'Disable the Guest account'
        (Get-PlanItem -Plan $plan -Setting 'EnableLUA').DesiredValue | Should -Be 1
        (Get-PlanItem -Plan $plan -Setting 'EnableLUA').RequiresReboot | Should -BeTrue
        (Get-PlanItem -Plan $plan -Setting 'ConsentPromptBehaviorAdmin').DesiredValue | Should -Be 2
        (Get-PlanItem -Plan $plan -Setting 'PromptOnSecureDesktop').DesiredValue | Should -Be 1
        (Get-PlanItem -Plan $plan -Setting 'LimitBlankPasswordUse').DesiredValue | Should -Be 1
        $plan.Setting | Should -Not -Contain 'Built-in Administrator'
        $plan.Setting | Should -Not -Contain 'Built-in Administrator name'
    }

    It 'reports the Administrators group and whether the current user is a member, without changing anything' {
        $report = $script:laDefault.Execute.Summary.Items | Where-Object { $_.Category -eq 'AdministratorsMembers' }
        $report.Result | Should -Be 'ReportOnly'
        $report.CurrentValue | Should -Match '2 member\(s\)'
        $report.CurrentValue | Should -Match 'current user is a member: (True|False)'
    }

    It 'applies lockout via net.exe in window-before-duration order, disables Guest by SID, and writes UAC when executing elevated' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $m = @(Get-OpsMutationRecord -Path $script:laDefault.ExecuteLog)
        @($m | Where-Object { $_.Command -eq 'net.exe' } | ForEach-Object { $_.Target }) |
            Should -Be @('accounts /lockoutthreshold:10', 'accounts /lockoutwindow:15', 'accounts /lockoutduration:15')
        $disable = @($m | Where-Object { $_.Command -eq 'Disable-LocalUser' })
        $disable.Count | Should -Be 1
        $disable[0].Target | Should -Be "$($script:sidBase)-501"
        ($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*\EnableLUA' }).Detail | Should -Be '1'
        ($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*\ConsentPromptBehaviorAdmin' }).Detail | Should -Be '2'
        $script:laDefault.Execute.Summary.RebootRequired | Should -BeTrue
        $rollback = Get-Content -LiteralPath $script:laDefault.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        (@($rollback.ChangedSettings) | Where-Object { $_.Setting -eq 'lockoutwindow' }).PriorValue | Should -Be 30
    }

    It 'reports NoChange and makes no write when the fixture already matches' {
        $dir = Join-Path $script:workRoot 'la-nochange'
        $pair = Invoke-Pair -Script $script:laScript -Tag 'la-nochange' -Argument @{ ReportDirectory = $dir } `
            -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) `
            -Extra (Get-NetExeStubText -Line $script:netCompliant)
        Assert-OpsNoChangeUnderWhatIf -Pair $pair
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog).Count | Should -Be 0
        $pair.Execute.Summary.AppliedCount | Should -Be 0
        $pair.Execute.Summary.SkippedCount | Should -Be 0
        $pair.Execute.Summary.NoChangeCount | Should -Be 8
        $pair.Execute.Summary.RebootRequired | Should -BeFalse
    }

    It 'honours custom lockout values and rejects a window longer than the duration' {
        $dir = Join-Path $script:workRoot 'la-custom'
        $pair = Invoke-Pair -Script $script:laScript -Tag 'la-custom' `
            -Argument @{ ReportDirectory = $dir; LockoutThreshold = 5; LockoutDurationMinutes = 60; LockoutObservationWindowMinutes = 45 } `
            -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $script:netDefault)
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        $plan = Get-LatestJson -Directory $dir -Pattern 'local-account-policy-apply-plan-*.json'
        # Raising both: duration (60) is not below the current window (30), so it goes first.
        @(@($plan | Where-Object { $_.Category -eq 'Lockout' }).Setting) | Should -Be @('lockoutthreshold', 'lockoutduration', 'lockoutwindow')
        (Get-PlanItem -Plan $plan -Setting 'lockoutduration').DesiredValue | Should -Be 60

        $bad = Invoke-ScriptUnderTest -RelativePath "scripts\it-operations\windows-hardening\$($script:laScript)" -ModulePath $script:systemModulePath `
            -Setup (Get-WindowsMutationStubText -MutationLogPath (Join-Path $script:workRoot 'la-bad.log')) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'la-bad'); LockoutDurationMinutes = 10; LockoutObservationWindowMinutes = 20; WhatIf = $true }
        $bad.ExitCode | Should -Not -Be 0
        $bad.Output | Should -Match 'cannot exceed'
    }

    It 'skips the lockout items, applying nothing blind, when net accounts output cannot be parsed' {
        $dir = Join-Path $script:workRoot 'la-unparseable'
        $garbled = @('Force user logoff: Never', 'Lockout threshold: ten', 'Something unexpected happened.')
        $pair = Invoke-Pair -Script $script:laScript -Tag 'la-unparseable' -Argument @{ ReportDirectory = $dir } `
            -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $garbled)
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        $lockout = @($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'Lockout' })
        $lockout.Count | Should -Be 3
        @($lockout.CurrentValue | Sort-Object -Unique) | Should -Be @('unknown')
        foreach ($i in $lockout) { $i.Result | Should -BeLike 'Skipped:*' }
        @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'net.exe' }).Count | Should -Be 0
    }

    It 'skips a lockout line whose threshold, duration or window is not in the expected shape' {
        $dir = Join-Path $script:workRoot 'la-shape'
        # Ten data lines instead of nine: a changed layout must not be read by position.
        $shifted = @('Extra line added by a future Windows:        1') + $script:netDefault
        $pair = Invoke-Pair -Script $script:laScript -Tag 'la-shape' -Argument @{ ReportDirectory = $dir } `
            -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $shifted)
        $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
        @($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'Lockout' -and $_.Result -like 'Skipped:*' }).Count | Should -Be 3
    }

    Context '-DisableBuiltInAdministrator' {
        It 'is refused when the built-in account is the only enabled administrator' {
            $dir = Join-Path $script:workRoot 'la-admin-only'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-admin-only' -Argument @{ ReportDirectory = $dir; DisableBuiltInAdministrator = $true } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersOnlyBuiltIn) -Extra (Get-NetExeStubText -Line $script:netCompliant)
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            $item = $pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'BuiltInAdminDisable' }
            $item.Result | Should -BeLike 'Skipped: no other enabled local administrator*'
            @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Disable-LocalUser' -and $_.Target -like '*-500' }).Count | Should -Be 0
        }

        It 'is refused when the only other administrator is disabled' {
            $dir = Join-Path $script:workRoot 'la-admin-disabled-other'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-admin-disabled-other' -Argument @{ ReportDirectory = $dir; DisableBuiltInAdministrator = $true } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersAliceDisabled) -Extra (Get-NetExeStubText -Line $script:netCompliant)
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            ($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'BuiltInAdminDisable' }).Result | Should -BeLike 'Skipped:*'
            @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Disable-LocalUser' -and $_.Target -like '*-500' }).Count | Should -Be 0
        }

        It 'is refused, not assumed safe, when the Administrators group cannot be read' {
            $dir = Join-Path $script:workRoot 'la-admin-unreadable'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-admin-unreadable' -Argument @{ ReportDirectory = $dir; DisableBuiltInAdministrator = $true } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersTwoAdmins + "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS_ERROR = '1'`n") `
                -Extra (Get-NetExeStubText -Line $script:netCompliant)
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            ($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'BuiltInAdminDisable' }).Result | Should -BeLike 'Skipped:*'
            ($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'AdministratorsMembers' }).CurrentValue | Should -Be 'unknown'
            @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Disable-LocalUser' -and $_.Target -like '*-500' }).Count | Should -Be 0
        }

        It 'disables the -500 account by SID when another enabled administrator exists' {
            $dir = Join-Path $script:workRoot 'la-admin-ok'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-admin-ok' -Argument @{ ReportDirectory = $dir; DisableBuiltInAdministrator = $true } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $script:netCompliant)
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $plan = Get-LatestJson -Directory $dir -Pattern 'local-account-policy-apply-plan-*.json'
            $item = Get-PlanItem -Plan $plan -Setting 'Built-in Administrator'
            $item.Action | Should -Be 'Disable the built-in Administrator account'
            $item.Sid | Should -Be "$($script:sidBase)-500"
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $d = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Disable-LocalUser' })
            $d.Count | Should -Be 1
            $d[0].Target | Should -Be "$($script:sidBase)-500"
        }
    }

    Context '-RenameBuiltInAdministrator' {
        It 'renames the -500 account by SID and records the prior name' {
            $dir = Join-Path $script:workRoot 'la-rename'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-rename' -Argument @{ ReportDirectory = $dir; RenameBuiltInAdministrator = 'labadmin' } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $script:netCompliant)
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $plan = Get-LatestJson -Directory $dir -Pattern 'local-account-policy-apply-plan-*.json'
            $item = Get-PlanItem -Plan $plan -Setting 'Built-in Administrator name'
            $item.CurrentValue | Should -Be 'Administrator'
            $item.DesiredValue | Should -Be 'labadmin'
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $r = @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Rename-LocalUser' })
            $r.Count | Should -Be 1
            $r[0].Target | Should -Be "$($script:sidBase)-500"
            $r[0].Detail | Should -Be 'labadmin'
            $rollback = Get-Content -LiteralPath $pair.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
            @($rollback.ChangedSettings)[0].PriorValue | Should -Be 'Administrator'
        }

        It 'skips a name another account already uses and rejects an invalid name' {
            $dir = Join-Path $script:workRoot 'la-rename-clash'
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-rename-clash' -Argument @{ ReportDirectory = $dir; RenameBuiltInAdministrator = 'alice' } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersGuestOff) -Extra (Get-NetExeStubText -Line $script:netCompliant)
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            ($pair.Execute.Summary.Items | Where-Object { $_.Category -eq 'BuiltInAdminRename' }).Result | Should -BeLike 'Skipped:*'
            @(Get-OpsMutationRecord -Path $pair.ExecuteLog | Where-Object { $_.Command -eq 'Rename-LocalUser' }).Count | Should -Be 0

            $bad = Invoke-ScriptUnderTest -RelativePath "scripts\it-operations\windows-hardening\$($script:laScript)" -ModulePath $script:systemModulePath `
                -Setup (Get-WindowsMutationStubText -MutationLogPath (Join-Path $script:workRoot 'la-badname.log')) `
                -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'la-badname'); RenameBuiltInAdministrator = 'bad;name'; WhatIf = $true }
            $bad.ExitCode | Should -Not -Be 0
        }
    }

    Context 'null shapes' {
        It 'completes with every read empty or failing and applies nothing blind' {
            $dir = Join-Path $script:workRoot 'la-nulls'
            $fixture = (ConvertTo-RegistryFixtureText -Table @{ $script:uacPath = $null; $script:lsaPath = $null }) +
            "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS_ERROR = '1'`n"
            $pair = Invoke-Pair -Script $script:laScript -Tag 'la-nulls' `
                -Argument @{ ReportDirectory = $dir; DisableBuiltInAdministrator = $true; RenameBuiltInAdministrator = 'labadmin' } `
                -Fixture $fixture -Extra (Get-NetExeStubText -Line @())
            Assert-OpsNoChangeUnderWhatIf -Pair $pair
            $pair.Execute.ExitCode | Should -Be 0 -Because $pair.Execute.Output
            foreach ($cat in 'GuestAccount', 'BuiltInAdminDisable', 'BuiltInAdminRename', 'Lockout') {
                foreach ($i in @($pair.Execute.Summary.Items | Where-Object { $_.Category -eq $cat })) {
                    $i.Result | Should -BeLike 'Skipped:*' -Because $cat
                    $i.CurrentValue | Should -Be 'unknown'
                }
            }
            # Missing registry keys are 'absent' and are set, which needs elevation.
            (Get-PlanItem -Plan (Get-LatestJson -Directory $dir -Pattern 'local-account-policy-apply-plan-*.json') -Setting 'EnableLUA').CurrentValue | Should -Be 'absent'
        }
    }

    Context '-Rollback' {
        BeforeAll {
            $script:laRbDir = Join-Path $script:workRoot 'la-rollback'
            New-Item -ItemType Directory -Path $script:laRbDir -Force | Out-Null
            $sid = $script:sidBase
            $entries = @(
                @{ Category = 'Lockout'; Setting = 'lockoutthreshold'; Kind = 'Lockout'; Path = ''; Name = ''; ValueType = ''; Sid = ''; PriorValue = 0; AppliedValue = 10 }
                @{ Category = 'Lockout'; Setting = 'lockoutwindow'; Kind = 'Lockout'; Path = ''; Name = ''; ValueType = ''; Sid = ''; PriorValue = 30; AppliedValue = 15 }
                @{ Category = 'Lockout'; Setting = 'lockoutduration'; Kind = 'Lockout'; Path = ''; Name = ''; ValueType = ''; Sid = ''; PriorValue = 30; AppliedValue = 15 }
                @{ Category = 'GuestAccount'; Setting = 'Guest account'; Kind = 'LocalUserEnabled'; Path = ''; Name = ''; ValueType = ''; Sid = "$sid-501"; PriorValue = 'Enabled'; AppliedValue = 'Disabled' }
                @{ Category = 'BuiltInAdminRename'; Setting = 'Built-in Administrator name'; Kind = 'LocalUserName'; Path = ''; Name = ''; ValueType = ''; Sid = "$sid-500"; PriorValue = 'Administrator'; AppliedValue = 'labadmin' }
                @{ Category = 'UacEnableLua'; Setting = 'EnableLUA'; Kind = 'Registry'; Path = $script:uacPath; Name = 'EnableLUA'; ValueType = 'DWord'; Sid = ''; PriorValue = 'absent'; AppliedValue = 1 }
                @{ Category = 'UacConsentPrompt'; Setting = 'ConsentPromptBehaviorAdmin'; Kind = 'Registry'; Path = $script:uacPath; Name = 'ConsentPromptBehaviorAdmin'; ValueType = 'DWord'; Sid = ''; PriorValue = 5; AppliedValue = 2 }
            )
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = $entries } | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath (Join-Path $script:laRbDir 'local-account-policy-rollback-20260101_000000.json') -Encoding utf8
            $script:laRb = Invoke-Pair -Script $script:laScript -Tag 'la-rollback' -Argument @{ ReportDirectory = $script:laRbDir; Rollback = $true } `
                -Fixture ((ConvertTo-RegistryFixtureText -Table $script:uacCompliant) + $script:usersTwoAdmins) -Extra (Get-NetExeStubText -Line $script:netCompliant)
        }

        It 'plans the prior values from the planted file and changes nothing under -WhatIf' {
            Assert-OpsNoChangeUnderWhatIf -Pair $script:laRb
            $script:laRb.Execute.ExitCode | Should -Be 0 -Because $script:laRb.Execute.Output
            $plan = Get-LatestJson -Directory $script:laRbDir -Pattern 'local-account-policy-rollback-plan-*.json'
            (Get-PlanItem -Plan $plan -Setting 'lockoutthreshold').DesiredValue | Should -Be 0
            (Get-PlanItem -Plan $plan -Setting 'Guest account').DesiredValue | Should -Be 'Enabled'
            (Get-PlanItem -Plan $plan -Setting 'Built-in Administrator name').DesiredValue | Should -Be 'Administrator'
            (Get-PlanItem -Plan $plan -Setting 'EnableLUA').DesiredValue | Should -Be 'absent'
            # Restoring a duration of 30 above the applied window of 15: duration first, then window.
            @(@($plan | Where-Object { $_.Category -eq 'Lockout' }).Setting) | Should -Be @('lockoutthreshold', 'lockoutduration', 'lockoutwindow')
        }

        It 'restores the account state, lockout values and registry values when executing elevated' {
            if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
            $m = @(Get-OpsMutationRecord -Path $script:laRb.ExecuteLog)
            @($m | Where-Object { $_.Command -eq 'net.exe' } | ForEach-Object { $_.Target }) |
                Should -Be @('accounts /lockoutthreshold:0', 'accounts /lockoutduration:30', 'accounts /lockoutwindow:30')
            ($m | Where-Object { $_.Command -eq 'Enable-LocalUser' }).Target | Should -Be "$($script:sidBase)-501"
            ($m | Where-Object { $_.Command -eq 'Rename-LocalUser' }).Detail | Should -Be 'Administrator'
            @($m | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -like '*\EnableLUA' }).Count | Should -Be 1
            ($m | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -like '*\ConsentPromptBehaviorAdmin' }).Detail | Should -Be '5'
        }
    }
}

Describe 'Set-WindowsRemoteAccessPosture rollback safety' {
    BeforeAll {
        $script:raSafeCounter = 0
        $script:raSafeScript = 'scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1'
        $script:raSafeFullPath = Join-Path (Get-RepositoryRoot) $script:raSafeScript
        $script:raSafeName = 'remote-access-posture-rollback-20260101_000000.json'
        $script:raSafeWinRm = @'

$global:OpsWinRm = [string]$env:OPSTOOLKIT_TEST_WINRM
function Get-Service {
    [CmdletBinding()]
    param($Name)
    if (-not $global:OpsWinRm -or $global:OpsWinRm -eq 'absent') { return }
    $parts = $global:OpsWinRm -split '/'
    [pscustomobject]@{ Name = 'WinRM'; StartType = $parts[0]; Status = $parts[1] }
}
'@

        function Get-RaLiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:raSafeFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        function New-RaSafeDir {
            $script:raSafeCounter++
            $dir = Join-Path $script:workRoot "raSafety$($script:raSafeCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        function New-RaRegEntry {
            param($Category = 'RemoteAssistance', $Path = $script:raPath, $Name = 'fAllowToGetHelp', $Prior = 1, $Kind = 'Registry', $PriorStatus = '', $Setting = $null)
            if ($null -eq $Setting) { $Setting = $Name }
            [pscustomobject]@{ Category = $Category; Setting = $Setting; Kind = $Kind; Path = $Path; Name = $Name; ValueType = 'DWord'; PriorStatus = $PriorStatus; PriorValue = $Prior; AppliedValue = 0 }
        }

        function New-RaServiceEntry {
            param($Setting = 'WinRM', $Prior = 'Manual/Running', $PriorStatus = 'Running', $Path = '', $Name = '')
            [pscustomobject]@{ Category = 'WinRmService'; Setting = $Setting; Kind = 'Service'; Path = $Path; Name = $Name; ValueType = ''; PriorStatus = $PriorStatus; PriorValue = $Prior; AppliedValue = 'Disabled/Stopped' }
        }

        function Write-RaRollbackFile {
            param([string]$Dir, [string]$Name = $script:raSafeName, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-RaRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute)
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $run = Invoke-ScriptUnderTest -RelativePath $script:raSafeScript -ModulePath $script:systemModulePath `
                -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $script:raSafeWinRm) -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Assert-RaRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-RaRollback -Dir $Dir -Tag "raRefused$($script:raSafeCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'remote-access-posture-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'remote-access-posture-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because "$Because must be refused before any change"
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the registry values and service the forward plan sets, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'unknown category'; Entry = (New-RaRegEntry -Category 'DeleteEverything') },
            @{ Name = 'path outside the control'; Entry = (New-RaRegEntry -Path 'HKLM:\SOFTWARE\Evil') },
            @{ Name = 'path of another control'; Entry = (New-RaRegEntry -Category 'RdpNla' -Path $script:raPath -Name 'UserAuthentication') },
            @{ Name = 'value name outside the control'; Entry = (New-RaRegEntry -Name 'fAllowFullControl') },
            @{ Name = 'Setting differs from Name'; Entry = (New-RaRegEntry -Setting 'Other') },
            @{ Name = 'registry category with Kind Service'; Entry = (New-RaRegEntry -Kind 'Service') },
            @{ Name = 'registry entry carrying a PriorStatus'; Entry = (New-RaRegEntry -PriorStatus 'Running') },
            @{ Name = 'service other than WinRM'; Entry = (New-RaServiceEntry -Setting 'Spooler') },
            @{ Name = 'service entry with a registry path'; Entry = (New-RaServiceEntry -Path $script:raPath) },
            @{ Name = 'service start type outside the restorable set'; Entry = (New-RaServiceEntry -Prior 'Evil/Running') },
            @{ Name = 'service status outside the set'; Entry = (New-RaServiceEntry -Prior 'Manual/Exploded' -PriorStatus 'Exploded') }
        )
        foreach ($case in $cases) {
            $dir = New-RaSafeDir
            $null = Write-RaRollbackFile -Dir $dir -Entry @((New-RaRegEntry), $case.Entry)
            Assert-RaRefused -Dir $dir -FileName $script:raSafeName -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-RaSafeDir
        $null = Write-RaRollbackFile -Dir $dir -Entry @((New-RaRegEntry), (New-RaRegEntry), (New-RaRegEntry -Category 'Evil'))
        $r = Invoke-RaRollback -Dir $dir -Tag 'raIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 2 '
        $r.Run.Output | Should -Match 'Evil'
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "RemoteAssistance" } }'
            'ChangedSettings a string'  = '{ "ChangedSettings": "all" }'
            'ChangedSettings one valid entry, not in an array' = ('{ "ChangedSettings": ' + ((New-RaRegEntry) | ConvertTo-Json -Compress) + ' }')
            'top level is an array'     = '[ { "Category": "RemoteAssistance" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "RemoteAssistance" ] }'
            'entry lacks PriorValue'    = '{ "ChangedSettings": [ { "Category": "RemoteAssistance", "Setting": "fAllowToGetHelp", "Kind": "Registry", "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "Name": "fAllowToGetHelp" } ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-RaSafeDir
            Set-Content -LiteralPath (Join-Path $dir $script:raSafeName) -Value $bodies[$label] -Encoding utf8
            Assert-RaRefused -Dir $dir -FileName $script:raSafeName -Because $label
        }
    }

    It 'refuses a prior value of the wrong type or outside the range of its control' {
        $cases = @(
            @{ Name = 'word maybe'; Entry = (New-RaRegEntry -Prior 'maybe') },
            @{ Name = 'unknown'; Entry = (New-RaRegEntry -Prior 'unknown') },
            @{ Name = 'numeric text'; Entry = (New-RaRegEntry -Prior '1') },
            @{ Name = 'above the range of fAllowToGetHelp'; Entry = (New-RaRegEntry -Prior 2) },
            @{ Name = 'negative'; Entry = (New-RaRegEntry -Prior -1) },
            @{ Name = 'fraction'; Entry = (New-RaRegEntry -Prior 0.5) },
            @{ Name = 'boolean'; Entry = (New-RaRegEntry -Prior $true) },
            @{ Name = 'null'; Entry = (New-RaRegEntry -Prior $null) },
            @{ Name = 'array'; Entry = (New-RaRegEntry -Prior @(0, 1)) },
            @{ Name = 'SecurityLayer above 2'; Entry = (New-RaRegEntry -Category 'RdpSecurityLayer' -Path $script:rdpTcpPath -Name 'SecurityLayer' -Prior 3) },
            @{ Name = 'service prior without a status'; Entry = (New-RaServiceEntry -Prior 'Manual') },
            @{ Name = 'service prior is a number'; Entry = (New-RaServiceEntry -Prior 3) },
            @{ Name = 'service PriorStatus disagrees with PriorValue'; Entry = (New-RaServiceEntry -Prior 'Manual/Stopped' -PriorStatus 'Running') }
        )
        foreach ($case in $cases) {
            $dir = New-RaSafeDir
            $null = Write-RaRollbackFile -Dir $dir -Entry @($case.Entry)
            Assert-RaRefused -Dir $dir -FileName $script:raSafeName -Because $case.Name
        }
    }

    It 'accepts every entry the forward plan can produce, so the validator cannot drift from it' {
        $fixture = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 0 }
            $script:rdpTcpPath = @{ UserAuthentication = 0 }
            $script:raPath = @{ fAllowToGetHelp = 1 }
            $script:tsPolicyPath = $null
        }
        $log = Join-Path $script:workRoot 'raDriftApply.log'
        $apply = Invoke-ScriptUnderTest -RelativePath $script:raSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $fixture + "`n`$env:OPSTOOLKIT_TEST_WINRM = 'Manual/Running'`n" + $script:raSafeWinRm) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'raDriftPlan'); DisableRemoteDesktop = $true; DisableWinRM = $true; WhatIf = $true }
        $apply.ExitCode | Should -Be 0 -Because $apply.Output
        $forward = @(Get-Content -LiteralPath $apply.Summary.PlanJsonPath -Raw | ConvertFrom-Json | Where-Object { $_.Kind -in @('Registry', 'Service') })
        @($forward | ForEach-Object { $_.Category } | Sort-Object) | Should -Be @('RdpDisable', 'RdpNla', 'RdpSecurityLayer', 'RemoteAssistance', 'WinRmService')
        $entries = @($forward | ForEach-Object {
                [pscustomobject]@{ Category = $_.Category; Setting = $_.Setting; Kind = $_.Kind; Path = $_.Path; Name = $_.Name; ValueType = $_.ValueType
                    PriorStatus = $_.PriorStatus; PriorValue = $_.CurrentValue; AppliedValue = $_.DesiredValue }
            })
        $dir = New-RaSafeDir
        $null = Write-RaRollbackFile -Dir $dir -Entry $entries
        $r = Invoke-RaRollback -Dir $dir -Tag 'raDriftRollback'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items).Count | Should -Be 5
    }

    It 'picks the newest rollback file by name and not a consumed one' {
        $dir = New-RaSafeDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'remote-access-posture-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-RaRollbackFile -Dir $dir -Entry @((New-RaRegEntry -Prior 1))
        $r = Invoke-RaRollback -Dir $dir -Tag 'raConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        $plan = Get-Content -LiteralPath $r.Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('fAllowToGetHelp')

        # Name order, not write time: the file with the earlier name is written last.
        $dir2 = New-RaSafeDir
        $newerName = Write-RaRollbackFile -Dir $dir2 -Name 'remote-access-posture-rollback-20260201_000000.json' -Entry @((New-RaRegEntry -Prior 0))
        Start-Sleep -Milliseconds 50
        $null = Write-RaRollbackFile -Dir $dir2 -Name 'remote-access-posture-rollback-20260101_000000.json' -Entry @((New-RaRegEntry -Prior 1))
        $r2 = Invoke-RaRollback -Dir $dir2 -Tag 'raNameOrder'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        (Split-Path -Leaf $r2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $newerName)
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-RaSafeDir
        $file = Write-RaRollbackFile -Dir $dir -Entry @((New-RaRegEntry))
        $r = Invoke-RaRollback -Dir $dir -Tag 'raUnelevatedExec' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:raSafeName
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf' {
        $dir = New-RaSafeDir
        $file = Write-RaRollbackFile -Dir $dir -Entry @((New-RaRegEntry))
        $r = Invoke-RaRollback -Dir $dir -Tag 'raWhatIfKeeps'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:raSafeName
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0

        # With nothing to revert there is no item to preview, so only the -WhatIf rule itself keeps the file.
        $dir2 = New-RaSafeDir
        $file2 = Write-RaRollbackFile -Dir $dir2 -Entry @()
        $r2 = Invoke-RaRollback -Dir $dir2 -Tag 'raWhatIfKeeps2'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        Test-Path -LiteralPath $file2 | Should -BeTrue
        $r2.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
    }

    It 'consumes the file after an executing rollback with nothing left to revert' {
        $dir = New-RaSafeDir
        $file = Write-RaRollbackFile -Dir $dir -Entry @()
        $r = Invoke-RaRollback -Dir $dir -Tag 'raConsumeEmpty' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'remote-access-posture-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        $again = Invoke-RaRollback -Dir $dir -Tag 'raConsumeEmpty2' -Execute
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
    }

    It 'decides consumption in a pure function lifted from the script' {
        $text = Get-RaLiftedFunctionText -Name 'Test-RollbackFileConsumable'
        $decide = [scriptblock]::Create("param(`$State, [bool]`$Preview)`n$text`nTest-RollbackFileConsumable -State `$State -Preview `$Preview")
        function New-RaState { param([string[]]$Result) @($Result | ForEach-Object { [pscustomobject]@{ Result = $_ } }) }

        & $decide (New-RaState 'Reverted', 'NoChange', 'Reverted') $false | Should -BeTrue
        & $decide (New-RaState 'NoChange') $false | Should -BeTrue
        & $decide (New-RaState 'Reverted', 'Failed: access denied') $false | Should -BeFalse
        & $decide (New-RaState 'Reverted', 'Skipped: requires elevation') $false | Should -BeFalse
        & $decide (New-RaState 'Previewed', 'Previewed') $false | Should -BeFalse
        & $decide (New-RaState 'Reverted', 'Previewed') $false | Should -BeFalse
        & $decide (New-RaState 'Reverted', 'Reverted') $true | Should -BeFalse -Because '-WhatIf never consumes'
        & $decide (New-RaState 'NoChange') $true | Should -BeFalse
    }

    It 'validates one entry in a pure function lifted from the script, against the tables it is given' {
        $text = Get-RaLiftedFunctionText -Name 'Get-RollbackEntryProblem'
        $check = [scriptblock]::Create("param(`$Entry, `$Registry, `$Service)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -RegistryControls `$Registry -ServiceControl `$Service")
        $registry = @([pscustomobject]@{ Category = 'RemoteAssistance'; Path = $script:raPath; Name = 'fAllowToGetHelp'; Min = 0; Max = 1 })
        $service = [pscustomobject]@{ Category = 'WinRmService'; ServiceName = 'WinRM'; StartupTypes = @('Manual', 'Disabled'); Statuses = @('Running', 'Stopped') }

        & $check (New-RaRegEntry -Prior 1) $registry $service | Should -BeNullOrEmpty
        & $check (New-RaRegEntry -Prior 0) $registry $service | Should -BeNullOrEmpty
        & $check (New-RaRegEntry -Prior 'absent') $registry $service | Should -BeNullOrEmpty
        & $check (New-RaServiceEntry) $registry $service | Should -BeNullOrEmpty
        & $check (New-RaRegEntry -Prior 2) $registry $service | Should -Not -BeNullOrEmpty
        & $check (New-RaRegEntry -Prior 'Absent') $registry $service | Should -Not -BeNullOrEmpty -Because 'absent is matched exactly'
        & $check (New-RaRegEntry -Category 'RdpNla' -Path $script:rdpTcpPath -Name 'UserAuthentication') $registry $service | Should -Not -BeNullOrEmpty -Because 'the category is not in the table it was given'
        & $check (New-RaServiceEntry -Prior 'Automatic/Running') $registry $service | Should -Not -BeNullOrEmpty -Because 'the start type is not in the list it was given'
        & $check $null $registry $service | Should -Not -BeNullOrEmpty
    }

    It 'rolls back newest first and consumes each file as it goes' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $dir = New-RaSafeDir
        $enabled = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 0 }
            $script:rdpTcpPath = @{ UserAuthentication = 0 }
            $script:raPath = @{ fAllowToGetHelp = 1 }
            $script:tsPolicyPath = $null
        }
        $compliant = ConvertTo-RegistryFixtureText -Table @{
            $script:tsPath = @{ fDenyTSConnections = 0 }
            $script:rdpTcpPath = @{ UserAuthentication = 1; SecurityLayer = 2 }
            $script:raPath = @{ fAllowToGetHelp = 0 }
            $script:tsPolicyPath = $null
        }
        $log1 = Join-Path $script:workRoot 'raLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'raLifoApply2.log'
        # Apply 1 changes the registry values. Apply 2, a second later, disables WinRM on a machine whose
        # registry values already match.
        $apply1 = Invoke-ScriptUnderTest -RelativePath $script:raSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + $enabled + $script:raSafeWinRm) -Argument @{ ReportDirectory = $dir; Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $apply2 = Invoke-ScriptUnderTest -RelativePath $script:raSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + $compliant + "`n`$env:OPSTOOLKIT_TEST_WINRM = 'Manual/Running'`n" + $script:raSafeWinRm) `
            -Argument @{ ReportDirectory = $dir; DisableWinRM = $true; Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-RaRollback -Dir $dir -Tag 'raLifoRollback1' -Execute
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $m1 = @(Get-OpsMutationRecord -Path $rb1.Log)
        @($m1 | Where-Object { $_.Command -eq 'Set-Service' }).Count | Should -Be 1
        @($m1 | Where-Object { $_.Command -eq 'Set-ItemProperty' }).Count | Should -Be 0

        $rb2 = Invoke-RaRollback -Dir $dir -Tag 'raLifoRollback2' -Execute
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        $m2 = @(Get-OpsMutationRecord -Path $rb2.Log)
        @($m2 | Where-Object { $_.Command -eq 'Set-ItemProperty' }).Count | Should -BeGreaterThan 0
        @($m2 | Where-Object { $_.Command -eq 'Set-Service' }).Count | Should -Be 0

        $rb3 = Invoke-RaRollback -Dir $dir -Tag 'raLifoRollback3' -Execute
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
    }
}

Describe 'Set-WindowsLocalAccountPolicy rollback safety' {
    BeforeAll {
        $script:laSafeCounter = 0
        $script:laSafeScript = 'scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1'
        $script:laSafeFullPath = Join-Path (Get-RepositoryRoot) $script:laSafeScript
        $script:laSafeName = 'local-account-policy-rollback-20260101_000000.json'
        $script:laSafeSid = 'S-1-5-21-111111111-222222222-333333333'
        $script:laSafeNet = Get-NetExeStubText -Line $script:netDefault
        $script:laSafeUsers = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:laSafeSid)-500|True;Guest|$($script:laSafeSid)-501|True;alice|$($script:laSafeSid)-1001|True'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:laSafeSid)-500|User;HOST\alice|$($script:laSafeSid)-1001|User'`n"
        $script:laSafeUsersGuestOff = "`n`$env:OPSTOOLKIT_TEST_LOCALUSERS = 'Administrator|$($script:laSafeSid)-500|True;Guest|$($script:laSafeSid)-501|False;alice|$($script:laSafeSid)-1001|True'" +
        "`n`$env:OPSTOOLKIT_TEST_LOCALADMINS = 'HOST\Administrator|$($script:laSafeSid)-500|User;HOST\alice|$($script:laSafeSid)-1001|User'`n"
        $script:laSafeNonCompliant = ConvertTo-RegistryFixtureText -Table @{
            $script:uacPath = @{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 0 }
            $script:lsaPath = @{ LimitBlankPasswordUse = 0 }
        }
        $script:laSafeCompliant = ConvertTo-RegistryFixtureText -Table @{
            $script:uacPath = @{ EnableLUA = 1; ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
            $script:lsaPath = @{ LimitBlankPasswordUse = 1 }
        }

        function Get-LaLiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:laSafeFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        function New-LaSafeDir {
            $script:laSafeCounter++
            $dir = Join-Path $script:workRoot "laSafety$($script:laSafeCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        function New-LaLockoutEntry {
            param($Setting = 'lockoutthreshold', $Prior = 0, $Applied = 10, $Kind = 'Lockout', $Category = 'Lockout', $Sid = '')
            [pscustomobject]@{ Category = $Category; Setting = $Setting; Kind = $Kind; Path = ''; Name = ''; ValueType = ''; Sid = $Sid; PriorValue = $Prior; AppliedValue = $Applied }
        }

        function New-LaAccountEntry {
            param($Category = 'GuestAccount', $Setting = 'Guest account', $Kind = 'LocalUserEnabled', $Sid = "$($script:laSafeSid)-501", $Prior = 'Enabled', $Path = '')
            [pscustomobject]@{ Category = $Category; Setting = $Setting; Kind = $Kind; Path = $Path; Name = ''; ValueType = ''; Sid = $Sid; PriorValue = $Prior; AppliedValue = 'Disabled' }
        }

        function New-LaRenameEntry {
            param($Prior = 'Administrator', $Sid = "$($script:laSafeSid)-500")
            [pscustomobject]@{ Category = 'BuiltInAdminRename'; Setting = 'Built-in Administrator name'; Kind = 'LocalUserName'; Path = ''; Name = ''; ValueType = ''; Sid = $Sid; PriorValue = $Prior; AppliedValue = 'labadmin' }
        }

        function New-LaRegEntry {
            param($Category = 'UacConsentPrompt', $Path = $script:uacPath, $Name = 'ConsentPromptBehaviorAdmin', $Prior = 5, $Kind = 'Registry', $Sid = '', $Setting = $null)
            if ($null -eq $Setting) { $Setting = $Name }
            [pscustomobject]@{ Category = $Category; Setting = $Setting; Kind = $Kind; Path = $Path; Name = $Name; ValueType = 'DWord'; Sid = $Sid; PriorValue = $Prior; AppliedValue = 2 }
        }

        function Write-LaRollbackFile {
            param([string]$Dir, [string]$Name = $script:laSafeName, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-LaRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute)
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $run = Invoke-ScriptUnderTest -RelativePath $script:laSafeScript -ModulePath $script:systemModulePath `
                -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $script:laSafeUsers + $script:laSafeNet) -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Assert-LaRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-LaRollback -Dir $Dir -Tag "laRefused$($script:laSafeCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'local-account-policy-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'local-account-policy-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because "$Because must be refused before any change"
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the lockout settings, accounts and registry values the forward plan changes, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'unknown category'; Entry = (New-LaLockoutEntry -Category 'DeleteAccounts') },
            @{ Name = 'lockout setting the script never sets'; Entry = (New-LaLockoutEntry -Setting 'forcelogoff') },
            @{ Name = 'lockout with the wrong Kind'; Entry = (New-LaLockoutEntry -Kind 'Registry') },
            @{ Name = 'lockout carrying a Sid'; Entry = (New-LaLockoutEntry -Sid "$($script:laSafeSid)-500") },
            @{ Name = 'Guest entry pointed at the built-in Administrator SID'; Entry = (New-LaAccountEntry -Sid "$($script:laSafeSid)-500") },
            @{ Name = 'Guest entry pointed at an ordinary user SID'; Entry = (New-LaAccountEntry -Sid "$($script:laSafeSid)-1001") },
            @{ Name = 'Guest entry with a well-known system SID'; Entry = (New-LaAccountEntry -Sid 'S-1-5-18') },
            @{ Name = 'Guest entry with an empty Sid'; Entry = (New-LaAccountEntry -Sid '') },
            @{ Name = 'rename entry pointed at the Guest SID'; Entry = (New-LaRenameEntry -Sid "$($script:laSafeSid)-501") },
            @{ Name = 'account entry with the wrong Kind'; Entry = (New-LaAccountEntry -Kind 'LocalUserName') },
            @{ Name = 'account entry with the wrong Setting'; Entry = (New-LaAccountEntry -Setting 'Everyone') },
            @{ Name = 'account entry carrying a registry Path'; Entry = (New-LaAccountEntry -Path $script:uacPath) },
            @{ Name = 'registry path of another control'; Entry = (New-LaRegEntry -Category 'UacEnableLua' -Path $script:lsaPath -Name 'EnableLUA') },
            @{ Name = 'registry path outside the controls'; Entry = (New-LaRegEntry -Path 'HKLM:\SOFTWARE\Evil') },
            @{ Name = 'registry value name outside the control'; Entry = (New-LaRegEntry -Name 'EnableSmartScreen') },
            @{ Name = 'registry entry with the wrong Kind'; Entry = (New-LaRegEntry -Kind 'Lockout') },
            @{ Name = 'registry entry carrying a Sid'; Entry = (New-LaRegEntry -Sid "$($script:laSafeSid)-500") }
        )
        foreach ($case in $cases) {
            $dir = New-LaSafeDir
            $null = Write-LaRollbackFile -Dir $dir -Entry @((New-LaLockoutEntry), $case.Entry)
            Assert-LaRefused -Dir $dir -FileName $script:laSafeName -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-LaSafeDir
        $null = Write-LaRollbackFile -Dir $dir -Entry @((New-LaLockoutEntry), (New-LaLockoutEntry), (New-LaLockoutEntry -Category 'Evil'))
        $r = Invoke-LaRollback -Dir $dir -Tag 'laIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 2 '
        $r.Run.Output | Should -Match 'Evil'
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "Lockout" } }'
            'ChangedSettings one valid entry, not in an array' = ('{ "ChangedSettings": ' + ((New-LaLockoutEntry) | ConvertTo-Json -Compress) + ' }')
            'ChangedSettings a string'  = '{ "ChangedSettings": "all" }'
            'top level is an array'     = '[ { "Category": "Lockout" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "Lockout" ] }'
            'entry lacks PriorValue'    = '{ "ChangedSettings": [ { "Category": "Lockout", "Setting": "lockoutthreshold", "Kind": "Lockout", "Path": "", "Name": "", "Sid": "", "AppliedValue": 10 } ] }'
            'entry lacks Sid'           = '{ "ChangedSettings": [ { "Category": "Lockout", "Setting": "lockoutthreshold", "Kind": "Lockout", "Path": "", "Name": "", "PriorValue": 0, "AppliedValue": 10 } ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-LaSafeDir
            Set-Content -LiteralPath (Join-Path $dir $script:laSafeName) -Value $bodies[$label] -Encoding utf8
            Assert-LaRefused -Dir $dir -FileName $script:laSafeName -Because $label
        }
    }

    It 'refuses a value of the wrong type or outside the range of its setting' {
        $cases = @(
            @{ Name = 'threshold prior is a word'; Entry = (New-LaLockoutEntry -Prior 'ten') },
            @{ Name = 'threshold prior is numeric text'; Entry = (New-LaLockoutEntry -Prior '10') },
            @{ Name = 'threshold prior unknown'; Entry = (New-LaLockoutEntry -Prior 'unknown') },
            @{ Name = 'threshold above 999'; Entry = (New-LaLockoutEntry -Prior 1000) },
            @{ Name = 'threshold negative'; Entry = (New-LaLockoutEntry -Prior -1) },
            @{ Name = 'duration zero'; Entry = (New-LaLockoutEntry -Setting 'lockoutduration' -Prior 0) },
            @{ Name = 'window above 99999'; Entry = (New-LaLockoutEntry -Setting 'lockoutwindow' -Prior 100000) },
            @{ Name = 'lockout prior is an array'; Entry = (New-LaLockoutEntry -Prior @(1, 2)) },
            @{ Name = 'lockout prior is null'; Entry = (New-LaLockoutEntry -Prior $null) },
            @{ Name = 'lockout AppliedValue is text'; Entry = (New-LaLockoutEntry -Applied 'x') },
            @{ Name = 'lockout AppliedValue is null'; Entry = (New-LaLockoutEntry -Applied $null) },
            @{ Name = 'Guest prior wrong case'; Entry = (New-LaAccountEntry -Prior 'enabled') },
            @{ Name = 'Guest prior is a word'; Entry = (New-LaAccountEntry -Prior 'Maybe') },
            @{ Name = 'Guest prior is a boolean'; Entry = (New-LaAccountEntry -Prior $true) },
            @{ Name = 'Guest prior absent'; Entry = (New-LaAccountEntry -Prior 'absent') },
            @{ Name = 'rename prior has a forbidden character'; Entry = (New-LaRenameEntry -Prior 'bad;name') },
            @{ Name = 'rename prior has a slash'; Entry = (New-LaRenameEntry -Prior 'a/b') },
            @{ Name = 'rename prior longer than 20 characters'; Entry = (New-LaRenameEntry -Prior ('a' * 21)) },
            @{ Name = 'rename prior empty'; Entry = (New-LaRenameEntry -Prior '') },
            @{ Name = 'rename prior only dots'; Entry = (New-LaRenameEntry -Prior '..') },
            @{ Name = 'rename prior with leading space'; Entry = (New-LaRenameEntry -Prior ' admin') },
            @{ Name = 'rename prior is a number'; Entry = (New-LaRenameEntry -Prior 5) },
            @{ Name = 'rename prior is null'; Entry = (New-LaRenameEntry -Prior $null) },
            @{ Name = 'registry prior unknown'; Entry = (New-LaRegEntry -Prior 'unknown') },
            @{ Name = 'registry prior numeric text'; Entry = (New-LaRegEntry -Prior '2') },
            @{ Name = 'ConsentPromptBehaviorAdmin above 5'; Entry = (New-LaRegEntry -Prior 6) },
            @{ Name = 'EnableLUA above 1'; Entry = (New-LaRegEntry -Category 'UacEnableLua' -Name 'EnableLUA' -Prior 2) },
            @{ Name = 'registry prior is a boolean'; Entry = (New-LaRegEntry -Prior $true) },
            @{ Name = 'registry prior is a fraction'; Entry = (New-LaRegEntry -Prior 0.5) },
            @{ Name = 'registry ValueType is an array'; Entry = (& { $e = New-LaRegEntry; $e.ValueType = @('DWord', 'String'); $e }) },
            @{ Name = 'registry AppliedValue is an object'; Entry = (& { $e = New-LaRegEntry; $e.AppliedValue = [pscustomobject]@{ a = 1 }; $e }) }
        )
        foreach ($case in $cases) {
            $dir = New-LaSafeDir
            $null = Write-LaRollbackFile -Dir $dir -Entry @($case.Entry)
            Assert-LaRefused -Dir $dir -FileName $script:laSafeName -Because $case.Name
        }
    }

    It 'accepts every entry the forward plan can produce, so the validator cannot drift from it' {
        $log = Join-Path $script:workRoot 'laDriftApply.log'
        $apply = Invoke-ScriptUnderTest -RelativePath $script:laSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + $script:laSafeNonCompliant + $script:laSafeUsers + $script:laSafeNet) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'laDriftPlan'); DisableBuiltInAdministrator = $true; RenameBuiltInAdministrator = 'labadmin'; WhatIf = $true }
        $apply.ExitCode | Should -Be 0 -Because $apply.Output
        $forward = @(Get-Content -LiteralPath $apply.Summary.PlanJsonPath -Raw | ConvertFrom-Json |
                Where-Object { $_.Kind -in @('Registry', 'Lockout', 'LocalUserEnabled', 'LocalUserName') })
        @($forward | ForEach-Object { $_.Category } | Sort-Object) |
            Should -Be @('BlankPasswordLimit', 'BuiltInAdminDisable', 'BuiltInAdminRename', 'GuestAccount', 'Lockout', 'Lockout', 'Lockout', 'UacConsentPrompt', 'UacEnableLua', 'UacSecureDesktop')
        $entries = @($forward | ForEach-Object {
                [pscustomobject]@{ Category = $_.Category; Setting = $_.Setting; Kind = $_.Kind; Path = $_.Path; Name = $_.Name; ValueType = $_.ValueType
                    Sid = $_.Sid; PriorValue = $_.CurrentValue; AppliedValue = $_.DesiredValue }
            })
        $dir = New-LaSafeDir
        $null = Write-LaRollbackFile -Dir $dir -Entry $entries
        $r = Invoke-LaRollback -Dir $dir -Tag 'laDriftRollback'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items).Count | Should -Be 10
    }

    It 'picks the newest rollback file by name and not a consumed one' {
        $dir = New-LaSafeDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'local-account-policy-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-LaRollbackFile -Dir $dir -Entry @((New-LaRegEntry -Prior 5))
        $r = Invoke-LaRollback -Dir $dir -Tag 'laConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        $plan = Get-Content -LiteralPath $r.Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('ConsentPromptBehaviorAdmin')

        # Name order, not write time: the file with the earlier name is written last.
        $dir2 = New-LaSafeDir
        $newerName = Write-LaRollbackFile -Dir $dir2 -Name 'local-account-policy-rollback-20260201_000000.json' -Entry @((New-LaRegEntry -Prior 4))
        Start-Sleep -Milliseconds 50
        $null = Write-LaRollbackFile -Dir $dir2 -Name 'local-account-policy-rollback-20260101_000000.json' -Entry @((New-LaRegEntry -Prior 5))
        $r2 = Invoke-LaRollback -Dir $dir2 -Tag 'laNameOrder'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        (Split-Path -Leaf $r2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $newerName)
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-LaSafeDir
        $file = Write-LaRollbackFile -Dir $dir -Entry @((New-LaRegEntry))
        $r = Invoke-LaRollback -Dir $dir -Tag 'laUnelevatedExec' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:laSafeName
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf' {
        $dir = New-LaSafeDir
        $file = Write-LaRollbackFile -Dir $dir -Entry @((New-LaRegEntry))
        $r = Invoke-LaRollback -Dir $dir -Tag 'laWhatIfKeeps'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $script:laSafeName
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0

        # With nothing to revert there is no item to preview, so only the -WhatIf rule itself keeps the file.
        $dir2 = New-LaSafeDir
        $file2 = Write-LaRollbackFile -Dir $dir2 -Entry @()
        $r2 = Invoke-LaRollback -Dir $dir2 -Tag 'laWhatIfKeeps2'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        Test-Path -LiteralPath $file2 | Should -BeTrue
        $r2.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
    }

    It 'consumes the file after an executing rollback with nothing left to revert' {
        $dir = New-LaSafeDir
        $file = Write-LaRollbackFile -Dir $dir -Entry @()
        $r = Invoke-LaRollback -Dir $dir -Tag 'laConsumeEmpty' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'local-account-policy-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        $again = Invoke-LaRollback -Dir $dir -Tag 'laConsumeEmpty2' -Execute
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
    }

    It 'decides consumption in a pure function lifted from the script' {
        $text = Get-LaLiftedFunctionText -Name 'Test-RollbackFileConsumable'
        $decide = [scriptblock]::Create("param(`$State, [bool]`$Preview)`n$text`nTest-RollbackFileConsumable -State `$State -Preview `$Preview")
        function New-LaState { param([string[]]$Result) @($Result | ForEach-Object { [pscustomobject]@{ Result = $_ } }) }

        & $decide (New-LaState 'Reverted', 'NoChange', 'Reverted') $false | Should -BeTrue
        & $decide (New-LaState 'NoChange') $false | Should -BeTrue
        & $decide (New-LaState 'Reverted', 'Failed: access denied') $false | Should -BeFalse
        & $decide (New-LaState 'Reverted', 'Skipped: requires elevation') $false | Should -BeFalse
        & $decide (New-LaState 'Previewed', 'Previewed') $false | Should -BeFalse
        & $decide (New-LaState 'Reverted', 'Previewed') $false | Should -BeFalse
        & $decide (New-LaState 'Reverted', 'Reverted') $true | Should -BeFalse -Because '-WhatIf never consumes'
        & $decide (New-LaState 'NoChange') $true | Should -BeFalse
    }

    It 'validates one entry in a pure function lifted from the script, against the tables it is given' {
        $text = Get-LaLiftedFunctionText -Name 'Get-RollbackEntryProblem'
        $check = [scriptblock]::Create("param(`$Entry, `$Registry, `$Lockout, `$Account)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -RegistryControls `$Registry -LockoutControls `$Lockout -AccountControls `$Account")
        $registry = @([pscustomobject]@{ Category = 'UacConsentPrompt'; Kind = 'Registry'; Path = $script:uacPath; Name = 'ConsentPromptBehaviorAdmin'; Min = 0; Max = 5 })
        $lockout = @([pscustomobject]@{ Category = 'Lockout'; Kind = 'Lockout'; Name = 'lockoutthreshold'; Min = 0; Max = 999 })
        $account = @(
            [pscustomobject]@{ Category = 'GuestAccount'; Setting = 'Guest account'; Kind = 'LocalUserEnabled'; SidSuffix = '501'; ValueKind = 'Enabled' }
            [pscustomobject]@{ Category = 'BuiltInAdminRename'; Setting = 'Built-in Administrator name'; Kind = 'LocalUserName'; SidSuffix = '500'; ValueKind = 'Name' }
        )

        & $check (New-LaRegEntry -Prior 5) $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaRegEntry -Prior 'absent') $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaLockoutEntry -Prior 0 -Applied 10) $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaAccountEntry -Prior 'Disabled') $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaRenameEntry -Prior 'Administrateur') $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaRenameEntry -Prior 'Local Admin') $registry $lockout $account | Should -BeNullOrEmpty
        & $check (New-LaRegEntry -Prior 6) $registry $lockout $account | Should -Not -BeNullOrEmpty
        & $check (New-LaRegEntry -Category 'UacEnableLua' -Name 'EnableLUA' -Prior 1) $registry $lockout $account | Should -Not -BeNullOrEmpty -Because 'the category is not in the table it was given'
        & $check (New-LaLockoutEntry -Setting 'lockoutduration' -Prior 5) $registry $lockout $account | Should -Not -BeNullOrEmpty -Because 'the setting is not in the table it was given'
        & $check (New-LaAccountEntry -Sid "$($script:laSafeSid)-500") $registry $lockout $account | Should -Not -BeNullOrEmpty -Because 'Guest is found by RID 501'
        & $check (New-LaAccountEntry -Category 'BuiltInAdminDisable' -Setting 'Built-in Administrator' -Sid "$($script:laSafeSid)-500") $registry $lockout $account | Should -Not -BeNullOrEmpty -Because 'the category is not in the table it was given'
        & $check (New-LaRenameEntry -Prior 'bad|name') $registry $lockout $account | Should -Not -BeNullOrEmpty
        & $check $null $registry $lockout $account | Should -Not -BeNullOrEmpty
    }

    It 'rolls back newest first and consumes each file as it goes' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $dir = New-LaSafeDir
        $log1 = Join-Path $script:workRoot 'laLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'laLifoApply2.log'
        # Apply 1 changes lockout, Guest and the registry values. Apply 2, a second later, renames the built-in
        # Administrator on a machine whose other settings already match.
        $apply1 = Invoke-ScriptUnderTest -RelativePath $script:laSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + $script:laSafeNonCompliant + $script:laSafeUsers + $script:laSafeNet) `
            -Argument @{ ReportDirectory = $dir; Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $netCompliant = Get-NetExeStubText -Line $script:netCompliant
        $apply2 = Invoke-ScriptUnderTest -RelativePath $script:laSafeScript -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + $script:laSafeCompliant + $script:laSafeUsersGuestOff + $netCompliant) `
            -Argument @{ ReportDirectory = $dir; RenameBuiltInAdministrator = 'labadmin'; Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-LaRollback -Dir $dir -Tag 'laLifoRollback1' -Execute
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $m1 = @(Get-OpsMutationRecord -Path $rb1.Log)
        @($m1 | Where-Object { $_.Command -eq 'Rename-LocalUser' }).Count | Should -Be 1
        @($m1 | Where-Object { $_.Command -in @('net.exe', 'Set-ItemProperty') }).Count | Should -Be 0

        $rb2 = Invoke-LaRollback -Dir $dir -Tag 'laLifoRollback2' -Execute
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        $m2 = @(Get-OpsMutationRecord -Path $rb2.Log)
        @($m2 | Where-Object { $_.Command -eq 'net.exe' }).Count | Should -BeGreaterThan 0
        @($m2 | Where-Object { $_.Command -eq 'Rename-LocalUser' }).Count | Should -Be 0

        $rb3 = Invoke-LaRollback -Dir $dir -Tag 'laLifoRollback3' -Execute
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
    }
}
