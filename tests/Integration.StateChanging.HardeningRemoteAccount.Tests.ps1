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
