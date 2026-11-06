#Requires -Modules Pester

# Contract tests for the fake system modules under tests\Fixtures. They pin the one rule every fake follows:
#   1. A fake's mutation recorder writes with -WhatIf:$false, so a caller's -WhatIf (or an ambient
#      $WhatIfPreference) can never silence the log a "nothing changed under -WhatIf" test reads.
#   2. A fake mutating cmdlet declares SupportsShouldProcess exactly when the real cmdlet does (read from
#      the real module's metadata with Get-Command, 2026-11-06) and then records nothing under -WhatIf, as
#      the real one changes nothing. One that the real cmdlet does not support takes no -WhatIf at all.
#   3. Read fakes narrow their results by the filter parameters the real cmdlet has, wildcards included.
# Each case runs in a child process with the staged fakes first on PSModulePath, so nothing here can reach
# a real module or the real machine. The recorder source rule covers every fake, BitLocker and
# Microsoft.PowerShell.LocalAccounts included.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:pwsh = (Get-Process -Id $PID).Path
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-fakecontract-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:staging = Use-FakeSystemModule
    $script:fixtures = Join-Path $PSScriptRoot 'Fixtures'
    $script:counter = 0

    function Invoke-FakeChild {
        # Runs Body in a child pwsh with the fakes first on PSModulePath; the body emits objects, returned as JSON.
        param([Parameter(Mandatory = $true)][string]$Body)
        $script:counter++
        $log = Join-Path $script:workRoot "m$($script:counter).log"
        $file = Join-Path $script:workRoot "c$($script:counter).ps1"
        $head = @"
`$ErrorActionPreference = 'Stop'
`$env:PSModulePath = '$($script:staging)' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Get-Log { if (Test-Path -LiteralPath `$env:OPSTOOLKIT_TEST_MUTATION_LOG) { @(Get-Content -LiteralPath `$env:OPSTOOLKIT_TEST_MUTATION_LOG | ForEach-Object { `$_ | ConvertFrom-Json }) } else { @() } }
function Clear-Log { Remove-Item -LiteralPath `$env:OPSTOOLKIT_TEST_MUTATION_LOG -ErrorAction SilentlyContinue }
"@
        Set-Content -LiteralPath $file -Encoding utf8 -Value ($head + "`n" + $Body)
        $out = & $script:pwsh -NoProfile -NonInteractive -File $file 2>&1
        if ($LASTEXITCODE -ne 0) { throw "child failed: $($out -join [Environment]::NewLine)" }
        # -WhatIf narrates "What if:" lines on stdout, so keep only the JSON line the body ends with.
        $json = @($out | Where-Object { $_ -is [string] -and $_ -match '^[\[{]' } | Select-Object -Last 1) -join ''
        if ($json.Trim()) { $json | ConvertFrom-Json } else { $null }
    }
}

AfterAll {
    foreach ($p in @($script:workRoot, $script:staging)) {
        if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'recorder source rule' {
    It 'every fake recorder and fixture writer passes -WhatIf:$false to Add-Content and Set-Content' {
        $owned = @(Get-ChildItem -LiteralPath $script:fixtures -Filter '*.psm1' -Recurse -File)
        $owned.Count | Should -BeGreaterThan 10
        $bad = foreach ($f in $owned) {
            $n = 0
            foreach ($line in Get-Content -LiteralPath $f.FullName) {
                $n++
                if ($line -match '^\s*(Add-Content|Set-Content)\b' -and $line -notmatch '-WhatIf:\$false') { "$($f.Name):$n $($line.Trim())" }
            }
        }
        @($bad) | Should -BeNullOrEmpty
    }
}

Describe 'mutation recorders under an ambient -WhatIf' {
    It 'still writes the log for fakes whose real cmdlet takes no -WhatIf' {
        $r = Invoke-FakeChild -Body @'
Import-Module Defender, ScheduledTasks, Dism, ProcessMitigations, ConfigCI -Force
$WhatIfPreference = $true
Add-MpPreference -ExclusionPath 'C:\fake\excluded'
Set-MpPreference -PUAProtection 1
Remove-MpPreference -ExclusionPath 'C:\fake\excluded'
Disable-ScheduledTask -TaskName 'T' -TaskPath '\P\'
Enable-ScheduledTask -TaskName 'T' -TaskPath '\P\'
Enable-WindowsOptionalFeature -Online -FeatureName F -NoRestart | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName F -NoRestart | Out-Null
Set-ProcessMitigation -System -Enable DEP
Get-ProcessMitigation -RegistryConfigFilePath (Join-Path $env:TEMP 'ops-fakecontract-export.xml')
ConvertFrom-CIPolicy -XmlFilePath 'x.xml' -BinaryFilePath (Join-Path $env:TEMP 'ops-fakecontract.cip') | Out-Null
Remove-Item (Join-Path $env:TEMP 'ops-fakecontract-export.xml'), (Join-Path $env:TEMP 'ops-fakecontract.cip') -Force -WhatIf:$false -ErrorAction SilentlyContinue
@(Get-Log | ForEach-Object { $_.Command }) | ConvertTo-Json -Compress
'@
        @($r) | Should -Contain 'Add-MpPreference'
        @($r) | Should -Contain 'Set-MpPreference'
        @($r) | Should -Contain 'Remove-MpPreference'
        @($r) | Should -Contain 'Disable-ScheduledTask'
        @($r) | Should -Contain 'Enable-ScheduledTask'
        @($r) | Should -Contain 'Enable-WindowsOptionalFeature'
        @($r) | Should -Contain 'Disable-WindowsOptionalFeature'
        @($r) | Should -Contain 'Set-ProcessMitigation'
        @($r) | Should -Contain 'ConvertFrom-CIPolicy'
    }

    It 'still writes the log for the ActiveDirectory and WebAdministration fakes' {
        $r = Invoke-FakeChild -Body @"
Import-Module '$($script:fixtures)\FakeActiveDirectory\FakeActiveDirectory.psm1', '$($script:fixtures)\FakeWebAdministration\FakeWebAdministration.psm1' -Force
`$WhatIfPreference = `$true
Disable-ADAccount -Identity 'u1'
Set-WebConfigurationProperty -PSPath 'IIS:\Sites\a' -Filter 'f' -Name 'n' -Value 1
Restart-WebAppPool -Name 'p'
@(Get-Log | ForEach-Object { `$_.Command }) | ConvertTo-Json -Compress
"@
        @($r) | Should -Contain 'Disable-ADAccount'
        @($r) | Should -Contain 'Set-WebConfigurationProperty'
        @($r) | Should -Contain 'Restart-WebAppPool'
    }
}

Describe 'SupportsShouldProcess matches the real cmdlet' {
    It 'declares -WhatIf exactly where the real cmdlet does' {
        # Expected values come from Get-Command on the real modules, read-only (2026-11-06).
        $r = Invoke-FakeChild -Body @'
Import-Module Defender, ScheduledTasks, Dism, ProcessMitigations, ConfigCI, SmbShare, PrintManagement, NetSecurity -Force
$names = 'Add-MpPreference','Set-MpPreference','Remove-MpPreference','Disable-ScheduledTask','Enable-ScheduledTask',
 'Enable-WindowsOptionalFeature','Disable-WindowsOptionalFeature','Set-ProcessMitigation','Set-RuleOption','Set-CIPolicyIdInfo',
 'Set-SmbServerConfiguration','Set-SmbClientConfiguration','Add-Printer','Remove-Printer',
 'Set-NetFirewallProfile','Set-NetFirewallRule','Enable-NetFirewallRule','Disable-NetFirewallRule'
$map = [ordered]@{}
foreach ($n in $names) { $map[$n] = (Get-Command $n).Parameters.ContainsKey('WhatIf') }
$map | ConvertTo-Json -Compress
'@
        $expectedTrue = 'Set-SmbServerConfiguration', 'Set-SmbClientConfiguration', 'Add-Printer', 'Remove-Printer',
        'Set-NetFirewallProfile', 'Set-NetFirewallRule', 'Enable-NetFirewallRule', 'Disable-NetFirewallRule'
        foreach ($p in $r.PSObject.Properties) {
            $p.Value | Should -Be ($p.Name -in $expectedTrue) -Because "$($p.Name) must match the real cmdlet's -WhatIf support"
        }
    }

    It 'records nothing for a ShouldProcess fake under -WhatIf and records the same call without it' {
        $r = Invoke-FakeChild -Body @'
Import-Module SmbShare, PrintManagement, NetSecurity -Force
$calls = {
    param($extra)
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force @extra
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force @extra
    Add-Printer -ConnectionName '\\srv\p' @extra
    Remove-Printer -Name 'p' @extra
    Set-NetFirewallProfile -Name Public -Enabled True @extra
    Set-NetFirewallRule -Name r -Enabled False @extra
    Enable-NetFirewallRule -Name r @extra
    Disable-NetFirewallRule -Name r @extra
}
Clear-Log
& $calls @{ WhatIf = $true }
$under = @(Get-Log).Count
Clear-Log
$global:WhatIfPreference = $true
& $calls @{}
$ambient = @(Get-Log).Count
$global:WhatIfPreference = $false
Clear-Log
& $calls @{}
[pscustomobject]@{ WhatIfSwitch = $under; Ambient = $ambient; Normal = @(Get-Log).Count } | ConvertTo-Json -Compress
'@
        $r.WhatIfSwitch | Should -Be 0
        $r.Ambient | Should -Be 0
        $r.Normal | Should -Be 8
    }
}

Describe 'read fakes honour their filters' {
    It 'Get-ScheduledTask narrows by TaskName and TaskPath, wildcards included' {
        $r = Invoke-FakeChild -Body @'
Import-Module ScheduledTasks -Force
$env:OPSTOOLKIT_TEST_TASKS = '\A\|One|Ready;\A\|Two|Disabled;\B\|One|Ready'
[pscustomobject]@{
    All       = @(Get-ScheduledTask).Count
    ByName    = @(Get-ScheduledTask -TaskName One).Count
    ByPath    = @(Get-ScheduledTask -TaskPath '\A\').Count
    Both      = @(Get-ScheduledTask -TaskPath '\B\' -TaskName One).Count
    Wild      = @(Get-ScheduledTask -TaskName 'T*').Count
    PathWild  = @(Get-ScheduledTask -TaskPath '\*').Count
    Many      = @(Get-ScheduledTask -TaskName 'One', 'Two').Count
    None      = @(Get-ScheduledTask -TaskName 'Nope').Count
} | ConvertTo-Json -Compress
'@
        $r.All | Should -Be 3
        $r.ByName | Should -Be 2
        $r.ByPath | Should -Be 2
        $r.Both | Should -Be 1
        $r.Wild | Should -Be 1
        $r.PathWild | Should -Be 3
        $r.Many | Should -Be 3
        $r.None | Should -Be 0
    }

    It 'Get-Printer narrows by Name, wildcards included' {
        $r = Invoke-FakeChild -Body @'
Import-Module PrintManagement -Force
$env:OPSTOOLKIT_TEST_PRINTERS = '\\srv\a|Connection;\\srv\b|Connection;Local1|Local'
[pscustomobject]@{
    All = @(Get-Printer).Count; One = @(Get-Printer -Name 'Local1').Count
    Wild = @(Get-Printer -Name '\\srv\*').Count; None = @(Get-Printer -Name 'x').Count
} | ConvertTo-Json -Compress
'@
        $r.All | Should -Be 3
        $r.One | Should -Be 1
        $r.Wild | Should -Be 2
        $r.None | Should -Be 0
    }

    It 'the firewall getters narrow by Name, DisplayName, Group, Direction, Action and profile Name' {
        $r = Invoke-FakeChild -Body @'
Import-Module NetSecurity -Force
$env:OPSTOOLKIT_TEST_FW_RULES = '[{"Name":"a1","DisplayName":"Alpha one","Group":"G1","Direction":"Inbound","Action":"Allow"},{"Name":"a2","DisplayName":"Alpha two","Group":"G2","Direction":"Outbound","Action":"Block"},{"Name":"b1","DisplayName":"Beta","Group":"G2","Direction":"Inbound","Action":"Block"}]'
[pscustomobject]@{
    All = @(Get-NetFirewallRule).Count; Name = @(Get-NetFirewallRule -Name 'a*').Count
    Display = @(Get-NetFirewallRule -DisplayName 'Beta').Count; Group = @(Get-NetFirewallRule -Group 'G2').Count
    Direction = @(Get-NetFirewallRule -Direction Outbound).Count; Action = @(Get-NetFirewallRule -Action Block).Count
    Filter = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name 'b1')).Count
    FilterAll = @(Get-NetFirewallPortFilter).Count
    Profiles = @(Get-NetFirewallProfile -All).Count; ProfileOne = @(Get-NetFirewallProfile -Name 'Public').Count
    ProfileWild = @(Get-NetFirewallProfile -Name 'P*').Count
} | ConvertTo-Json -Compress
'@
        $r.All | Should -Be 3
        $r.Name | Should -Be 2
        $r.Display | Should -Be 1
        $r.Group | Should -Be 2
        $r.Direction | Should -Be 1
        $r.Action | Should -Be 2
        $r.Filter | Should -Be 1
        $r.FilterAll | Should -Be 3
        $r.Profiles | Should -Be 3
        $r.ProfileOne | Should -Be 1
        $r.ProfileWild | Should -Be 2
    }

    It 'Get-WindowsOptionalFeature narrows by FeatureName and rejects an unknown one' {
        $r = Invoke-FakeChild -Body @'
Import-Module Dism -Force
$env:OPSTOOLKIT_TEST_OPTFEATURES = 'A=Enabled;B=Disabled'
$unknown = try { Get-WindowsOptionalFeature -Online -FeatureName 'Z'; 'no throw' } catch { 'threw' }
[pscustomobject]@{
    All = @(Get-WindowsOptionalFeature -Online).Count
    One = @(Get-WindowsOptionalFeature -Online -FeatureName 'B').FeatureName
    Unknown = $unknown
} | ConvertTo-Json -Compress
'@
        $r.All | Should -Be 2
        $r.One | Should -Be 'B'
        $r.Unknown | Should -Be 'threw'
    }

    It 'Get-ProcessMitigation answers -Name and -Id with that process, not the system values' {
        $r = Invoke-FakeChild -Body @'
Import-Module ProcessMitigations -Force
$env:OPSTOOLKIT_TEST_PM_SYSTEM = 'DEP=ON;SEHOP=ON'
$sys = Get-ProcessMitigation -System
$proc = Get-ProcessMitigation -Name 'app.exe'
[pscustomobject]@{ SysDep = $sys.DEP.Enable; ProcName = $proc.Name; ProcDep = $proc.DEP.Enable } | ConvertTo-Json -Compress
'@
        $r.SysDep | Should -Be 'ON'
        $r.ProcName | Should -Be 'app.exe'
        $r.ProcDep | Should -Be 'NOTSET'
    }
}
