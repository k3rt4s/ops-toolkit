<#
.SYNOPSIS
Collect a read-only iCloud for Windows health report (package, dependencies, services, drivers, hardening policies, TLS, clock, network, event log) into one text file.

.DESCRIPTION
Instructions:
- Run from an elevated Windows PowerShell or PowerShell 7. It changes nothing on the machine.
- Shortest form, straight from the public repo:
  irm https://raw.githubusercontent.com/k3rt4s/ops-toolkit/master/scripts/it-operations/workstation-setup/Export-ICloudDiagnostic.ps1 | iex
- The report goes to a Laptop_Setup folder inside the Proton Drive "My files" folder when one is
  found, so it syncs to your other machines. Otherwise it goes to the Desktop. The path is printed.
- Pass -OutputDirectory to choose the folder yourself.

Purpose:
"iCloud for Windows has not fully initialized" has several causes: a package that did not finish
registering, a missing runtime dependency, the Cloud Files filter driver not running, a policy
that blocks Store apps in the background, a hardened TLS stack, a wrong clock, or blocked Apple
endpoints. This script gathers every one of those in a single pass so the cause can be read from
one file instead of a run of separate commands.

The report can hold your Apple ID email from iCloud's own log lines. It is written only to the
local folder above and is never uploaded by this script.

Required syntax:
powershell -ExecutionPolicy Bypass -File .\Export-ICloudDiagnostic.ps1
powershell -ExecutionPolicy Bypass -File .\Export-ICloudDiagnostic.ps1 -OutputDirectory C:\Temp

.OUTPUTS
Writes icloud-diagnostic-<computer>-yyyyMMdd_HHmmss.txt and returns its full path.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Read-only. Windows PowerShell 5.1
compatible (ASCII only, no PowerShell 7 operators).
#>
[CmdletBinding()]
param(
    # Folder for the report. Default: <Proton Drive My files>\Laptop_Setup, else the Desktop.
    [Parameter()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:Lines = New-Object System.Collections.Generic.List[string]

function Add-Section {
    param([string]$Title)
    $script:Lines.Add('')
    $script:Lines.Add(('==== {0} ====' -f $Title))
}

function Add-Text {
    param($Value)
    if ($null -eq $Value) { $script:Lines.Add('(none)'); return }
    $text = ($Value | Out-String -Width 220).TrimEnd()
    if (-not $text) { $text = '(none)' }
    $script:Lines.Add($text)
}

function Invoke-Probe {
    # Runs one probe and records its output or its error; a failing probe never stops the report.
    param([string]$Title, [scriptblock]$Probe)
    Add-Section $Title
    try { Add-Text (& $Probe 2>&1) }
    catch { $script:Lines.Add(('ERROR: {0}' -f $_.Exception.Message)) }
}

function Get-RegistryValues {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return ('{0}: key absent' -f $Path) }
    $item = Get-ItemProperty -LiteralPath $Path
    $out = @($item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { '{0} = {1}' -f $_.Name, $_.Value })
    if ($out.Count -eq 0) { return ('{0}: key present, no values' -f $Path) }
    @(('{0}:' -f $Path)) + ($out | ForEach-Object { '  ' + $_ })
}

function Find-ProtonMyFiles {
    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add($env:USERPROFILE)
    foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) { if ($d.Root) { $roots.Add($d.Root) } }
    foreach ($r in $roots) {
        foreach ($pd in @(Get-ChildItem -LiteralPath $r -Directory -Filter 'Proton Drive*' -ErrorAction SilentlyContinue)) {
            $direct = Join-Path $pd.FullName 'My files'
            if (Test-Path -LiteralPath $direct) { return $direct }
            foreach ($sub in @(Get-ChildItem -LiteralPath $pd.FullName -Directory -ErrorAction SilentlyContinue)) {
                $nested = Join-Path $sub.FullName 'My files'
                if (Test-Path -LiteralPath $nested) { return $nested }
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------------------------
$script:Lines.Add(('iCloud diagnostic  {0}  {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Lines.Add(('User {0}  elevated={1}  PowerShell {2}' -f $env:USERNAME, $isAdmin, $PSVersionTable.PSVersion))

Invoke-Probe 'Windows version' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    '{0} {1} build {2}.{3}' -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuildNumber, $cv.UBR
}

Invoke-Probe 'iCloud and Apple packages (Store)' {
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like 'AppleInc.*' } |
        Select-Object Name, Version, Status, SignatureKind, IsDevelopmentMode, InstallLocation, @{ n = 'Users'; e = { ($_.PackageUserInformation | ForEach-Object { '{0}:{1}' -f $_.UserSecurityId.Username, $_.InstallState }) -join '; ' } } |
        Format-List
}

Invoke-Probe 'iCloud and Apple programs (desktop installer)' {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['Publisher'] -and $_.Publisher -match 'Apple' } |
        Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize
}

Invoke-Probe 'Store, App Installer and UI runtimes' {
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -match '^Microsoft\.(WindowsStore|DesktopAppInstaller|StorePurchaseApp|VCLibs|UI\.Xaml|NET\.Native|WindowsAppRuntime|Services\.Store\.Engagement)' } |
        Sort-Object Name, Version | Select-Object Name, Version, Architecture, Status | Format-Table -AutoSize
}

Invoke-Probe 'WebView2 runtime' {
    $ids = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $found = @($ids | Where-Object { Test-Path $_ } | ForEach-Object { '{0} = {1}' -f $_, (Get-ItemProperty $_).pv })
    if ($found.Count) { $found } else { 'WebView2 runtime not found' }
}

Invoke-Probe 'Services (Apple, Bonjour, sync, Store, clock)' {
    Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Apple|Bonjour|mDNS|iCloud|OneSyncSvc|cbdhsvc|CDPSvc|CDPUserSvc|WpnService|WpnUserService|InstallService|AppXSvc|ClipSVC|BITS|wuauserv|W32Time|TimeBrokerSvc|BrokerInfrastructure|BackgroundTaskInfrastructureService' } |
        Sort-Object Name | Select-Object Name, Status, StartType | Format-Table -AutoSize
}

Invoke-Probe 'Cloud Files filter driver (iCloud Drive placeholders)' {
    Get-CimInstance Win32_SystemDriver -Filter "Name='CldFlt'" | Select-Object Name, State, StartMode, Status | Format-List
    & fltmc.exe filters 2>&1 | Select-String -Pattern 'CldFlt|Filter Name'
}

Invoke-Probe 'Hardening and policy registry values' {
    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    )
    foreach ($p in $paths) { Get-RegistryValues $p }
    Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like 'AppleInc*' } | ForEach-Object { Get-RegistryValues $_.PSPath.Replace('Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER', 'HKCU:') }
}

Invoke-Probe 'Schannel protocols, ciphers and .NET strong crypto' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    foreach ($proto in @(Get-ChildItem (Join-Path $base 'Protocols') -ErrorAction SilentlyContinue)) {
        foreach ($side in @(Get-ChildItem $proto.PSPath -ErrorAction SilentlyContinue)) { Get-RegistryValues ('{0}\Protocols\{1}\{2}' -f $base, $proto.PSChildName, $side.PSChildName) }
    }
    foreach ($c in @(Get-ChildItem (Join-Path $base 'Ciphers') -ErrorAction SilentlyContinue)) { Get-RegistryValues ('{0}\Ciphers\{1}' -f $base, $c.PSChildName) }
    Get-RegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010002'
    Get-RegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    Get-RegistryValues 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    Get-RegistryValues 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    Get-RegistryValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
}

Invoke-Probe 'Hardening runs recorded under the data root' {
    foreach ($d in 'C:\Code_data\workspace\hardening-applied', 'C:\Code_data\workspace\hardening-preview') {
        if (Test-Path $d) { Get-ChildItem $d -Directory | Select-Object @{ n = 'Folder'; e = { $d + '\' + $_.Name } }, LastWriteTime | Format-Table -AutoSize }
        else { '{0}: absent' -f $d }
    }
}

Invoke-Probe 'Clock and time sync' {
    'Local {0}  UTC {1}  zone {2}' -f (Get-Date), (Get-Date).ToUniversalTime(), (Get-TimeZone).Id
    & w32tm.exe /query /status 2>&1
}

Invoke-Probe 'Network to Apple endpoints' {
    foreach ($h in 'setup.icloud.com', 'gateway.icloud.com', 'configuration.apple.com', 'idmsa.apple.com', 'www.apple.com') {
        $tcp = $false
        try { $c = New-Object Net.Sockets.TcpClient; $iar = $c.BeginConnect($h, 443, $null, $null); $tcp = $iar.AsyncWaitHandle.WaitOne(5000) -and $c.Connected; $c.Close() } catch { $tcp = $false }
        # The machine's own TLS default is used, so a hardened or broken TLS setting shows up here.
        $https = ''
        try {
            $r = Invoke-WebRequest -Uri ('https://{0}/' -f $h) -UseBasicParsing -TimeoutSec 10 -Method Head -ErrorAction Stop
            $https = 'HTTP ' + [int]$r.StatusCode
        }
        catch {
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $https = 'HTTP ' + [int]$_.Exception.Response.StatusCode + ' (TLS ok)' }
            else { $https = 'FAILED ' + $_.Exception.Message }
        }
        '{0,-28} tcp443={1,-5} {2}' -f $h, $tcp, $https
    }
    '.NET SecurityProtocol default: {0}' -f [Net.ServicePointManager]::SecurityProtocol
    & netsh.exe winhttp show proxy 2>&1
}

Invoke-Probe 'Event log: Apple and iCloud errors, last 7 days' {
    $since = (Get-Date).AddDays(-7)
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 3000 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Apple|iCloud|Bonjour' -or $_.Message -match 'iCloud|AppleInc|Apple ' } |
        Select-Object -First 40 TimeCreated, ProviderName, Id, LevelDisplayName, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(400, ($_.Message -replace '\s+', ' ').Length)) } } |
        Format-List
}

Invoke-Probe 'Event log: AppX deployment errors for Apple packages, last 7 days' {
    $since = (Get-Date).AddDays(-7)
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppXDeploymentServer/Operational'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 3000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'AppleInc' } |
        Select-Object -First 25 TimeCreated, Id, LevelDisplayName, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(400, ($_.Message -replace '\s+', ' ').Length)) } } |
        Format-List
}

Invoke-Probe 'iCloud app data and newest log lines' {
    $pkgRoot = Join-Path $env:LOCALAPPDATA 'Packages'
    foreach ($pkg in @(Get-ChildItem $pkgRoot -Directory -Filter 'AppleInc.iCloud*' -ErrorAction SilentlyContinue)) {
        'Package data: ' + $pkg.FullName
        $logs = @(Get-ChildItem $pkg.FullName -Recurse -File -Include '*.log', '*.txt' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 4)
        foreach ($l in $logs) {
            '--- {0}  ({1})' -f $l.FullName, $l.LastWriteTime
            Get-Content -LiteralPath $l.FullName -Tail 400 -ErrorAction SilentlyContinue | Select-String -Pattern 'error|fail|initiali|denied|timeout|exception' | Select-Object -Last 30 | ForEach-Object { $_.Line.Substring(0, [Math]::Min(300, $_.Line.Length)) }
        }
    }
    foreach ($d in (Join-Path $env:APPDATA 'Apple Computer\Logs'), (Join-Path $env:LOCALAPPDATA 'Apple Inc\iCloud')) { '{0}: {1}' -f $d, (Test-Path $d) }
}

# ---------------------------------------------------------------------------------------------
# Write the report
# ---------------------------------------------------------------------------------------------
if (-not $OutputDirectory) {
    $myFiles = Find-ProtonMyFiles
    if ($myFiles) { $OutputDirectory = Join-Path $myFiles 'Laptop_Setup' }
    else { $OutputDirectory = [Environment]::GetFolderPath('Desktop') }
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$file = Join-Path $OutputDirectory ('icloud-diagnostic-{0}-{1}.txt' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
[System.IO.File]::WriteAllText($file, ($script:Lines -join "`r`n") + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host ''
Write-Host ('iCloud diagnostic written to: {0}' -f $file) -ForegroundColor Green
$file
