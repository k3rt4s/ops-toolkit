<#
.SYNOPSIS
Build a fresh Windows 11 workstation to match a developer and security-consulting setup: apps, tools, editor, shell, workspace, and a hardening preview.

.DESCRIPTION
Instructions:
- Runs on a stock Windows 11 install with only Windows PowerShell 5.1 and winget (App Installer).
  Nothing else needs to be installed first. The file is self-contained: download it by itself.
- Run from an ELEVATED Windows PowerShell in the account you will use every day. The per-user
  settings (Git, VS Code, shell profile, environment variables, gh login) land in that account.
- Run with -WhatIf first. It lists every package, setting, and clone it would touch and changes nothing.
- Safe to re-run. Every step checks current state first, so a failed or interrupted run resumes by
  running the same command again. Use -Phase to run only some phases.
- Hardening is PREVIEW ONLY here. Phase 8 runs the five Windows 11 hardening scripts with -WhatIf and
  prints the apply commands. Nothing is hardened until you run those commands yourself.
- Writes a run folder under -ReportDirectory with a log, results.csv/json, and summary.json.
- Reboots are never forced. If Docker Desktop or WSL needs one, the summary says so.

Phases:
 1 Preflight          admin, Windows 11, winget, network
 2 Windows settings   long paths, execution policy, show file extensions and hidden files
 3 Packages           winget installs for the chosen -Group sets
 4 Git and modules    git identity, PowerShell modules for Windows PowerShell and PowerShell 7
 5 Editor and shell   VS Code extensions and settings, Windows Terminal, PowerShell profile, env vars
 6 Workspace          folder layout, gh login, clone ops-toolkit, optional private workspace repo and repos
 7 Docker and WSL     WSL kernel update (only when the AiContainers group is chosen)
 8 Hardening preview  five hardening scripts in -WhatIf, plans written to the report folder
 9 Summary            results, manual steps, apply commands

Purpose:
Rebuilding a workstation by hand loses settings nobody wrote down. This script is the written-down
version: the package list, extension list, editor and shell settings, and workspace layout of a
working machine, applied the same way every time and verified by the result list.

It deliberately does not copy anything secret or machine-specific: no credentials, tokens, browser
profiles, Claude or Codex state, vendor or gaming utilities, or GPU-specific drivers. Private
repository names are never stored here: with -WorkspaceRepo and a gh login it clones the
repositories the logged-in account owns.

Required syntax:
powershell -ExecutionPolicy Bypass -File .\Install-WorkstationBootstrap.ps1 -WhatIf
powershell -ExecutionPolicy Bypass -File .\Install-WorkstationBootstrap.ps1 -GitUserName "Your Name" -GitUserEmail you@example.com
powershell -ExecutionPolicy Bypass -File .\Install-WorkstationBootstrap.ps1 -WorkspaceRepo https://github.com/<owner>/<workspace-repo>.git
powershell -ExecutionPolicy Bypass -File .\Install-WorkstationBootstrap.ps1 -Phase 8

.OUTPUTS
Writes workstation-bootstrap-yyyyMMdd_HHmmss\ under -ReportDirectory containing run.log, results.csv,
results.json, and summary.json. Returns the summary object. Exit code 0 when no step failed, 1 when
at least one step failed, 2 when a prerequisite is missing.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Windows PowerShell 5.1 compatible by design
(ASCII only, no PowerShell 7 operators), because it is the first script run on a machine that has
no PowerShell 7 yet.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Accepts 'Core,Comms' as one string too: powershell.exe -File passes a comma list as a single token.
    [Parameter()]
    [string[]]$Group = @('Core', 'Comms', 'AiContainers'),

    # Phases to run, 1 to 9. Accepts '1,6,8' as one string for the same reason.
    [Parameter()]
    [string[]]$Phase = @('1', '2', '3', '4', '5', '6', '7', '8', '9'),

    [Parameter()]
    [string]$GitUserName,

    [Parameter()]
    [string]$GitUserEmail,

    [Parameter()]
    [string]$WorkspaceRepo,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceRoot = 'C:\Code',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DataRoot = 'C:\Code_data',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OpsToolkitUrl = 'https://github.com/k3rt4s/ops-toolkit.git',

    [Parameter()]
    [string]$OllamaModelsPath,

    [Parameter()]
    [switch]$SkipRepoClone,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $env:USERPROFILE 'workstation-bootstrap')
)

Set-StrictMode -Version 2.0

$Group = @($Group | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($g in $Group) {
    if (@('Core', 'Comms', 'AiContainers') -notcontains $g) { throw ("Unknown -Group '{0}'. Valid: Core, Comms, AiContainers." -f $g) }
}
$Phase = @($Phase | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
        $n = 0
        if (-not [int]::TryParse($_, [ref]$n) -or $n -lt 1 -or $n -gt 9) { throw ("Unknown -Phase '{0}'. Valid: 1 to 9." -f $_) }
        $n
    })
# Native tools write progress to stderr; under Windows PowerShell 5.1 'Stop' would turn that into a
# terminating error. Steps check exit codes and use -ErrorAction Stop where a throw is wanted.
$ErrorActionPreference = 'Continue'

$script:Results = New-Object System.Collections.ArrayList
$script:RunDir = $null
$script:RebootHint = $false
$script:ManualSteps = New-Object System.Collections.ArrayList
$script:PhaseNames = @{
    1 = 'Preflight'; 2 = 'Windows settings'; 3 = 'Packages'; 4 = 'Git and modules'; 5 = 'Editor and shell'
    6 = 'Workspace'; 7 = 'Docker and WSL'; 8 = 'Hardening preview'; 9 = 'Summary'
}

# ---------------------------------------------------------------------------------------------
# Catalog. Package IDs were each resolved with 'winget show --exact' when this list was written.
# ---------------------------------------------------------------------------------------------
function New-Pkg {
    param([string]$Group, [string]$Id, [string]$Note, [string]$Override)
    [pscustomobject]@{ Group = $Group; Id = $Id; Note = $Note; Override = $Override }
}

$script:Packages = @(
    New-Pkg 'Core' 'Microsoft.PowerShell' 'PowerShell 7'
    New-Pkg 'Core' 'Microsoft.WindowsTerminal' 'Windows Terminal'
    New-Pkg 'Core' 'Git.Git' 'Git for Windows'
    New-Pkg 'Core' 'GitHub.cli' 'GitHub CLI'
    New-Pkg 'Core' 'Microsoft.VisualStudioCode' 'VS Code'
    New-Pkg 'Core' 'Notepad++.Notepad++' 'Notepad++'
    New-Pkg 'Core' 'Python.Python.3.12' 'Python 3.12'
    New-Pkg 'Core' 'Python.Python.3.13' 'Python 3.13 (default via PY_PYTHON)'
    New-Pkg 'Core' 'Python.Python.3.14' 'Python 3.14'
    New-Pkg 'Core' 'OpenJS.NodeJS.LTS' 'Node.js LTS'
    New-Pkg 'Core' 'DenoLand.Deno' 'Deno (yt-dlp JavaScript challenges)'
    New-Pkg 'Core' 'JohnMacFarlane.Pandoc' 'Pandoc'
    New-Pkg 'Core' 'Hashicorp.Terraform' 'Terraform'
    New-Pkg 'Core' 'AquaSecurity.Trivy' 'Trivy'
    New-Pkg 'Core' 'Google.CloudSDK' 'Google Cloud SDK'
    New-Pkg 'Core' 'Gyan.FFmpeg' 'ffmpeg'
    New-Pkg 'Core' 'OliverBetz.ExifTool' 'ExifTool'
    New-Pkg 'Core' 'QPDF.QPDF' 'qpdf'
    New-Pkg 'Core' 'yt-dlp.yt-dlp' 'yt-dlp'
    New-Pkg 'Core' 'IDRIX.VeraCrypt' 'VeraCrypt'
    New-Pkg 'Core' 'Microsoft.VisualStudio.2022.BuildTools' 'VS 2022 Build Tools, C++ workload (native Python wheels)' '--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
    New-Pkg 'Comms' 'Google.Chrome' 'Chrome'
    New-Pkg 'Comms' 'Mozilla.Thunderbird' 'Thunderbird'
    New-Pkg 'Comms' 'Proton.ProtonMailBridge' 'Proton Mail Bridge'
    New-Pkg 'Comms' 'Proton.ProtonVPN' 'Proton VPN'
    New-Pkg 'Comms' 'Proton.ProtonDrive' 'Proton Drive'
    New-Pkg 'Comms' 'Google.GoogleDrive' 'Google Drive'
    New-Pkg 'Comms' 'SlackTechnologies.Slack' 'Slack'
    New-Pkg 'Comms' 'Zoom.Zoom' 'Zoom'
    New-Pkg 'Comms' 'Microsoft.Teams' 'Teams'
    New-Pkg 'Comms' 'Discord.Discord' 'Discord'
    New-Pkg 'Comms' 'TeamViewer.TeamViewer' 'TeamViewer'
    New-Pkg 'Comms' 'Anki.Anki' 'Anki'
    New-Pkg 'Comms' 'DigiDNA.iMazing' 'iMazing'
    New-Pkg 'Comms' 'TheDocumentFoundation.LibreOffice' 'LibreOffice'
    New-Pkg 'Comms' 'Anthropic.Claude' 'Claude desktop'
    New-Pkg 'AiContainers' 'Microsoft.WSL' 'WSL'
    New-Pkg 'AiContainers' 'Docker.DockerDesktop' 'Docker Desktop'
    New-Pkg 'AiContainers' 'Ollama.Ollama' 'Ollama'
)

$script:VsCodeExtensions = @(
    'anthropic.claude-code', 'christian-kohler.npm-intellisense', 'davidanson.vscode-markdownlint',
    'donjayamanne.githistory', 'dotjoshjohnson.xml', 'eamodio.gitlens', 'github.vscode-github-actions',
    'github.vscode-pull-request-github', 'grapecity.gc-excelviewer', 'hashicorp.terraform',
    'mechatroner.rainbow-csv', 'ms-azuretools.vscode-azureresourcegroups', 'ms-azuretools.vscode-bicep',
    'ms-azuretools.vscode-containers', 'ms-azuretools.vscode-docker', 'ms-dotnettools.vscode-dotnet-runtime',
    'ms-mssql.mssql', 'ms-python.debugpy', 'ms-python.python', 'ms-python.vscode-pylance',
    'ms-python.vscode-python-envs', 'ms-vscode-remote.remote-containers', 'ms-vscode-remote.remote-wsl',
    'ms-vscode.azurecli', 'ms-vscode.notepadplusplus-keybindings', 'ms-vscode.powershell',
    'openai.chatgpt', 'openai.codex-audio', 'run-at-scale.terraform-doc-snippets',
    'saoudrizwan.claude-dev', 'tomoki1207.pdf'
)

# Editor settings worth mirroring. Machine-specific keys (tenant IDs, SQL connections, the
# PowerShell host name) are left out on purpose. Existing keys are never overwritten.
$script:VsCodeSettings = [ordered]@{
    'workbench.editor.empty.hint'                         = 'hidden'
    'explorer.confirmDragAndDrop'                         = $false
    'explorer.confirmDelete'                              = $false
    'python.createEnvironment.trigger'                    = 'off'
    'python.terminal.useEnvFile'                          = $true
    'python.analysis.excludeLibraryDiagnostics'           = $true
    'claudeCode.preferredLocation'                        = 'panel'
    'claudeCode.hideOnboarding'                           = $true
    'terminal.integrated.enableMultiLinePasteWarning'     = 'never'
    'terminal.integrated.initialHint'                     = $false
    'editor.renderWhitespace'                             = 'all'
    'git.enableSmartCommit'                               = $true
    'git.autofetch'                                       = $true
    'powershell.suppressTerminalStoppedNotification'      = $true
}

$script:Modules7 = @(
    'Az.Accounts', 'Az.KeyVault', 'ExchangeOnlineManagement', 'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Reports',
    'Pester', 'PSScriptAnalyzer', 'ImportExcel', 'NTFSSecurity'
)
$script:Modules51 = @('ImportExcel', 'NTFSSecurity')

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = 'Gray'
    if ($Level -eq 'FAIL') { $color = 'Red' } elseif ($Level -eq 'WARN') { $color = 'Yellow' } elseif ($Level -eq 'PHASE') { $color = 'Cyan' }
    Write-Host $line -ForegroundColor $color
    if ($script:RunDir) {
        Add-Content -LiteralPath (Join-Path $script:RunDir 'run.log') -Value $line -WhatIf:$false -ErrorAction SilentlyContinue
    }
}

function Add-Result {
    param([int]$PhaseNumber, [string]$Item, [string]$Status, [string]$Detail = '')
    [void]$script:Results.Add([pscustomobject]@{
            Phase  = $PhaseNumber
            Item   = $Item
            Status = $Status
            Detail = $Detail
        })
    $level = 'INFO'
    if ($Status -eq 'Failed') { $level = 'FAIL' } elseif ($Status -eq 'Skipped') { $level = 'WARN' }
    Write-Log ('P{0} {1}: {2} {3}' -f $PhaseNumber, $Item, $Status, $Detail) $level
}

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

function Find-Tool {
    param([string]$Name, [string[]]$ExtraPaths = @())
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in $ExtraPaths) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    return $null
}

function Test-WingetInstalled {
    param([string]$Id)
    & winget list --id $Id --exact --accept-source-agreements --disable-interactivity 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Install-WingetPackage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [pscustomobject]$Package)

    $label = '{0} ({1})' -f $Package.Id, $Package.Note
    if (Test-WingetInstalled -Id $Package.Id) {
        Add-Result $PhaseNumber $label 'AlreadyPresent'
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Package.Id, 'winget install')) {
        Add-Result $PhaseNumber $label 'WhatIf' 'would install'
        return
    }
    $wingetArgs = @('install', '--id', $Package.Id, '--exact', '--source', 'winget', '--silent',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($Package.Override) { $wingetArgs += @('--override', $Package.Override) }
    & winget @wingetArgs | Out-Null
    $code = $LASTEXITCODE
    # 0 = installed, -1978335189 (0x8A15002B) = already current, 3010 = installed, reboot pending.
    if ($code -eq 0 -or $code -eq -1978335189) {
        Add-Result $PhaseNumber $label 'Installed'
    }
    elseif ($code -eq 3010) {
        $script:RebootHint = $true
        Add-Result $PhaseNumber $label 'Installed' 'reboot pending'
    }
    elseif ($code -eq -1978335215) {
        # 0x8A150011: the vendor shipped a newer installer than winget's manifest records. Never bypass the hash.
        Add-Result $PhaseNumber $label 'Failed' 'winget exit -1978335215 (installer hash mismatch; vendor is ahead of the winget manifest)'
        [void]$script:ManualSteps.Add(('Install {0} by hand from the vendor site, or re-run phase 3 later once winget catches up.' -f $Package.Note))
    }
    else {
        Add-Result $PhaseNumber $label 'Failed' ('winget exit {0}' -f $code)
    }
}

function Set-RegistryValueIfDifferent {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $label = '{0}\{1}' -f $Path, $Name
    $current = $null
    try { $current = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $current = $null }
    if ($null -ne $current -and $current -eq $Value) { Add-Result $PhaseNumber $label 'AlreadyPresent' ([string]$Value); return }
    if (-not $PSCmdlet.ShouldProcess($label, ('set to {0}' -f $Value))) { Add-Result $PhaseNumber $label 'WhatIf' ('would set {0}' -f $Value); return }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Add-Result $PhaseNumber $label 'Applied' ([string]$Value)
    }
    catch { Add-Result $PhaseNumber $label 'Failed' $_.Exception.Message }
}

function Set-UserEnvVar {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$Name, [string]$Value)
    $current = [Environment]::GetEnvironmentVariable($Name, 'User')
    if ($current -eq $Value) { Add-Result $PhaseNumber ('env ' + $Name) 'AlreadyPresent' $Value; return }
    if (-not $PSCmdlet.ShouldProcess($Name, ('set user variable to {0}' -f $Value))) { Add-Result $PhaseNumber ('env ' + $Name) 'WhatIf' $Value; return }
    [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
    Add-Result $PhaseNumber ('env ' + $Name) 'Applied' $Value
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-ModuleInstall {
    # Runs Install-Module inside the named host so modules land in that host's module path.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$HostExe, [string]$HostLabel, [string[]]$Name)
    foreach ($m in $Name) {
        $label = '{0} module {1}' -f $HostLabel, $m
        $check = "if (Get-Module -ListAvailable -Name '$m') { exit 0 } else { exit 3 }"
        & $HostExe -NoProfile -NonInteractive -Command $check | Out-Null
        if ($LASTEXITCODE -eq 0) { Add-Result $PhaseNumber $label 'AlreadyPresent'; continue }
        if (-not $PSCmdlet.ShouldProcess($label, 'Install-Module')) { Add-Result $PhaseNumber $label 'WhatIf' 'would install'; continue }
        $cmd = "`$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; " +
        "if (`$PSVersionTable.PSVersion.Major -lt 6) { try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null } catch { } }; " +
        "Install-Module -Name '$m' -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop"
        & $HostExe -NoProfile -NonInteractive -Command $cmd | Out-Null
        if ($LASTEXITCODE -eq 0) { Add-Result $PhaseNumber $label 'Installed' } else { Add-Result $PhaseNumber $label 'Failed' ('exit {0}' -f $LASTEXITCODE) }
    }
}

# ---------------------------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------------------------
function Invoke-Phase1Preflight {
    $p = 1
    $isAdmin = Test-IsAdministrator
    if ($isAdmin) { Add-Result $p 'Elevated session' 'OK' }
    elseif ($WhatIfPreference) { Add-Result $p 'Elevated session' 'Skipped' 'not elevated; allowed because -WhatIf changes nothing' }
    else { Add-Result $p 'Elevated session' 'Failed' 'run from an elevated PowerShell'; return $false }

    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -ge 22000) { Add-Result $p 'Windows 11' 'OK' ('build {0}' -f $build) }
    else { Add-Result $p 'Windows 11' 'Failed' ('build {0} is older than Windows 11' -f $build); return $false }

    Update-SessionPath
    $winget = Find-Tool 'winget'
    if ($winget) { Add-Result $p 'winget' 'OK' ((& winget --version) -join ' ') }
    else { Add-Result $p 'winget' 'Failed' 'App Installer is missing; update it from the Microsoft Store and re-run'; return $false }

    try {
        $null = Invoke-WebRequest -Uri 'https://github.com' -UseBasicParsing -Method Head -TimeoutSec 20
        Add-Result $p 'Network (github.com)' 'OK'
    }
    catch { Add-Result $p 'Network (github.com)' 'Failed' $_.Exception.Message; return $false }
    return $true
}

function Invoke-Phase2WindowsSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $p = 2
    Set-RegistryValueIfDifferent -PhaseNumber $p -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1
    Set-RegistryValueIfDifferent -PhaseNumber $p -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0
    Set-RegistryValueIfDifferent -PhaseNumber $p -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1
    Set-RegistryValueIfDifferent -PhaseNumber $p -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSuperHidden' -Value 1

    $current = Get-ExecutionPolicy -Scope CurrentUser
    if ($current -eq 'RemoteSigned') { Add-Result $p 'Execution policy CurrentUser' 'AlreadyPresent' 'RemoteSigned' }
    elseif ($PSCmdlet.ShouldProcess('CurrentUser', 'Set-ExecutionPolicy RemoteSigned')) {
        try { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop; Add-Result $p 'Execution policy CurrentUser' 'Applied' 'RemoteSigned' }
        catch { Add-Result $p 'Execution policy CurrentUser' 'Failed' $_.Exception.Message }
    }
    else { Add-Result $p 'Execution policy CurrentUser' 'WhatIf' 'would set RemoteSigned' }
}

function Invoke-Phase3Packages {
    $p = 3
    foreach ($pkg in $script:Packages) {
        if ($Group -notcontains $pkg.Group) { continue }
        Install-WingetPackage -PhaseNumber $p -Package $pkg
    }
    Update-SessionPath
}

function Invoke-Phase4GitAndModules {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $p = 4
    Update-SessionPath
    $git = Find-Tool 'git' @("$env:ProgramFiles\Git\cmd\git.exe")
    if ($GitUserName -and $GitUserEmail) {
        if (-not $git) {
            if ($WhatIfPreference) { Add-Result $p 'git identity' 'WhatIf' 'git not installed yet; would set after install' } else { Add-Result $p 'git identity' 'Failed' 'git not found' }
        }
        else {
            $curName = (& $git config --global user.name) -join ''
            $curMail = (& $git config --global user.email) -join ''
            if ($curName -eq $GitUserName -and $curMail -eq $GitUserEmail) { Add-Result $p 'git identity' 'AlreadyPresent' $GitUserEmail }
            elseif ($PSCmdlet.ShouldProcess('git --global', 'set user.name and user.email')) {
                & $git config --global user.name $GitUserName
                & $git config --global user.email $GitUserEmail
                Add-Result $p 'git identity' 'Applied' $GitUserEmail
            }
            else { Add-Result $p 'git identity' 'WhatIf' ('would set {0}' -f $GitUserEmail) }
        }
    }
    else { Add-Result $p 'git identity' 'Skipped' 'pass -GitUserName and -GitUserEmail to set it' }

    $pwsh = Find-Tool 'pwsh' @("$env:ProgramFiles\PowerShell\7\pwsh.exe")
    $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Invoke-ModuleInstall -PhaseNumber $p -HostExe $ps51 -HostLabel 'WindowsPowerShell' -Name $script:Modules51
    if ($pwsh) { Invoke-ModuleInstall -PhaseNumber $p -HostExe $pwsh -HostLabel 'PowerShell7' -Name $script:Modules7 }
    elseif ($WhatIfPreference) { Add-Result $p 'PowerShell 7 modules' 'WhatIf' 'pwsh not installed yet; would install after phase 3' }
    else { Add-Result $p 'PowerShell 7 modules' 'Failed' 'pwsh not found; re-run phase 3 then phase 4' }
}

function Set-VsCodeSettingsMerge {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber)
    $dir = Join-Path $env:APPDATA 'Code\User'
    $file = Join-Path $dir 'settings.json'
    $existing = $null
    if (Test-Path -LiteralPath $file) {
        $raw = Get-Content -LiteralPath $file -Raw
        if ($raw -and $raw.Trim()) {
            try { $existing = $raw | ConvertFrom-Json -ErrorAction Stop }
            catch { Add-Result $PhaseNumber 'VS Code settings.json' 'Skipped' 'existing file has comments or is not plain JSON; merge by hand'; return }
        }
    }
    if (-not $existing) { $existing = New-Object psobject }
    $added = New-Object System.Collections.ArrayList
    foreach ($k in $script:VsCodeSettings.Keys) {
        if (-not (@($existing.PSObject.Properties | ForEach-Object { $_.Name }) -contains $k)) {
            $existing | Add-Member -NotePropertyName $k -NotePropertyValue $script:VsCodeSettings[$k]
            [void]$added.Add($k)
        }
    }
    if ($added.Count -eq 0) { Add-Result $PhaseNumber 'VS Code settings.json' 'AlreadyPresent'; return }
    if (-not $PSCmdlet.ShouldProcess($file, ('add {0} settings' -f $added.Count))) { Add-Result $PhaseNumber 'VS Code settings.json' 'WhatIf' ('would add {0} keys' -f $added.Count); return }
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Write-Utf8NoBom -Path $file -Text ($existing | ConvertTo-Json -Depth 8)
    Add-Result $PhaseNumber 'VS Code settings.json' 'Applied' ('added {0} keys' -f $added.Count)
}

function Set-WindowsTerminalSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber)
    $dir = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
    $file = Join-Path $dir 'settings.json'
    if (Test-Path -LiteralPath $file) { Add-Result $PhaseNumber 'Windows Terminal settings' 'Skipped' 'settings.json already exists; left alone'; return }
    if (-not $PSCmdlet.ShouldProcess($file, 'create minimal settings')) { Add-Result $PhaseNumber 'Windows Terminal settings' 'WhatIf' 'would create'; return }
    $json = @'
{
    "$help": "https://aka.ms/terminal-documentation",
    "$schema": "https://aka.ms/terminal-profiles-schema",
    "defaultProfile": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
    "copyFormatting": "none",
    "copyOnSelect": false,
    "keybindings": [
        { "id": "Terminal.CopyToClipboard", "keys": "ctrl+c" },
        { "id": "Terminal.PasteFromClipboard", "keys": "ctrl+v" },
        { "id": "Terminal.FindText", "keys": "ctrl+shift+f" },
        { "id": "Terminal.DuplicatePaneAuto", "keys": "alt+shift+d" }
    ]
}
'@
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Utf8NoBom -Path $file -Text $json
    Add-Result $PhaseNumber 'Windows Terminal settings' 'Applied' 'default profile PowerShell 7, copy and paste keys'
}

function Set-PowerShellProfileBlock {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber)
    $docs = [Environment]::GetFolderPath('MyDocuments')
    $file = Join-Path $docs 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
    $begin = '# >>> workstation-bootstrap >>>'
    $end = '# <<< workstation-bootstrap <<<'
    $block = @"
$begin
# workon: create or activate a per-project venv named after the current folder.
function workon {
    `$ProjectName = Split-Path -Leaf (Get-Location)
    `$VenvPath = "`$env:USERPROFILE\.local\python\venvs\`$ProjectName"
    if (!(Test-Path `$VenvPath)) { python -m venv `$VenvPath }
    & "`$VenvPath\Scripts\Activate.ps1"
}
# Unblock workspace scripts: cloud sync re-adds the Mark of the Web.
`$CodeScriptsRoot = '$WorkspaceRoot\scripts'
if (Test-Path `$CodeScriptsRoot) {
    Get-ChildItem -Path `$CodeScriptsRoot -Recurse -Include *.ps1,*.psm1,*.psd1 -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue
}
$end
"@
    $text = ''
    if (Test-Path -LiteralPath $file) { $text = Get-Content -LiteralPath $file -Raw }
    if ($text -and $text.Contains($begin)) { Add-Result $PhaseNumber 'Windows PowerShell profile' 'AlreadyPresent'; return }
    if (-not $PSCmdlet.ShouldProcess($file, 'append managed profile block')) { Add-Result $PhaseNumber 'Windows PowerShell profile' 'WhatIf' 'would append workon and unblock block'; return }
    New-Item -ItemType Directory -Path (Split-Path -Parent $file) -Force | Out-Null
    Add-Content -LiteralPath $file -Value ("`r`n" + $block + "`r`n")
    Add-Result $PhaseNumber 'Windows PowerShell profile' 'Applied' 'workon function and script unblock'
}

function Invoke-Phase5EditorAndShell {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $p = 5
    Update-SessionPath
    $code = Find-Tool 'code' @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\bin\code.cmd'),
        (Join-Path $env:ProgramFiles 'Microsoft VS Code\bin\code.cmd'))
    if ($code) {
        $installed = @(& $code --list-extensions 2>$null | ForEach-Object { $_.ToLowerInvariant() })
        foreach ($ext in $script:VsCodeExtensions) {
            if ($installed -contains $ext) { Add-Result $p ('VS Code extension ' + $ext) 'AlreadyPresent'; continue }
            if (-not $PSCmdlet.ShouldProcess($ext, 'code --install-extension')) { Add-Result $p ('VS Code extension ' + $ext) 'WhatIf' 'would install'; continue }
            & $code --install-extension $ext --force 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { Add-Result $p ('VS Code extension ' + $ext) 'Installed' } else { Add-Result $p ('VS Code extension ' + $ext) 'Failed' ('exit {0}' -f $LASTEXITCODE) }
        }
    }
    elseif ($WhatIfPreference) { Add-Result $p 'VS Code extensions' 'WhatIf' ('VS Code not installed yet; would install {0} extensions' -f $script:VsCodeExtensions.Count) }
    else { Add-Result $p 'VS Code extensions' 'Failed' 'code command not found; re-run phase 3 then phase 5' }

    Set-VsCodeSettingsMerge -PhaseNumber $p
    Set-WindowsTerminalSettings -PhaseNumber $p
    Set-PowerShellProfileBlock -PhaseNumber $p

    $pyCache = Join-Path $env:USERPROFILE '.local\python\pycache'
    Set-UserEnvVar -PhaseNumber $p -Name 'PY_PYTHON' -Value '3.13'
    Set-UserEnvVar -PhaseNumber $p -Name 'PYTHONPYCACHEPREFIX' -Value $pyCache
    Set-UserEnvVar -PhaseNumber $p -Name 'python313' -Value (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')
    if ($Group -contains 'AiContainers') {
        Set-UserEnvVar -PhaseNumber $p -Name 'OLLAMA_CONTEXT_LENGTH' -Value '16384'
        Set-UserEnvVar -PhaseNumber $p -Name 'OLLAMA_KV_CACHE_TYPE' -Value 'q8_0'
        if ($OllamaModelsPath) { Set-UserEnvVar -PhaseNumber $p -Name 'OLLAMA_MODELS' -Value $OllamaModelsPath }
        else { Add-Result $p 'env OLLAMA_MODELS' 'Skipped' 'pass -OllamaModelsPath to move model storage off the system drive' }
    }
}

function New-DirectoryIfMissing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$Path)
    if (Test-Path -LiteralPath $Path) { Add-Result $PhaseNumber ('folder ' + $Path) 'AlreadyPresent'; return }
    if (-not $PSCmdlet.ShouldProcess($Path, 'create folder')) { Add-Result $PhaseNumber ('folder ' + $Path) 'WhatIf' 'would create'; return }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Add-Result $PhaseNumber ('folder ' + $Path) 'Applied'
}

function Invoke-GitClone {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$Git, [string]$Url, [string]$Destination, [string]$Label)
    if (Test-Path -LiteralPath (Join-Path $Destination '.git')) { Add-Result $PhaseNumber ('clone ' + $Label) 'AlreadyPresent' $Destination; return }
    if (-not $PSCmdlet.ShouldProcess($Url, ('git clone to {0}' -f $Destination))) { Add-Result $PhaseNumber ('clone ' + $Label) 'WhatIf' $Destination; return }
    & $Git clone $Url $Destination 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Add-Result $PhaseNumber ('clone ' + $Label) 'Applied' $Destination } else { Add-Result $PhaseNumber ('clone ' + $Label) 'Failed' ('git exit {0}' -f $LASTEXITCODE) }
}

function Invoke-GitAdopt {
    # Turns an existing non-empty folder into a clone: init, fetch, then a non-forced checkout so a
    # colliding untracked file stops the checkout instead of being overwritten.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$PhaseNumber, [string]$Git, [string]$Url, [string]$Destination, [string]$Label)
    if (-not $PSCmdlet.ShouldProcess($Url, ('git init, fetch and checkout inside existing {0}' -f $Destination))) { Add-Result $PhaseNumber ('clone ' + $Label) 'WhatIf' $Destination; return }
    & $Git -C $Destination init -q 2>$null | Out-Null
    & $Git -C $Destination remote add origin $Url 2>$null | Out-Null
    & $Git -C $Destination fetch -q origin 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Add-Result $PhaseNumber ('clone ' + $Label) 'Failed' ('git fetch exit {0}' -f $LASTEXITCODE); return }
    & $Git -C $Destination remote set-head origin -a 2>$null | Out-Null
    $head = (& $Git -C $Destination symbolic-ref --short refs/remotes/origin/HEAD 2>$null)
    if (-not $head) { Add-Result $PhaseNumber ('clone ' + $Label) 'Failed' 'could not find the remote default branch'; return }
    $branch = ([string]$head) -replace '^origin/', ''
    & $Git -C $Destination checkout -B $branch --track $head 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Add-Result $PhaseNumber ('clone ' + $Label) 'Applied' ('existing folder adopted on ' + $branch) }
    else { Add-Result $PhaseNumber ('clone ' + $Label) 'Failed' ('git checkout exit {0}; an untracked file collides with a tracked one' -f $LASTEXITCODE) }
}

function Invoke-Phase6Workspace {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $p = 6
    Update-SessionPath
    $git = Find-Tool 'git' @("$env:ProgramFiles\Git\cmd\git.exe")
    $gh = Find-Tool 'gh' @("$env:ProgramFiles\GitHub CLI\gh.exe")
    if (-not $git -or -not $gh) {
        if ($WhatIfPreference) { Add-Result $p 'Workspace' 'WhatIf' 'git or gh not installed yet; would continue after phase 3' }
        else { Add-Result $p 'Workspace' 'Failed' 'git or gh not found; re-run phase 3 then phase 6' }
        return
    }

    # gh login first: the private workspace repo and the repo list both need it.
    & $gh auth status 2>$null | Out-Null
    $loggedIn = ($LASTEXITCODE -eq 0)
    if ($loggedIn) { Add-Result $p 'gh login' 'AlreadyPresent' }
    elseif ($PSCmdlet.ShouldProcess('GitHub', 'gh auth login (opens a browser)')) {
        Write-Log 'gh login: a one-time code is shown next. Open https://github.com/login/device in any browser, enter it, and approve within a few minutes. The clipboard copy can fail in an elevated shell; type the code.'
        & $gh auth login --web --git-protocol https
        & $gh auth status 2>$null | Out-Null
        $loggedIn = ($LASTEXITCODE -eq 0)
        if ($loggedIn) { Add-Result $p 'gh login' 'Applied' } else {
            Add-Result $p 'gh login' 'Failed' 'login did not complete; private clones will be skipped'
            [void]$script:ManualSteps.Add('Run gh auth login by hand, then re-run this script with -Phase 6 (plus -GitUserName, -GitUserEmail and -WorkspaceRepo) to clone the workspace and your repos.')
        }
    }
    else { Add-Result $p 'gh login' 'WhatIf' 'would open a browser login' }
    if ($loggedIn) { & $gh auth setup-git 2>$null | Out-Null }

    # The workspace repo is the root folder itself, so it must be cloned before the layout exists.
    $rootHasContent = (Test-Path -LiteralPath $WorkspaceRoot) -and (@(Get-ChildItem -LiteralPath $WorkspaceRoot -Force -ErrorAction SilentlyContinue).Count -gt 0)
    if ($WorkspaceRepo) {
        if (Test-Path -LiteralPath (Join-Path $WorkspaceRoot '.git')) { Add-Result $p 'workspace repo' 'AlreadyPresent' $WorkspaceRoot }
        elseif ($rootHasContent -and $loggedIn) { Invoke-GitAdopt -PhaseNumber $p -Git $git -Url $WorkspaceRepo -Destination $WorkspaceRoot -Label 'workspace repo' }
        elseif ($loggedIn) { Invoke-GitClone -PhaseNumber $p -Git $git -Url $WorkspaceRepo -Destination $WorkspaceRoot -Label 'workspace repo' }
        else { Add-Result $p 'workspace repo' 'Skipped' 'needs gh login' }
    }
    else { Add-Result $p 'workspace repo' 'Skipped' 'pass -WorkspaceRepo to clone the private workspace repo into the root' }

    foreach ($sub in 'projects', 'venvs', 'worktrees', 'scripts') { New-DirectoryIfMissing -PhaseNumber $p -Path (Join-Path $WorkspaceRoot $sub) }
    New-DirectoryIfMissing -PhaseNumber $p -Path $DataRoot
    New-DirectoryIfMissing -PhaseNumber $p -Path (Join-Path $DataRoot 'workspace')

    Invoke-GitClone -PhaseNumber $p -Git $git -Url $OpsToolkitUrl -Destination (Join-Path $WorkspaceRoot 'projects\ops-toolkit') -Label 'ops-toolkit'

    if ($SkipRepoClone) { Add-Result $p 'owned repos' 'Skipped' '-SkipRepoClone'; return }
    if (-not $loggedIn) { Add-Result $p 'owned repos' 'Skipped' 'needs gh login'; return }
    $workspaceName = ''
    if ($WorkspaceRepo) { $workspaceName = ([System.IO.Path]::GetFileNameWithoutExtension(($WorkspaceRepo.TrimEnd('/') -split '[/:]')[-1])) }
    $listJson = (& $gh repo list --source --no-archived --limit 500 --json name,nameWithOwner) -join ''
    $repos = @()
    # Windows PowerShell 5.1 returns a JSON array as one object; piping it to ForEach-Object unrolls it.
    try { $repos = @($listJson | ConvertFrom-Json -ErrorAction Stop | ForEach-Object { $_ }) } catch { Add-Result $p 'owned repos' 'Failed' 'could not read gh repo list'; return }
    foreach ($r in $repos) {
        if ($workspaceName -and $r.name -eq $workspaceName) { continue }
        Invoke-GitClone -PhaseNumber $p -Git $git -Url ('https://github.com/{0}.git' -f $r.nameWithOwner) -Destination (Join-Path $WorkspaceRoot ('projects\' + $r.name)) -Label $r.name
    }
}

function Invoke-Phase7DockerWsl {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $p = 7
    if ($Group -notcontains 'AiContainers') { Add-Result $p 'Docker and WSL' 'Skipped' 'AiContainers group not selected'; return }
    Update-SessionPath
    $wsl = Find-Tool 'wsl' @((Join-Path $env:SystemRoot 'System32\wsl.exe'))
    if (-not $wsl) { Add-Result $p 'WSL update' 'Skipped' 'wsl.exe not present yet; reboot, then re-run phase 7'; $script:RebootHint = $true; return }
    if (-not $PSCmdlet.ShouldProcess('WSL', 'wsl --update')) { Add-Result $p 'WSL update' 'WhatIf' 'would run wsl --update'; return }
    & $wsl --update 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Add-Result $p 'WSL update' 'Applied' } else { Add-Result $p 'WSL update' 'Skipped' ('wsl exit {0}; reboot and re-run phase 7' -f $LASTEXITCODE); $script:RebootHint = $true }
    [void]$script:ManualSteps.Add('Start Docker Desktop once, accept its terms, and let it finish enabling WSL 2 (a reboot may be requested).')
}

function Get-HardeningCommand {
    param([string]$OpsRoot)
    $dir = Join-Path $OpsRoot 'scripts\it-operations\windows-hardening'
    @(
        [pscustomobject]@{ Name = 'Privacy and telemetry'; Script = (Join-Path $dir 'Set-Windows11PrivacyHardening.ps1') }
        [pscustomobject]@{ Name = 'Schannel TLS 1.2-only'; Script = (Join-Path $dir 'Set-WindowsSchannelTlsHardening.ps1') }
        [pscustomobject]@{ Name = 'Workstation lock posture'; Script = (Join-Path $dir 'Set-WorkstationLockPosture.ps1') }
        [pscustomobject]@{ Name = 'Browser credential posture'; Script = (Join-Path $dir 'Set-BrowserCredentialPosture.ps1') }
        [pscustomobject]@{ Name = 'AppX bloatware removal'; Script = (Join-Path $dir 'Remove-WindowsProvisionedBloatwareApps.ps1') }
    )
}

function Invoke-Phase8HardeningPreview {
    $p = 8
    $opsRoot = Join-Path $WorkspaceRoot 'projects\ops-toolkit'
    $pwsh = Find-Tool 'pwsh' @("$env:ProgramFiles\PowerShell\7\pwsh.exe")
    $planDir = Join-Path $DataRoot 'workspace\hardening-preview'
    if (-not (Test-Path -LiteralPath (Join-Path $opsRoot 'scripts\it-operations\windows-hardening'))) {
        Add-Result $p 'Hardening preview' 'Skipped' ('ops-toolkit not found at {0}; run phase 6 first' -f $opsRoot)
        return
    }
    if (-not $pwsh) { Add-Result $p 'Hardening preview' 'Skipped' 'pwsh not installed'; return }
    foreach ($h in (Get-HardeningCommand -OpsRoot $opsRoot)) {
        # Always -WhatIf: this phase has no apply path by design.
        if ($WhatIfPreference) { Add-Result $p ('Hardening preview ' + $h.Name) 'WhatIf' 'would run the script with -WhatIf'; continue }
        $out = Join-Path $planDir (($h.Name -replace '[^A-Za-z0-9]+', '-'))
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        & $pwsh -NoProfile -ExecutionPolicy Bypass -File $h.Script -ReportDirectory $out -WhatIf | Out-Null
        if ($LASTEXITCODE -eq 0) { Add-Result $p ('Hardening preview ' + $h.Name) 'Applied' ('plan written to ' + $out) }
        else { Add-Result $p ('Hardening preview ' + $h.Name) 'Failed' ('exit {0}' -f $LASTEXITCODE) }
    }
    $scriptDir = 'scripts\it-operations\windows-hardening'
    [void]$script:ManualSteps.Add(('Read the hardening plans under {0}, then apply one at a time from an elevated pwsh in {1}:' -f $planDir, $opsRoot))
    foreach ($h in (Get-HardeningCommand -OpsRoot $opsRoot)) {
        $leaf = Split-Path -Leaf $h.Script
        $applyDir = Join-Path $DataRoot ('workspace\hardening-applied\' + ($h.Name -replace '[^A-Za-z0-9]+', '-'))
        [void]$script:ManualSteps.Add(('  pwsh -File .\{0}\{1} -ReportDirectory "{2}"' -f $scriptDir, $leaf, $applyDir))
    }
    [void]$script:ManualSteps.Add('  Verify afterwards: pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1')
    [void]$script:ManualSteps.Add('  The AppX removal script needs -RemoveProvisionedPackages -InstalledPackageScope AllUsers to remove for new users too; read its header first.')
}

function Invoke-Phase9Summary {
    $p = 9
    $byStatus = $script:Results | Group-Object Status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
    Add-Result $p 'Result counts' 'OK' ($byStatus -join ', ')
    [void]$script:ManualSteps.Add('Sign in by hand: Proton (Drive, Mail Bridge, VPN), Google Drive, Slack, Zoom, Teams, Discord, Claude, and az / gcloud / Connect-MgGraph as needed.')
    [void]$script:ManualSteps.Add('Copy by hand from the old machine (never stored here): ~\.claude (settings, CLAUDE.md, memory), the workspace profile.local.md, and any .env or credentials files.')
    [void]$script:ManualSteps.Add('Not mirrored on purpose: vendor and gaming utilities, CUDA and GPU drivers, Chocolatey duplicates, Python 3.10, the SetACL tool, Cloudflare client. Add them if this hardware needs them.')
    if ($script:RebootHint) { [void]$script:ManualSteps.Add('REBOOT: at least one install asked for it. Reboot, then re-run this script to finish any step marked Skipped or Failed.') }
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
# The run folder and its reports are the plan itself, so they are written even under -WhatIf.
$script:RunDir = Join-Path $ReportDirectory ('workstation-bootstrap-' + $runStamp)
New-Item -ItemType Directory -Path $script:RunDir -Force -WhatIf:$false | Out-Null
Write-Log ('Run folder: ' + $script:RunDir)
Write-Log ('Groups: ' + ($Group -join ', ') + '; phases: ' + (($Phase | Sort-Object) -join ','))

$exitCode = 0
$preflightOk = $true
foreach ($n in ($Phase | Sort-Object -Unique)) {
    if (-not $preflightOk -and $n -gt 1) { break }
    Write-Log ('=== Phase {0}: {1}' -f $n, $script:PhaseNames[$n]) 'PHASE'
    try {
        switch ($n) {
            1 { $preflightOk = Invoke-Phase1Preflight; if (-not $preflightOk) { $exitCode = 2 } }
            2 { Invoke-Phase2WindowsSettings }
            3 { Invoke-Phase3Packages }
            4 { Invoke-Phase4GitAndModules }
            5 { Invoke-Phase5EditorAndShell }
            6 { Invoke-Phase6Workspace }
            7 { Invoke-Phase7DockerWsl }
            8 { Invoke-Phase8HardeningPreview }
            9 { Invoke-Phase9Summary }
        }
    }
    catch { Add-Result $n ('Phase ' + $n + ' unexpected error') 'Failed' $_.Exception.Message }
}

$failedCount = @($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count
if ($exitCode -eq 0 -and $failedCount -gt 0) { $exitCode = 1 }
$summary = [pscustomobject]@{
    RunFolder     = $script:RunDir
    WhatIf        = [bool]$WhatIfPreference
    Groups        = $Group
    Phases        = ($Phase | Sort-Object -Unique)
    StepCount     = $script:Results.Count
    FailedCount   = $failedCount
    RebootHint    = $script:RebootHint
    ManualSteps   = @($script:ManualSteps)
    ExitCode      = $exitCode
}
$script:Results | Export-Csv -LiteralPath (Join-Path $script:RunDir 'results.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false
Write-Utf8NoBom -Path (Join-Path $script:RunDir 'results.json') -Text (ConvertTo-Json -InputObject @($script:Results) -Depth 4)
Write-Utf8NoBom -Path (Join-Path $script:RunDir 'summary.json') -Text (ConvertTo-Json -InputObject $summary -Depth 4)

Write-Host ''
Write-Host ('Steps: {0}   Failed: {1}   Report: {2}' -f $script:Results.Count, $failedCount, $script:RunDir)
if ($script:ManualSteps.Count -gt 0) {
    Write-Host ''
    Write-Host 'Next steps:'
    $script:ManualSteps | ForEach-Object { Write-Host (' - ' + $_) }
}
$summary
exit $exitCode
