<#
.SYNOPSIS
Import an Azure VPN Client XML profile for a Windows 11 user and write review reports.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\ops-toolkit\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Download the Azure VPN Client profile XML from Azure, then pass it with -ProfileXmlPath.
- Run in the target Windows 11 user's context so the profile is imported into that user's Azure VPN Client state.
- Always run with -WhatIf first and review the generated plan/state reports.
- Generated reports are written under reports\azure by default.

.PURPOSE
Use this script to stage and import an Azure VPN Client XML profile on Windows
11. It validates the XML, copies it into the Azure VPN Client LocalState folder,
optionally backs up an existing profile file, invokes azurevpn, and writes
plan/state reports.

.REQUIRED SYNTAX
pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig.xml -WhatIf
pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig_aad.xml -ForceImport -BackupExisting

.OUTPUTS
Writes plan/state JSON reports under reports\azure by default. Returns a
summary object with source, staged profile, backup path, command, and result.

.STATUS
Active script kept in the reorganized ops-toolkit repo. Windows 11 target.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ProfileXmlPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserProfilePath = $env:USERPROFILE,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AzureVpnCommand,

    [Parameter()]
    [switch]$ForceImport,

    [Parameter()]
    [switch]$BackupExisting,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig.xml -WhatIf
  pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig_aad.xml -ForceImport -BackupExisting

Options:
  -ProfileXmlPath   Downloaded Azure VPN Client XML profile to import.
  -UserProfilePath  Target Windows user profile path. Defaults to the current user's profile.
  -AzureVpnCommand  Optional full path to azurevpn.exe or an app execution alias.
  -ForceImport      Pass -f to azurevpn so an existing profile can be replaced.
  -BackupExisting   Back up an existing staged XML file before replacing it.
  -ReportDirectory  Plan/state output directory.
  -WhatIf           Preview folder creation, XML copy, backup, and import command.
'@
}

function Resolve-ReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-AzureVpnCommand {
    param(
        [Parameter()]
        [string]$CommandPath
    )

    if ($CommandPath) {
        if (Test-Path -LiteralPath $CommandPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $CommandPath).Path
        }

        $explicitCommand = Get-Command -Name $CommandPath -ErrorAction SilentlyContinue
        if ($explicitCommand) {
            return $explicitCommand.Source
        }

        throw "Azure VPN Client command '$CommandPath' was not found."
    }

    foreach ($candidate in @('azurevpn.exe', 'azurevpn')) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved) {
            return $resolved.Source
        }
    }

    $windowsAppsAlias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\azurevpn.exe'
    if (Test-Path -LiteralPath $windowsAppsAlias -PathType Leaf) {
        return $windowsAppsAlias
    }

    throw 'Azure VPN Client command was not found. Install Azure VPN Client from Microsoft Store, then enable its azurevpn app execution alias or pass -AzureVpnCommand.'
}

if (-not $ProfileXmlPath) {
    Show-Usage
    exit 2
}

if (-not (Test-Path -LiteralPath $ProfileXmlPath -PathType Leaf)) {
    throw "Profile XML path '$ProfileXmlPath' was not found."
}

if (-not (Test-Path -LiteralPath $UserProfilePath -PathType Container)) {
    throw "User profile path '$UserProfilePath' was not found."
}

$profileFile = Get-Item -LiteralPath $ProfileXmlPath
if ($profileFile.Extension -ne '.xml') {
    throw "Profile file '$($profileFile.FullName)' must be an Azure VPN Client XML profile."
}

try {
    [xml]$profileXml = Get-Content -LiteralPath $profileFile.FullName -Raw
} catch {
    throw "Profile file '$($profileFile.FullName)' is not valid XML. $($_.Exception.Message)"
}

if (-not $profileXml.azvpnprofile) {
    throw "Profile file '$($profileFile.FullName)' does not look like an Azure VPN Client profile. Expected root element 'azvpnprofile'."
}

$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$planPath = Join-Path $resolvedReportDirectory "azure-vpn-profile-import-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "azure-vpn-profile-import-state-$timestamp.json"
$localStatePath = Join-Path $UserProfilePath 'AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState'
$targetProfilePath = Join-Path $localStatePath $profileFile.Name
$backupPath = if (Test-Path -LiteralPath $targetProfilePath -PathType Leaf) {
    Join-Path $resolvedReportDirectory "azure-vpn-profile-backup-$timestamp-$($profileFile.Name)"
} else {
    $null
}
$importArguments = @('-i', $profileFile.Name)
if ($ForceImport) {
    $importArguments += '-f'
}
$command = if ($WhatIfPreference) {
    if ($AzureVpnCommand) { $AzureVpnCommand } else { 'azurevpn' }
} else {
    Resolve-AzureVpnCommand -CommandPath $AzureVpnCommand
}

$plan = [pscustomobject]@{
    GeneratedAt = Get-Date
    SourceProfile = $profileFile.FullName
    UserProfilePath = (Resolve-Path -LiteralPath $UserProfilePath).Path
    LocalStatePath = $localStatePath
    TargetProfilePath = $targetProfilePath
    ExistingProfileWillBeBackedUp = [bool]($BackupExisting -and $backupPath)
    BackupPath = if ($BackupExisting) { $backupPath } else { $null }
    ForceImport = [bool]$ForceImport
    Command = $command
    Arguments = $importArguments -join ' '
}
Set-Content -LiteralPath $planPath -Value ($plan | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false

$results = [System.Collections.Generic.List[string]]::new()
if ($PSCmdlet.ShouldProcess($localStatePath, 'Create Azure VPN Client LocalState folder')) {
    New-Item -ItemType Directory -Path $localStatePath -Force | Out-Null
    $results.Add('LocalStateReady')
} else {
    $results.Add('LocalStatePreviewed')
}

if ($BackupExisting -and $backupPath -and (Test-Path -LiteralPath $targetProfilePath -PathType Leaf)) {
    if ($PSCmdlet.ShouldProcess($targetProfilePath, "Back up existing Azure VPN Client XML profile to $backupPath")) {
        Copy-Item -LiteralPath $targetProfilePath -Destination $backupPath -Force
        $results.Add('ExistingProfileBackedUp')
    } else {
        $results.Add('ExistingProfileBackupPreviewed')
    }
}

if ($PSCmdlet.ShouldProcess($targetProfilePath, 'Copy Azure VPN Client XML profile')) {
    Copy-Item -LiteralPath $profileFile.FullName -Destination $targetProfilePath -Force
    $results.Add('ProfileCopied')
} else {
    $results.Add('ProfileCopyPreviewed')
}

if ($PSCmdlet.ShouldProcess($targetProfilePath, "Import Azure VPN Client profile with '$command $($importArguments -join ' ')'")) {
    Push-Location -LiteralPath $localStatePath
    try {
        & $command @importArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Azure VPN Client import failed with exit code $LASTEXITCODE."
        }
        $results.Add('ProfileImported')
    } finally {
        Pop-Location
    }
} else {
    $results.Add('ProfileImportPreviewed')
}

$state = [pscustomobject]@{
    GeneratedAt = Get-Date
    SourceProfile = $profileFile.FullName
    LocalStatePath = $localStatePath
    ImportedProfile = $targetProfilePath
    BackupPath = if ($BackupExisting) { $backupPath } else { $null }
    ForceImport = [bool]$ForceImport
    Command = $command
    Arguments = $importArguments -join ' '
    Results = $results -join ';'
}
Set-Content -LiteralPath $statePath -Value ($state | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    SourceProfile = $profileFile.FullName
    ImportedProfile = $targetProfilePath
    BackupPath = $state.BackupPath
    Command = $command
    Results = $state.Results
    PlanPath = (Resolve-Path -LiteralPath $planPath).Path
    StatePath = (Resolve-Path -LiteralPath $statePath).Path
}
