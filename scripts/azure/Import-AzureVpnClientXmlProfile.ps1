<#
.SYNOPSIS
Import an Azure VPN Client XML profile for the current Windows user.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Download the Azure VPN Client profile XML from Azure, then pass it with -ProfileXmlPath.
- Run in the target user's context so the profile is imported into that user's Azure VPN Client state.
- Use -WhatIf first to preview the target path and import command.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
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
    [switch]$ForceImport
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig.xml -WhatIf
  pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig_aad.xml -ForceImport

Options:
  -ProfileXmlPath   Downloaded Azure VPN Client XML profile to import.
  -UserProfilePath  Target Windows user profile path. Defaults to the current user's profile.
  -AzureVpnCommand  Optional full path to azurevpn.exe or an app execution alias.
  -ForceImport      Pass -f to azurevpn so an existing profile can be replaced.
  -WhatIf           Preview folder creation, XML copy, and import command.
'@
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

if (-not (Test-Path -LiteralPath $UserProfilePath -PathType Container)) {
    throw "User profile path '$UserProfilePath' was not found."
}

$localStatePath = Join-Path $UserProfilePath 'AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState'
$targetProfilePath = Join-Path $localStatePath $profileFile.Name

if ($PSCmdlet.ShouldProcess($localStatePath, 'Create Azure VPN Client LocalState folder')) {
    New-Item -ItemType Directory -Path $localStatePath -Force | Out-Null
}

if ($PSCmdlet.ShouldProcess($targetProfilePath, 'Copy Azure VPN Client XML profile')) {
    Copy-Item -LiteralPath $profileFile.FullName -Destination $targetProfilePath -Force
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

if ($PSCmdlet.ShouldProcess($targetProfilePath, "Import Azure VPN Client profile with '$command $($importArguments -join ' ')'")) {
    Push-Location -LiteralPath $localStatePath
    try {
        & $command @importArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Azure VPN Client import failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }
}

[pscustomobject]@{
    SourceProfile = $profileFile.FullName
    LocalStatePath = $localStatePath
    ImportedProfile = $targetProfilePath
    ForceImport = [bool]$ForceImport
    Command = $command
}
