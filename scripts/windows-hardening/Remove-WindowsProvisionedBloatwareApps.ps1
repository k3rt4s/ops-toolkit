<#
.SYNOPSIS
Remove unwanted AppX and provisioned Windows apps and related registry keys.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Remove-WindowsProvisionedBloatwareApps.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- Run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$PackageNamePattern = @(
        'BubbleWitch3Saga',
        'CandyCrush',
        'Facebook',
        'Flipboard',
        'Microsoft.BingNews',
        'Microsoft.MicrosoftOfficeHub',
        'Microsoft.Office.Lens',
        'Microsoft.Office.OneNote',
        'Microsoft.Office.Sway',
        'Microsoft.OneConnect',
        'Microsoft.People',
        'Microsoft.Print3D',
        'Microsoft.SkypeApp',
        'Microsoft.StorePurchaseApp',
        'Microsoft.WindowsMaps',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.ZuneMusic',
        'Microsoft.ZuneVideo',
        'Minecraft',
        'PandoraMediaInc',
        'Royal Revolt',
        'Spotify',
        'Twitter',
        'Wunderlist'
    ),

    [Parameter()]
    [string[]]$ProtectedPackageNamePattern = @(
        'Microsoft.DesktopAppInstaller',
        'Microsoft.MSPaint',
        'Microsoft.WindowsCalculator',
        'Microsoft.Windows.Photos',
        'Microsoft.WindowsStore',
        'Microsoft.WindowsCamera',
        'Microsoft.WindowsNotepad'
    ),

    [Parameter()]
    [switch]$AllUsers,

    [Parameter()]
    [switch]$RemoveProvisionedPackages,

    [Parameter()]
    [switch]$ApplyConsumerFeatureHardening,

    [Parameter()]
    [switch]$RestartExplorer
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Test-PackageNameMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Pattern
    )

    foreach ($item in $Pattern) {
        if ($Name -like "*$item*") {
            return $true
        }
    }

    return $false
}

function Invoke-AppxPackageRemoval {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string[]]$PackageNamePattern,

        [Parameter(Mandatory)]
        [string[]]$ProtectedPackageNamePattern,

        [Parameter()]
        [switch]$AllUsers
    )

    $queryParameters = @{}
    if ($AllUsers) {
        $queryParameters.AllUsers = $true
    }

    $packages = Get-AppxPackage @queryParameters | Where-Object {
        (Test-PackageNameMatch -Name $_.Name -Pattern $PackageNamePattern) -and
        -not (Test-PackageNameMatch -Name $_.Name -Pattern $ProtectedPackageNamePattern)
    }

    foreach ($package in $packages) {
        if ($PSCmdlet.ShouldProcess($package.PackageFullName, 'Remove AppX package')) {
            Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Continue
        }
    }
}

function Invoke-AppxProvisionedPackageRemoval {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string[]]$PackageNamePattern,

        [Parameter(Mandatory)]
        [string[]]$ProtectedPackageNamePattern
    )

    $packages = Get-AppxProvisionedPackage -Online | Where-Object {
        (Test-PackageNameMatch -Name $_.DisplayName -Pattern $PackageNamePattern) -and
        -not (Test-PackageNameMatch -Name $_.DisplayName -Pattern $ProtectedPackageNamePattern)
    }

    foreach ($package in $packages) {
        if ($PSCmdlet.ShouldProcess($package.PackageName, 'Remove provisioned AppX package')) {
            Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Continue | Out-Null
        }
    }
}

function Set-RegistryDwordValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$Value
    )

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD value to $Value")) {
        New-Item -Path $Path -Force | Out-Null
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}

function Invoke-ConsumerFeatureHardening {
    [CmdletBinding()]
    param()

    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoTileApplicationNotification' -Value 1
}

Invoke-AppxPackageRemoval `
    -PackageNamePattern $PackageNamePattern `
    -ProtectedPackageNamePattern $ProtectedPackageNamePattern `
    -AllUsers:$AllUsers

if ($RemoveProvisionedPackages) {
    Invoke-AppxProvisionedPackageRemoval `
        -PackageNamePattern $PackageNamePattern `
        -ProtectedPackageNamePattern $ProtectedPackageNamePattern
}

if ($ApplyConsumerFeatureHardening) {
    Invoke-ConsumerFeatureHardening
}

if ($RestartExplorer -and $PSCmdlet.ShouldProcess('explorer.exe', 'Restart Explorer')) {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe
}
