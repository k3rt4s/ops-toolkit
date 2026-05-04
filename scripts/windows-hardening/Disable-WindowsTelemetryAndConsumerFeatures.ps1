<#
.SYNOPSIS
Disable Windows telemetry, consumer features, scheduled tasks, and related services.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Disable-WindowsTelemetryAndConsumerFeatures.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- Run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$DisableScheduledTasks,

    [Parameter()]
    [switch]$DisableServices
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

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

function Invoke-TelemetryRegistryHardening {
    [CmdletBinding()]
    param()

    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value 1
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic' -Name 'FirstRunSucceeded' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'Value' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'Value' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoTileApplicationNotification' -Value 1
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Value 0
    Set-RegistryDwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Value 0
    Set-RegistryDwordValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Value 0
}

function Disable-ScheduledTelemetryTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string[]]$TaskName
    )

    foreach ($name in $TaskName) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task -and $PSCmdlet.ShouldProcess($name, 'Disable scheduled task')) {
            $task | Disable-ScheduledTask | Out-Null
        }
    }
}

function Disable-TelemetryService {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string[]]$Name
    )

    foreach ($serviceName in $Name) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) {
            continue
        }

        if ($service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($serviceName, 'Stop service')) {
            Stop-Service -Name $serviceName -ErrorAction Continue
        }

        if ($PSCmdlet.ShouldProcess($serviceName, 'Set service startup type to Disabled')) {
            Set-Service -Name $serviceName -StartupType Disabled
        }
    }
}

Invoke-TelemetryRegistryHardening

if ($DisableScheduledTasks) {
    Disable-ScheduledTelemetryTask -TaskName @(
        'XblGameSaveTask',
        'Consolidator',
        'UsbCeip',
        'DmClient',
        'DmClientOnScenarioDownload'
    )
}

if ($DisableServices) {
    Disable-TelemetryService -Name @(
        'dmwappushservice',
        'DiagTrack'
    )
}
