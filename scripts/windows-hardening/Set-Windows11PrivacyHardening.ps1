<#
.SYNOPSIS
Plan, apply, and roll back Windows 11 privacy, telemetry, and consumer-feature hardening.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell before applying live HKLM, service, or task changes.
- Backups are written before live registry changes unless -SkipRegistryBackup is used.
- Use -Rollback to restore policy values to default/not-configured or re-enable user settings.
- This script is scoped to Windows 11. It exits on older Windows builds unless -SkipWindows11Check is used.

.PURPOSE
Use this to reduce optional Windows 11 diagnostic data, tailored experiences,
advertising identifiers, consumer suggestions, Windows Search web suggestions,
activity history, feedback prompts, selected app privacy surfaces, and related
content-delivery settings. Optional switches can also disable selected telemetry
scheduled tasks and services.

The hardening list was checked against Microsoft Windows privacy documentation.
It intentionally does not disable security-sensitive Microsoft connections such
as Defender, SmartScreen, Windows Update, licensing, or root certificate updates.

.REQUIRED SYNTAX
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -Rollback -WhatIf

.OUTPUTS
Writes plan and state-list CSV/JSON files under reports\windows-hardening by
default. Live runs also export relevant registry branches to .reg files before
changes unless -SkipRegistryBackup is used. Returns a summary object with
report and backup paths, changed/skipped counts, restart-required status, and
the items disabled after hardening or enabled/default-restored after rollback.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Required', 'Security')]
    [string]$DiagnosticDataLevel = 'Required',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\windows-hardening'),

    [Parameter()]
    [switch]$IncludeScheduledTasks,

    [Parameter()]
    [switch]$IncludeServices,

    [Parameter()]
    [switch]$SkipCurrentUserSettings,

    [Parameter()]
    [switch]$SkipRegistryBackup,

    [Parameter()]
    [switch]$SkipWindows11Check,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows 11 privacy hardening.

Usage:
  pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
  pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1
  pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -Rollback -WhatIf

Options:
  -DiagnosticDataLevel    Required or Security. Default: Required.
                           Security is intended for Windows Enterprise/Education/Server-style use.
  -ReportDirectory        Plan and backup output directory.
  -IncludeScheduledTasks  Disable or roll back selected telemetry/customer-experience scheduled tasks.
  -IncludeServices        Disable or roll back selected telemetry services.
  -SkipCurrentUserSettings
                           Do not change HKCU privacy/content-delivery settings.
  -SkipRegistryBackup     Do not export registry backup files before live registry changes.
  -SkipWindows11Check     Allow execution on non-Windows 11 builds.
  -Rollback               Restore values to Windows default/not-configured or enabled settings.
  -WhatIf                 Write the plan and preview changes.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsBuildNumber {
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    [int]$currentVersion.CurrentBuildNumber
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $property) {
        return $null
    }

    $property.$Name
}

function Get-RegistryPlanItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'String')]
        [string]$PropertyType,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$DesiredValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet('SetValue', 'DeleteValue')]
        [string]$DesiredAction,

        [Parameter(Mandatory = $true)]
        [string]$DesiredState,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $currentValue = Get-RegistryValue -Path $Path -Name $Name
    $exists = $null -ne $currentValue
    $valueMatches = $exists -and ([string]$currentValue -eq [string]$DesiredValue)
    $action = switch ($DesiredAction) {
        'DeleteValue' { if ($exists) { 'DeleteValue' } else { 'NoChange' } }
        'SetValue' { if ($valueMatches) { 'NoChange' } elseif ($exists) { 'SetValue' } else { 'CreateValue' } }
    }

    [pscustomobject]@{
        ItemType = 'Registry'
        Category = $Category
        Target = "$Path\$Name"
        RegistryPath = $Path
        ValueName = $Name
        PropertyType = $PropertyType
        CurrentValue = $currentValue
        DesiredValue = if ($DesiredAction -eq 'DeleteValue') { '<delete>' } else { $DesiredValue }
        DesiredState = $DesiredState
        Action = $action
        Reason = $Reason
    }
}

function Add-DWordPlanItem {
    param(
        [Parameter()]
        [System.Collections.Generic.List[object]]$Plan,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$HardenedValue,

        [Parameter()]
        [int]$RollbackValue,

        [Parameter()]
        [switch]$RollbackDeletesValue,

        [Parameter(Mandatory = $true)]
        [string]$HardenedState,

        [Parameter(Mandatory = $true)]
        [string]$RollbackState,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter()]
        [switch]$Rollback
    )

    $desiredAction = if ($Rollback -and $RollbackDeletesValue) { 'DeleteValue' } else { 'SetValue' }
    $desiredValue = if ($Rollback) { $RollbackValue } else { $HardenedValue }
    $desiredState = if ($Rollback) { $RollbackState } else { $HardenedState }

    $Plan.Add((Get-RegistryPlanItem -Category $Category -Path $Path -Name $Name -PropertyType DWord -DesiredValue $desiredValue -DesiredAction $desiredAction -DesiredState $desiredState -Reason $Reason))
}

function Get-ServicePlanItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Manual', 'Automatic', 'Disabled')]
        [string]$RollbackStartupType,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter()]
        [switch]$Rollback
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ItemType = 'Service'
        Category = 'Service'
        Target = $Name
        CurrentValue = if ($service) { "$($service.Status); startup type evaluated during apply" } else { 'Missing' }
        DesiredValue = if ($Rollback) { $RollbackStartupType } else { 'Stopped; Disabled' }
        DesiredState = if ($Rollback) { 'Enabled' } else { 'Disabled' }
        RollbackStartupType = $RollbackStartupType
        Action = if (-not $service) { 'Missing' } elseif ($Rollback) { 'EnableService' } else { 'DisableService' }
        Reason = $Reason
    }
}

function Get-ScheduledTaskPlanItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskPath,

        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter()]
        [switch]$Rollback
    )

    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ItemType = 'ScheduledTask'
        Category = 'ScheduledTask'
        Target = "$TaskPath$TaskName"
        TaskPath = $TaskPath
        TaskName = $TaskName
        CurrentValue = if ($task) { $task.State } else { 'Missing' }
        DesiredValue = if ($Rollback) { 'Enabled' } else { 'Disabled' }
        DesiredState = if ($Rollback) { 'Enabled' } else { 'Disabled' }
        Action = if (-not $task) { 'Missing' } elseif ($Rollback) { 'EnableScheduledTask' } else { 'DisableScheduledTask' }
        Reason = $Reason
    }
}

function Get-Windows11PrivacyHardeningPlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Required', 'Security')]
        [string]$DiagnosticDataLevel,

        [Parameter()]
        [switch]$IncludeScheduledTasks,

        [Parameter()]
        [switch]$IncludeServices,

        [Parameter()]
        [switch]$SkipCurrentUserSettings,

        [Parameter()]
        [switch]$Rollback
    )

    $plan = [System.Collections.Generic.List[object]]::new()
    $telemetryValue = if ($DiagnosticDataLevel -eq 'Security') { 0 } else { 1 }

    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -HardenedValue $telemetryValue -RollbackDeletesValue -HardenedState "DiagnosticData:$DiagnosticDataLevel" -RollbackState 'NotConfigured' -Reason "Set Windows diagnostic data level to $DiagnosticDataLevel." -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -HardenedValue $telemetryValue -RollbackDeletesValue -HardenedState "DiagnosticData:$DiagnosticDataLevel" -RollbackState 'NotConfigured' -Reason "Set local Windows diagnostic data level to $DiagnosticDataLevel." -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -HardenedValue $telemetryValue -RollbackDeletesValue -HardenedState "DiagnosticData:$DiagnosticDataLevel" -RollbackState 'NotConfigured' -Reason "Set 32-bit policy view diagnostic data level to $DiagnosticDataLevel." -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name DisableOneSettingsDownloads -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Prevent Windows from downloading OneSettings configuration.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name DisableTelemetryOptInChangeNotification -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable diagnostic data opt-in change notifications.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Feedback' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name DoNotShowFeedbackNotifications -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable Windows feedback notifications.' -Rollback:$Rollback

    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsConsumerFeatures -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable Microsoft consumer experiences and suggested app installs.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableConsumerAccountStateContent -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable cloud consumer account state content.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableTailoredExperiencesWithDiagnosticData -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable tailored experiences based on diagnostic data.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Advertising' -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable advertising ID at the machine level.' -Rollback:$Rollback

    Add-DWordPlanItem -Plan $plan -Category 'Search' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name DisableWebSearch -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable web search integration in Windows Search.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Search' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable legacy Cortana policy surface when present.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Location' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableLocation -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable Windows location platform by policy.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Location' -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name SensorPermissionState -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable legacy sensor permission override.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Location' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name Status -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable location service configuration status.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'ActivityHistory' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable activity history feed.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'ActivityHistory' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name PublishUserActivities -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable publishing user activities.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'ActivityHistory' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name UploadUserActivities -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable uploading user activities.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'InputPersonalization' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name AllowInputPersonalization -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable input personalization collection.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsGetDiagnosticInfo -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app access to diagnostic information.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsAccessLocation -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app access to location.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsAccessMotion -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app access to motion data.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsSyncWithDevices -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app sync with unpaired devices.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsAccessTasks -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app access to tasks.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsActivateWithVoice -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app voice activation.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsActivateWithVoiceAboveLock -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny app voice activation above lock.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'AppPrivacy' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name LetAppsRunInBackground -HardenedValue 2 -RollbackDeletesValue -HardenedState 'ForceDenied' -RollbackState 'NotConfigured' -Reason 'Deny Store apps running in the background by policy.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'DeliveryOptimization' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name DODownloadMode -HardenedValue 0 -RollbackDeletesValue -HardenedState 'HTTPOnly' -RollbackState 'NotConfigured' -Reason 'Disable peer-to-peer Delivery Optimization downloads.' -Rollback:$Rollback
    Add-DWordPlanItem -Plan $plan -Category 'Feeds' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name EnableFeeds -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable Windows feeds/news and interests policy surface.' -Rollback:$Rollback

    if (-not $SkipCurrentUserSettings) {
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserAdvertising' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable current-user advertising ID.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserSearch' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name BingSearchEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable current-user Bing web search integration.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserSearch' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name CortanaConsent -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable current-user Cortana consent setting when present.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserFeedback' -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name NumberOfSIUFInPeriod -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable feedback frequency prompts.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserFeedback' -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name PeriodInNanoSeconds -HardenedValue 0 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable feedback prompt period.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserTailoredExperiences' -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableTailoredExperiencesWithDiagnosticData -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable current-user tailored experiences with diagnostic data.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsSpotlightFeatures -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable Windows Spotlight features by policy.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableCloudOptimizedContent -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable cloud optimized content by policy.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name ContentDeliveryAllowed -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable current-user content delivery.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name OemPreInstalledAppsEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable OEM app suggestions.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable preinstalled app suggestions.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEverEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable historic preinstalled app suggestions flag.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SilentInstalledAppsEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable silent suggested app installs.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338388Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable Windows Spotlight app suggestions.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338389Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable Windows tips suggestions.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338393Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable suggested content in Settings.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-353694Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable suggested content.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-353696Enabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable suggested content.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SystemPaneSuggestionsEnabled -HardenedValue 0 -RollbackValue 1 -HardenedState 'Disabled' -RollbackState 'Enabled' -Reason 'Disable Start/System pane suggestions.' -Rollback:$Rollback
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserNotifications' -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name NoTileApplicationNotification -HardenedValue 1 -RollbackDeletesValue -HardenedState 'Disabled' -RollbackState 'NotConfigured' -Reason 'Disable tile application notifications policy.' -Rollback:$Rollback
    }

    if ($IncludeScheduledTasks) {
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Application Experience\' -TaskName 'Microsoft Compatibility Appraiser' -Reason 'Toggle compatibility telemetry scheduled task.' -Rollback:$Rollback))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Application Experience\' -TaskName 'ProgramDataUpdater' -Reason 'Toggle program data telemetry scheduled task.' -Rollback:$Rollback))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\' -TaskName 'Consolidator' -Reason 'Toggle customer experience scheduled task.' -Rollback:$Rollback))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\' -TaskName 'UsbCeip' -Reason 'Toggle USB CEIP scheduled task.' -Rollback:$Rollback))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Feedback\Siuf\' -TaskName 'DmClient' -Reason 'Toggle feedback SIUF client task.' -Rollback:$Rollback))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Feedback\Siuf\' -TaskName 'DmClientOnScenarioDownload' -Reason 'Toggle feedback scenario task.' -Rollback:$Rollback))
    }

    if ($IncludeServices) {
        $plan.Add((Get-ServicePlanItem -Name 'DiagTrack' -RollbackStartupType Automatic -Reason 'Toggle Connected User Experiences and Telemetry service.' -Rollback:$Rollback))
        $plan.Add((Get-ServicePlanItem -Name 'dmwappushservice' -RollbackStartupType Manual -Reason 'Toggle WAP push message routing service where present.' -Rollback:$Rollback))
    }

    @($plan)
}

function Export-RegistryBackup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirectory
    )

    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null

    $exports = @(
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            File = 'policy-data-collection.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
            File = 'local-data-collection.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            File = 'cloud-content.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            File = 'machine-advertising-info.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            File = 'windows-search-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
            File = 'location-sensors-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
            File = 'windows-system-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'
            File = 'input-personalization-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            File = 'app-privacy-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            File = 'delivery-optimization-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'
            File = 'windows-feeds-policy.reg'
        },
        @{
            Key = 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            File = 'current-user-cloud-content-policy.reg'
        },
        @{
            Key = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            File = 'current-user-content-delivery.reg'
        },
        @{
            Key = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
            File = 'current-user-search.reg'
        },
        @{
            Key = 'HKCU\Software\Microsoft\Siuf'
            File = 'current-user-siuf.reg'
        }
    )

    $results = foreach ($export in $exports) {
        $path = Join-Path $BackupDirectory $export.File
        $exitCode = $null
        $status = 'Skipped'

        if ($PSCmdlet.ShouldProcess($export.Key, "Export registry backup to $path")) {
            $process = Start-Process -FilePath reg.exe -ArgumentList @('export', $export.Key, $path, '/y') -NoNewWindow -Wait -PassThru
            $exitCode = $process.ExitCode
            $status = if ($exitCode -eq 0) { 'Exported' } else { 'Failed' }
        }

        [pscustomobject]@{
            RegistryKey = $export.Key
            BackupPath = $path
            Status = $status
            ExitCode = $exitCode
        }
    }

    @($results)
}

function Set-PlannedRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -eq 'NoChange') {
        return $false
    }

    if ($Item.Action -eq 'DeleteValue') {
        if ($PSCmdlet.ShouldProcess($Item.Target, 'Delete registry value')) {
            Remove-ItemProperty -LiteralPath $Item.RegistryPath -Name $Item.ValueName -ErrorAction SilentlyContinue
            return $true
        }

        return $false
    }

    if ($PSCmdlet.ShouldProcess($Item.Target, "Set $($Item.PropertyType) to $($Item.DesiredValue)")) {
        New-Item -Path $Item.RegistryPath -Force | Out-Null
        New-ItemProperty -Path $Item.RegistryPath -Name $Item.ValueName -Value $Item.DesiredValue -PropertyType $Item.PropertyType -Force | Out-Null
        return $true
    }

    $false
}

function Set-PlannedScheduledTaskState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -notin @('DisableScheduledTask', 'EnableScheduledTask')) {
        return $false
    }

    $operation = if ($Item.Action -eq 'EnableScheduledTask') { 'Enable scheduled task' } else { 'Disable scheduled task' }
    if ($PSCmdlet.ShouldProcess($Item.Target, $operation)) {
        if ($Item.Action -eq 'EnableScheduledTask') {
            Enable-ScheduledTask -TaskPath $Item.TaskPath -TaskName $Item.TaskName | Out-Null
        } else {
            Disable-ScheduledTask -TaskPath $Item.TaskPath -TaskName $Item.TaskName | Out-Null
        }

        return $true
    }

    $false
}

function Set-PlannedServiceState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -notin @('DisableService', 'EnableService')) {
        return $false
    }

    $serviceName = $Item.Target
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return $false
    }

    if ($Item.Action -eq 'DisableService') {
        if ($service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($serviceName, 'Stop service')) {
            Stop-Service -Name $serviceName -ErrorAction Continue
        }

        if ($PSCmdlet.ShouldProcess($serviceName, 'Set service startup type to Disabled')) {
            Set-Service -Name $serviceName -StartupType Disabled
            return $true
        }

        return $false
    }

    if ($PSCmdlet.ShouldProcess($serviceName, "Set service startup type to $($Item.RollbackStartupType)")) {
        Set-Service -Name $serviceName -StartupType $Item.RollbackStartupType
        return $true
    }

    $false
}

function Get-RunStateList {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Plan,

        [Parameter(Mandatory = $true)]
        [hashtable]$Statuses
    )

    foreach ($item in $Plan) {
        if ($item.Action -eq 'Missing') {
            continue
        }

        $status = if ($Statuses.ContainsKey($item.Target)) { $Statuses[$item.Target] } else { 'NoChange' }
        [pscustomobject]@{
            ItemType = $item.ItemType
            Category = $item.Category
            Target = $item.Target
            DesiredState = $item.DesiredState
            DesiredValue = $item.DesiredValue
            Action = $item.Action
            Result = $status
            Reason = $item.Reason
        }
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$buildNumber = Get-WindowsBuildNumber
if (-not $SkipWindows11Check -and $buildNumber -lt 22000) {
    throw "This script is scoped to Windows 11. Detected build $buildNumber. Use -SkipWindows11Check only after reviewing the plan for this OS."
}

$operationName = if ($Rollback) { 'rollback' } else { 'hardening' }
$plan = Get-Windows11PrivacyHardeningPlan -DiagnosticDataLevel $DiagnosticDataLevel -IncludeScheduledTasks:$IncludeScheduledTasks -IncludeServices:$IncludeServices -SkipCurrentUserSettings:$SkipCurrentUserSettings -Rollback:$Rollback
$planCsvPath = Join-Path $resolvedReportDirectory "windows11-privacy-$operationName-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "windows11-privacy-$operationName-plan-$timestamp.json"
$stateCsvPath = Join-Path $resolvedReportDirectory "windows11-privacy-$operationName-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "windows11-privacy-$operationName-state-$timestamp.json"

$plan | Export-Csv -Path $planCsvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$plan | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $planJsonPath -Encoding utf8 -WhatIf:$false

Write-Information "Windows 11 privacy $operationName plan written to $planCsvPath" -InformationAction Continue
Write-Information "Windows 11 privacy $operationName plan JSON written to $planJsonPath" -InformationAction Continue

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw 'Run from an elevated PowerShell session before applying live Windows 11 privacy changes. Use -WhatIf to generate a review plan without elevation.'
}

$backupDirectory = $null
$backupResults = @()
if (-not $WhatIfPreference -and -not $SkipRegistryBackup) {
    $backupDirectory = Join-Path $resolvedReportDirectory "windows11-privacy-registry-backup-$timestamp"
    $backupResults = Export-RegistryBackup -BackupDirectory $backupDirectory
}

$changedCount = 0
$skippedCount = 0
$runStatuses = @{}
foreach ($item in $plan) {
    if ($item.Action -in @('NoChange', 'Missing')) {
        $skippedCount++
        $runStatuses[$item.Target] = $item.Action
        continue
    }

    $changed = switch ($item.ItemType) {
        'Registry' { Set-PlannedRegistryValue -Item $item -WhatIf:$WhatIfPreference }
        'ScheduledTask' { Set-PlannedScheduledTaskState -Item $item -WhatIf:$WhatIfPreference }
        'Service' { Set-PlannedServiceState -Item $item -WhatIf:$WhatIfPreference }
        default { $false }
    }

    if ($changed) {
        $changedCount++
        $runStatuses[$item.Target] = 'Changed'
    } elseif ($WhatIfPreference) {
        $runStatuses[$item.Target] = 'Previewed'
    } else {
        $skippedCount++
        $runStatuses[$item.Target] = 'Skipped'
    }
}

$stateList = @(Get-RunStateList -Plan $plan -Statuses $runStatuses)
$stateList | Export-Csv -Path $stateCsvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateList | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stateJsonPath -Encoding utf8 -WhatIf:$false

Write-Information "Windows 11 privacy $operationName state list written to $stateCsvPath" -InformationAction Continue
Write-Information "Windows 11 privacy $operationName state list JSON written to $stateJsonPath" -InformationAction Continue

[pscustomobject]@{
    TargetOs = 'Windows 11'
    Operation = if ($Rollback) { 'Rollback' } else { 'Harden' }
    DetectedBuild = $buildNumber
    DiagnosticDataLevel = if ($Rollback) { 'RestoredToDefault' } else { $DiagnosticDataLevel }
    PlanCsvPath = (Resolve-Path -LiteralPath $planCsvPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $stateCsvPath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RegistryBackupDirectory = if ($backupDirectory) { (Resolve-Path -LiteralPath $backupDirectory).Path } else { $null }
    RegistryBackupResults = @($backupResults)
    IncludeScheduledTasks = [bool]$IncludeScheduledTasks
    IncludeServices = [bool]$IncludeServices
    PlannedChangeCount = @($plan | Where-Object { $_.Action -notin @('NoChange', 'Missing') }).Count
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    RestartRequired = $true
    DisabledAfterRun = if ($Rollback) { @() } else { @($stateList) }
    EnabledOrDefaultAfterRollback = if ($Rollback) { @($stateList) } else { @() }
    Notes = if ($Rollback) { 'Review reports before rollback. Sign out/in or reboot after applying live rollback changes.' } else { 'Review reports before live runs. Sign out/in or reboot after applying live privacy hardening changes.' }
}
