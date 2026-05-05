<#
.SYNOPSIS
Plan and apply Windows 11 privacy, telemetry, and consumer-feature hardening.

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
- This script is scoped to Windows 11. It exits on older Windows builds unless -SkipWindows11Check is used.

.PURPOSE
Use this to reduce optional Windows 11 diagnostic data, tailored experiences,
advertising identifiers, consumer suggestions, Windows Search web suggestions,
and related content-delivery settings. Optional switches can also disable
selected telemetry scheduled tasks and services.

.REQUIRED SYNTAX
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1

.OUTPUTS
Writes a plan CSV and JSON under reports\windows-hardening by default. Live runs
also export relevant registry branches to .reg files before changes unless
-SkipRegistryBackup is used. Returns a summary object with report and backup
paths, changed/skipped counts, and restart-required status.

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
    [switch]$SkipWindows11Check
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows 11 privacy hardening.

Usage:
  pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
  pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1

Options:
  -DiagnosticDataLevel    Required or Security. Default: Required.
                           Security is intended for Windows Enterprise/Education/Server-style use.
  -ReportDirectory        Plan and backup output directory.
  -IncludeScheduledTasks  Disable selected telemetry/customer-experience scheduled tasks.
  -IncludeServices        Disable selected telemetry services.
  -SkipCurrentUserSettings
                           Do not change HKCU privacy/content-delivery settings.
  -SkipRegistryBackup     Do not export registry backup files before live changes.
  -SkipWindows11Check     Allow execution on non-Windows 11 builds.
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

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$DesiredValue,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $currentValue = Get-RegistryValue -Path $Path -Name $Name
    $exists = $null -ne $currentValue
    $valueMatches = $exists -and ([string]$currentValue -eq [string]$DesiredValue)

    [pscustomobject]@{
        ItemType = 'Registry'
        Category = $Category
        Target = "$Path\$Name"
        RegistryPath = $Path
        ValueName = $Name
        PropertyType = $PropertyType
        CurrentValue = $currentValue
        DesiredValue = $DesiredValue
        Action = if ($valueMatches) { 'NoChange' } elseif ($exists) { 'SetValue' } else { 'CreateValue' }
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
        [int]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $Plan.Add((Get-RegistryPlanItem -Category $Category -Path $Path -Name $Name -PropertyType DWord -DesiredValue $Value -Reason $Reason))
}

function Get-ServicePlanItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ItemType = 'Service'
        Category = 'Service'
        Target = $Name
        CurrentValue = if ($service) { "$($service.Status); StartupType unknown until apply" } else { 'Missing' }
        DesiredValue = 'Stopped; Disabled'
        Action = if ($service) { 'DisableService' } else { 'Missing' }
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
        [string]$Reason
    )

    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ItemType = 'ScheduledTask'
        Category = 'ScheduledTask'
        Target = "$TaskPath$TaskName"
        TaskPath = $TaskPath
        TaskName = $TaskName
        CurrentValue = if ($task) { $task.State } else { 'Missing' }
        DesiredValue = 'Disabled'
        Action = if ($task) { 'DisableScheduledTask' } else { 'Missing' }
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
        [switch]$SkipCurrentUserSettings
    )

    $plan = [System.Collections.Generic.List[object]]::new()
    $telemetryValue = if ($DiagnosticDataLevel -eq 'Security') { 0 } else { 1 }

    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value $telemetryValue -Reason "Set Windows diagnostic data level to $DiagnosticDataLevel."
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -Value $telemetryValue -Reason "Set local Windows diagnostic data level to $DiagnosticDataLevel."
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -Value $telemetryValue -Reason "Set 32-bit policy view diagnostic data level to $DiagnosticDataLevel."
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name DisableOneSettingsDownloads -Value 1 -Reason 'Prevent Windows from downloading OneSettings configuration.'
    Add-DWordPlanItem -Plan $plan -Category 'DiagnosticData' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name DisableTelemetryOptInChangeNotification -Value 1 -Reason 'Disable diagnostic data opt-in change notifications.'

    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsConsumerFeatures -Value 1 -Reason 'Disable Microsoft consumer experiences and suggested app installs.'
    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableConsumerAccountStateContent -Value 1 -Reason 'Disable cloud consumer account state content.'
    Add-DWordPlanItem -Plan $plan -Category 'CloudContent' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableTailoredExperiencesWithDiagnosticData -Value 1 -Reason 'Disable tailored experiences based on diagnostic data.'
    Add-DWordPlanItem -Plan $plan -Category 'Advertising' -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -Value 0 -Reason 'Disable advertising ID at the machine level.'

    Add-DWordPlanItem -Plan $plan -Category 'Search' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name DisableWebSearch -Value 1 -Reason 'Disable web search integration in Windows Search.'
    Add-DWordPlanItem -Plan $plan -Category 'Search' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Value 0 -Reason 'Disable legacy Cortana policy surface when present.'
    Add-DWordPlanItem -Plan $plan -Category 'Location' -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name SensorPermissionState -Value 0 -Reason 'Disable legacy sensor permission override.'
    Add-DWordPlanItem -Plan $plan -Category 'Location' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name Status -Value 0 -Reason 'Disable location service configuration status.'

    if (-not $SkipCurrentUserSettings) {
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserAdvertising' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -Value 0 -Reason 'Disable current-user advertising ID.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserSearch' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name BingSearchEnabled -Value 0 -Reason 'Disable current-user Bing web search integration.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserSearch' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name CortanaConsent -Value 0 -Reason 'Disable current-user Cortana consent setting when present.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserFeedback' -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name NumberOfSIUFInPeriod -Value 0 -Reason 'Disable feedback frequency prompts.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserFeedback' -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name PeriodInNanoSeconds -Value 0 -Reason 'Disable feedback prompt period.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name ContentDeliveryAllowed -Value 0 -Reason 'Disable current-user content delivery.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name OemPreInstalledAppsEnabled -Value 0 -Reason 'Disable OEM app suggestions.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEnabled -Value 0 -Reason 'Disable preinstalled app suggestions.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEverEnabled -Value 0 -Reason 'Disable historic preinstalled app suggestions flag.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SilentInstalledAppsEnabled -Value 0 -Reason 'Disable silent suggested app installs.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338388Enabled -Value 0 -Reason 'Disable Windows Spotlight app suggestions.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338389Enabled -Value 0 -Reason 'Disable Windows tips suggestions.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-338393Enabled -Value 0 -Reason 'Disable suggested content in Settings.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-353694Enabled -Value 0 -Reason 'Disable suggested content.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SubscribedContent-353696Enabled -Value 0 -Reason 'Disable suggested content.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserContentDelivery' -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SystemPaneSuggestionsEnabled -Value 0 -Reason 'Disable Start/System pane suggestions.'
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserNotifications' -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name NoTileApplicationNotification -Value 1 -Reason 'Disable tile application notifications policy.'
    }

    if ($IncludeScheduledTasks) {
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Application Experience\' -TaskName 'Microsoft Compatibility Appraiser' -Reason 'Disable compatibility telemetry scheduled task.'))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Application Experience\' -TaskName 'ProgramDataUpdater' -Reason 'Disable program data telemetry scheduled task.'))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\' -TaskName 'Consolidator' -Reason 'Disable customer experience scheduled task.'))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\' -TaskName 'UsbCeip' -Reason 'Disable USB CEIP scheduled task.'))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Feedback\Siuf\' -TaskName 'DmClient' -Reason 'Disable feedback SIUF client task.'))
        $plan.Add((Get-ScheduledTaskPlanItem -TaskPath '\Microsoft\Windows\Feedback\Siuf\' -TaskName 'DmClientOnScenarioDownload' -Reason 'Disable feedback scenario task.'))
    }

    if ($IncludeServices) {
        $plan.Add((Get-ServicePlanItem -Name 'DiagTrack' -Reason 'Disable Connected User Experiences and Telemetry service.'))
        $plan.Add((Get-ServicePlanItem -Name 'dmwappushservice' -Reason 'Disable WAP push message routing service where present.'))
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

    if ($PSCmdlet.ShouldProcess($Item.Target, "Set $($Item.PropertyType) to $($Item.DesiredValue)")) {
        New-Item -Path $Item.RegistryPath -Force | Out-Null
        New-ItemProperty -Path $Item.RegistryPath -Name $Item.ValueName -Value $Item.DesiredValue -PropertyType $Item.PropertyType -Force | Out-Null
        return $true
    }

    $false
}

function Disable-PlannedScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -ne 'DisableScheduledTask') {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($Item.Target, 'Disable scheduled task')) {
        Disable-ScheduledTask -TaskPath $Item.TaskPath -TaskName $Item.TaskName | Out-Null
        return $true
    }

    $false
}

function Disable-PlannedService {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -ne 'DisableService') {
        return $false
    }

    $serviceName = $Item.Target
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return $false
    }

    if ($service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($serviceName, 'Stop service')) {
        Stop-Service -Name $serviceName -ErrorAction Continue
    }

    if ($PSCmdlet.ShouldProcess($serviceName, 'Set service startup type to Disabled')) {
        Set-Service -Name $serviceName -StartupType Disabled
        return $true
    }

    $false
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$buildNumber = Get-WindowsBuildNumber
if (-not $SkipWindows11Check -and $buildNumber -lt 22000) {
    throw "This script is scoped to Windows 11. Detected build $buildNumber. Use -SkipWindows11Check only after reviewing the plan for this OS."
}

$plan = Get-Windows11PrivacyHardeningPlan -DiagnosticDataLevel $DiagnosticDataLevel -IncludeScheduledTasks:$IncludeScheduledTasks -IncludeServices:$IncludeServices -SkipCurrentUserSettings:$SkipCurrentUserSettings
$planCsvPath = Join-Path $resolvedReportDirectory "windows11-privacy-hardening-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "windows11-privacy-hardening-plan-$timestamp.json"

$plan | Export-Csv -Path $planCsvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$plan | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $planJsonPath -Encoding utf8 -WhatIf:$false

Write-Information "Windows 11 privacy hardening plan written to $planCsvPath" -InformationAction Continue
Write-Information "Windows 11 privacy hardening plan JSON written to $planJsonPath" -InformationAction Continue

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw 'Run from an elevated PowerShell session before applying live Windows 11 privacy hardening changes. Use -WhatIf to generate a review plan without elevation.'
}

$backupDirectory = $null
$backupResults = @()
if (-not $WhatIfPreference -and -not $SkipRegistryBackup) {
    $backupDirectory = Join-Path $resolvedReportDirectory "windows11-privacy-registry-backup-$timestamp"
    $backupResults = Export-RegistryBackup -BackupDirectory $backupDirectory
}

$changedCount = 0
$skippedCount = 0
foreach ($item in $plan) {
    if ($item.Action -in @('NoChange', 'Missing')) {
        $skippedCount++
        continue
    }

    $changed = switch ($item.ItemType) {
        'Registry' { Set-PlannedRegistryValue -Item $item -WhatIf:$WhatIfPreference }
        'ScheduledTask' { Disable-PlannedScheduledTask -Item $item -WhatIf:$WhatIfPreference }
        'Service' { Disable-PlannedService -Item $item -WhatIf:$WhatIfPreference }
        default { $false }
    }

    if ($changed) {
        $changedCount++
    }
}

[pscustomobject]@{
    TargetOs = 'Windows 11'
    DetectedBuild = $buildNumber
    DiagnosticDataLevel = $DiagnosticDataLevel
    PlanCsvPath = (Resolve-Path -LiteralPath $planCsvPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    RegistryBackupDirectory = if ($backupDirectory) { (Resolve-Path -LiteralPath $backupDirectory).Path } else { $null }
    RegistryBackupResults = @($backupResults)
    IncludeScheduledTasks = [bool]$IncludeScheduledTasks
    IncludeServices = [bool]$IncludeServices
    PlannedChangeCount = @($plan | Where-Object { $_.Action -notin @('NoChange', 'Missing') }).Count
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    RestartRequired = $true
    Notes = 'Review reports before live runs. Sign out/in or reboot after applying live privacy hardening changes.'
}
