<#
.SYNOPSIS
Plan, apply, and roll back workstation idle-lock and sleep posture for security and performance.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to enable the power-scheme password-on-wake flag (-EnableConsoleLock) or the
  machine-wide inactivity lock (-EnableMachineWideLock).
- Use -Rollback to restore the exact values this script changed.
- Generated reports are written under C:\Code_data\ops-toolkit\windows-hardening by default,
  per the workspace data-hygiene rule (generated data lives under C:\Code_data, never in the repo).

Purpose:
Puts a workstation into a secure idle posture: never sleep or hibernate on AC power, require a
password after a configurable screensaver timeout, and optionally enforce a power-scheme
password-on-wake flag and a machine-wide inactivity lock via Group Policy registry.

MODERN STANDBY NOTE: This laptop uses S0 Low Power Idle (Connected Standby), not traditional S3
sleep. On S0 systems the standby-timeout-ac setting has no effect because S3 is unavailable.
S0 is triggered instead by the display powering off (monitor-timeout-ac). This script therefore
sets monitor-timeout-ac to Never (0) on AC so the power manager does not signal "display off"
and S0 is never triggered while on AC power. The screensaver still blanks and locks the screen
visually because it is driven by HKCU registry settings, not the power plan.

Every change is recorded in a rollback JSON so the posture can be precisely reversed with
-Rollback. Non-elevated settings (sleep, monitor, screensaver) apply without admin rights.
The optional ConsoleLock and machine-wide policy settings require an elevated shell.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableConsoleLock      # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableMachineWideLock  # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, plus a rollback JSON capturing the
prior value of every setting changed so a later -Rollback can revert precisely.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Set-WorkstationPerformance.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$IdleTimeoutMinutes = 10,

    [Parameter()]
    [switch]$SkipScreensaverLock,

    [Parameter()]
    [switch]$SkipSleepHibernate,

    # On Modern Standby (S0) systems, setting monitor-timeout-ac to 0 prevents
    # S0 from triggering while on AC. Pass this switch to leave it unchanged.
    [Parameter()]
    [switch]$SkipMonitorTimeout,

    [Parameter()]
    [switch]$EnableConsoleLock,

    [Parameter()]
    [switch]$EnableMachineWideLock,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = 'C:\Code_data\ops-toolkit\windows-hardening',

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:DesktopRegPath = 'HKCU:\Control Panel\Desktop'
$script:PolicyRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

function Show-Usage {
    Write-Output @'
Set workstation idle-lock and sleep posture for security and performance.

Usage:
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -WhatIf
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableConsoleLock      # elevated
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableMachineWideLock  # elevated
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -Rollback -WhatIf

Options:
  -IdleTimeoutMinutes      Screensaver timeout in minutes (1-120). Default: 10.
  -SkipScreensaverLock     Do not change screensaver lock settings.
  -SkipSleepHibernate      Do not change AC sleep/hibernate settings.
  -SkipMonitorTimeout      Do not set monitor-timeout-ac to Never. By default this script sets it
                           to 0 (Never) on AC to prevent S0 Low Power Idle on Modern Standby laptops.
  -EnableConsoleLock       Set the power-scheme password-on-wake flag for AC+DC (requires elevation).
  -EnableMachineWideLock   Set machine-wide inactivity lock via HKLM policy (requires elevation).
  -ReportDirectory         Plan, state, and rollback output directory.
  -Rollback                Restore all settings this script previously changed.
  -WhatIf                  Write reports and preview changes without applying them.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DesktopRegValue {
    param([Parameter(Mandatory = $true)][string]$Name)
    (Get-ItemProperty -Path $script:DesktopRegPath -Name $Name -ErrorAction SilentlyContinue).$Name
}

# Query a power setting for the active AC scheme and return the value in minutes.
# powercfg /query returns seconds; powercfg /change accepts minutes. Storing in minutes
# throughout means rollback can pass the value straight back to powercfg /change.
function Get-PowercfgAcMinute {
    param(
        [Parameter(Mandatory = $true)][string]$SubGroup,
        [Parameter(Mandatory = $true)][string]$Setting
    )
    $lines = (powercfg /query SCHEME_CURRENT $SubGroup $Setting) 2>$null
    foreach ($l in $lines) {
        if ($l -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
            $seconds = [Convert]::ToInt64($matches[1], 16)
            return [int][math]::Floor($seconds / 60)
        }
    }
    $null
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    param(
        [Parameter(Mandatory = $true)][int]$IdleTimeoutMinutes,
        [switch]$SkipScreensaverLock,
        [switch]$SkipSleepHibernate,
        [switch]$SkipMonitorTimeout,
        [switch]$EnableConsoleLock,
        [switch]$EnableMachineWideLock
    )

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $timeoutSecs = $IdleTimeoutMinutes * 60

    if (-not $SkipSleepHibernate) {
        $curSleepMin = Get-PowercfgAcMinute -SubGroup 'SUB_SLEEP' -Setting 'STANDBYIDLE'
        $curHibMin = Get-PowercfgAcMinute -SubGroup 'SUB_SLEEP' -Setting 'HIBERNATEIDLE'

        $items.Add([pscustomobject]@{
                Category = 'AcSleep'; Setting = 'standby-timeout-ac'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curSleepMin) { $curSleepMin } else { 'unknown' }
                DesiredValue = 0
                Action = if ($curSleepMin -eq 0) { 'No change (standby-timeout-ac already 0 — Never)' } else { 'Set standby-timeout-ac to Never (0 min) on AC' }
            })
        $items.Add([pscustomobject]@{
                Category = 'AcHibernate'; Setting = 'hibernate-timeout-ac'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curHibMin) { $curHibMin } else { 'unknown' }
                DesiredValue = 0
                Action = if ($curHibMin -eq 0) { 'No change (hibernate-timeout-ac already 0 — Never)' } else { 'Set hibernate-timeout-ac to Never (0 min) on AC' }
            })
    }

    if (-not $SkipMonitorTimeout) {
        $curMonMin = Get-PowercfgAcMinute -SubGroup 'SUB_VIDEO' -Setting 'VIDEOIDLE'
        $items.Add([pscustomobject]@{
                Category = 'AcMonitor'; Setting = 'monitor-timeout-ac'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curMonMin) { $curMonMin } else { 'unknown' }
                DesiredValue = 0
                Action = if ($curMonMin -eq 0) { 'No change (monitor-timeout-ac already 0 — Never)' } else { 'Set monitor-timeout-ac to Never (0 min) on AC — prevents S0 Low Power Idle on Modern Standby' }
            })
    }

    if (-not $SkipScreensaverLock) {
        $curActive = Get-DesktopRegValue 'ScreenSaveActive'
        $curSecure = Get-DesktopRegValue 'ScreenSaverIsSecure'
        $curTimeout = Get-DesktopRegValue 'ScreenSaveTimeOut'
        $curExe = Get-DesktopRegValue 'SCRNSAVE.EXE'

        $items.Add([pscustomobject]@{
                Category = 'ScreensaverActive'; Setting = 'ScreenSaveActive'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curActive) { $curActive } else { 'absent' }
                DesiredValue = '1'
                Action = if ($curActive -eq '1') { 'No change (screensaver already enabled)' } else { 'Enable screensaver' }
            })
        $items.Add([pscustomobject]@{
                Category = 'ScreensaverSecure'; Setting = 'ScreenSaverIsSecure'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curSecure) { $curSecure } else { 'absent' }
                DesiredValue = '1'
                Action = if ($curSecure -eq '1') { 'No change (password on resume already required)' } else { 'Require password on screensaver resume' }
            })
        $items.Add([pscustomobject]@{
                Category = 'ScreensaverTimeout'; Setting = 'ScreenSaveTimeOut'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curTimeout) { $curTimeout } else { 'absent' }
                DesiredValue = "$timeoutSecs"
                Action = if ($curTimeout -eq "$timeoutSecs") { "No change (timeout already $IdleTimeoutMinutes min)" } else { "Set screensaver timeout to $IdleTimeoutMinutes minutes ($timeoutSecs seconds)" }
            })
        $ssExe = Join-Path $env:SystemRoot 'System32\scrnsave.scr'
        $items.Add([pscustomobject]@{
                Category = 'ScreensaverExe'; Setting = 'SCRNSAVE.EXE'; RequiresAdmin = $false
                CurrentValue = if ($null -ne $curExe) { $curExe } else { 'absent' }
                DesiredValue = $ssExe
                Action = if ($curExe -eq $ssExe) { 'No change (blank screensaver already set)' } else { "Set screensaver to blank ($ssExe)" }
            })
    }

    if ($EnableConsoleLock) {
        $items.Add([pscustomobject]@{
                Category = 'ConsoleLock'; Setting = 'CONSOLELOCK'; RequiresAdmin = $true
                CurrentValue = 0; DesiredValue = 1
                Action = 'Set CONSOLELOCK = 1 (require password on wake) for AC and DC'
            })
    }

    if ($EnableMachineWideLock) {
        $curMachine = (Get-ItemProperty -Path $script:PolicyRegPath -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
        $items.Add([pscustomobject]@{
                Category = 'MachineWideLock'; Setting = 'InactivityTimeoutSecs'; RequiresAdmin = $true
                CurrentValue = if ($null -ne $curMachine) { $curMachine } else { 'absent' }
                DesiredValue = $timeoutSecs
                Action = if ($curMachine -eq $timeoutSecs) { "No change (machine-wide lock already $IdleTimeoutMinutes min)" } else { "Set machine-wide inactivity lock to $IdleTimeoutMinutes minutes ($timeoutSecs seconds)" }
            })
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'lock-posture-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No lock-posture-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
        $items.Add([pscustomobject]@{
                Category = $entry.Category; Setting = $entry.Setting
                RequiresAdmin = [bool]$entry.RequiresAdmin
                CurrentValue = $entry.AppliedValue; DesiredValue = $entry.PriorValue
                Action = "Restore $($entry.Category) '$($entry.Setting)' to '$($entry.PriorValue)'"
            })
    }
    $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        switch ($Item.Category) {
            'AcSleep' {
                # /change takes minutes; DesiredValue is stored in minutes throughout.
                powercfg /change standby-timeout-ac $Item.DesiredValue | Out-Null
            }
            'AcHibernate' {
                powercfg /change hibernate-timeout-ac $Item.DesiredValue | Out-Null
            }
            'AcMonitor' {
                # Setting to 0 (Never) prevents S0 Low Power Idle on Modern Standby.
                powercfg /change monitor-timeout-ac $Item.DesiredValue | Out-Null
            }
            'ConsoleLock' {
                powercfg /setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK $Item.DesiredValue | Out-Null
                powercfg /setdcvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK $Item.DesiredValue | Out-Null
                powercfg /setactive SCHEME_CURRENT | Out-Null
            }
            'MachineWideLock' {
                if ("$($Item.DesiredValue)" -eq 'absent') {
                    Remove-ItemProperty -Path $script:PolicyRegPath -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue
                } else {
                    if (-not (Test-Path -LiteralPath $script:PolicyRegPath)) {
                        New-Item -Path $script:PolicyRegPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $script:PolicyRegPath -Name InactivityTimeoutSecs -Value ([int]$Item.DesiredValue) -Type DWord -Force
                }
            }
            default {
                # ScreensaverActive, ScreensaverSecure, ScreensaverTimeout, ScreensaverExe
                if ("$($Item.DesiredValue)" -eq 'absent') {
                    Remove-ItemProperty -Path $script:DesktopRegPath -Name $Item.Setting -ErrorAction SilentlyContinue
                } else {
                    Set-ItemProperty -Path $script:DesktopRegPath -Name $Item.Setting -Value "$($Item.DesiredValue)" -Type String -Force
                }
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting
            RequiresAdmin = $Item.RequiresAdmin
            PriorValue = $Item.CurrentValue; AppliedValue = $Item.DesiredValue
        })
    if ($Rollback) { 'Reverted' } else { 'Applied' }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$plan = @(if ($Rollback) {
        Get-RollbackPlan
    } else {
        Get-ForwardPlan -IdleTimeoutMinutes $IdleTimeoutMinutes `
            -SkipScreensaverLock:$SkipScreensaverLock -SkipSleepHibernate:$SkipSleepHibernate `
            -SkipMonitorTimeout:$SkipMonitorTimeout `
            -EnableConsoleLock:$EnableConsoleLock -EnableMachineWideLock:$EnableMachineWideLock
    })

$planPath = Join-Path $resolvedReportDirectory "lock-posture-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "lock-posture-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "lock-posture-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "lock-posture-$mode-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = Invoke-PlanItem -Item $item -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

# Write rollback record on a live forward run that changed at least one setting.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "lock-posture-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        IdleTimeoutMinutes = $IdleTimeoutMinutes
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WorkstationLockPosture ($mode)"
    IdleTimeoutMinutes = $IdleTimeoutMinutes
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
