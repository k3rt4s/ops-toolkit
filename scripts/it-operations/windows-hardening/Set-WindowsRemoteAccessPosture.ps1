<#
.SYNOPSIS
Plan, apply, and roll back the local Remote Desktop, Remote Assistance, and WinRM posture of a standalone Windows 11 machine.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to apply: every change is a machine-wide registry value or a service change.
- The default run never switches a remote-access feature off that is working today. It requires
  Network Level Authentication (UserAuthentication 1) and the TLS security layer (SecurityLayer 2)
  on Remote Desktop, but only when Remote Desktop is currently enabled, and it turns Remote
  Assistance off (fAllowToGetHelp 0).
- -DisableRemoteDesktop sets fDenyTSConnections 1. It is refused (plan item 'Skipped: current
  session is remote') when the running session is a Remote Desktop session, and also when that
  cannot be determined, because turning RDP off from inside an RDP session ends your way back in.
  What breaks: every inbound Remote Desktop connection to this machine.
- -DisableWinRM sets the WinRM service to Disabled and stops it. The prior startup type and status
  are recorded and -Rollback restores them. It is refused inside a PowerShell remoting session.
  What breaks: Invoke-Command, Enter-PSSession and any remote management tool that uses WinRM.
- The plan also carries report-only items (no change is ever made for them): whether a WinRM
  listener is configured, and whether a Remote Desktop policy value overrides the local setting.
  Anything that cannot be read is reported as 'unknown', never as compliant.
- Use -Rollback to restore the exact values this script changed from the newest unconsumed rollback
  file in the report directory. Each executing -Rollback that restores everything marks its file
  consumed, so running -Rollback again undoes the run before it, newest first.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  developer's workstation must never be applied to someone else's machine. Generated reports
  belong under a data root outside the repo.

Purpose:
Reduces the remote-administration attack surface of a workgroup (not domain-joined, not
Intune-managed) machine using local registry values and the service manager only. No Group
Policy, Active Directory, or Entra mechanism is used. A Group Policy or MDM setting that already
manages the same value will overwrite the local value; the report-only policy item shows when a
Remote Desktop policy value is present.

Every change is recorded in a rollback JSON so the posture can be reversed with -Rollback. No
reboot is required for any change made here.

Rollback: -Rollback reads the newest remote-access-posture-rollback-<timestamp>.json in the report
directory (newest by name). Before any plan is written or any change made, every recorded entry is
checked and the whole file is refused, also under -WhatIf, with an error naming the file and the
first bad entry when the JSON does not parse, ChangedSettings is not an array, or an entry names a
category, registry path or value name this script does not set, or carries a prior value of the
wrong type or outside the range of that value (the same control tables the forward plan uses). The
only service it can touch is WinRM. Move a refused file aside to roll back an older run. After an
executing -Rollback in which every item was reverted or needed no change, the file is renamed
remote-access-posture-rollback-<timestamp>.consumed-<timestamp>.json and is no longer picked; under
-WhatIf, or when any item failed or was skipped, it is left in place and the summary says so.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1 -ReportDirectory <dir>                         # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1 -ReportDirectory <dir> -DisableRemoteDesktop  # elevated, local console only
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1 -ReportDirectory <dir> -DisableWinRM          # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsRemoteAccessPosture.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, plus a rollback JSON capturing the
prior value of every setting changed so a later -Rollback can revert precisely. Emits a summary
object with the report paths, result counts, RebootRequired, and the per-item results.

.NOTES
Status:
Active script in the ops-toolkit repo. Part of the Windows 11 standalone hardening baseline.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$DisableRemoteDesktop,

    [Parameter()]
    [switch]$DisableWinRM,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:TerminalServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$script:RdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$script:RemoteAssistancePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$script:TsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$script:WsmanListenerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener'

# Every registry value the forward plan can write, and the range of values a rollback may restore.
# Get-RegistryPlanEntry reads Path and Name from this table and the rollback validator accepts exactly
# these, so they cannot drift. Min and Max bound the DWord values the control can hold.
$script:RegistryControls = @(
    [pscustomobject]@{ Category = 'RdpNla'; Path = $script:RdpTcpPath; Name = 'UserAuthentication'; Min = 0; Max = 1 }
    [pscustomobject]@{ Category = 'RdpSecurityLayer'; Path = $script:RdpTcpPath; Name = 'SecurityLayer'; Min = 0; Max = 2 }
    [pscustomobject]@{ Category = 'RdpDisable'; Path = $script:TerminalServerPath; Name = 'fDenyTSConnections'; Min = 0; Max = 1 }
    [pscustomobject]@{ Category = 'RemoteAssistance'; Path = $script:RemoteAssistancePath; Name = 'fAllowToGetHelp'; Min = 0; Max = 1 }
)
# The one service the forward plan can change, with the startup types and statuses a rollback may restore.
$script:ServiceControl = [pscustomobject]@{
    Category = 'WinRmService'; ServiceName = 'WinRM'
    StartupTypes = @('Automatic', 'AutomaticDelayedStart', 'Manual', 'Disabled')
    Statuses = @('Running', 'Stopped', 'Paused', 'StartPending', 'StopPending', 'ContinuePending', 'PausePending')
}
$script:RollbackSourceFile = $null
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Returns 'remote', 'local' or 'unknown'. SESSIONNAME starts with RDP- inside a Remote Desktop
# session, and GetSystemMetrics(SM_REMOTESESSION = 0x1000) is non-zero for any process attached to
# a Terminal Services client session, including one where SESSIONNAME was lost. Either says remote.
function Get-SessionRemoteState {
    if ([string]$env:SESSIONNAME -match '^RDP-') { return 'remote' }
    try {
        if (-not ('OpsToolkit.SessionNative' -as [type])) {
            Add-Type -Namespace 'OpsToolkit' -Name 'SessionNative' -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex);'
        }
        if ([OpsToolkit.SessionNative]::GetSystemMetrics(0x1000) -ne 0) { return 'remote' }
        return 'local'
    } catch {
        if ([string]$env:SESSIONNAME) { return 'local' }
        return 'unknown'
    }
}

function Test-IsPowerShellRemotingSession {
    $null -ne (Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue)
}

# Returns @{ State = 'present'|'absent'|'unknown'; Value = <value or $null> }. A missing key or
# value is 'absent'; anything that stops the read is 'unknown' and is never treated as compliant.
function Get-RegistryValueState {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    try {
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return @{ State = 'absent'; Value = $null }
    } catch {
        return @{ State = 'unknown'; Value = $null }
    }
    if ($null -ne $props -and $props.PSObject.Properties[$Name]) {
        return @{ State = 'present'; Value = $props.PSObject.Properties[$Name].Value }
    }
    @{ State = 'absent'; Value = $null }
}

function Get-PlanEntry {
    param(
        [string]$Category, [string]$Setting, [string]$Kind, [string]$Path = '', [string]$Name = '',
        [string]$ValueType = '', $CurrentValue, $DesiredValue, [bool]$RequiresAdmin = $true,
        [bool]$RequiresReboot = $false, [string]$PriorStatus = '', [string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; Kind = $Kind; Path = $Path; Name = $Name
        ValueType = $ValueType; RequiresAdmin = $RequiresAdmin; RequiresReboot = $RequiresReboot
        PriorStatus = $PriorStatus; CurrentValue = $CurrentValue; DesiredValue = $DesiredValue
        Action = $Action
    }
}

function Get-RegistryControl {
    param([Parameter(Mandatory = $true)][string]$Category)
    $hit = @($script:RegistryControls | Where-Object { $_.Category -eq $Category })
    if ($hit.Count -ne 1) { throw "No registry control for category '$Category' is defined." }
    $hit[0]
}

# A DWord registry item. $Gate, when set, replaces the action text and leaves the item unapplied.
function Get-RegistryPlanEntry {
    param(
        [string]$Category, [int]$Desired, [string]$Label, [string]$Gate = ''
    )
    $control = Get-RegistryControl -Category $Category
    $Path = $control.Path
    $Name = $control.Name
    $state = Get-RegistryValueState -Path $Path -Name $Name
    $current = switch ($state.State) { 'present' { $state.Value } 'absent' { 'absent' } default { 'unknown' } }
    $action = if ($Gate) { $Gate }
    elseif ($state.State -eq 'unknown') { "Skipped: current value of $Name could not be read" }
    elseif ($state.State -eq 'present' -and "$($state.Value)" -eq "$Desired") { "No change ($Label already $Desired)" }
    else { "Set $Label ($Name) to $Desired" }
    Get-PlanEntry -Category $Category -Setting $Name -Kind 'Registry' -Path $Path -Name $Name -ValueType 'DWord' `
        -CurrentValue $current -DesiredValue $Desired -Action $action
}

function Get-ForwardPlan {
    param([switch]$DisableRemoteDesktop, [switch]$DisableWinRM)

    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    # Remote Desktop. The NLA and security-layer items are applied only when Remote Desktop is
    # confirmed enabled; when it is off they are listed for the record and left alone.
    $deny = Get-RegistryValueState -Path $script:TerminalServerPath -Name 'fDenyTSConnections'
    $rdpGate = ''
    if ($deny.State -eq 'present' -and "$($deny.Value)" -eq '1') {
        $rdpGate = 'No change (Remote Desktop is disabled, NLA settings left alone)'
    } elseif (-not ($deny.State -eq 'present' -and "$($deny.Value)" -eq '0')) {
        $rdpGate = 'Skipped: Remote Desktop state could not be confirmed as enabled'
    }
    # With -DisableRemoteDesktop the NLA settings are moot, so they are left alone.
    if ($DisableRemoteDesktop -and -not $rdpGate) { $rdpGate = 'No change (Remote Desktop is being disabled in this run)' }
    $items.Add((Get-RegistryPlanEntry -Category 'RdpNla' -Desired 1 `
                -Label 'Network Level Authentication' -Gate $rdpGate))
    $items.Add((Get-RegistryPlanEntry -Category 'RdpSecurityLayer' -Desired 2 `
                -Label 'RDP security layer (TLS)' -Gate $rdpGate))

    if ($DisableRemoteDesktop) {
        $remote = Get-SessionRemoteState
        $gate = switch ($remote) {
            'remote' { 'Skipped: current session is remote' }
            'unknown' { 'Skipped: could not determine whether the current session is remote' }
            default { '' }
        }
        $items.Add((Get-RegistryPlanEntry -Category 'RdpDisable' `
                    -Desired 1 -Label 'Remote Desktop connections denied' -Gate $gate))
    }

    $items.Add((Get-RegistryPlanEntry -Category 'RemoteAssistance' `
                -Desired 0 -Label 'Remote Assistance'))

    if ($DisableWinRM) {
        $service = $null
        $readError = $false
        try {
            $service = Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq $script:ServiceControl.ServiceName } | Select-Object -First 1
        } catch { $readError = $true }
        if ($readError) {
            $items.Add((Get-PlanEntry -Category $script:ServiceControl.Category -Setting $script:ServiceControl.ServiceName -Kind 'Service' -CurrentValue 'unknown' `
                        -DesiredValue 'Disabled/Stopped' -Action 'Skipped: WinRM service state could not be read'))
        } elseif ($null -eq $service) {
            $items.Add((Get-PlanEntry -Category $script:ServiceControl.Category -Setting $script:ServiceControl.ServiceName -Kind 'Service' -CurrentValue 'absent' `
                        -DesiredValue 'Disabled/Stopped' -Action 'No change (WinRM service is not installed)'))
        } else {
            $start = [string]$service.StartType
            $status = [string]$service.Status
            $action = if (Test-IsPowerShellRemotingSession) { 'Skipped: current session is a PowerShell remoting session' }
            elseif ($start -eq 'Disabled' -and $status -eq 'Stopped') { 'No change (WinRM already Disabled and Stopped)' }
            else { 'Set WinRM service to Disabled and stop it' }
            $items.Add((Get-PlanEntry -Category $script:ServiceControl.Category -Setting $script:ServiceControl.ServiceName -Kind 'Service' -CurrentValue "$start/$status" `
                        -DesiredValue 'Disabled/Stopped' -PriorStatus $status -Action $action))
        }
    }

    # Report-only: listener configuration. The listener list is the WinRM listener registry key; a
    # missing key means none are configured, any other read failure is unknown.
    $listenerValue = 'unknown'
    try {
        $listeners = @(Get-ChildItem -LiteralPath $script:WsmanListenerPath -ErrorAction Stop)
        $listenerValue = if ($listeners.Count -eq 0) { 'none' } else { "$($listeners.Count) listener(s) configured" }
    } catch [System.Management.Automation.ItemNotFoundException] {
        $listenerValue = 'none'
    } catch {
        $listenerValue = 'unknown'
    }
    $items.Add((Get-PlanEntry -Category 'WinRmListener' -Setting 'WinRM listeners' -Kind 'Report' -RequiresAdmin $false `
                -CurrentValue $listenerValue -DesiredValue 'none' -Action 'Report only: WinRM listener configuration (not changed)'))

    # Report-only: a Remote Desktop policy value overrides the local fDenyTSConnections value.
    $policy = Get-RegistryValueState -Path $script:TsPolicyPath -Name 'fDenyTSConnections'
    $policyValue = switch ($policy.State) { 'present' { "policy value $($policy.Value)" } 'absent' { 'no policy value' } default { 'unknown' } }
    $items.Add((Get-PlanEntry -Category 'RdpPolicyOverride' -Setting 'Terminal Services policy fDenyTSConnections' -Kind 'Report' `
                -RequiresAdmin $false -CurrentValue $policyValue -DesiredValue 'no policy value' `
                -Action 'Report only: a policy value overrides the local Remote Desktop setting (not changed)'))

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # The timestamp pattern keeps this from matching the 'remote-access-posture-rollback-plan-*' and '-state-*' reports.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'remote-access-posture-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^remote-access-posture-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# Returns $null when the entry is acceptable, otherwise a short text saying what is wrong with it.
# A registry entry must name a category in the control table with that control's exact path and value
# name, and a prior value that is 'absent' or a whole number inside the control's range. A service
# entry must be the one WinRM service control with a startup type and status the restore can apply.
# Pure: it reads nothing but its arguments.
function Get-RollbackEntryProblem {
    param($Entry, [Parameter(Mandatory = $true)]$RegistryControls, [Parameter(Mandatory = $true)]$ServiceControl)
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($field in 'Category', 'Setting', 'Kind', 'Path', 'Name', 'PriorValue') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
    }
    foreach ($field in 'Category', 'Setting', 'Kind') {
        if ($Entry.$field -isnot [string]) { return "$field is not a string" }
    }
    foreach ($field in 'Path', 'Name') {
        if ($null -ne $Entry.$field -and $Entry.$field -isnot [string]) { return "$field is not a string" }
    }
    foreach ($field in 'ValueType', 'PriorStatus', 'AppliedValue') {
        if ($Entry.PSObject.Properties[$field]) {
            $v = $Entry.PSObject.Properties[$field].Value
            if ($null -ne $v -and $v -isnot [string] -and $v -isnot [int] -and $v -isnot [long]) { return "$field is not a single value" }
        }
    }
    $prior = $Entry.PriorValue
    if ($Entry.Category -eq $ServiceControl.Category) {
        if ($Entry.Kind -ne 'Service') { return "Kind '$($Entry.Kind)' is not Service for category $($Entry.Category)" }
        if ($Entry.Setting -ne $ServiceControl.ServiceName) { return "Setting '$($Entry.Setting)' is not the $($ServiceControl.ServiceName) service" }
        if (-not [string]::IsNullOrEmpty($Entry.Path) -or -not [string]::IsNullOrEmpty($Entry.Name)) { return 'a service entry must not carry a registry Path or Name' }
        if ($prior -isnot [string] -or $prior -notmatch '^([A-Za-z]+)/([A-Za-z]+)$') { return "PriorValue '$prior' is not <StartType>/<Status>" }
        $startType = $Matches[1]
        $status = $Matches[2]
        if ($startType -notin @($ServiceControl.StartupTypes)) { return "PriorValue start type '$startType' is not one the restore can set" }
        if ($status -notin @($ServiceControl.Statuses)) { return "PriorValue status '$status' is not a service status" }
        $priorStatus = if ($Entry.PSObject.Properties['PriorStatus']) { $Entry.PriorStatus } else { $null }
        if ($priorStatus -isnot [string] -or $priorStatus -ne $status) { return "PriorStatus '$priorStatus' does not match the status in PriorValue" }
        return $null
    }
    $control = @($RegistryControls | Where-Object { $_.Category -eq $Entry.Category })
    if ($control.Count -ne 1) { return "Category '$($Entry.Category)' is not one this script records" }
    $control = $control[0]
    if ($Entry.Kind -ne 'Registry') { return "Kind '$($Entry.Kind)' is not Registry for category $($Entry.Category)" }
    if ($Entry.Path -ne $control.Path) { return "Path '$($Entry.Path)' is not the registry key this script sets for $($Entry.Category)" }
    if ($Entry.Name -ne $control.Name -or $Entry.Setting -ne $control.Name) { return "Name '$($Entry.Name)' is not the value this script sets for $($Entry.Category)" }
    if ($Entry.PSObject.Properties['PriorStatus'] -and -not [string]::IsNullOrEmpty($Entry.PSObject.Properties['PriorStatus'].Value)) { return 'a registry entry must not carry a PriorStatus' }
    if ($prior -is [string]) {
        if ($prior -ceq 'absent') { return $null }
        return "PriorValue '$prior' is neither absent nor a whole number"
    }
    if ($prior -isnot [int] -and $prior -isnot [long]) { return "PriorValue '$prior' is neither absent nor a whole number" }
    if ($prior -lt $control.Min -or $prior -gt $control.Max) { return "PriorValue $prior of $($control.Name) is outside $($control.Min) to $($control.Max)" }
    $null
}

# True only for an executing rollback in which nothing failed, was skipped or was merely previewed.
# Only then is the rollback file spent; anything less leaves it for a retry.
function Test-RollbackFileConsumable {
    param($State, [bool]$Preview)
    if ($Preview) { return $false }
    if ($null -eq $State) { return $true }
    foreach ($item in @($State)) {
        if ($null -eq $item) { return $false }
        if ("$($item.Result)" -notin @('Reverted', 'NoChange')) { return $false }
    }
    $true
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No remote-access-posture-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $advice = 'Nothing was changed. Move this file aside (out of the report directory) to roll back an older run.'
    try {
        $data = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Rollback file '$($file.FullName)' refused: it could not be read as JSON ($($_.Exception.Message)). $advice"
    }
    if ($null -eq $data -or $data -isnot [pscustomobject] -or -not $data.PSObject.Properties['ChangedSettings']) {
        throw "Rollback file '$($file.FullName)' refused: it has no ChangedSettings array. $advice"
    }
    $changed = $data.ChangedSettings
    if ($changed -isnot [array]) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is not an array. $advice"
    }
    $entries = @($changed)
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $problem = Get-RollbackEntryProblem -Entry $entries[$i] -RegistryControls $script:RegistryControls -ServiceControl $script:ServiceControl
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    $script:RollbackSourceFile = $file

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $entries) {
        $items.Add((Get-PlanEntry -Category $entry.Category -Setting $entry.Setting -Kind $entry.Kind -Path $entry.Path `
                    -Name $entry.Name -ValueType $entry.ValueType -RequiresAdmin $true `
                    -PriorStatus ([string]$entry.PriorStatus) -CurrentValue $entry.AppliedValue -DesiredValue $entry.PriorValue `
                    -Action "Restore $($entry.Category) '$($entry.Setting)' to '$($entry.PriorValue)'"))
    }
    $items
}

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.Action -like 'Report only*') { return 'ReportOnly' }
    if ($Item.Action -like 'Skipped:*') { return $Item.Action }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        if ($Item.Kind -eq 'Service') {
            if ($Rollback) {
                $startup = "$($Item.DesiredValue)".Split('/')[0]
                Set-Service -Name $script:ServiceControl.ServiceName -StartupType $startup -ErrorAction Stop
                if ($Item.PriorStatus -eq 'Running') { Start-Service -Name $script:ServiceControl.ServiceName -ErrorAction Stop }
            } else {
                # Disable first so the service manager cannot restart it after the stop.
                Set-Service -Name $script:ServiceControl.ServiceName -StartupType Disabled -ErrorAction Stop
                if ($Item.PriorStatus -ne 'Stopped') { Stop-Service -Name $script:ServiceControl.ServiceName -Force -ErrorAction Stop }
            }
        } else {
            if ("$($Item.DesiredValue)" -eq 'absent') {
                Remove-ItemProperty -Path $Item.Path -Name $Item.Name -ErrorAction Stop
            } else {
                if (-not (Test-Path -LiteralPath $Item.Path)) {
                    New-Item -Path $Item.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Item.Path -Name $Item.Name -Value ([int]$Item.DesiredValue) -Type DWord -ErrorAction Stop
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; Kind = $Item.Kind; Path = $Item.Path; Name = $Item.Name
            ValueType = $Item.ValueType; PriorStatus = $Item.PriorStatus
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
        Get-ForwardPlan -DisableRemoteDesktop:$DisableRemoteDesktop -DisableWinRM:$DisableWinRM
    })

$planPath = Join-Path $resolvedReportDirectory "remote-access-posture-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "remote-access-posture-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "remote-access-posture-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "remote-access-posture-$mode-state-$timestamp.json"

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

$rollbackSourcePath = $null
$rollbackConsumedPath = $null
$rollbackNote = $null
if ($Rollback -and $script:RollbackSourceFile) {
    $rollbackSourcePath = $script:RollbackSourceFile.FullName
    if (Test-RollbackFileConsumable -State $state -Preview ([bool]$WhatIfPreference)) {
        # Bookkeeping after a real change, not a previewed one: -WhatIf:$false on purpose.
        $consumedName = $script:RollbackSourceFile.Name -replace '\.json$', ".consumed-$timestamp.json"
        try {
            Rename-Item -LiteralPath $rollbackSourcePath -NewName $consumedName -WhatIf:$false -ErrorAction Stop
            $rollbackConsumedPath = Join-Path (Split-Path -Parent $rollbackSourcePath) $consumedName
            $rollbackNote = 'Rollback file consumed; the next -Rollback undoes the previous run.'
        } catch {
            $rollbackNote = "Rollback file could not be marked consumed ($($_.Exception.Message)); move it aside before the next -Rollback or it is replayed."
            Write-Warning $rollbackNote
        }
    } elseif ($WhatIfPreference) {
        $rollbackNote = 'Rollback file left unconsumed: -WhatIf changes nothing.'
    } else {
        $rollbackNote = 'Rollback file left unconsumed: at least one item failed or was skipped, so -Rollback can be run again.'
    }
}

$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "remote-access-posture-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WindowsRemoteAccessPosture ($mode)"
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    RebootRequired = [bool](@($state | Where-Object { $_.RequiresReboot -and $_.Result -in @('Applied', 'Reverted') }).Count -gt 0)
    Items = @($state)
}
