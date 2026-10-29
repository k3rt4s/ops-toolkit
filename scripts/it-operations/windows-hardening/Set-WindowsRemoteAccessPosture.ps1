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
- Use -Rollback to restore the exact values this script changed from the newest rollback file in
  the report directory.
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

# A DWord registry item. $Gate, when set, replaces the action text and leaves the item unapplied.
function Get-RegistryPlanEntry {
    param(
        [string]$Category, [string]$Path, [string]$Name, [int]$Desired, [string]$Label, [string]$Gate = ''
    )
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
    $items.Add((Get-RegistryPlanEntry -Category 'RdpNla' -Path $script:RdpTcpPath -Name 'UserAuthentication' -Desired 1 `
                -Label 'Network Level Authentication' -Gate $rdpGate))
    $items.Add((Get-RegistryPlanEntry -Category 'RdpSecurityLayer' -Path $script:RdpTcpPath -Name 'SecurityLayer' -Desired 2 `
                -Label 'RDP security layer (TLS)' -Gate $rdpGate))

    if ($DisableRemoteDesktop) {
        $remote = Get-SessionRemoteState
        $gate = switch ($remote) {
            'remote' { 'Skipped: current session is remote' }
            'unknown' { 'Skipped: could not determine whether the current session is remote' }
            default { '' }
        }
        $items.Add((Get-RegistryPlanEntry -Category 'RdpDisable' -Path $script:TerminalServerPath -Name 'fDenyTSConnections' `
                    -Desired 1 -Label 'Remote Desktop connections denied' -Gate $gate))
    }

    $items.Add((Get-RegistryPlanEntry -Category 'RemoteAssistance' -Path $script:RemoteAssistancePath -Name 'fAllowToGetHelp' `
                -Desired 0 -Label 'Remote Assistance'))

    if ($DisableWinRM) {
        $service = $null
        $readError = $false
        try {
            $service = Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq 'WinRM' } | Select-Object -First 1
        } catch { $readError = $true }
        if ($readError) {
            $items.Add((Get-PlanEntry -Category 'WinRmService' -Setting 'WinRM' -Kind 'Service' -CurrentValue 'unknown' `
                        -DesiredValue 'Disabled/Stopped' -Action 'Skipped: WinRM service state could not be read'))
        } elseif ($null -eq $service) {
            $items.Add((Get-PlanEntry -Category 'WinRmService' -Setting 'WinRM' -Kind 'Service' -CurrentValue 'absent' `
                        -DesiredValue 'Disabled/Stopped' -Action 'No change (WinRM service is not installed)'))
        } else {
            $start = [string]$service.StartType
            $status = [string]$service.Status
            $action = if (Test-IsPowerShellRemotingSession) { 'Skipped: current session is a PowerShell remoting session' }
            elseif ($start -eq 'Disabled' -and $status -eq 'Stopped') { 'No change (WinRM already Disabled and Stopped)' }
            else { 'Set WinRM service to Disabled and stop it' }
            $items.Add((Get-PlanEntry -Category 'WinRmService' -Setting 'WinRM' -Kind 'Service' -CurrentValue "$start/$status" `
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
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No remote-access-posture-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
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
                Set-Service -Name 'WinRM' -StartupType $startup -ErrorAction Stop
                if ($Item.PriorStatus -eq 'Running') { Start-Service -Name 'WinRM' -ErrorAction Stop }
            } else {
                # Disable first so the service manager cannot restart it after the stop.
                Set-Service -Name 'WinRM' -StartupType Disabled -ErrorAction Stop
                if ($Item.PriorStatus -ne 'Stopped') { Stop-Service -Name 'WinRM' -Force -ErrorAction Stop }
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
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    RebootRequired = [bool](@($state | Where-Object { $_.RequiresReboot -and $_.Result -in @('Applied', 'Reverted') }).Count -gt 0)
    Items = @($state)
}
