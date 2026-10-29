<#
.SYNOPSIS
Plan, apply, and roll back PowerShell logging, process-creation command-line auditing, advanced audit policy, and event log sizes.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to apply: every control here is machine-wide and needs administrator rights.
  Without elevation each item is marked 'Skipped: requires elevation'.
- Use -Rollback to restore what the last live run changed.
- -ReportDirectory is mandatory: this is a public repository, so no report path is assumed.
  Supply a directory outside the repo on every run.

Purpose:
Builds the forensic visibility a standalone workstation lacks by default:
- PowerShell Script Block Logging (event 4104) and Module Logging for all modules ('*'), through the
  Windows PowerShell policy keys under HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell. These
  keys govern Windows PowerShell 5.1 only; PowerShell 7 reads separate PowerShellCore policy keys
  that this script does not touch.
- Process creation events (4688) carry the full command line: ProcessCreationIncludeCmdLine_Enabled = 1.
- The advanced audit policy subcategories a workstation baseline needs (credential validation,
  account and group management, logon, logoff, lockout, special logon, removable storage, policy
  change, sensitive privilege use, security system extension, system integrity, process creation).
  Subcategories are addressed by GUID, never by name, so the script works on any display language.
  A subcategory that already audits what is wanted is left alone, and a forward run only turns audit
  flags on: it never turns an existing flag off. Note that reading a subcategory's current setting
  matches the English words Success, Failure, and No Auditing; on another display language the
  setting reads as unknown and the subcategory is reported Skipped and not changed, because the
  prior value could not be recorded for rollback.
- Event log maximum sizes for Security, Microsoft-Windows-PowerShell/Operational, and Windows
  PowerShell (parameters, in bytes). A log that is already as large or larger is never shrunk.

Opt-in controls:
- -LogScriptBlockInvocation also logs script block start and stop events. This is very verbose on a
  workstation that runs many scripts and will fill the PowerShell log quickly.
- -TranscriptDirectory <path> enables PowerShell transcription into that directory. Transcripts
  record everything shown at the console, which can include secrets typed or printed there
  (passwords, tokens, recovery keys). Create the directory first and restrict its ACL to
  administrators and the log reader before enabling, and treat its contents as sensitive.

Before changing the audit policy the script runs auditpol /backup to auditpol-backup-<timestamp>.csv
in the report directory, on a -WhatIf run as well as a live run, because the file records the state the
plan was built against. If the backup cannot be written, a live run changes no audit policy.
-Rollback restores registry values and log sizes to their recorded prior values and restores the
audit policy with auditpol /restore from that backup file. The restore replaces the whole audit
policy with its state at backup time, so any audit policy change made by other means after the
backup is lost too.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir>                         # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -TranscriptDirectory <path>   # elevated, read the transcript warning
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, the auditpol backup CSV, and on a live
run that changed something a rollback JSON holding every prior value and the backup path. Returns a
summary object with the report paths, counts, and RebootRequired (always false for this script).

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Set-WindowsExploitMitigation.ps1.
Event log sizes are bytes (wevtutil sl /ms:). Sizes are rounded up to a multiple of 64 KB.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Also log script block start and stop events. Verbose.
    [Parameter()]
    [switch]$LogScriptBlockInvocation,

    # Enable PowerShell transcription into this directory. Transcripts can capture secrets typed at
    # the console; ACL-restrict the directory.
    [Parameter()]
    [ValidateScript({ [System.IO.Path]::IsPathRooted($_) })]
    [string]$TranscriptDirectory,

    [Parameter()]
    [switch]$SkipAuditPolicy,

    [Parameter()]
    [switch]$SkipEventLogSize,

    # Bytes. Default 256 MB.
    [Parameter()]
    [ValidateRange(1048576, 137438953472)]
    [int64]$SecurityLogSizeBytes = 268435456,

    # Bytes. Default 256 MB.
    [Parameter()]
    [ValidateRange(1048576, 137438953472)]
    [int64]$PowerShellOperationalLogSizeBytes = 268435456,

    # Bytes. Default 64 MB.
    [Parameter()]
    [ValidateRange(1048576, 137438953472)]
    [int64]$WindowsPowerShellLogSizeBytes = 67108864,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:AuditBackupPath = $null
$script:AuditBackupError = $null

$script:PsPolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$script:AuditSystemKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$script:WantInvocationLogging = [bool]$LogScriptBlockInvocation
$script:TranscriptPath = $TranscriptDirectory
$script:ManageEventLogSize = -not $SkipEventLogSize
$script:EventLogTargets = @(
    @{ Name = 'Security'; Size = $SecurityLogSizeBytes }
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; Size = $PowerShellOperationalLogSizeBytes }
    @{ Name = 'Windows PowerShell'; Size = $WindowsPowerShellLogSizeBytes }
)

# Advanced audit policy subcategories. GUIDs verified against `auditpol /list /subcategory:* /v`.
$script:AuditSubcategories = @(
    @{ Name = 'Credential Validation'; Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
    @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Logoff'; Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
    @{ Name = 'Account Lockout'; Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $true }
    @{ Name = 'Special Logon'; Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
    @{ Name = 'Removable Storage'; Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Audit Policy Change'; Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Authentication Policy Change'; Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
    @{ Name = 'Sensitive Privilege Use'; Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Security System Extension'; Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
    @{ Name = 'System Integrity'; Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true }
    @{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
)

function Show-Usage {
    Write-Output @'
Plan, apply, and roll back PowerShell logging, 4688 command lines, audit policy, and event log sizes.

Usage:
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -WhatIf
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir>                         # elevated
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -TranscriptDirectory <path>
  pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsAuditLogging.ps1 -ReportDirectory <dir> -Rollback -WhatIf

Options:
  -LogScriptBlockInvocation          Also log script block start/stop events (verbose).
  -TranscriptDirectory               Enable PowerShell transcription into this directory. Transcripts can
                                     capture secrets typed at the console; ACL-restrict the directory.
  -SkipAuditPolicy                   Do not change advanced audit policy.
  -SkipEventLogSize                  Do not change event log sizes.
  -SecurityLogSizeBytes              Security log maximum size in bytes. Default 268435456.
  -PowerShellOperationalLogSizeBytes PowerShell/Operational log maximum size in bytes. Default 268435456.
  -WindowsPowerShellLogSizeBytes     Windows PowerShell log maximum size in bytes. Default 67108864.
  -ReportDirectory                   Plan, state, backup, and rollback output directory. Required, no default.
  -Rollback                          Restore the prior state recorded by the last live run.
  -WhatIf                            Write reports and the auditpol backup, change nothing else.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs a native tool (or its test stub) without letting stderr terminate the script, and returns
# the exit code and output lines. LASTEXITCODE is reset first because strict mode throws on an
# unset variable and a stale value from an earlier call must not be read as this call's result.
function Invoke-Native {
    param([Parameter(Mandatory = $true)][string]$Exe, [string[]]$ArgumentList = @())
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Set-Variable -Name LASTEXITCODE -Scope Global -Value 0 -WhatIf:$false
        $output = @(& $Exe @ArgumentList 2>&1 | ForEach-Object { "$_" })
        $code = [int](Get-Variable -Name LASTEXITCODE -Scope Global -ValueOnly)
    } finally {
        $ErrorActionPreference = $previous
    }
    [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function Get-RegValue {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    # Read every value and pick one: a value named '*' (Module Logging) would be a wildcard to
    # -Name, and strict mode throws on a missing property.
    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -ne $props -and $props.PSObject.Properties[$Name]) { $props.PSObject.Properties[$Name].Value }
}

# Returns None | Success | Failure | SuccessAndFailure | unknown for one subcategory GUID.
function Get-AuditSetting {
    param([Parameter(Mandatory = $true)][string]$Guid)
    $result = Invoke-Native -Exe 'auditpol.exe' -ArgumentList @('/get', "/subcategory:$Guid", '/r')
    if ($result.ExitCode -ne 0) { return 'unknown' }
    $line = @($result.Output | Where-Object { $_ -match [regex]::Escape($Guid) }) | Select-Object -First 1
    if (-not $line) { return 'unknown' }
    # Positional columns: the header row is localized, the column order is not.
    $row = @($line | ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion')[0]
    $text = "$($row.Inclusion)"
    $hasSuccess = $text -match 'Success'
    $hasFailure = $text -match 'Failure'
    if ($hasSuccess -and $hasFailure) { return 'SuccessAndFailure' }
    if ($hasSuccess) { return 'Success' }
    if ($hasFailure) { return 'Failure' }
    if ($text -match 'No Auditing') { return 'None' }
    'unknown'
}

# Returns the log's maximum size in bytes, or $null when it cannot be read.
function Get-EventLogMaxSize {
    param([Parameter(Mandatory = $true)][string]$LogName)
    $result = Invoke-Native -Exe 'wevtutil.exe' -ArgumentList @('gl', $LogName)
    if ($result.ExitCode -ne 0) { return $null }
    foreach ($line in $result.Output) {
        if ($line -match '^\s*maxSize:\s*(\d+)\s*$') { return [int64]$matches[1] }
    }
    $null
}

function Get-RegistrySpec {
    $spec = [System.Collections.Generic.List[hashtable]]::new()
    $sbl = Join-Path $script:PsPolicyRoot 'ScriptBlockLogging'
    $spec.Add(@{ Category = 'ScriptBlockLogging'; Path = $sbl; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1 })
    if ($script:WantInvocationLogging) {
        $spec.Add(@{ Category = 'ScriptBlockLogging'; Path = $sbl; Name = 'EnableScriptBlockInvocationLogging'; Type = 'DWord'; Value = 1 })
    }
    $mod = Join-Path $script:PsPolicyRoot 'ModuleLogging'
    $spec.Add(@{ Category = 'ModuleLogging'; Path = $mod; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1 })
    $spec.Add(@{ Category = 'ModuleLogging'; Path = (Join-Path $mod 'ModuleNames'); Name = '*'; Type = 'String'; Value = '*' })
    if ($script:TranscriptPath) {
        $tr = Join-Path $script:PsPolicyRoot 'Transcription'
        $spec.Add(@{ Category = 'Transcription'; Path = $tr; Name = 'EnableTranscripting'; Type = 'DWord'; Value = 1 })
        $spec.Add(@{ Category = 'Transcription'; Path = $tr; Name = 'OutputDirectory'; Type = 'String'; Value = $script:TranscriptPath })
        $spec.Add(@{ Category = 'Transcription'; Path = $tr; Name = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1 })
    }
    $spec.Add(@{ Category = 'ProcessCreationCommandLine'; Path = $script:AuditSystemKey; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1 })
    $spec.ToArray()
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($s in Get-RegistrySpec) {
        $cur = Get-RegValue -Path $s.Path -Name $s.Name
        $same = ($null -ne $cur -and "$cur" -eq "$($s.Value)")
        $items.Add([pscustomobject]@{
                Category = $s.Category; Setting = $s.Name; Path = $s.Path; ValueType = $s.Type
                RequiresAdmin = $true; RequiresReboot = $false; SetSuccess = $false; SetFailure = $false
                CurrentValue = if ($null -ne $cur) { $cur } else { 'absent' }; DesiredValue = $s.Value
                Action = if ($same) { "No change ($($s.Category) '$($s.Name)' already $($s.Value))" } else { "Set $($s.Category) '$($s.Name)' to '$($s.Value)'" }
            })
    }

    if (-not $SkipAuditPolicy) {
        foreach ($sub in $script:AuditSubcategories) {
            $cur = Get-AuditSetting -Guid $sub.Guid
            $hasSuccess = $cur -in @('Success', 'SuccessAndFailure')
            $hasFailure = $cur -in @('Failure', 'SuccessAndFailure')
            $setSuccess = ($sub.Success -and -not $hasSuccess)
            $setFailure = ($sub.Failure -and -not $hasFailure)
            $wantedText = if ($sub.Success -and $sub.Failure) { 'SuccessAndFailure' } elseif ($sub.Success) { 'Success' } else { 'Failure' }
            $flags = @(if ($setSuccess) { 'Success' }; if ($setFailure) { 'Failure' }) -join ' and '
            $items.Add([pscustomobject]@{
                    Category = 'AuditPolicy'; Setting = $sub.Name; Path = $sub.Guid; ValueType = 'auditpol'
                    RequiresAdmin = $true; RequiresReboot = $false
                    CurrentValue = $cur; DesiredValue = $wantedText
                    SetSuccess = $setSuccess; SetFailure = $setFailure
                    Action = if ($cur -eq 'unknown') { "Skipped: current audit setting of $($sub.Name) could not be read, so it is not changed" }
                    elseif (-not $setSuccess -and -not $setFailure) { "No change ($($sub.Name) already audits $wantedText)" }
                    else { "Enable $flags auditing for $($sub.Name) (currently $cur)" }
                })
        }
    }

    if ($script:ManageEventLogSize) {
        foreach ($log in $script:EventLogTargets) {
            $desired = [int64]([math]::Ceiling($log.Size / 65536) * 65536)
            $cur = Get-EventLogMaxSize -LogName $log.Name
            $action = if ($null -eq $cur) {
                "Skipped: current size of '$($log.Name)' could not be read, so it is not changed (a larger log must never be shrunk)"
            } elseif ($cur -ge $desired) {
                "No change ('$($log.Name)' is already $cur bytes, at least $desired)"
            } else {
                "Set '$($log.Name)' maximum size to $desired bytes (currently $cur)"
            }
            $items.Add([pscustomobject]@{
                    Category = 'EventLogSize'; Setting = $log.Name; Path = 'wevtutil.exe'; ValueType = 'bytes'
                    RequiresAdmin = $true; RequiresReboot = $false; SetSuccess = $false; SetFailure = $false
                    CurrentValue = if ($null -ne $cur) { $cur } else { 'unknown' }; DesiredValue = $desired
                    Action = $action
                })
        }
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'audit-logging-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^audit-logging-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No audit-logging-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $restoreAdded = $false
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
        if ($entry.Category -eq 'AuditPolicy') {
            if ($restoreAdded) { continue }
            $restoreAdded = $true
            $backup = if ($data.PSObject.Properties['AuditBackupPath']) { "$($data.AuditBackupPath)" } else { '' }
            $items.Add([pscustomobject]@{
                    Category = 'AuditPolicyRestore'; Setting = 'auditpol /restore'; Path = $backup; ValueType = 'auditpol'
                    RequiresAdmin = $true; RequiresReboot = $false
                    CurrentValue = 'changed'; DesiredValue = 'backup'
                    Action = "Restore the whole audit policy from '$backup' (undoes every audit policy change made after the backup)"
                })
            continue
        }
        $prior = "$($entry.PriorValue)"
        $items.Add([pscustomobject]@{
                Category = $entry.Category; Setting = $entry.Setting; Path = $entry.Path; ValueType = $entry.ValueType
                RequiresAdmin = [bool]$entry.RequiresAdmin; RequiresReboot = $false
                CurrentValue = $entry.AppliedValue; DesiredValue = $entry.PriorValue
                Action = "Restore $($entry.Category) '$($entry.Setting)' to '$prior'"
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
    if ($Item.Action -like 'Skipped*') { return $Item.Action }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($Item.Category -eq 'AuditPolicy' -and -not $script:AuditBackupPath -and -not $WhatIfPreference) {
        return 'Skipped: auditpol backup failed, so no audit policy is changed without a restore point'
    }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        switch ($Item.Category) {
            'AuditPolicy' {
                $argumentList = @('/set', "/subcategory:$($Item.Path)")
                if ($Item.SetSuccess) { $argumentList += '/success:enable' }
                if ($Item.SetFailure) { $argumentList += '/failure:enable' }
                $r = Invoke-Native -Exe 'auditpol.exe' -ArgumentList $argumentList
                if ($r.ExitCode -ne 0) { throw "auditpol /set exited $($r.ExitCode): $($r.Output -join ' ')" }
            }
            'AuditPolicyRestore' {
                if (-not $Item.Path -or -not (Test-Path -LiteralPath $Item.Path)) { throw "auditpol backup file not found: '$($Item.Path)'" }
                $r = Invoke-Native -Exe 'auditpol.exe' -ArgumentList @('/restore', "/file:$($Item.Path)")
                if ($r.ExitCode -ne 0) { throw "auditpol /restore exited $($r.ExitCode): $($r.Output -join ' ')" }
            }
            'EventLogSize' {
                $r = Invoke-Native -Exe 'wevtutil.exe' -ArgumentList @('sl', $Item.Setting, "/ms:$($Item.DesiredValue)")
                if ($r.ExitCode -ne 0) { throw "wevtutil sl exited $($r.ExitCode): $($r.Output -join ' ')" }
            }
            default {
                if ("$($Item.DesiredValue)" -eq 'absent') {
                    # '*' is a wildcard to Remove-ItemProperty -Name; escape it so only that one value goes.
                    Remove-ItemProperty -Path $Item.Path -Name ([System.Management.Automation.WildcardPattern]::Escape($Item.Setting)) -ErrorAction SilentlyContinue
                } else {
                    if (-not (Test-Path -Path $Item.Path)) { New-Item -Path $Item.Path -Force | Out-Null }
                    $value = if ($Item.ValueType -eq 'DWord') { [int]$Item.DesiredValue } else { "$($Item.DesiredValue)" }
                    Set-ItemProperty -Path $Item.Path -Name $Item.Setting -Value $value -Type $Item.ValueType
                }
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; Path = $Item.Path; ValueType = $Item.ValueType
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

# Restore point for the audit policy. Taken before anything is read into a plan decision that
# matters, and on a preview run too: it is a plan artifact, not the change being previewed.
$backupWanted = $Rollback -or -not $SkipAuditPolicy
if ($backupWanted) {
    $backupFile = Join-Path $resolvedReportDirectory "auditpol-backup-$timestamp.csv"
    $b = Invoke-Native -Exe 'auditpol.exe' -ArgumentList @('/backup', "/file:$backupFile")
    if ($b.ExitCode -eq 0 -and (Test-Path -LiteralPath $backupFile)) {
        $script:AuditBackupPath = $backupFile
    } else {
        $script:AuditBackupError = "auditpol /backup exited $($b.ExitCode): $($b.Output -join ' ')"
        Write-Warning "auditpol backup failed: $($script:AuditBackupError)"
    }
}

$plan = @(if ($Rollback) { Get-RollbackPlan } else { Get-ForwardPlan })

$planPath = Join-Path $resolvedReportDirectory "audit-logging-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "audit-logging-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "audit-logging-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "audit-logging-$mode-state-$timestamp.json"

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

# Rollback record on a live forward run that changed at least one setting.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "audit-logging-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        AuditBackupPath = $script:AuditBackupPath
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WindowsAuditLogging ($mode)"
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    AuditBackupPath = $script:AuditBackupPath
    AuditBackupError = $script:AuditBackupError
    RollbackJsonPath = $rollbackPath
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    RebootRequired = $false
    Items = @($state)
}
