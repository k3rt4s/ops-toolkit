<#
.SYNOPSIS
Plan, apply, and roll back local account lockout, Guest, built-in Administrator, and UAC policy on a standalone Windows 11 machine.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to apply: every change is a machine-wide account, policy, or registry change.
- The default run sets the local account lockout policy (threshold, duration, observation window),
  disables the Guest account, and sets the User Account Control values EnableLUA 1,
  ConsentPromptBehaviorAdmin 2 (prompt for consent on the secure desktop for every elevation), PromptOnSecureDesktop 1,
  and LimitBlankPasswordUse 1.
- Lockout defaults are threshold 10, duration 15 minutes, observation window 15 minutes. The
  observation window may not exceed the duration. The current values are read from the output of
  net.exe accounts by line position, so a localized Windows is handled; when that output cannot be
  parsed the three lockout items are 'Skipped: ...' and nothing is applied blind. Do not count on
  the built-in Administrator (RID 500) as a lockout escape: from Windows 11 22H2 the 'Allow
  Administrator account lockout' policy is on by default, so it can be locked out like any other
  local administrator. After the threshold of bad passwords an account stays locked for the
  duration, which on a single-administrator machine means waiting it out.
- The Guest account is found by its well-known SID ending -501, never by name.
- -DisableBuiltInAdministrator disables the built-in Administrator (SID ending -500, found by SID).
  It is refused (plan item 'Skipped: ...') unless at least one OTHER enabled local user is a member
  of the local Administrators group, because disabling the only administrator leaves the machine
  with no way to elevate. What breaks: anything signing in or elevating as the built-in account.
- -RenameBuiltInAdministrator <name> renames the built-in Administrator (SID ending -500). What
  breaks: scripts, scheduled tasks, or shortcuts that refer to the account by its old name.
- Report-only item (no change is ever made): the members of the local Administrators group and
  whether the current user is one. A daily-use account that is an administrator is a least-privilege
  finding; use a separate standard account for daily work.
- UAC changes take effect for new sessions; a change to EnableLUA requires a reboot and is
  flagged RequiresReboot. Anything that cannot be read is reported as 'unknown', never as compliant.
- The 24H2 Administrator Protection setting is deliberately not covered: its registry value name and
  data were not verified against Microsoft documentation, so it is left out rather than guessed.
- Windows Hello enrollment, LAPS, and domain policy are out of scope for a standalone machine.
- Use -Rollback to restore the exact values this script changed from the newest rollback file in
  the report directory.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  developer's workstation must never be applied to someone else's machine. Generated reports
  belong under a data root outside the repo.

Purpose:
Raises the cost of password guessing and of misuse of well-known accounts on a workgroup (not
domain-joined, not Intune-managed) machine using local tools only: net.exe accounts, the
Microsoft.PowerShell.LocalAccounts cmdlets, and local policy registry values. No Group Policy,
Active Directory, or Entra mechanism is used.

Every change is recorded in a rollback JSON so the policy can be reversed with -Rollback.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir>                                 # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir> -LockoutThreshold 5 -LockoutDurationMinutes 30 -LockoutObservationWindowMinutes 30
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir> -DisableBuiltInAdministrator   # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir> -RenameBuiltInAdministrator <name>  # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsLocalAccountPolicy.ps1 -ReportDirectory <dir> -Rollback -WhatIf

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
    [ValidateRange(1, 999)]
    [int]$LockoutThreshold = 10,

    [Parameter()]
    [ValidateRange(1, 99999)]
    [int]$LockoutDurationMinutes = 15,

    [Parameter()]
    [ValidateRange(1, 99999)]
    [int]$LockoutObservationWindowMinutes = 15,

    [Parameter()]
    [switch]$DisableBuiltInAdministrator,

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')]
    [string]$RenameBuiltInAdministrator,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if (-not $Rollback -and $LockoutObservationWindowMinutes -gt $LockoutDurationMinutes) {
    throw "LockoutObservationWindowMinutes ($LockoutObservationWindowMinutes) cannot exceed LockoutDurationMinutes ($LockoutDurationMinutes)."
}

$script:UacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
        [string]$ValueType = '', [string]$Sid = '', $CurrentValue, $DesiredValue, [bool]$RequiresAdmin = $true,
        [bool]$RequiresReboot = $false, [string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; Kind = $Kind; Path = $Path; Name = $Name
        ValueType = $ValueType; Sid = $Sid; RequiresAdmin = $RequiresAdmin; RequiresReboot = $RequiresReboot
        CurrentValue = $CurrentValue; DesiredValue = $DesiredValue; Action = $Action
    }
}

function Get-RegistryPlanEntry {
    param(
        [string]$Category, [string]$Path, [string]$Name, [int]$Desired, [string]$Label, [switch]$NeedsReboot
    )
    $state = Get-RegistryValueState -Path $Path -Name $Name
    $current = switch ($state.State) { 'present' { $state.Value } 'absent' { 'absent' } default { 'unknown' } }
    $action = if ($state.State -eq 'unknown') { "Skipped: current value of $Name could not be read" }
    elseif ($state.State -eq 'present' -and "$($state.Value)" -eq "$Desired") { "No change ($Label already $Desired)" }
    else { "Set $Label ($Name) to $Desired" }
    Get-PlanEntry -Category $Category -Setting $Name -Kind 'Registry' -Path $Path -Name $Name -ValueType 'DWord' `
        -CurrentValue $current -DesiredValue $Desired -RequiresReboot ([bool]($NeedsReboot -and $action -like 'Set*')) -Action $action
}

# Runs net.exe accounts and returns the text lines. A non-zero exit code throws.
function Invoke-NetAccount {
    param([string[]]$Argument = @())
    $global:LASTEXITCODE = 0
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& net.exe accounts @Argument 2>&1 | ForEach-Object { "$_" })
    } finally {
        $ErrorActionPreference = $previous
    }
    $code = 0
    $exitVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $exitVariable) { $code = [int]$exitVariable.Value }
    if ($code -ne 0) { throw "net.exe accounts $($Argument -join ' ') failed with exit code ${code}: $($output -join ' ')" }
    $output
}

# Reads the lockout policy without depending on the display language: net accounts prints nine
# 'label:  value' lines in a fixed order (force logoff, min password age, max password age, min
# password length, history, lockout threshold, lockout duration, lockout window, computer role).
# Returns $null unless the shape matches, with the two numeric password fields as a sanity check.
function Get-LockoutState {
    try {
        $lines = Invoke-NetAccount
    } catch {
        return $null
    }
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match '^(.+?):\s{2,}(\S.*?)\s*$') { $values.Add($Matches[2]) }
    }
    if ($values.Count -ne 9) { return $null }
    if ($values[1] -notmatch '^\d+$' -or $values[3] -notmatch '^\d+$') { return $null }
    if ($values[6] -notmatch '^\d+$' -or $values[7] -notmatch '^\d+$') { return $null }
    # 'Never' (any language) is the only non-numeric threshold value and means 0.
    $threshold = if ($values[5] -match '^\d+$') { [int]$values[5] } else { 0 }
    @{ Threshold = $threshold; Duration = [int]$values[6]; Window = [int]$values[7] }
}

# The window must never exceed the duration while the two are changed one call at a time.
# Lowering: window first. Raising: duration first. Returns 'DurationFirst' or 'WindowFirst'.
function Get-LockoutOrder {
    param([int]$CurrentWindow, [int]$DesiredDuration)
    if ($DesiredDuration -ge $CurrentWindow) { 'DurationFirst' } else { 'WindowFirst' }
}

function Get-LockoutItem {
    param([int]$Threshold, [int]$Duration, [int]$Window)
    $state = Get-LockoutState
    $specs = @(
        @{ Name = 'lockoutthreshold'; Label = 'Account lockout threshold'; Key = 'Threshold'; Desired = $Threshold }
        @{ Name = 'lockoutduration'; Label = 'Account lockout duration (minutes)'; Key = 'Duration'; Desired = $Duration }
        @{ Name = 'lockoutwindow'; Label = 'Lockout observation window (minutes)'; Key = 'Window'; Desired = $Window }
    )
    $built = @{}
    foreach ($spec in $specs) {
        if ($null -eq $state) {
            $built[$spec.Name] = Get-PlanEntry -Category 'Lockout' -Setting $spec.Name -Kind 'Lockout' -CurrentValue 'unknown' `
                -DesiredValue $spec.Desired -Action "Skipped: $($spec.Label) could not be read from net.exe accounts"
            continue
        }
        $current = $state[$spec.Key]
        $action = if ($current -eq $spec.Desired) { "No change ($($spec.Label) already $current)" }
        else { "Set $($spec.Label) to $($spec.Desired)" }
        $built[$spec.Name] = Get-PlanEntry -Category 'Lockout' -Setting $spec.Name -Kind 'Lockout' -CurrentValue $current `
            -DesiredValue $spec.Desired -Action $action
    }
    $curWindow = if ($null -ne $state) { $state.Window } else { 0 }
    if ((Get-LockoutOrder -CurrentWindow $curWindow -DesiredDuration $Duration) -eq 'DurationFirst') {
        $built['lockoutthreshold']; $built['lockoutduration']; $built['lockoutwindow']
    } else {
        $built['lockoutthreshold']; $built['lockoutwindow']; $built['lockoutduration']
    }
}

# Local users, or $null when the read fails. Shape: Name, Sid, Enabled.
function Get-LocalUserList {
    try {
        $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID; Enabled = [bool]$_.Enabled }
            })
        , $users
    } catch {
        $null
    }
}

# Local Administrators members, or $null when the read fails (orphaned SIDs make it fail outright).
function Get-AdministratorsMemberList {
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID; ObjectClass = [string]$_.ObjectClass }
            })
        , $members
    } catch {
        $null
    }
}

function Get-AccountItem {
    param([switch]$DisableBuiltInAdministrator, [string]$RenameBuiltInAdministrator)

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $users = Get-LocalUserList
    $members = Get-AdministratorsMemberList

    # Guest, by well-known SID.
    if ($null -eq $users) {
        $items.Add((Get-PlanEntry -Category 'GuestAccount' -Setting 'Guest account' -Kind 'LocalUserEnabled' -CurrentValue 'unknown' `
                    -DesiredValue 'Disabled' -Action 'Skipped: local users could not be read'))
    } else {
        $guest = @($users | Where-Object { $_.Sid -match '-501$' }) | Select-Object -First 1
        if ($null -eq $guest) {
            $items.Add((Get-PlanEntry -Category 'GuestAccount' -Setting 'Guest account' -Kind 'LocalUserEnabled' -CurrentValue 'absent' `
                        -DesiredValue 'Disabled' -Action 'No change (no Guest account is present)'))
        } else {
            $now = if ($guest.Enabled) { 'Enabled' } else { 'Disabled' }
            $items.Add((Get-PlanEntry -Category 'GuestAccount' -Setting 'Guest account' -Kind 'LocalUserEnabled' -Sid $guest.Sid `
                        -CurrentValue $now -DesiredValue 'Disabled' `
                        -Action $(if ($guest.Enabled) { 'Disable the Guest account' } else { 'No change (Guest account already disabled)' })))
        }
    }

    $builtIn = $null
    if ($null -ne $users) { $builtIn = @($users | Where-Object { $_.Sid -match '-500$' }) | Select-Object -First 1 }

    if ($DisableBuiltInAdministrator) {
        if ($null -eq $users) {
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminDisable' -Setting 'Built-in Administrator' -Kind 'LocalUserEnabled' `
                        -CurrentValue 'unknown' -DesiredValue 'Disabled' -Action 'Skipped: local users could not be read'))
        } elseif ($null -eq $builtIn) {
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminDisable' -Setting 'Built-in Administrator' -Kind 'LocalUserEnabled' `
                        -CurrentValue 'absent' -DesiredValue 'Disabled' -Action 'No change (no built-in Administrator account is present)'))
        } else {
            $now = if ($builtIn.Enabled) { 'Enabled' } else { 'Disabled' }
            $action = if (-not $builtIn.Enabled) { 'No change (built-in Administrator already disabled)' }
            elseif ($null -eq $members) { 'Skipped: Administrators group members could not be read, so another enabled administrator cannot be confirmed' }
            else {
                $byName = @{}
                foreach ($u in $users) { $byName[$u.Sid] = $u }
                $others = @($members | Where-Object {
                        $_.ObjectClass -eq 'User' -and $_.Sid -notmatch '-50[01]$' -and $byName.ContainsKey($_.Sid) -and $byName[$_.Sid].Enabled
                    })
                if ($others.Count -eq 0) { 'Skipped: no other enabled local administrator exists, refusing to disable the only administrator' }
                else { 'Disable the built-in Administrator account' }
            }
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminDisable' -Setting 'Built-in Administrator' -Kind 'LocalUserEnabled' `
                        -Sid $builtIn.Sid -CurrentValue $now -DesiredValue 'Disabled' -Action $action))
        }
    }

    if ($RenameBuiltInAdministrator) {
        if ($null -eq $users) {
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminRename' -Setting 'Built-in Administrator name' -Kind 'LocalUserName' `
                        -CurrentValue 'unknown' -DesiredValue $RenameBuiltInAdministrator -Action 'Skipped: local users could not be read'))
        } elseif ($null -eq $builtIn) {
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminRename' -Setting 'Built-in Administrator name' -Kind 'LocalUserName' `
                        -CurrentValue 'absent' -DesiredValue $RenameBuiltInAdministrator -Action 'No change (no built-in Administrator account is present)'))
        } else {
            $clash = @($users | Where-Object { $_.Name -eq $RenameBuiltInAdministrator -and $_.Sid -ne $builtIn.Sid }).Count -gt 0
            $action = if ($builtIn.Name -eq $RenameBuiltInAdministrator) { "No change (built-in Administrator already named '$RenameBuiltInAdministrator')" }
            elseif ($clash) { "Skipped: another local account is already named '$RenameBuiltInAdministrator'" }
            else { "Rename the built-in Administrator to '$RenameBuiltInAdministrator'" }
            $items.Add((Get-PlanEntry -Category 'BuiltInAdminRename' -Setting 'Built-in Administrator name' -Kind 'LocalUserName' `
                        -Sid $builtIn.Sid -CurrentValue $builtIn.Name -DesiredValue $RenameBuiltInAdministrator -Action $action))
        }
    }

    # Report-only: who is an administrator, and is the current user one.
    if ($null -eq $members) {
        $items.Add((Get-PlanEntry -Category 'AdministratorsMembers' -Setting 'Local Administrators group' -Kind 'Report' -RequiresAdmin $false `
                    -CurrentValue 'unknown' -DesiredValue 'daily-use account is a standard user' `
                    -Action 'Report only: Administrators group members could not be read (not changed)'))
    } else {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $mine = [string]$identity.User.Value
        $inToken = $false
        foreach ($g in @($identity.Groups)) { if ([string]$g.Value -eq 'S-1-5-32-544') { $inToken = $true } }
        $direct = @($members | Where-Object { $_.Sid -eq $mine }).Count -gt 0
        $isMember = $inToken -or $direct
        $names = (@($members | ForEach-Object { $_.Name }) -join ', ')
        $items.Add((Get-PlanEntry -Category 'AdministratorsMembers' -Setting 'Local Administrators group' -Kind 'Report' -RequiresAdmin $false `
                    -CurrentValue "$(@($members).Count) member(s): $names; current user is a member: $isMember" `
                    -DesiredValue 'daily-use account is a standard user' `
                    -Action 'Report only: use a separate standard account for daily work and elevate only when needed (not changed)'))
    }

    $items
}

function Get-ForwardPlan {
    param(
        [int]$Threshold, [int]$Duration, [int]$Window,
        [switch]$DisableBuiltInAdministrator, [string]$RenameBuiltInAdministrator
    )
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($i in @(Get-LockoutItem -Threshold $Threshold -Duration $Duration -Window $Window)) { $items.Add($i) }
    foreach ($i in @(Get-AccountItem -DisableBuiltInAdministrator:$DisableBuiltInAdministrator -RenameBuiltInAdministrator $RenameBuiltInAdministrator)) { $items.Add($i) }
    $items.Add((Get-RegistryPlanEntry -Category 'UacEnableLua' -Path $script:UacPath -Name 'EnableLUA' -Desired 1 -Label 'UAC Admin Approval Mode' -NeedsReboot))
    $items.Add((Get-RegistryPlanEntry -Category 'UacConsentPrompt' -Path $script:UacPath -Name 'ConsentPromptBehaviorAdmin' -Desired 2 `
                -Label 'UAC admin prompt (consent on the secure desktop for every elevation)'))
    $items.Add((Get-RegistryPlanEntry -Category 'UacSecureDesktop' -Path $script:UacPath -Name 'PromptOnSecureDesktop' -Desired 1 `
                -Label 'UAC secure desktop prompt'))
    $items.Add((Get-RegistryPlanEntry -Category 'BlankPasswordLimit' -Path $script:LsaPath -Name 'LimitBlankPasswordUse' -Desired 1 `
                -Label 'blank-password network logon restriction'))
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # The timestamp pattern keeps this from matching the 'local-account-policy-rollback-plan-*' and '-state-*' reports.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'local-account-policy-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^local-account-policy-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No local-account-policy-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $entries = @($data.ChangedSettings | Where-Object { $_ })
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $entries) {
        $items.Add((Get-PlanEntry -Category $entry.Category -Setting $entry.Setting -Kind $entry.Kind -Path $entry.Path `
                    -Name $entry.Name -ValueType $entry.ValueType -Sid ([string]$entry.Sid) -RequiresAdmin $true `
                    -CurrentValue $entry.AppliedValue -DesiredValue $entry.PriorValue `
                    -Action "Restore $($entry.Category) '$($entry.Setting)' to '$($entry.PriorValue)'"))
    }
    # Keep the window at or below the duration while restoring them one call at a time.
    $dur = @($items | Where-Object { $_.Setting -eq 'lockoutduration' }) | Select-Object -First 1
    $win = @($items | Where-Object { $_.Setting -eq 'lockoutwindow' }) | Select-Object -First 1
    if ($dur -and $win) {
        $slot = [math]::Min($items.IndexOf($dur), $items.IndexOf($win))
        [void]$items.Remove($dur)
        [void]$items.Remove($win)
        if ((Get-LockoutOrder -CurrentWindow ([int]$win.CurrentValue) -DesiredDuration ([int]$dur.DesiredValue)) -eq 'DurationFirst') {
            $items.Insert($slot, $win)
            $items.Insert($slot, $dur)
        } else {
            $items.Insert($slot, $dur)
            $items.Insert($slot, $win)
        }
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
        switch ($Item.Kind) {
            'Lockout' {
                [void](Invoke-NetAccount -Argument @("/$($Item.Setting):$($Item.DesiredValue)"))
            }
            'LocalUserEnabled' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new([string]$Item.Sid)
                if ("$($Item.DesiredValue)" -eq 'Enabled') { Enable-LocalUser -SID $sid -ErrorAction Stop }
                else { Disable-LocalUser -SID $sid -ErrorAction Stop }
            }
            'LocalUserName' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new([string]$Item.Sid)
                Rename-LocalUser -SID $sid -NewName ([string]$Item.DesiredValue) -ErrorAction Stop
            }
            default {
                if ("$($Item.DesiredValue)" -eq 'absent') {
                    Remove-ItemProperty -Path $Item.Path -Name $Item.Name -ErrorAction Stop
                } else {
                    if (-not (Test-Path -LiteralPath $Item.Path)) {
                        New-Item -Path $Item.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $Item.Path -Name $Item.Name -Value ([int]$Item.DesiredValue) -Type DWord -ErrorAction Stop
                }
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; Kind = $Item.Kind; Path = $Item.Path; Name = $Item.Name
            ValueType = $Item.ValueType; Sid = $Item.Sid
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
        Get-ForwardPlan -Threshold $LockoutThreshold -Duration $LockoutDurationMinutes -Window $LockoutObservationWindowMinutes `
            -DisableBuiltInAdministrator:$DisableBuiltInAdministrator -RenameBuiltInAdministrator $RenameBuiltInAdministrator
    })

$planPath = Join-Path $resolvedReportDirectory "local-account-policy-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "local-account-policy-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "local-account-policy-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "local-account-policy-$mode-state-$timestamp.json"

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
    $rollbackPath = Join-Path $resolvedReportDirectory "local-account-policy-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WindowsLocalAccountPolicy ($mode)"
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
