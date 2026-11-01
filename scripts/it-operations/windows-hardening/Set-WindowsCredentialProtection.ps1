<#
.SYNOPSIS
Plan, apply, and roll back local credential-protection registry settings on a standalone Windows 11 machine.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON. The plan also lists report-only
  rows (is virtualization-based security running, are Secure Boot and a TPM present) that are read
  and never changed.
- Run elevated to apply. Every setting is a machine registry value, so a non-elevated live run
  marks each one "Skipped: requires elevation". Nearly all of them need a reboot to take effect.
- Use -Rollback to restore the exact prior values from the latest unconsumed rollback file in the
  report directory. A value that was absent before is removed again. Each executing -Rollback that
  reverts everything marks its file consumed (see Rollback below), so running -Rollback again
  undoes the previous run, newest first.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  developer's workstation must never be applied to someone else's machine. Supply it on every run.

Purpose:
Raises the cost of stealing credentials from memory on a workgroup machine, using local registry
values only (no Group Policy, no Active Directory).

Default run (least disruptive):
- LSA protection (RunAsPPL = 2, protected process WITHOUT a UEFI lock).
- WDigest plaintext caching off (UseLogonCredential = 0).
- NTLMv2 only on this machine (LmCompatibilityLevel = 5) and no LM hash storage (NoLMHash = 1).

Opt-in, because each can break something:
- -EnableCredentialGuard: LsaCfgFlags = 2 (Credential Guard WITHOUT a UEFI lock) plus the
  virtualization-based security prerequisites. Credential Guard blocks NTLMv1 and MS-CHAPv2, so it
  breaks some VPN and Wi-Fi (PEAP-MSCHAPv2) setups, and it can conflict with older hypervisor
  products and Hyper-V saved-state guests.
- -EnableMemoryIntegrity: HVCI (memory integrity), Enabled = 1, plus the virtualization-based
  security prerequisites. BEFORE using it, open Windows Security > Device security > Core isolation
  and check the memory integrity page for incompatible drivers; HVCI with an incompatible driver
  can stop that driver (and the hardware or software depending on it) from loading. This script
  does not scan drivers.
- -UefiLock: changes the LSA protection value to 1 and, only when -EnableCredentialGuard is also
  passed, the Credential Guard value (LsaCfgFlags) to 1 (both WITH a UEFI lock). A UEFI lock is stored in firmware variables: clearing the registry value, and so
  -Rollback, does NOT remove it. Undoing a UEFI lock needs Microsoft's opt-out procedure and tool
  (the Device Guard and Credential Guard readiness or opt-out tooling, which asks for physical
  presence at the next boot). Use it only after the default has run cleanly for a while.
- -RequireDmaProtection: sets the VBS platform requirement to Secure Boot plus DMA protection (3)
  instead of Secure Boot only (1). Machines without an IOMMU will then not start VBS. The VBS rows
  are planned only under -EnableCredentialGuard or -EnableMemoryIntegrity, so -RequireDmaProtection
  on its own is a no-op.

Value meanings used (Microsoft Learn): RunAsPPL 1 = enabled with UEFI lock, 2 = enabled without UEFI
lock (Windows 11 22H2 and later). LsaCfgFlags 1 = Credential Guard enabled with UEFI lock, 2 =
enabled without lock, 0 = disabled. RequirePlatformSecurityFeatures 1 = Secure Boot, 3 = Secure Boot
and DMA protection. Some LSA protection add-on security products load a driver into LSASS and fail
under RunAsPPL; keep recovery media available before changing the Lsa key.

Outbound NTLM blocking is a domain item and is deliberately not covered here.

Rollback: -Rollback reads the newest credential-protection-rollback-<timestamp>.json in the report
directory. Before any plan is written or any change made, it checks every recorded entry against the
registry controls this script's own forward plan can set (category, registry path and value name; the
full set, whatever switches the original run used) and checks the value types (a prior value is a
whole number, 'absent' or 'unknown'; an applied value is a whole number or 'absent'). A file that does
not parse, lacks a ChangedSettings array, or holds any entry outside that set is refused whole with an
error naming the file and the first bad entry, also under -WhatIf; move that file aside to roll back
an older run. After an executing -Rollback in which every item was reverted or needed no change, the
file is renamed credential-protection-rollback-<timestamp>.consumed-<timestamp>.json and is no longer
picked. Under -WhatIf, or when any item failed or was skipped (for example not elevated), the file is
left in place and the summary says so.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1 -ReportDirectory <dir>      # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1 -ReportDirectory <dir> -EnableCredentialGuard -EnableMemoryIntegrity
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1 -ReportDirectory <dir> -EnableCredentialGuard -UefiLock
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes credential-protection plan and state CSV/JSON under the report directory, plus a rollback
JSON capturing the prior value of every setting changed. The summary object carries RebootRequired.

.NOTES
Status:
Active script in the ops-toolkit repo. Reads current virtualization-based security, Secure Boot and
TPM state read-only; a read that fails is reported as unknown, never as compliant.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$EnableCredentialGuard,

    [Parameter()]
    [switch]$EnableMemoryIntegrity,

    [Parameter()]
    [switch]$UefiLock,

    [Parameter()]
    [switch]$RequireDmaProtection,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:WDigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$script:DeviceGuardPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$script:HvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'

# Every registry value the forward plan can write. Get-ForwardPlan reads its category, path and name
# from here, and the rollback validator accepts exactly these rows, so the two cannot drift.
$script:RegistryControls = @(
    [pscustomobject]@{ Id = 'RunAsPPL'; Category = 'LsaProtection'; Path = $script:LsaPath; Name = 'RunAsPPL' }
    [pscustomobject]@{ Id = 'UseLogonCredential'; Category = 'WDigest'; Path = $script:WDigestPath; Name = 'UseLogonCredential' }
    [pscustomobject]@{ Id = 'LmCompatibilityLevel'; Category = 'Ntlm'; Path = $script:LsaPath; Name = 'LmCompatibilityLevel' }
    [pscustomobject]@{ Id = 'NoLMHash'; Category = 'Ntlm'; Path = $script:LsaPath; Name = 'NoLMHash' }
    [pscustomobject]@{ Id = 'EnableVirtualizationBasedSecurity'; Category = 'Vbs'; Path = $script:DeviceGuardPath; Name = 'EnableVirtualizationBasedSecurity' }
    [pscustomobject]@{ Id = 'RequirePlatformSecurityFeatures'; Category = 'Vbs'; Path = $script:DeviceGuardPath; Name = 'RequirePlatformSecurityFeatures' }
    [pscustomobject]@{ Id = 'MemoryIntegrity'; Category = 'MemoryIntegrity'; Path = $script:HvciPath; Name = 'Enabled' }
    [pscustomobject]@{ Id = 'LsaCfgFlags'; Category = 'CredentialGuard'; Path = $script:LsaPath; Name = 'LsaCfgFlags' }
)
$script:RollbackSourceFile = $null
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:WantCredentialGuard = [bool]$EnableCredentialGuard
$script:WantMemoryIntegrity = [bool]$EnableMemoryIntegrity
$script:WantDmaProtection = [bool]$RequireDmaProtection

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Returns the DWord value, the string 'absent' when the key or value is missing, or 'unknown'
# when the key exists but cannot be read. Never throws and never returns $null.
function Get-RegistryState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    } catch {
        if (-not (Test-Path -LiteralPath $Path)) { return 'absent' }
        return 'unknown'
    }
    if ($null -ne $props -and $props.PSObject.Properties[$Name]) {
        $value = $props.PSObject.Properties[$Name].Value
        if ($null -eq $value) { return 'unknown' }
        return $value
    }
    'absent'
}

# A value counts as meeting the target when it equals it, or when a UEFI-locked value (1) is
# already present and the target is the unlocked value (2): both protect, and the lock cannot
# be lowered from the registry anyway.
function Test-MeetsTarget {
    param($Current, $Desired, [switch]$LockedSatisfiesUnlocked)
    if ("$Current" -eq "$Desired") { return $true }
    if ($LockedSatisfiesUnlocked -and "$Desired" -eq '2' -and "$Current" -eq '1') { return $true }
    $false
}

function Get-RegistryControl {
    param([Parameter(Mandatory = $true)][string]$Id)
    $hit = @($script:RegistryControls | Where-Object { $_.Id -eq $Id })
    if ($hit.Count -ne 1) { throw "No registry control '$Id' is defined." }
    $hit[0]
}

function Add-RegistryItem {
    param(
        [Parameter(Mandatory = $true)]$Items,
        [Parameter(Mandatory = $true)]$Control,
        [Parameter(Mandatory = $true)][int]$Desired,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$LockedSatisfiesUnlocked
    )
    $Category = $Control.Category
    $Path = $Control.Path
    $Name = $Control.Name
    $current = Get-RegistryState -Path $Path -Name $Name
    $meets = Test-MeetsTarget -Current $current -Desired $Desired -LockedSatisfiesUnlocked:$LockedSatisfiesUnlocked
    $Items.Add([pscustomobject]@{
            Category = $Category; Setting = $Name; RegistryPath = $Path
            RequiresAdmin = $true; RequiresReboot = $true
            CurrentValue = $current; DesiredValue = $Desired
            Action = if ($meets) { "No change ($Name already $current)" } else { "Set $Name = $Desired. $Label" }
        })
}

function Get-DeviceGuardRuntime {
    # Read-only. Returns an object with the raw numbers, or $null when the class cannot be read.
    try {
        $dg = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop) |
            Select-Object -First 1
        if ($null -eq $dg) { return $null }
        $running = @()
        if ($dg.PSObject.Properties['SecurityServicesRunning'] -and $null -ne $dg.SecurityServicesRunning) {
            $running = @($dg.SecurityServicesRunning)
        }
        $vbs = 'unknown'
        if ($dg.PSObject.Properties['VirtualizationBasedSecurityStatus'] -and $null -ne $dg.VirtualizationBasedSecurityStatus) {
            $vbs = [int]$dg.VirtualizationBasedSecurityStatus
        }
        [pscustomobject]@{ Running = $running; VbsStatus = $vbs }
    } catch {
        $null
    }
}

function Get-ReportOnlyItem {
    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    $runtime = Get-DeviceGuardRuntime

    $vbsText = 'unknown'
    $cgText = 'unknown'
    $hvciText = 'unknown'
    if ($null -ne $runtime) {
        $vbsText = switch ($runtime.VbsStatus) { 0 { 'off' } 1 { 'enabled but not running' } 2 { 'running' } default { 'unknown' } }
        $cgText = if (@($runtime.Running) -contains 1) { 'running' } else { 'not running' }
        $hvciText = if (@($runtime.Running) -contains 2) { 'running' } else { 'not running' }
    }
    $rows.Add([pscustomobject]@{ Category = 'Report'; Setting = 'VbsRunning'; CurrentValue = $vbsText })
    $rows.Add([pscustomobject]@{ Category = 'Report'; Setting = 'CredentialGuardRunning'; CurrentValue = $cgText })
    $rows.Add([pscustomobject]@{ Category = 'Report'; Setting = 'MemoryIntegrityRunning'; CurrentValue = $hvciText })

    $secureBoot = 'unknown'
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        $secureBoot = if ($sb) { 'enabled' } else { 'disabled' }
    } catch { $secureBoot = 'unknown' }
    $rows.Add([pscustomobject]@{ Category = 'Report'; Setting = 'SecureBoot'; CurrentValue = $secureBoot })

    $tpmText = 'unknown'
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($null -ne $tpm -and $tpm.PSObject.Properties['TpmPresent']) { $tpmText = if ($tpm.TpmPresent) { 'present' } else { 'absent' } }
    } catch { $tpmText = 'unknown' }
    $rows.Add([pscustomobject]@{ Category = 'Report'; Setting = 'TpmPresent'; CurrentValue = $tpmText })

    foreach ($row in $rows) {
        $row | Add-Member -NotePropertyName RegistryPath -NotePropertyValue '' -Force
        $row | Add-Member -NotePropertyName RequiresAdmin -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName RequiresReboot -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName DesiredValue -NotePropertyValue 'n/a' -Force
        $row | Add-Member -NotePropertyName Action -NotePropertyValue "Report only: $($row.Setting) is $($row.CurrentValue)" -Force
    }
    $rows
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $lockValue = if ($UefiLock) { 1 } else { 2 }
    $lockNote = if ($UefiLock) { 'WITH UEFI lock: registry rollback cannot remove it.' } else { 'Without UEFI lock.' }

    Add-RegistryItem -Items $items -Control (Get-RegistryControl 'RunAsPPL') -Desired $lockValue `
        -Label "Run LSASS as a protected process. $lockNote" -LockedSatisfiesUnlocked:(-not $UefiLock)

    Add-RegistryItem -Items $items -Control (Get-RegistryControl 'UseLogonCredential') -Desired 0 `
        -Label 'Stop WDigest keeping reusable logon credentials in memory.'

    Add-RegistryItem -Items $items -Control (Get-RegistryControl 'LmCompatibilityLevel') -Desired 5 `
        -Label 'Send NTLMv2 only and refuse LM and NTLMv1.'
    Add-RegistryItem -Items $items -Control (Get-RegistryControl 'NoLMHash') -Desired 1 `
        -Label 'Do not store LM password hashes.'

    if ($script:WantCredentialGuard -or $script:WantMemoryIntegrity) {
        $platform = if ($script:WantDmaProtection) { 3 } else { 1 }
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'EnableVirtualizationBasedSecurity') -Desired 1 `
            -Label 'Turn on virtualization-based security.'
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'RequirePlatformSecurityFeatures') -Desired $platform `
            -Label 'Platform requirement (1 Secure Boot, 3 Secure Boot and DMA protection).'
    }
    if ($script:WantMemoryIntegrity) {
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'MemoryIntegrity') -Desired 1 `
            -Label 'Turn on memory integrity (HVCI). Check Windows Security > Core isolation for incompatible drivers first.'
    }
    if ($script:WantCredentialGuard) {
        $cgValue = if ($UefiLock) { 1 } else { 2 }
        $cgNote = if ($UefiLock) { 'WITH UEFI lock: registry rollback cannot remove it.' } else { 'Without UEFI lock. Blocks NTLMv1 and MS-CHAPv2.' }
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'LsaCfgFlags') -Desired $cgValue `
            -Label "Turn on Credential Guard. $cgNote" -LockedSatisfiesUnlocked:(-not $UefiLock)
    }

    foreach ($row in @(Get-ReportOnlyItem)) { $items.Add($row) }
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # A rollback run writes credential-protection-rollback-plan-<ts>.json, which a bare
    # rollback-* wildcard would also match; only the timestamped record is a rollback file. A
    # consumed file (...rollback-<ts>.consumed-<ts>.json) fails the exact pattern on purpose, so
    # repeated rollbacks walk back one run at a time. The timestamp in the name orders them.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'credential-protection-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^credential-protection-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# Returns $null when the entry is acceptable, otherwise a short text saying what is wrong with it.
# An entry is acceptable only when its category, registry path and value name are a row of $Controls
# and its values have the types a restore can act on. Pure: it reads nothing but its arguments.
function Get-RollbackEntryProblem {
    param($Entry, [Parameter(Mandatory = $true)]$Controls)
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($field in 'Category', 'Setting', 'RegistryPath', 'PriorValue', 'AppliedValue') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
    }
    foreach ($field in 'Category', 'Setting', 'RegistryPath') {
        $text = $Entry.PSObject.Properties[$field].Value
        if ($text -isnot [string] -or [string]::IsNullOrWhiteSpace($text)) { return "$field is not a non-empty string" }
    }
    $known = @($Controls | Where-Object {
            $_.Category -eq $Entry.Category -and $_.Path -eq $Entry.RegistryPath -and $_.Name -eq $Entry.Setting
        })
    if ($known.Count -eq 0) {
        return "Category '$($Entry.Category)', registry path '$($Entry.RegistryPath)', value '$($Entry.Setting)' is not a control this script sets"
    }
    $prior = $Entry.PriorValue
    $priorIsText = $prior -is [string] -and $prior -in @('absent', 'unknown')
    $priorIsNumber = ($prior -is [int] -or $prior -is [long]) -and $prior -ge [int]::MinValue -and $prior -le [int]::MaxValue
    $priorOk = $priorIsText -or $priorIsNumber
    if (-not $priorOk) { return "PriorValue '$prior' is not a whole number, 'absent' or 'unknown'" }
    $applied = $Entry.AppliedValue
    $appliedIsText = $applied -is [string] -and $applied -eq 'absent'
    $appliedIsNumber = ($applied -is [int] -or $applied -is [long]) -and $applied -ge [int]::MinValue -and $applied -le [int]::MaxValue
    $appliedOk = $appliedIsText -or $appliedIsNumber
    if (-not $appliedOk) { return "AppliedValue '$applied' is not a whole number or 'absent'" }
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
    if (-not $file) { throw "No credential-protection-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
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
        $problem = Get-RollbackEntryProblem -Entry $entries[$i] -Controls $script:RegistryControls
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    $script:RollbackSourceFile = $file

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $entries) {
        $prior = $entry.PriorValue
        $unreadable = ("$prior" -eq 'unknown')
        $items.Add([pscustomobject]@{
                Category = $entry.Category; Setting = $entry.Setting; RegistryPath = $entry.RegistryPath
                RequiresAdmin = $true; RequiresReboot = $true
                CurrentValue = $entry.AppliedValue; DesiredValue = $prior
                Action = if ($unreadable) { "No change (prior value of $($entry.Setting) was unknown, nothing to restore)" } else { "Restore $($entry.Setting) to '$prior'" }
            })
    }
    $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Report') { return 'ReportOnly' }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess("$($Item.RegistryPath)\$($Item.Setting)", $Item.Action)) { return 'Previewed' }

    try {
        if ("$($Item.DesiredValue)" -eq 'absent') {
            Remove-ItemProperty -Path $Item.RegistryPath -Name $Item.Setting -ErrorAction SilentlyContinue
        } else {
            if (-not (Test-Path -LiteralPath $Item.RegistryPath)) {
                New-Item -Path $Item.RegistryPath -Force | Out-Null
            }
            Set-ItemProperty -Path $Item.RegistryPath -Name $Item.Setting -Value ([int]$Item.DesiredValue) -Type DWord -Force
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; RegistryPath = $Item.RegistryPath
            RequiresReboot = $Item.RequiresReboot
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
$plan = @(if ($Rollback) { Get-RollbackPlan } else { Get-ForwardPlan })

$planPath = Join-Path $resolvedReportDirectory "credential-protection-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "credential-protection-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "credential-protection-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "credential-protection-$mode-state-$timestamp.json"

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
    $rollbackPath = Join-Path $resolvedReportDirectory "credential-protection-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        UefiLock = [bool]$UefiLock
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$changedRequiringReboot = @($script:ChangedSettings | Where-Object { $_.RequiresReboot })

[pscustomobject]@{
    Operation = "WindowsCredentialProtection ($mode)"
    IsElevated = (Test-IsAdministrator)
    UefiLock = [bool]$UefiLock
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    RebootRequired = ($changedRequiringReboot.Count -gt 0)
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    Items = @($state)
}
