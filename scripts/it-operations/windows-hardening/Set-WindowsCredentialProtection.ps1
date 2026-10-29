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
- Use -Rollback to restore the exact prior values from the latest rollback file in the report
  directory. A value that was absent before is removed again.
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

function Add-RegistryItem {
    param(
        [Parameter(Mandatory = $true)]$Items,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Desired,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$LockedSatisfiesUnlocked
    )
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

    Add-RegistryItem -Items $items -Category 'LsaProtection' -Path $script:LsaPath -Name 'RunAsPPL' -Desired $lockValue `
        -Label "Run LSASS as a protected process. $lockNote" -LockedSatisfiesUnlocked:(-not $UefiLock)

    Add-RegistryItem -Items $items -Category 'WDigest' -Path $script:WDigestPath -Name 'UseLogonCredential' -Desired 0 `
        -Label 'Stop WDigest keeping reusable logon credentials in memory.'

    Add-RegistryItem -Items $items -Category 'Ntlm' -Path $script:LsaPath -Name 'LmCompatibilityLevel' -Desired 5 `
        -Label 'Send NTLMv2 only and refuse LM and NTLMv1.'
    Add-RegistryItem -Items $items -Category 'Ntlm' -Path $script:LsaPath -Name 'NoLMHash' -Desired 1 `
        -Label 'Do not store LM password hashes.'

    if ($script:WantCredentialGuard -or $script:WantMemoryIntegrity) {
        $platform = if ($script:WantDmaProtection) { 3 } else { 1 }
        Add-RegistryItem -Items $items -Category 'Vbs' -Path $script:DeviceGuardPath -Name 'EnableVirtualizationBasedSecurity' -Desired 1 `
            -Label 'Turn on virtualization-based security.'
        Add-RegistryItem -Items $items -Category 'Vbs' -Path $script:DeviceGuardPath -Name 'RequirePlatformSecurityFeatures' -Desired $platform `
            -Label 'Platform requirement (1 Secure Boot, 3 Secure Boot and DMA protection).'
    }
    if ($script:WantMemoryIntegrity) {
        Add-RegistryItem -Items $items -Category 'MemoryIntegrity' -Path $script:HvciPath -Name 'Enabled' -Desired 1 `
            -Label 'Turn on memory integrity (HVCI). Check Windows Security > Core isolation for incompatible drivers first.'
    }
    if ($script:WantCredentialGuard) {
        $cgValue = if ($UefiLock) { 1 } else { 2 }
        $cgNote = if ($UefiLock) { 'WITH UEFI lock: registry rollback cannot remove it.' } else { 'Without UEFI lock. Blocks NTLMv1 and MS-CHAPv2.' }
        Add-RegistryItem -Items $items -Category 'CredentialGuard' -Path $script:LsaPath -Name 'LsaCfgFlags' -Desired $cgValue `
            -Label "Turn on Credential Guard. $cgNote" -LockedSatisfiesUnlocked:(-not $UefiLock)
    }

    foreach ($row in @(Get-ReportOnlyItem)) { $items.Add($row) }
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # A rollback run writes credential-protection-rollback-plan-<ts>.json, which a bare
    # rollback-* wildcard would also match; only the timestamped record is a rollback file.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'credential-protection-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^credential-protection-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No credential-protection-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
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
    RebootRequired = ($changedRequiringReboot.Count -gt 0)
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    Items = @($state)
}
