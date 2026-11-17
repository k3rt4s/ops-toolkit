<#
.SYNOPSIS
Plan, apply, and roll back local credential-protection registry settings on a physical or VDI Windows 11 machine, standalone or joined, and list the modules LSA protection would stop loading.

.DESCRIPTION
- A live run (no -WhatIf) prompts before each change unless -Confirm:$false is passed; answer Yes to All
  to accept the rest. Unelevated, a live run changes nothing and marks each admin item 'Skipped: requires
  elevation'. Unelevated -WhatIf previews each admin item whose current value could be read and marks the
  rest 'Skipped: requires elevation (not read)'.
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
Raises the cost of stealing credentials from memory on a physical or VDI machine, standalone or
joined, using local registry values only (this script sets no Group Policy and no Active Directory
object).

LSA protection preflight (a report, never a blocker):
- On every apply run, including -WhatIf, the script first lists the modules that LSA protection
  (RunAsPPL) would stop loading into lsass, so the cause of events 3033 and 3063 is known before the
  restart. It reads the LSA package lists under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
  (Authentication Packages, Notification Packages, Security Packages) and the Security Packages value
  under Lsa\OSConfig, plus the Winsock name-space providers (for example Bonjour's mdnsNSP.dll is
  one), resolves each to a file and checks its Authenticode signature.
- A module is listed unless it is validly signed by Microsoft. The listed modules WILL STOP LOADING
  once LSA protection is on and the machine restarts; the script does not refuse to enable it.
  Third-party signed, unsigned and badly signed modules are listed with the reason.
- A module that cannot be resolved to a file or whose signature cannot be read is listed as
  Unread, never as safe. A source that cannot be read at all is also an Unread row.
- The report is credential-protection-lsa-preflight-<timestamp>.csv and .json in the report
  directory, and the summary carries LsaPreflightCsvPath, LsaPreflightJsonPath,
  LsaPreflightModuleCount, LsaPreflightListedCount (includes Unread) and LsaPreflightUnreadCount.
  -Rollback does not run it.
- Which registry values and which Winsock catalog really feed lsass has not been proven on a real
  host (see the comments at Get-LsaProtectionPreflight); treat an empty report as "nothing found in
  these sources", not as "nothing will be blocked".

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
- Credential Guard needs an Enterprise or Education edition. -EnableCredentialGuard reads EditionID
  from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion and applies the Credential Guard items
  (LsaCfgFlags, and the virtualization-based security rows when only Credential Guard needs them)
  only for Enterprise, EnterpriseN, EnterpriseS, EnterpriseSN, Education or EducationN. On any other
  edition (Windows 11 Pro is not licensed for it: Credential Guard then fails to start after the
  restart, LsaSrv event 6147) those rows end "Skipped" with a reason naming the edition and the
  licensing requirement, and the summary lists the reason. An EditionID that cannot be read ends
  "Failed", never as a pass. A row whose value is already in place stays "No change".
- Secure Boot guard: -EnableCredentialGuard and -EnableMemoryIntegrity write
  RequirePlatformSecurityFeatures (1 or 3), which tells Windows to refuse to start virtualization-
  based security without Secure Boot. On a machine where Secure Boot is off that would likely stop
  VBS and memory integrity at the next boot. Secure Boot is read with Confirm-SecureBootUEFI; unless
  it reads True (unsupported, legacy BIOS, unelevated or throwing all count as not confirmed) that one
  row ends "Skipped" with the reason. The other VBS and memory integrity rows still plan as before.
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
Writes credential-protection plan and state CSV/JSON under the report directory, an LSA protection
preflight CSV/JSON (apply runs only), plus a rollback JSON capturing the prior value of every
setting changed. The summary object carries RebootRequired and the LsaPreflight* counts.

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

# Editions licensed for Credential Guard (Microsoft Learn: Enterprise and Education, with N and
# LTSC variants). Anything else, Windows 11 Pro included, is not.
$script:CredentialGuardEditions = @('Enterprise', 'EnterpriseN', 'EnterpriseS', 'EnterpriseSN', 'Education', 'EducationN')

# Returns $null when Credential Guard may be applied, otherwise the result text for the item
# ('Failed: ...' for an unreadable edition, 'Skipped: ...' for an unlicensed one).
function Get-CredentialGuardEditionBlock {
    $edition = Get-RegistryState -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID'
    if ($edition -isnot [string] -or $edition -in @('absent', 'unknown') -or [string]::IsNullOrWhiteSpace($edition)) {
        return 'Failed: Windows edition could not be read (EditionID), so Credential Guard licensing cannot be confirmed; it requires an Enterprise or Education edition.'
    }
    if ($edition -notin $script:CredentialGuardEditions) {
        return "Skipped: Windows edition '$edition' is not licensed for Credential Guard, which requires an Enterprise or Education edition."
    }
    $null
}

# Returns 'True', 'False' or 'unknown'. A throw or a non-boolean answer is unknown, never True.
function Get-SecureBootState {
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb -is [bool]) { return "$sb" }
        'unknown'
    } catch { 'unknown' }
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
        [switch]$LockedSatisfiesUnlocked,
        [string]$Precondition = ''
    )
    $Category = $Control.Category
    $Path = $Control.Path
    $Name = $Control.Name
    $current = Get-RegistryState -Path $Path -Name $Name
    $meets = Test-MeetsTarget -Current $current -Desired $Desired -LockedSatisfiesUnlocked:$LockedSatisfiesUnlocked
    # A precondition only matters for a row that would write; a value already in place stays No change.
    $blocked = (-not $meets) -and $Precondition
    $Items.Add([pscustomobject]@{
            Category = $Category; Setting = $Name; RegistryPath = $Path
            RequiresAdmin = $true; RequiresReboot = $true
            CurrentValue = $current; DesiredValue = $Desired
            Action = if ($meets) { "No change ($Name already $current)" } elseif ($blocked) { "Not applied ($Name = $Desired): $($Precondition -replace '^(Skipped|Failed): ', '')" } else { "Set $Name = $Desired. $Label" }
            Precondition = if ($blocked) { $Precondition } else { '' }
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

    $secureBoot = switch (Get-SecureBootState) { 'True' { 'enabled' } 'False' { 'disabled' } default { 'unknown' } }
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

    # Credential Guard needs a licensed edition. An unlicensed or unreadable edition blocks its rows
    # and stops it counting as a reason to plan the VBS prerequisites.
    $cgBlock = $null
    $cgActive = $script:WantCredentialGuard
    if ($script:WantCredentialGuard) {
        $cgBlock = Get-CredentialGuardEditionBlock
        if ($cgBlock) { $cgActive = $false }
    }

    if ($cgActive -or $script:WantMemoryIntegrity) {
        $platform = if ($script:WantDmaProtection) { 3 } else { 1 }
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'EnableVirtualizationBasedSecurity') -Desired 1 `
            -Label 'Turn on virtualization-based security.'
        # RequirePlatformSecurityFeatures makes Windows refuse to start VBS without Secure Boot, so it
        # is written only when Secure Boot is confirmed on.
        $sbPrecondition = ''
        if ((Get-SecureBootState) -ne 'True') {
            $sbPrecondition = 'Skipped: Secure Boot is not confirmed on (off, unsupported or unreadable); requiring it would likely stop virtualization-based security and memory integrity at the next boot.'
        }
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'RequirePlatformSecurityFeatures') -Desired $platform `
            -Label 'Platform requirement (1 Secure Boot, 3 Secure Boot and DMA protection).' -Precondition $sbPrecondition
    }
    if ($script:WantMemoryIntegrity) {
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'MemoryIntegrity') -Desired 1 `
            -Label 'Turn on memory integrity (HVCI). Check Windows Security > Core isolation for incompatible drivers first.'
    }
    if ($script:WantCredentialGuard) {
        $cgValue = if ($UefiLock) { 1 } else { 2 }
        $cgNote = if ($UefiLock) { 'WITH UEFI lock: registry rollback cannot remove it.' } else { 'Without UEFI lock. Blocks NTLMv1 and MS-CHAPv2.' }
        Add-RegistryItem -Items $items -Control (Get-RegistryControl 'LsaCfgFlags') -Desired $cgValue `
            -Label "Turn on Credential Guard. $cgNote" -LockedSatisfiesUnlocked:(-not $UefiLock) `
            -Precondition ([string]$cgBlock)
    }

    foreach ($row in @(Get-ReportOnlyItem)) { $items.Add($row) }
    $items
}

# LSA protection preflight. Read-only. Lists the modules LSA protection (RunAsPPL) would stop
# loading into lsass so the operator sees the cause of events 3033 and 3063 before the restart.
#
# UNVERIFIED ON A REAL HOST (the script has never run on one, hard-elevated-run); these are the
# assumptions behind the candidate list, each to be confirmed against a machine that really logs
# 3033/3063 for a known module:
# - That the three LSA package values (Authentication Packages, Notification Packages, Security
#   Packages) under the Lsa key and the Security Packages value under Lsa\OSConfig are the registry
#   lists lsass loads packages from, and that a bare name (msv1_0) means <System32>\<name>.dll.
# - That the Winsock name-space provider catalog is NameSpace_Catalog5\Catalog_Entries64 (native) and
#   Catalog_Entries (32-bit) under Services\Winsock2\Parameters, with the DLL in each entry's
#   LibraryPath, and that lsass loads those providers (the Bonjour mdnsNSP.dll case on a real laptop
#   says it does; which lsass code path loads it is not established).
# - That a third-party signature is not enough: LSA plug-ins must carry a Microsoft signature, so a
#   validly third-party-signed module is listed. A module also cosigned by Microsoft (WHQL) is
#   treated as Microsoft only when its signer certificate subject and issuer both name Microsoft
#   Corporation; whether that matches the loader's own signing-level check is not established.
# - That Get-AuthenticodeSignature, which also consults catalog signatures, reports the Microsoft
#   signer for in-box catalog-signed DLLs.
# - Packages and providers loaded some other way (a Security Support Provider added by API at run
#   time, Smart Card or credential provider DLLs, plug-ins named by other keys) are not enumerated,
#   so an empty or short report is not proof that nothing will be blocked.
#
# The seams a test replaces are Get-ItemProperty, Get-ChildItem, Test-Path and
# Get-AuthenticodeSignature (functions shadowing the cmdlets), the same way the other tests shadow
# registry reads.

# Registry sources of LSA package names. Source is the label reported on each row.
$script:LsaPackageSources = @(
    [pscustomobject]@{ Source = 'Lsa\Authentication Packages'; Path = $script:LsaPath; Name = 'Authentication Packages' }
    [pscustomobject]@{ Source = 'Lsa\Notification Packages'; Path = $script:LsaPath; Name = 'Notification Packages' }
    [pscustomobject]@{ Source = 'Lsa\Security Packages'; Path = $script:LsaPath; Name = 'Security Packages' }
    [pscustomobject]@{ Source = 'Lsa\OSConfig\Security Packages'; Path = "$($script:LsaPath)\OSConfig"; Name = 'Security Packages' }
)
$script:WinsockNamespaceParents = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries64'
    'HKLM:\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries'
)

# Reads one registry value as a list of non-blank strings. Status is Read, Absent (key or value
# missing) or Unreadable. Values is always a string array, empty when nothing is there, and is
# returned inside an object so an empty list cannot unroll to $null (@($null) has Count 1).
function Get-LsaRegistryStringList {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $values = [System.Collections.Generic.List[string]]::new()
    try {
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    } catch {
        $missing = -not (Test-Path -LiteralPath $Path)
        return [pscustomobject]@{ Status = $(if ($missing) { 'Absent' } else { 'Unreadable' }); Values = $values.ToArray() }
    }
    if ($null -eq $props -or -not $props.PSObject.Properties[$Name]) {
        return [pscustomobject]@{ Status = 'Absent'; Values = $values.ToArray() }
    }
    $raw = $props.PSObject.Properties[$Name].Value
    if ($null -eq $raw) {
        return [pscustomobject]@{ Status = 'Unreadable'; Values = $values.ToArray() }
    }
    foreach ($item in @($raw)) {
        if ($null -eq $item) { continue }
        $text = ([string]$item).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) { $values.Add($text) }
    }
    [pscustomobject]@{ Status = 'Read'; Values = $values.ToArray() }
}

# Turns a registered module name into a file path, or $null when the entry is blank. Environment
# variables are expanded; a name with no directory is looked up in the system directory and gets
# .dll when it has no extension (the LSA package lists hold bare names such as msv1_0).
function Resolve-LsaModulePath {
    param(
        [AllowNull()][AllowEmptyString()][string]$Entry,
        [string]$SystemDirectory = (Join-Path $(if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }) 'System32')
    )
    if ([string]::IsNullOrWhiteSpace($Entry)) { return $null }
    $text = [Environment]::ExpandEnvironmentVariables($Entry.Trim()).Trim('"')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    if ([System.IO.Path]::GetExtension($text) -eq '') { $text = "$text.dll" }
    if (-not [System.IO.Path]::IsPathRooted($text)) { $text = Join-Path $SystemDirectory $text }
    $text
}

# Returns Verdict (Microsoft, ThirdParty, Unsigned, InvalidSignature or Unread), Signer and Detail.
# Only Microsoft is not listed. Anything that could not be checked is Unread, never Microsoft.
function Get-LsaModuleVerdict {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Verdict = 'Unread'; Signer = ''; Detail = 'file not found, so its signature could not be checked' }
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Verdict = 'Unread'; Signer = ''; Detail = "signature could not be read: $($_.Exception.Message)" }
    }
    if ($null -eq $sig -or -not $sig.PSObject.Properties['Status']) {
        return [pscustomobject]@{ Verdict = 'Unread'; Signer = ''; Detail = 'signature check returned nothing' }
    }
    $status = [string]$sig.Status
    $subject = ''
    $issuer = ''
    if ($sig.PSObject.Properties['SignerCertificate'] -and $null -ne $sig.SignerCertificate) {
        $cert = $sig.SignerCertificate
        if ($cert.PSObject.Properties['Subject'] -and $null -ne $cert.Subject) { $subject = [string]$cert.Subject }
        if ($cert.PSObject.Properties['Issuer'] -and $null -ne $cert.Issuer) { $issuer = [string]$cert.Issuer }
    }
    $microsoft = '(^|,\s*)O=Microsoft Corporation(,|$)'
    switch ($status) {
        'Valid' {
            if ($subject -match $microsoft -and $issuer -match $microsoft) {
                return [pscustomobject]@{ Verdict = 'Microsoft'; Signer = $subject; Detail = 'valid Microsoft signature' }
            }
            return [pscustomobject]@{ Verdict = 'ThirdParty'; Signer = $subject; Detail = 'valid signature, but the signer is not Microsoft' }
        }
        'NotSigned' { return [pscustomobject]@{ Verdict = 'Unsigned'; Signer = ''; Detail = 'no Authenticode signature' } }
        { $_ -in 'HashMismatch', 'NotTrusted', 'Incompatible', 'NotSupportedFileFormat' } {
            return [pscustomobject]@{ Verdict = 'InvalidSignature'; Signer = $subject; Detail = "signature status $status" }
        }
        default {
            return [pscustomobject]@{ Verdict = 'Unread'; Signer = $subject; Detail = "signature status $status could not be judged" }
        }
    }
}

function ConvertTo-LsaPreflightRow {
    param([string]$Source, [string]$Entry, [string]$ResolvedPath, [string]$Verdict, [string]$Signer, [string]$Detail)
    [pscustomobject]@{
        Source = $Source; Entry = $Entry; ResolvedPath = $ResolvedPath
        Verdict = $Verdict; Signer = $Signer
        Listed = ($Verdict -ne 'Microsoft')
        Unread = ($Verdict -eq 'Unread')
        Detail = $Detail
    }
}

# Returns one row per candidate module. Pure reads; never throws for a missing or unreadable source.
function Get-LsaProtectionPreflight {
    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    $verdicts = @{}
    $judge = {
        param([string]$Source, [string]$Entry)
        $path = Resolve-LsaModulePath -Entry $Entry
        if ($null -eq $path) { return }
        $key = $path.ToLowerInvariant()
        if (-not $verdicts.ContainsKey($key)) { $verdicts[$key] = Get-LsaModuleVerdict -Path $path }
        $v = $verdicts[$key]
        $rows.Add((ConvertTo-LsaPreflightRow -Source $Source -Entry $Entry -ResolvedPath $path -Verdict $v.Verdict -Signer $v.Signer -Detail $v.Detail))
    }

    foreach ($src in $script:LsaPackageSources) {
        $list = Get-LsaRegistryStringList -Path $src.Path -Name $src.Name
        if ($list.Status -eq 'Unreadable') {
            $rows.Add((ConvertTo-LsaPreflightRow -Source $src.Source -Entry '(whole list)' -ResolvedPath '' -Verdict 'Unread' -Signer '' -Detail "$($src.Name) under $($src.Path) exists but could not be read"))
            continue
        }
        foreach ($entry in $list.Values) { & $judge $src.Source $entry }
    }

    $catalogRead = 0
    foreach ($parent in $script:WinsockNamespaceParents) {
        try {
            $children = @(Get-ChildItem -LiteralPath $parent -ErrorAction Stop)
        } catch {
            if (Test-Path -LiteralPath $parent) {
                $rows.Add((ConvertTo-LsaPreflightRow -Source 'Winsock namespace providers' -Entry $parent -ResolvedPath '' -Verdict 'Unread' -Signer '' -Detail 'the catalog key exists but could not be enumerated'))
                $catalogRead++
            }
            continue
        }
        $catalogRead++
        foreach ($child in $children) {
            $childPath = "$parent\$($child.PSChildName)"
            $lib = Get-LsaRegistryStringList -Path $childPath -Name 'LibraryPath'
            if ($lib.Status -ne 'Read' -or $lib.Values.Count -eq 0) {
                $rows.Add((ConvertTo-LsaPreflightRow -Source 'Winsock namespace providers' -Entry $childPath -ResolvedPath '' -Verdict 'Unread' -Signer '' -Detail "provider entry has no readable LibraryPath ($($lib.Status))"))
                continue
            }
            & $judge 'Winsock namespace providers' $lib.Values[0]
        }
    }
    if ($catalogRead -eq 0) {
        $rows.Add((ConvertTo-LsaPreflightRow -Source 'Winsock namespace providers' -Entry ($script:WinsockNamespaceParents -join '; ') -ResolvedPath '' -Verdict 'Unread' -Signer '' -Detail 'the Winsock name-space catalog was not found, so name-service providers could not be listed'))
    }
    $rows
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

# True when the plan could not read the item's current value, the same test Test-WindowsHardeningState.ps1
# uses to count an item Unread: an Action that starts Unreadable, Cannot assess or Skipped, or a current value of
# unknown or unreadable (alone or after = or ;).
function Test-PlanItemUnread {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ("$($Item.Action)" -match '^(Unreadable|Cannot assess|Skipped)') { return $true }
    if ("$($Item.CurrentValue)" -match '(^|[=;])\s*(unknown|unreadable)\b') { return $true }
    $false
}

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Report') { return 'ReportOnly' }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.PSObject.Properties['Precondition'] -and -not [string]::IsNullOrEmpty([string]$Item.Precondition)) { return [string]$Item.Precondition }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) {
        # A live run changes nothing and says so. Under -WhatIf only, an item whose current value was read goes on
        # to ShouldProcess so its "What if:" line prints; one whose value was not read stays a skip.
        if (-not $WhatIfPreference) { return 'Skipped: requires elevation' }
        if (Test-PlanItemUnread -Item $Item) { return 'Skipped: requires elevation (not read)' }
    }
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

# LSA protection preflight: a report, never a gate. It runs before any change, also under -WhatIf,
# and a failure to build it is recorded and warned about, never allowed to stop the apply.
$preflight = @()
$preflightCsvPath = $null
$preflightJsonPath = $null
$preflightError = $null
$preflightNote = $null
if (-not $Rollback) {
    try {
        $preflight = @(Get-LsaProtectionPreflight)
        $preflightCsvPath = Join-Path $resolvedReportDirectory "credential-protection-lsa-preflight-$timestamp.csv"
        $preflightJsonPath = Join-Path $resolvedReportDirectory "credential-protection-lsa-preflight-$timestamp.json"
        $preflight | Export-Csv -Path $preflightCsvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
        if (-not (Test-Path -LiteralPath $preflightCsvPath) -or (Get-Item -LiteralPath $preflightCsvPath).Length -eq 0) {
            # Export-Csv writes no file, or an empty one, for an empty list; an empty report still has its header.
            Set-Content -LiteralPath $preflightCsvPath -Value '"Source","Entry","ResolvedPath","Verdict","Signer","Listed","Unread","Detail"' -Encoding utf8 -WhatIf:$false
        }
        $preflightJson = if ($preflight.Count) { ConvertTo-Json -InputObject @($preflight) -Depth 4 } else { '[]' }
        Set-Content -LiteralPath $preflightJsonPath -Value $preflightJson -Encoding utf8 -WhatIf:$false
        $listedNow = @($preflight | Where-Object { $_.Listed })
        $ppl = @($plan | Where-Object { $_.Setting -eq 'RunAsPPL' })
        if ($ppl.Count -gt 0 -and "$($ppl[0].Action)" -like 'No change*') {
            $preflightNote = 'LSA protection is already set, so the listed modules are blocked as soon as it is running; this run changes nothing about them.'
        } elseif ($listedNow.Count -gt 0) {
            $preflightNote = "$($listedNow.Count) module(s) will stop loading into lsass once LSA protection is on and the machine restarts (including $(@($listedNow | Where-Object { $_.Unread }).Count) that could not be read). See $preflightCsvPath."
        } else {
            $preflightNote = 'No module outside Microsoft-signed ones was found in the sources read; see the limits in the script help.'
        }
        if ($listedNow.Count -gt 0) { Write-Warning $preflightNote }
    } catch {
        $preflightError = "LSA protection preflight failed: $($_.Exception.Message)"
        $preflightCsvPath = $null
        $preflightJsonPath = $null
        Write-Warning $preflightError
    }
}

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
    LsaPreflightCsvPath = $preflightCsvPath
    LsaPreflightJsonPath = $preflightJsonPath
    LsaPreflightModuleCount = @($preflight).Count
    LsaPreflightListedCount = @($preflight | Where-Object { $_.Listed }).Count
    LsaPreflightUnreadCount = @($preflight | Where-Object { $_.Unread }).Count
    LsaPreflightNote = $preflightNote
    LsaPreflightError = $preflightError
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    RebootRequired = ($changedRequiringReboot.Count -gt 0)
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    PreconditionNotes = @($state | Where-Object { $_.PSObject.Properties['Precondition'] -and $_.Precondition } |
            ForEach-Object { "$($_.Setting): $($_.Precondition)" })
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    Items = @($state)
}
