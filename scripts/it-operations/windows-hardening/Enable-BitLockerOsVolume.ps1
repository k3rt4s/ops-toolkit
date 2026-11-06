<#
.SYNOPSIS
Plan, apply, and roll back BitLocker encryption of the operating-system volume with a TPM protector, saving a recovery password to a directory the operator names before encryption starts.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON. The plan lists every
  precondition and the ordered steps.
- Where the recovery key goes is decided before anything changes, in this order: -RecoveryKeyDirectory
  when given (it always wins; a Folder value in the organisation settings is then ignored and the
  summary says so); otherwise the BitLockerKeyBackup section of the organisation settings
  (Get-OpsOrgSettings, %ProgramData%\OpsToolkit\settings.json): Folder (the same directory rules
  below), EntraId (BackupToAAD-BitLockerKeyProtector, needs an Entra joined or hybrid joined host
  as read by Get-OpsHostContext) or ActiveDirectory (Backup-BitLockerKeyProtector, needs a domain
  joined host). When no destination is usable the run is refused: the plan carries a
  'Key backup: not configured' precondition, nothing is changed and a live run exits non-zero.
  Encryption is never started unless this run's key backup succeeded: a failed Entra ID or
  Active Directory backup removes the just-added recovery protector, exactly as a failed key file
  write or read-back does, and stops without enabling. Reports record where the key went
  (destination, folder path or 'Entra ID'/'Active Directory', protector ID), never the key. The
  cmdlet names, their parameters and the join facts are unverified on a live machine.
- A -RecoveryKeyDirectory (or a settings Folder) must be a directory that already exists on a volume
  OTHER than the operating-system volume, for example a removable drive or a network share
  you can reach when this machine will not boot. The script refuses, and changes nothing, if
  the directory is missing, is on the operating-system volume ($env:SystemDrive), or cannot be
  written to (a probe file is written and deleted on a live run only). A substituted drive
  (subst) or a mapped drive is followed to its real target, and a UNC path whose host is this
  computer (localhost, 127.0.0.1, ::1, the computer name, or a \\. or \\? device path) is
  refused, as is any drive the script cannot look up.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  workstation must never be applied to someone else's machine. Generated reports belong under a
  data root outside the repo.
- Windows automatic device encryption may already have encrypted the volume on its own, with a TPM
  protector and a recovery password. When the volume is EncryptionInProgress, EncryptionPaused or
  FullyEncrypted and already carries a RecoveryPassword protector, this script adds no second one and does not enable
  anything. It plans one BackupRecoveryProtector row per existing recovery password protector,
  and a live run writes each to the same kind of key file under -RecoveryKeyDirectory (same off-the-
  OS-volume rules and write probe, behind ShouldProcess; a key file that already holds that
  protector's password is NoChange, one that does not is a failure). The summary reports the
  volume's VolumeStatus and ProtectionStatus. The backup file holds the password in clear text, like
  the one written on an enable. The backup is not recorded in a rollback file: -Rollback never
  deletes it or decrypts a volume this script did not enable.
- An already-protected volume that has no RecoveryPassword protector (for example a TPM-only
  protector) gets no backup row and no new protector. The plan carries a report-only row saying
  there is no recovery password to back up, so a no-change run is not mistaken for a backed-up one.
- Secure Boot: firmware that shows Secure Boot as on can still make Confirm-SecureBootUEFI read
  False while it is in Setup Mode with no Platform Key (PK), until the factory keys are restored in
  firmware setup. The Secure Boot precondition then stops the run, correctly: it is reading the
  state the firmware is actually in.
- Run elevated. A non-elevated live run stops on the elevation precondition ('Failed: session is not
  elevated'), changes nothing and exits non-zero; under -WhatIf it is 'Skipped: requires elevation'
  and exits 0.
- Preconditions, each a plan item, and any failure stops the run before anything changes: the
  session is elevated, the TPM is present and ready (Get-Tpm), Secure Boot is on
  (Confirm-SecureBootUEFI; unreadable is a stop with the reason, never a pass), and the volume
  is not already protected. A volume that is already encrypted or encrypting, or that carries a
  TPM protector from an enable still waiting on its hardware-test restart, is NoChange for the
  whole run and exits 0. Not elevated, the TPM and Secure Boot rows, and a volume row whose read
  failed, are 'Skipped: requires elevation (not read)'.
- Order on a live run, and the ordering is the safety: add a recovery password key protector;
  write the recovery password, protector ID, computer name and date to
  <RecoveryKeyDirectory>\BitLocker-Recovery-<computer>-<protectorId>.txt; read that file back and
  confirm it holds the password; only then enable BitLocker with a TPM protector, XTS-AES 256
  and used-space-only encryption. If the write or the read-back fails the script removes the
  recovery protector it just added and stops without enabling anything.
- The recovery password is never written to the plan, state, summary, rollback JSON or console.
  Reports hold only the protector ID and the key file path; the rollback JSON holds the protector
  ID but no key file path. The key file itself holds the
  password in clear text: move it off the machine to a password manager or sealed storage, and
  restrict who can read the directory.
- Enable-BitLocker without -SkipHardwareTest runs a hardware test at the next restart, and
  encryption begins after it. Restart when convenient; the summary reports RebootRequired.
- -Rollback runs Disable-BitLocker on the volume recorded in the newest unconsumed rollback file
  (newest by name), and only if that file shows this script enabled it. Decryption takes hours,
  proportional to disk size, and is not a quick undo. Keep the recovery key file until decryption
  completes.
- Rollback can only decrypt the operating-system volume this script enables. Before any plan is
  written or any change made, the whole file is checked and refused, also under -WhatIf, with an
  error naming the file and the first bad entry (or the top-level fields), when the JSON does not
  parse, ChangedSettings is missing, not an array or empty, a record carries any field this script
  does not write (so a key file path, an added protector or a second volume cannot be smuggled
  in), MountPoint is not the operating-system volume ($env:SystemDrive), ProtectorId is not a
  GUID, ScriptEnabledBitLocker is not true, EncryptionMethod is not XtsAes256, or a value is not
  a string or a boolean as recorded. The rollback only ever calls Disable-BitLocker on that one
  volume; it never adds a protector and never reads or writes a key file. Move a refused file
  aside (out of the report directory) to roll back an older run. After an executing -Rollback
  that completed, the file is renamed bitlocker-enable-rollback-<timestamp>.consumed-<timestamp>.json
  and is no longer picked; under -WhatIf, or when the step failed or was skipped, it is left in
  place and the summary says so.
- A volume that is mid-decryption (VolumeStatus DecryptionInProgress or DecryptionPaused) is its
  own case: the script reports that state, plans no enable and no policy write, and stops with
  nothing changed ('Failed: OS volume is being decrypted ...' on the OsVolumeNotProtected row; a live
  run exits non-zero, -WhatIf exits 0, like every other failed precondition). The TPM, Secure Boot
  and key-directory rows are 'Skipped: not evaluated'. There is no override switch: wait for the
  decryption to finish, or resume or finish it deliberately, then run this script again.
- -UseTpmAndPin (opt-in, with -StartupPin <SecureString>, both required together) protects the
  volume with a TPM plus a pre-boot PIN instead of a TPM alone, which is the stronger posture
  because a TPM-only volume unlocks for anyone who can boot the machine. Without the switch the
  script behaves exactly as before. The PIN is a SecureString only: a plain-text PIN is not
  accepted, and a PIN is never written to a plan, state, summary, rollback or key file, the
  console or an error message. It is read once to check the rules (numeric digits 0-9 only, 6 to
  20 of them; the enhanced-PIN policy is not planned, so letters and symbols are refused) and
  then handed to Enable-BitLocker as the SecureString. A PIN that breaks the rules stops the run
  with nothing changed and a message that does not repeat it. Build the SecureString yourself
  (Read-Host -AsSecureString) so it is never typed into a command line or a saved script.
  With the switch the plan also carries:
  - A NotVirtualMachine precondition. The script refuses a virtual machine (Win32_ComputerSystem
    Model or Manufacturer naming Hyper-V 'Virtual Machine', VMware, VirtualBox, KVM or QEMU, Xen,
    Parallels, Bochs, Amazon EC2, Google Compute Engine, OpenStack, Alibaba Cloud or Nutanix AHV)
    because nobody can type a PIN at boot on a host such as an Azure Virtual Desktop session host,
    and the host would never start. If the model cannot be read the run also stops: undetermined
    is never a pass. The refusal is a recorded 'Failed:' precondition, so a live run exits
    non-zero after writing its reports and -WhatIf exits 0.
  - A StartupPin precondition that checks the PIN rules above without recording the value.
  - Six FvePolicy rows writing the startup-authentication policy under
    HKLM\SOFTWARE\Policies\Microsoft\FVE, applied before the enable because Enable-BitLocker
    refuses a PIN protector until the policy allows one: UseAdvancedStartup 1, EnableBDEWithNoTPM 0,
    UseTPM 0 (no TPM-only), UseTPMPIN 1 (require a startup PIN), UseTPMKey 0, UseTPMKeyPIN 0.
    A value that already equals the target is NoChange. The key is created only when it is missing,
    so an existing policy key and its other values are never replaced. The value names and codes
    follow the BitLocker group policy settings reference, 'Require additional authentication at
    startup' (https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings).
    The exact names and numbers (in particular that 0 is Do not allow and 1 is Require) have NOT been
    verified on a live machine in this build; confirm them on a test machine before relying on them.
  - The prior value of each policy value ('absent', a number, or 'unknown' when it could not be read)
    goes in the rollback file as a record with only Category 'FvePolicy', Name and PriorValue; no
    registry path is recorded. -Rollback validates those records against the same value table, then
    restores each prior value (removes a value that was absent) after the decryption step. An
    'unknown' prior is NoChange with a note, because it cannot be restored. If the enable fails or
    is declined after policy values were written, the script restores them at once.
  - The hardware test after the enable asks for the PIN at the next restart: restart only when
    someone who knows the PIN is at the machine.
  - A volume that is already protected is not converted: with -UseTpmAndPin the plan carries a
    report-only row saying so, and no PIN, policy or protector change is made.

Purpose:
Without BitLocker, physical access to the machine or its drive gives full access to the data
whatever the account controls say. This enables it on the operating-system volume in the one
order that cannot leave the machine encrypted with a recovery key that exists nowhere else.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -RecoveryKeyDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -RecoveryKeyDirectory <dir>      # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -WhatIf                          # key destination from the organisation settings
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -Rollback -WhatIf
pwsh -NoProfile -Command "& '.\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1' -ReportDirectory <dir> -RecoveryKeyDirectory <dir> -UseTpmAndPin -StartupPin (Read-Host 'Startup PIN' -AsSecureString) -WhatIf"

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, plus on a live run that enabled
BitLocker a rollback JSON holding the volume and protector ID (never the password, the PIN or a key
file path) and, with -UseTpmAndPin, the prior value of each FVE policy value it wrote. Returns a
summary object.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Export-BitLockerEscrowStatus.ps1, which
reports whether a recovery key exists after this has run.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Enable')]
param(
    [Parameter(ParameterSetName = 'Enable')]
    [Parameter(ParameterSetName = 'EnableTpmPin')]
    [ValidateNotNullOrEmpty()]
    [string]$RecoveryKeyDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'EnableTpmPin')]
    [switch]$UseTpmAndPin,

    [Parameter(Mandatory = $true, ParameterSetName = 'EnableTpmPin')]
    [System.Security.SecureString]$StartupPin,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Hardening') -Force

$script:Prefix = 'bitlocker-enable'
# Where this run's recovery key goes: set once in Main (Resolve-KeyBackupDestination), never in a rollback.
$script:ParamKeyDirectory = if ($PSBoundParameters.ContainsKey('RecoveryKeyDirectory')) { $RecoveryKeyDirectory } else { $null }
$script:KeyDest = [pscustomobject]@{ Type = 'None'; Location = ''; Source = 'None'; Reason = ''; IgnoredSettingsFolder = '' }
$script:OrgSettings = $null
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:StopReason = $null
$script:AlreadyProtected = $false
$script:ResolvedKeyDirectory = $null
$script:RollbackSourceFile = $null
$script:BackupCategory = 'BackupRecoveryProtector'
$script:BackupPlanned = $false
$script:OsVolumeStatus = $null
$script:OsProtectionStatus = $null
# What the forward run records, shared with the rollback validator. The rollback file may carry
# exactly these fields and no other: in particular no key file path and nothing that adds a protector.
$script:EnableCategory = 'EnableOsVolume'
$script:EncryptionMethod = 'XtsAes256'
$script:RollbackTopField = @('Timestamp', 'ComputerName', 'MountPoint', 'ProtectorId', 'ScriptEnabledBitLocker', 'EncryptionMethod', 'ChangedSettings')
$script:RollbackEntryField = @('Category', 'MountPoint', 'ProtectorId', 'ScriptEnabledBitLocker', 'EncryptionMethod')
# -UseTpmAndPin: the startup-authentication policy written before the enable, and the record of what it replaced.
# Names and codes follow the BitLocker group policy settings reference (Learn); NOT verified on a live machine.
$script:UsePin = (($PSCmdlet.ParameterSetName -eq 'EnableTpmPin') -and [bool]$UseTpmAndPin)
# Held as a SecureString only, here and nowhere else; the helpers below read this variable, never a parameter.
$script:StartupPin = $StartupPin
$script:FveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$script:FveCategory = 'FvePolicy'
$script:FveRestoreCategory = 'RestoreFvePolicy'
$script:FveControl = @(
    [pscustomobject]@{ Name = 'UseAdvancedStartup'; Value = 1 }
    [pscustomobject]@{ Name = 'EnableBDEWithNoTPM'; Value = 0 }
    [pscustomobject]@{ Name = 'UseTPM'; Value = 0 }
    [pscustomobject]@{ Name = 'UseTPMPIN'; Value = 1 }
    [pscustomobject]@{ Name = 'UseTPMKey'; Value = 0 }
    [pscustomobject]@{ Name = 'UseTPMKeyPIN'; Value = 0 }
)
$script:FveRollbackField = @('Category', 'Name', 'PriorValue')
$script:PolicyChanges = [System.Collections.Generic.List[pscustomobject]]::new()
$script:Decrypting = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PlanItem {
    param(
        [string]$Category, [string]$Setting, [bool]$RequiresAdmin, [bool]$RequiresReboot = $false,
        $CurrentValue, $DesiredValue, [string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; RequiresAdmin = $RequiresAdmin
        RequiresReboot = $RequiresReboot
        CurrentValue = "$CurrentValue"; DesiredValue = "$DesiredValue"; Action = $Action
        Detail = ''
    }
}

# The two drive lookups below call plain commands (subst, Get-CimInstance) so a test can shadow them.
# Each throws when it cannot answer; the caller treats that as a refusal, never a pass.
function Get-SubstitutedDriveTarget {
    # Returns the target of a SUBST drive ('D:'), or $null when that drive is not substituted.
    param([Parameter(Mandatory = $true)][string]$DriveLetter)

    $global:LASTEXITCODE = 0
    $lines = @(& subst 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($global:LASTEXITCODE -ne 0) { throw "subst exited $($global:LASTEXITCODE)" }
    foreach ($line in $lines) {
        if ($line -notmatch '^([A-Za-z]:)\\: => (.+)$') { throw "unrecognised subst output '$line'" }
        if ($Matches[1] -ieq $DriveLetter) {
            $target = $Matches[2].Trim()
            if ($target -match '^UNC\\') { $target = '\\' + $target.Substring(4) }
            return $target
        }
    }
    $null
}

function Get-MappedDriveRemotePath {
    # Returns the UNC path of a mapped network drive ('D:'), or $null when the drive is not a network drive.
    param([Parameter(Mandatory = $true)][string]$DriveLetter)

    $disk = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$DriveLetter'" -ErrorAction Stop | Select-Object -First 1)
    if ($disk.Count -eq 0 -or $null -eq $disk[0]) { throw "Win32_LogicalDisk returned nothing for $DriveLetter" }
    if ([int]$disk[0].DriveType -ne 4) { return $null }
    $provider = [string]$disk[0].ProviderName
    if ([string]::IsNullOrWhiteSpace($provider)) { throw "network drive $DriveLetter reported no remote path" }
    $provider
}

function Test-IsThisComputerHost {
    param([Parameter(Mandatory = $true)][string]$HostName)

    $name = $HostName.Trim('[', ']').ToLowerInvariant()
    $computer = ([string]$env:COMPUTERNAME).ToLowerInvariant()
    if ($name -in @('localhost', '127.0.0.1', '::1', '.', '?', '0-0-0-0-0-0-0-1.ipv6-literal.net')) { return $true }
    if ($name -match '^127\.\d+\.\d+\.\d+$') { return $true }
    if ($computer -and ($name -eq $computer -or $name.StartsWith("$computer."))) { return $true }
    $false
}

# Returns why the path is on, or cannot be shown to be off, the operating-system volume; $null when it is off it.
# Follows SUBST drives and mapped network drives to their real target.
function Get-KeyDirectoryRefusal {
    param([Parameter(Mandatory = $true)][string]$Path, [int]$Depth = 0)

    $unverified = 'cannot be verified as off the operating-system volume'
    if ($Depth -gt 8) { return "$unverified (drive mappings nest too deeply to follow)" }
    if ($Path.StartsWith('\\')) {
        $hostName = ($Path.Substring(2) -split '\\')[0]
        if ([string]::IsNullOrWhiteSpace($hostName)) { return "$unverified (its UNC host could not be determined)" }
        if (Test-IsThisComputerHost -HostName $hostName) { return "is on this computer (UNC host '$hostName'), so it is on a local volume" }
        return $null
    }
    $root = [System.IO.Path]::GetPathRoot($Path)
    if ($root -notmatch '^[A-Za-z]:\\?$') { return "$unverified (its drive could not be determined)" }
    $drive = $root.Substring(0, 2)
    $system = [string]$env:SystemDrive
    if ($system -and ($drive -ieq $system.TrimEnd('\'))) { return "is on the operating-system volume $system" }

    try { $target = Get-SubstitutedDriveTarget -DriveLetter $drive } catch {
        return "$unverified (the SUBST table could not be read: $($_.Exception.Message))"
    }
    if ($null -ne $target) {
        $inner = Get-KeyDirectoryRefusal -Path $target -Depth ($Depth + 1)
        if ($inner) { return "is on drive $drive, which is substituted for '$target'; that target $inner" }
        return $null
    }
    try { $remote = Get-MappedDriveRemotePath -DriveLetter $drive } catch {
        return "$unverified (drive $drive could not be looked up: $($_.Exception.Message))"
    }
    if ($null -ne $remote) {
        $inner = Get-KeyDirectoryRefusal -Path $remote -Depth ($Depth + 1)
        if ($inner) { return "is on drive $drive, which is mapped to '$remote'; that path $inner" }
    }
    $null
}

# Refuses before anything is written. Throws; the caller has created no report directory yet.
function Resolve-RecoveryKeyDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Refusing: RecoveryKeyDirectory '$Path' does not exist or is not a directory. Nothing was changed."
    }
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    # The path as typed is checked too when it is a UNC or device path, in case resolving rewrote it.
    $candidates = @($resolved)
    if ($Path.StartsWith('\\') -and $Path -ne $resolved) { $candidates += $Path }
    foreach ($candidate in $candidates) {
        $reason = Get-KeyDirectoryRefusal -Path $candidate
        if ($reason) {
            throw "Refusing: RecoveryKeyDirectory '$candidate' $reason. A recovery key stored on the volume it protects cannot recover that volume. Nothing was changed."
        }
    }
    $resolved
}

# Decides where this run's recovery key goes: the parameter, else the organisation settings
# (Folder, EntraId, ActiveDirectory), else nowhere. Pure apart from reading the settings file.
# Type is Folder, EntraId, ActiveDirectory or NotConfigured; a settings file that is invalid or
# silent is NotConfigured with the reason, never a guess.
function Resolve-KeyBackupDestination {
    $settings = $script:OrgSettings.BitLockerKeyBackup
    $configured = ($settings.Status -eq 'Configured')
    if ($null -ne $script:ParamKeyDirectory) {
        $ignored = if ($configured -and $settings.Type -eq 'Folder') { [string]$settings.FolderPath } else { '' }
        return [pscustomobject]@{ Type = 'Folder'; Location = $script:ParamKeyDirectory; Source = 'Parameter'; Reason = ''; IgnoredSettingsFolder = $ignored }
    }
    if (-not $configured) {
        return [pscustomobject]@{ Type = 'NotConfigured'; Location = ''; Source = 'None'; Reason = [string]$settings.Reason; IgnoredSettingsFolder = '' }
    }
    switch ($settings.Type) {
        'Folder' { return [pscustomobject]@{ Type = 'Folder'; Location = [string]$settings.FolderPath; Source = 'Settings'; Reason = ''; IgnoredSettingsFolder = '' } }
        'EntraId' { return [pscustomobject]@{ Type = 'EntraId'; Location = 'Entra ID'; Source = 'Settings'; Reason = ''; IgnoredSettingsFolder = '' } }
        'ActiveDirectory' { return [pscustomobject]@{ Type = 'ActiveDirectory'; Location = 'Active Directory'; Source = 'Settings'; Reason = ''; IgnoredSettingsFolder = '' } }
    }
    [pscustomobject]@{ Type = 'NotConfigured'; Location = ''; Source = 'None'; Reason = "BitLockerKeyBackup type '$($settings.Type)' is not handled by this script"; IgnoredSettingsFolder = '' }
}

# Where the key goes, as text for a plan row: the folder path, 'Entra ID', 'Active Directory' or a refusal.
function Get-KeyDestinationText {
    switch ($script:KeyDest.Type) {
        'Folder' { return [string]$script:ResolvedKeyDirectory }
        'EntraId' { return 'Entra ID' }
        'ActiveDirectory' { return 'Active Directory' }
    }
    'no configured key backup destination'
}

# Escrows one recovery password protector to Entra ID or Active Directory. Throws on any failure; the
# caller treats a throw as "no key backup" and never starts encryption. The key value is never touched here.
function Invoke-ProtectorEscrow {
    param([Parameter(Mandatory = $true)][string]$Mount, [Parameter(Mandatory = $true)][string]$ProtectorId)
    if ($script:KeyDest.Type -eq 'EntraId') {
        BackupToAAD-BitLockerKeyProtector -MountPoint $Mount -KeyProtectorId $ProtectorId -ErrorAction Stop | Out-Null
    } elseif ($script:KeyDest.Type -eq 'ActiveDirectory') {
        Backup-BitLockerKeyProtector -MountPoint $Mount -KeyProtectorId $ProtectorId -ErrorAction Stop | Out-Null
    } else {
        throw "no escrow destination of type $($script:KeyDest.Type)"
    }
}

# The key file's text. Never log or print the result: it holds the recovery password in clear text.
function Get-RecoveryKeyFileText {
    param([string]$Mount, [string]$ProtectorId, [string]$KeyValue)
    @(
        'BitLocker recovery key'
        "Computer: $($env:COMPUTERNAME)"
        "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "Volume: $Mount"
        "Protector ID: $ProtectorId"
        "Recovery password: $KeyValue"
    ) -join [Environment]::NewLine
}

function Get-RecoveryKeyFilePath {
    param([string]$ProtectorId)
    Join-Path $script:ResolvedKeyDirectory "BitLocker-Recovery-$($env:COMPUTERNAME)-$($ProtectorId.Trim('{', '}')).txt"
}

function Get-OsVolumeState {
    # Returns an object with Readable, Reason, Volume. Unreadable is never a pass.
    $mount = [string]$env:SystemDrive
    try {
        $volume = @(Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop | Select-Object -First 1)
    } catch {
        return [pscustomobject]@{ Readable = $false; Reason = "Get-BitLockerVolume failed: $($_.Exception.Message)"; Volume = $null }
    }
    if ($volume.Count -eq 0 -or $null -eq $volume[0]) {
        return [pscustomobject]@{ Readable = $false; Reason = "Get-BitLockerVolume returned nothing for $mount"; Volume = $null }
    }
    [pscustomobject]@{ Readable = $true; Reason = ''; Volume = $volume[0] }
}

# Returns the DWord value as text, 'absent' when the key or value is missing, or 'unknown' when it
# cannot be read or is not a small non-negative integer. Never throws and never returns $null.
function Get-FveValue {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $props = Get-ItemProperty -LiteralPath $script:FveKey -ErrorAction Stop
    } catch {
        if (-not (Test-Path -LiteralPath $script:FveKey)) { return 'absent' }
        return 'unknown'
    }
    if ($null -eq $props -or -not $props.PSObject.Properties[$Name]) { return 'absent' }
    $value = $props.PSObject.Properties[$Name].Value
    if ($null -eq $value -or $value -isnot [int] -or $value -lt 0 -or $value -gt 999999999) { return 'unknown' }
    "$value"
}

# Returns why the PIN is not acceptable, or $null when it is. The PIN is read once here and never
# returned, logged or put in a message. Numeric only, 6 to 20 digits (the standard PIN rules).
function Get-StartupPinProblem {
    param([System.Security.SecureString]$Pin)
    if ($null -eq $Pin -or $Pin.Length -eq 0) { return 'no startup PIN was supplied' }
    $bstr = [IntPtr]::Zero
    $plain = $null
    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pin)
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($plain -cnotmatch '^[0-9]{6,20}\z') {
            return 'the startup PIN must be 6 to 20 digits (0-9 only); the value is not recorded'
        }
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plain = $null
    }
    $null
}

# True when the model or manufacturer names a hypervisor guest. Pure.
function Test-IsVirtualMachineIdentity {
    param([string]$Manufacturer, [string]$Model)
    if ($Model -match '(?i)virtual|vmware|kvm|qemu|bochs|hvm domu|xen|parallels|openstack|google compute engine|amazon ec2|\bAHV\b') { return $true }
    if ($Manufacturer -match '(?i)vmware|qemu|xen|innotek|parallels|bochs|red hat|amazon ec2|alibaba cloud|nutanix') { return $true }
    $false
}

# Returns Determined, IsVirtualMachine and Text. A failed read, or one with no model and no manufacturer, is
# not determined, and the caller treats that as a stop, never a pass.
function Get-VirtualMachineEvidence {
    try {
        $cs = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object -First 1)
    } catch {
        return [pscustomobject]@{ Determined = $false; IsVirtualMachine = $false; Text = "unread ($($_.Exception.Message))" }
    }
    if ($cs.Count -eq 0 -or $null -eq $cs[0]) {
        return [pscustomobject]@{ Determined = $false; IsVirtualMachine = $false; Text = 'unread (Win32_ComputerSystem returned nothing)' }
    }
    $model = [string](Get-OpsPropertyValue -InputObject $cs[0] -Name 'Model')
    $maker = [string](Get-OpsPropertyValue -InputObject $cs[0] -Name 'Manufacturer')
    if ([string]::IsNullOrWhiteSpace($model) -and [string]::IsNullOrWhiteSpace($maker)) {
        return [pscustomobject]@{ Determined = $false; IsVirtualMachine = $false; Text = 'unread (no Model or Manufacturer)' }
    }
    [pscustomobject]@{
        Determined = $true
        IsVirtualMachine = (Test-IsVirtualMachineIdentity -Manufacturer $maker -Model $model)
        Text = "Manufacturer=$maker;Model=$model"
    }
}

function Get-ForwardPlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $mount = [string]$env:SystemDrive
    $keyDir = Get-KeyDestinationText

    $os = Get-OsVolumeState
    $volStatus = 'unknown'
    $protStatus = 'unknown'
    $existingRecovery = @()
    $noRecoveryToBackUp = $false
    if ($os.Readable) {
        $volStatus = [string](Get-OpsPropertyValue -InputObject $os.Volume -Name 'VolumeStatus')
        $protStatus = [string](Get-OpsPropertyValue -InputObject $os.Volume -Name 'ProtectionStatus')
        # A TPM protector on a still-decrypted volume is an enable already done and waiting on the
        # hardware-test restart; a second run must not add another recovery protector.
        $tpmProtector = @(@(Get-OpsPropertyValue -InputObject $os.Volume -Name 'KeyProtector') |
                Where-Object { $_ -and [string]$_.KeyProtectorType -like 'Tpm*' })
        if ($tpmProtector.Count -gt 0 -and $volStatus -eq 'FullyDecrypted') { $volStatus = 'FullyDecrypted (enable pending restart)' }
        # A volume mid-decryption is neither protected nor ready for a fresh enable: its own case, a stop
        # with nothing planned and nothing changed. It is checked first so no other branch plans an enable on it.
        if ($volStatus -in @('DecryptionInProgress', 'DecryptionPaused')) {
            $script:Decrypting = $true
        } elseif ($volStatus -in @('FullyEncrypted', 'EncryptionInProgress', 'EncryptionPaused', 'FullyEncryptedWipeInProgress', 'EncryptionSuspended') -or $protStatus -eq 'On' -or $tpmProtector.Count -gt 0) {
            $script:AlreadyProtected = $true
        }
        # Automatic device encryption leaves an encrypted volume whose recovery password exists only on
        # the machine. Back each one up; a decrypted volume with a pending enable is not this case.
        $allRecovery = @(@(Get-OpsPropertyValue -InputObject $os.Volume -Name 'KeyProtector') |
                Where-Object { $_ -and [string]$_.KeyProtectorType -eq 'RecoveryPassword' })
        if ($volStatus -in @('FullyEncrypted', 'EncryptionInProgress', 'EncryptionPaused')) {
            $existingRecovery = $allRecovery
        }
        $noRecoveryToBackUp = [bool]($script:AlreadyProtected -and $allRecovery.Count -eq 0)
    }
    $script:OsVolumeStatus = $volStatus
    $script:OsProtectionStatus = $protStatus

    if ($script:KeyDest.Type -eq 'Folder') {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'RecoveryKeyDirectory' -RequiresAdmin $false `
                    -CurrentValue $keyDir -DesiredValue 'existing directory off the OS volume' `
                    -Action "Precondition: recovery key directory $keyDir exists and is not on $mount"))
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'KeyDirectoryWritable' -RequiresAdmin $false `
                    -CurrentValue 'not tested under -WhatIf' -DesiredValue 'writable' `
                    -Action 'Precondition: recovery key directory is writable (a probe file is written and deleted on a live run)'))
    } else {
        $keyAction = switch ($script:KeyDest.Type) {
            'EntraId' { 'Precondition: Key backup: Entra ID (host is Entra joined or hybrid joined, so BackupToAAD-BitLockerKeyProtector can escrow the recovery password)' }
            'ActiveDirectory' { 'Precondition: Key backup: Active Directory (host is domain joined, so Backup-BitLockerKeyProtector can escrow the recovery password)' }
            default { "Precondition: Key backup: not configured ($($script:KeyDest.Reason)); pass -RecoveryKeyDirectory or set BitLockerKeyBackup in the organisation settings" }
        }
        $keyCurrent = if ($script:KeyDest.Type -eq 'NotConfigured') { 'not configured' } else { 'join state not read yet' }
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'KeyBackup' -RequiresAdmin $false `
                    -CurrentValue $keyCurrent -DesiredValue "key escrowed to $keyDir before encryption starts" -Action $keyAction))
    }
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false `
                -CurrentValue (Test-IsAdministrator) -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Tpm' -RequiresAdmin $false `
                -CurrentValue 'unread' -DesiredValue 'TpmPresent and TpmReady' -Action 'Precondition: TPM is present and ready (Get-Tpm)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'SecureBoot' -RequiresAdmin $false `
                -CurrentValue 'unread' -DesiredValue 'True' -Action 'Precondition: Secure Boot is on (Confirm-SecureBootUEFI)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'OsVolumeNotProtected' -RequiresAdmin $false `
                -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus" -DesiredValue 'FullyDecrypted;Off' `
                -Action 'Precondition: OS volume is not already encrypted or encrypting'))

    # The PIN path only plans its checks and policy writes when an enable can actually follow.
    $pinActive = ($script:UsePin -and -not $script:AlreadyProtected -and -not $script:Decrypting)
    if ($pinActive) {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'NotVirtualMachine' -RequiresAdmin $false `
                    -CurrentValue 'unread' -DesiredValue 'physical machine' `
                    -Action 'Precondition: this is not a virtual machine (nobody can type a pre-boot PIN on a session host or other guest)'))
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'StartupPin' -RequiresAdmin $false `
                    -CurrentValue 'supplied (value never recorded)' -DesiredValue '6 to 20 digits, 0-9 only' `
                    -Action 'Precondition: the startup PIN is 6 to 20 digits'))
        foreach ($control in $script:FveControl) {
            $prior = Get-FveValue -Name $control.Name
            $policyAction = if ("$prior" -eq "$($control.Value)") {
                "No change ($($script:FveKey)\$($control.Name) is already $($control.Value))"
            } else {
                "Set $($script:FveKey)\$($control.Name) to $($control.Value) so BitLocker accepts a TPM plus startup PIN protector (prior value: $prior)"
            }
            $items.Add((Get-PlanItem -Category $script:FveCategory -Setting $control.Name -RequiresAdmin $true `
                        -CurrentValue $prior -DesiredValue "$($control.Value)" -Action $policyAction))
        }
    }

    $saveText = if ($script:KeyDest.Type -eq 'Folder') { "save it to $keyDir, read it back" } else { "back it up to $keyDir (encryption is not started unless the backup succeeds)" }
    $action = if ($script:Decrypting) {
        "No change (OS volume $mount is being decrypted: $volStatus, protection $protStatus; this script does not enable or protect a volume mid-decryption, so nothing is planned until decryption finishes)"
    } elseif ($script:AlreadyProtected) {
        "No change (OS volume $mount is already encrypted or encrypting: $volStatus, protection $protStatus)"
    } elseif ($script:UsePin) {
        "Protect ${mount}: add recovery password protector, $saveText, then enable BitLocker (TPM and startup PIN protector, $($script:EncryptionMethod), used space only)"
    } else {
        "Protect ${mount}: add recovery password protector, $saveText, then enable BitLocker (TPM protector, $($script:EncryptionMethod), used space only)"
    }
    $desired = if ($script:UsePin) { "TPM and startup PIN protector plus recovery password, $($script:EncryptionMethod)" } else { "TPM protector plus recovery password, $($script:EncryptionMethod)" }
    $items.Add((Get-PlanItem -Category $script:EnableCategory -Setting $mount -RequiresAdmin $true -RequiresReboot $true `
                -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus" -DesiredValue $desired `
                -Action $action))
    if ($script:UsePin -and $script:AlreadyProtected) {
        $items.Add((Get-PlanItem -Category 'Report' -Setting 'StartupPin' -RequiresAdmin $false `
                    -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus" -DesiredValue 'report only' `
                    -Action "No change (report only: -UseTpmAndPin has no effect because $mount is already protected; this script does not change the protectors of a volume it did not enable, so no PIN, policy or protector change is made)"))
    }
    if ($noRecoveryToBackUp) {
        $items.Add((Get-PlanItem -Category 'Report' -Setting 'RecoveryPassword' -RequiresAdmin $false `
                    -CurrentValue "VolumeStatus=$volStatus;no RecoveryPassword protector" -DesiredValue 'report only' `
                    -Action "No change (report only: $mount is already protected but has no recovery password protector, so there is no recovery password to back up; this script adds none to a volume it did not enable)"))
    }
    foreach ($protector in $existingRecovery) {
        $id = [string]$protector.KeyProtectorId
        $script:BackupPlanned = $true
        $backup = Get-PlanItem -Category $script:BackupCategory -Setting $id -RequiresAdmin $true `
            -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus;recovery password protector on $mount" `
            -DesiredValue "recovery password saved under $keyDir" `
            -Action "Back up the existing recovery password protector $id of ${mount} to $keyDir (no second protector is added and encryption is not touched)"
        $backup.Detail = "Volume=$mount;ProtectorId=$id"
        $items.Add($backup)
    }
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # Exact name: the wildcard form would also match the rollback-plan file a -Rollback run writes,
    # and a '.consumed-' file does not match, so a used file is never picked again.
    $pattern = '^' + [regex]::Escape($script:Prefix) + '-rollback-\d{8}_\d{6}\.json$'
    Get-ChildItem -LiteralPath $ReportDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# Returns $null when the record is acceptable, otherwise a short text saying what is wrong with it.
# A record (the file's top level, or one ChangedSettings entry) may carry only the fields in
# AllowedField, each of the type the forward run writes: the volume must be the operating-system
# volume (OsDrive), the protector ID a GUID, ScriptEnabledBitLocker true and the encryption method
# the one this script uses. A key file path, or any other field, is outside the set and is refused.
# Pure: it reads nothing but its arguments.
function Get-RollbackEntryProblem {
    param(
        $Entry,
        [Parameter(Mandatory = $true)][string[]]$AllowedField,
        [Parameter(Mandatory = $true)][string[]]$RequiredField,
        [string]$OsDrive,
        [Parameter(Mandatory = $true)][string]$EnableCategory,
        [Parameter(Mandatory = $true)][string]$EncryptionMethod
    )
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($property in $Entry.PSObject.Properties) {
        if ($property.Name -cnotin $AllowedField) { return "field '$($property.Name)' is not one this script records in a rollback file" }
    }
    foreach ($field in $RequiredField) {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
    }
    if ($Entry.PSObject.Properties['Category']) {
        if ($Entry.Category -isnot [string] -or $Entry.Category -cne $EnableCategory) { return "Category '$($Entry.Category)' is not $EnableCategory" }
    }
    foreach ($field in 'Timestamp', 'ComputerName') {
        if ($Entry.PSObject.Properties[$field]) {
            $v = $Entry.PSObject.Properties[$field].Value
            if ($v -isnot [string]) { return "$field is not a string" }
            if ($field -eq 'Timestamp' -and $v -cnotmatch '^\d{8}_\d{6}\z') { return "Timestamp '$v' is not a yyyyMMdd_HHmmss stamp" }
            if ($field -eq 'ComputerName' -and $v -cnotmatch '^[A-Za-z0-9_.-]{1,63}\z') { return "ComputerName '$v' is not a computer name" }
        }
    }
    if ($Entry.MountPoint -isnot [string] -or $Entry.MountPoint -cnotmatch '^[A-Za-z]:\z') { return "MountPoint '$($Entry.MountPoint)' is not a drive letter such as C:" }
    $os = if ($OsDrive) { $OsDrive.TrimEnd('\') } else { '' }
    if (-not $os) { return 'the operating-system volume could not be determined, so no volume can be matched' }
    if ($Entry.MountPoint -ine $os) { return "MountPoint '$($Entry.MountPoint)' is not the operating-system volume $os that this script encrypts" }
    if ($Entry.ProtectorId -isnot [string] -or $Entry.ProtectorId -notmatch '^\{[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\z') { return "ProtectorId '$($Entry.ProtectorId)' is not a protector GUID" }
    if ($Entry.ScriptEnabledBitLocker -isnot [bool] -or $Entry.ScriptEnabledBitLocker -ne $true) { return 'ScriptEnabledBitLocker is not true, so the file does not show this script enabled BitLocker' }
    if ($Entry.EncryptionMethod -isnot [string] -or $Entry.EncryptionMethod -cne $EncryptionMethod) { return "EncryptionMethod '$($Entry.EncryptionMethod)' is not $EncryptionMethod" }
    $null
}

# Returns $null when an FvePolicy record is acceptable, otherwise text saying what is wrong. The record may
# carry only Category, Name and PriorValue: the name must be one of the policy values this script writes
# (ControlName), so no other registry value can be named, and no path is recorded. Pure.
function Get-RollbackPolicyEntryProblem {
    param(
        $Entry,
        [Parameter(Mandatory = $true)][string[]]$ControlName,
        [Parameter(Mandatory = $true)][string]$PolicyCategory
    )
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($property in $Entry.PSObject.Properties) {
        if ($property.Name -cnotin @('Category', 'Name', 'PriorValue')) { return "field '$($property.Name)' is not one this script records for a policy value" }
    }
    foreach ($field in 'Category', 'Name', 'PriorValue') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
    }
    if ($Entry.Category -isnot [string] -or $Entry.Category -cne $PolicyCategory) { return "Category '$($Entry.Category)' is not $PolicyCategory" }
    if ($Entry.Name -isnot [string] -or $Entry.Name -cnotin $ControlName) { return "Name '$($Entry.Name)' is not a policy value this script writes" }
    if ($Entry.PriorValue -isnot [string] -or $Entry.PriorValue -cnotmatch '^(absent|unknown|[0-9]{1,9})\z') { return "PriorValue '$($Entry.PriorValue)' is not absent, unknown or a whole number" }
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
    if (-not $file) { throw "No $($script:Prefix)-rollback-<timestamp>.json found in $ReportDirectory. Nothing to roll back." }
    $advice = 'Nothing was changed. Move this file aside (out of the report directory) to roll back an older run.'
    try {
        $data = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Rollback file '$($file.FullName)' refused: it could not be read as JSON ($($_.Exception.Message)). $advice"
    }
    if ($null -eq $data -or $data -isnot [pscustomobject] -or -not $data.PSObject.Properties['ChangedSettings']) {
        throw "Rollback file '$($file.FullName)' refused: it has no ChangedSettings array. $advice"
    }
    if ($data.ChangedSettings -isnot [array]) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is not an array. $advice"
    }
    $entries = @($data.ChangedSettings)
    if ($entries.Count -eq 0) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is empty. $advice"
    }
    $osDrive = [string]$env:SystemDrive
    $problem = Get-RollbackEntryProblem -Entry $data -AllowedField $script:RollbackTopField `
        -RequiredField @('MountPoint', 'ProtectorId', 'ScriptEnabledBitLocker', 'EncryptionMethod', 'ChangedSettings') `
        -OsDrive $osDrive -EnableCategory $script:EnableCategory -EncryptionMethod $script:EncryptionMethod
    if ($problem) {
        throw "Rollback file '$($file.FullName)' refused at the top-level fields: $problem. $advice"
    }
    $policyEntries = [System.Collections.Generic.List[pscustomobject]]::new()
    $enableEntryCount = 0
    $policyNameSeen = @{}
    $controlName = @($script:FveControl | ForEach-Object { $_.Name })
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $isPolicy = ($entry -is [pscustomobject] -and $entry.PSObject.Properties['Category'] -and
            $entry.Category -is [string] -and $entry.Category -ceq $script:FveCategory)
        if ($isPolicy) {
            $problem = Get-RollbackPolicyEntryProblem -Entry $entry -ControlName $controlName -PolicyCategory $script:FveCategory
            if (-not $problem -and $policyNameSeen.ContainsKey($entry.Name)) { $problem = "policy value '$($entry.Name)' is listed twice" }
            if (-not $problem) {
                $policyNameSeen[$entry.Name] = $true
                [void]$policyEntries.Add($entry)
            }
        } else {
            $problem = Get-RollbackEntryProblem -Entry $entry -AllowedField $script:RollbackEntryField `
                -RequiredField $script:RollbackEntryField -OsDrive $osDrive `
                -EnableCategory $script:EnableCategory -EncryptionMethod $script:EncryptionMethod
            if (-not $problem -and ($entry.MountPoint -ine $data.MountPoint -or $entry.ProtectorId -ine $data.ProtectorId)) {
                $problem = 'MountPoint or ProtectorId differs from the file top level'
            }
            if (-not $problem) { $enableEntryCount++ }
        }
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    if ($enableEntryCount -eq 0) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings holds no $($script:EnableCategory) entry. $advice"
    }
    $script:RollbackSourceFile = $file

    $mount = $osDrive.TrimEnd('\')
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $items.Add((Get-PlanItem -Category 'DisableOsVolume' -Setting $mount -RequiresAdmin $true `
                -CurrentValue 'encrypted by this script' -DesiredValue 'decrypted' `
                -Action "Disable BitLocker on $mount (decryption takes hours and is not a quick undo; keep the recovery key file you saved until it completes)"))
    foreach ($policy in $policyEntries) {
        $current = Get-FveValue -Name $policy.Name
        $restoreAction = if ($policy.PriorValue -eq 'unknown') {
            "No change (the prior value of $($script:FveKey)\$($policy.Name) was not readable when this script wrote it, so it cannot be restored; set it by hand)"
        } elseif ($current -eq $policy.PriorValue) {
            "No change ($($script:FveKey)\$($policy.Name) already holds its prior value: $($policy.PriorValue))"
        } else {
            "Restore $($script:FveKey)\$($policy.Name) to its prior value ($($policy.PriorValue); current $current)"
        }
        $items.Add((Get-PlanItem -Category $script:FveRestoreCategory -Setting $policy.Name -RequiresAdmin $true `
                    -CurrentValue $current -DesiredValue $policy.PriorValue -Action $restoreAction))
    }
    $items
}

# Applies the precondition named by the item. Returns the result string; sets StopReason on a real failure.
function Test-PreconditionItem {
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    # An already-protected volume makes the whole run NoChange; the other checks are moot.
    if ($script:AlreadyProtected -and $Item.Setting -in @('Tpm', 'SecureBoot')) { return 'NoChange' }
    if ($script:AlreadyProtected -and -not $script:BackupPlanned -and $Item.Setting -in @('KeyDirectoryWritable', 'KeyBackup')) { return 'NoChange' }
    # A volume mid-decryption stops the run on its own row; the checks that only matter for an enable are
    # reported as not evaluated (not met, not failed), and nothing is written, not even the write probe.
    if ($script:Decrypting -and $Item.Setting -in @('Tpm', 'SecureBoot', 'KeyDirectoryWritable', 'KeyBackup')) {
        return 'Skipped: not evaluated (OS volume is being decrypted)'
    }

    switch ($Item.Setting) {
        'RecoveryKeyDirectory' { return 'Met' }
        'KeyBackup' {
            if ($script:KeyDest.Type -eq 'NotConfigured') {
                $script:StopReason = "Key backup: not configured ($($script:KeyDest.Reason)); nothing was changed. Pass -RecoveryKeyDirectory or set BitLockerKeyBackup in the organisation settings"
                return "Failed: $($script:StopReason)"
            }
            # The join facts are read, never assumed: $null (not determined) is as unmet as $false.
            try { $ctx = Get-OpsHostContext } catch { $ctx = $null }
            $factName = if ($script:KeyDest.Type -eq 'EntraId') { 'AzureAdJoined' } else { 'DomainJoined' }
            $fact = if ($null -ne $ctx) { Get-OpsPropertyValue -InputObject $ctx -Name $factName } else { $null }
            $Item.CurrentValue = "$factName=$(if ($null -eq $fact) { 'unknown' } else { $fact })"
            if ($fact -ne $true) {
                $need = if ($script:KeyDest.Type -eq 'EntraId') { 'an Entra joined or hybrid joined host' } else { 'a domain joined host' }
                $script:StopReason = "Key backup: $($script:KeyDest.Location) needs $need ($($Item.CurrentValue)); nothing was changed"
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
        'KeyDirectoryWritable' {
            if ($WhatIfPreference) { return 'Previewed' }
            $probe = Join-Path $script:ResolvedKeyDirectory (".ops-write-probe-" + [guid]::NewGuid().ToString('N'))
            try {
                Set-Content -LiteralPath $probe -Value 'probe' -Encoding ascii -ErrorAction Stop
                Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
            } catch {
                $script:StopReason = "recovery key directory is not writable: $($_.Exception.Message)"
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
        'Elevated' {
            if (Test-IsAdministrator) { return 'Met' }
            # A live run that cannot change anything must fail, not exit 0; a -WhatIf preview only reports it.
            # A planned recovery backup counts as a change: skipping it would exit 0 with no off-machine copy.
            if (-not $WhatIfPreference -and (-not $script:AlreadyProtected -or $script:BackupPlanned)) {
                $script:StopReason = 'session is not elevated'
                return "Failed: $($script:StopReason)"
            }
            return 'Skipped: requires elevation'
        }
        'Tpm' {
            # Get-Tpm and Confirm-SecureBootUEFI need elevation; unread is reported, never failed or passed.
            if (-not (Test-IsAdministrator)) { return 'Skipped: requires elevation (not read)' }
            try {
                $tpm = Get-Tpm -ErrorAction Stop
            } catch {
                $script:StopReason = "TPM state could not be read: $($_.Exception.Message)"
                return "Failed: $($script:StopReason)"
            }
            $present = Get-OpsPropertyValue -InputObject $tpm -Name 'TpmPresent'
            $ready = Get-OpsPropertyValue -InputObject $tpm -Name 'TpmReady'
            $Item.CurrentValue = "TpmPresent=$present;TpmReady=$ready"
            if ($present -ne $true -or $ready -ne $true) {
                $script:StopReason = "TPM is not present and ready ($($Item.CurrentValue))"
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
        'SecureBoot' {
            if (-not (Test-IsAdministrator)) { return 'Skipped: requires elevation (not read)' }
            try {
                $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            } catch {
                $Item.CurrentValue = 'unreadable'
                $script:StopReason = "Secure Boot state could not be read: $($_.Exception.Message)"
                return "Failed: $($script:StopReason)"
            }
            $Item.CurrentValue = "$sb"
            if ($sb -ne $true) {
                $script:StopReason = 'Secure Boot is not enabled'
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
        'NotVirtualMachine' {
            $vm = Get-VirtualMachineEvidence
            $Item.CurrentValue = $vm.Text
            if (-not $vm.Determined) {
                $script:StopReason = "could not tell whether this is a virtual machine ($($vm.Text)), so a startup PIN is refused: a guest nobody can type a PIN at would never start"
                return "Failed: $($script:StopReason)"
            }
            if ($vm.IsVirtualMachine) {
                $script:StopReason = "this is a virtual machine ($($vm.Text)); -UseTpmAndPin is refused because nobody can type a pre-boot PIN on a guest such as an Azure Virtual Desktop session host, and the host would never start"
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
        'StartupPin' {
            $pinProblem = Get-StartupPinProblem -Pin $script:StartupPin
            if ($pinProblem) {
                $script:StopReason = $pinProblem
                return "Failed: $pinProblem"
            }
            return 'Met'
        }
        'OsVolumeNotProtected' {
            if ($script:Decrypting) {
                $script:StopReason = "OS volume is being decrypted ($($script:OsVolumeStatus), protection $($script:OsProtectionStatus)); nothing was changed and no enable is planned until decryption finishes"
                return "Failed: OS volume is being decrypted ($($script:OsVolumeStatus)); nothing was changed and no enable is planned until decryption finishes"
            }
            if ($script:AlreadyProtected) { return 'NoChange' }
            $os = Get-OsVolumeState
            # Get-BitLockerVolume needs elevation too, so an unelevated failed read is unread, not a stop.
            if (-not $os.Readable -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation (not read)' }
            if (-not $os.Readable) {
                $script:StopReason = "OS volume state could not be read: $($os.Reason)"
                return "Failed: $($script:StopReason)"
            }
            $vs = [string](Get-OpsPropertyValue -InputObject $os.Volume -Name 'VolumeStatus')
            if ($vs -ne 'FullyDecrypted') {
                $script:StopReason = "OS volume is in state $vs, not FullyDecrypted"
                return "Failed: $($script:StopReason)"
            }
            return 'Met'
        }
    }
    "Failed: unknown precondition $($Item.Setting)"
}

# Writes one FVE policy DWord. The key is created only when it is missing: New-Item -Force on a key that
# exists replaces it and wipes its other values. Records the prior value so a rollback can restore it.
function Invoke-FvePolicySet {
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    $name = [string]$Item.Setting
    $prior = [string]$Item.CurrentValue
    if ($prior -cnotmatch '^(absent|[0-9]{1,9})$') { $prior = 'unknown' }
    try {
        if (-not (Test-Path -LiteralPath $script:FveKey)) { New-Item -Path $script:FveKey -Force | Out-Null }
        Set-ItemProperty -Path $script:FveKey -Name $name -Value ([int]$Item.DesiredValue) -Type DWord -Force -ErrorAction Stop
    } catch {
        $script:StopReason = "FVE policy write failed for ${name}: $($_.Exception.Message)"
        return "Failed: $($script:StopReason)"
    }
    [void]$script:PolicyChanges.Add([pscustomobject]@{ Category = $script:FveCategory; Name = $name; PriorValue = $prior })
    'Applied'
}

# Puts one FVE policy value back to its recorded prior value. 'absent' removes the value; 'unknown'
# cannot be restored and is NoChange with the reason in the text after a colon.
function Invoke-FveValueRestore {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Prior)

    if ($Prior -eq 'unknown') { return 'NoChange' }
    try {
        $current = Get-FveValue -Name $Name
        if ($current -eq $Prior) { return 'NoChange' }
        if ($Prior -eq 'absent') {
            Remove-ItemProperty -Path $script:FveKey -Name $Name -Force -ErrorAction Stop
        } else {
            if (-not (Test-Path -LiteralPath $script:FveKey)) { New-Item -Path $script:FveKey -Force | Out-Null }
            Set-ItemProperty -Path $script:FveKey -Name $Name -Value ([int]$Prior) -Type DWord -Force -ErrorAction Stop
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }
    'Reverted'
}

# Restores every policy value this run wrote, newest first, and returns text for the item's result.
# Empty when nothing was written. Used when the enable fails, is declined, or a policy row failed.
function Undo-FvePolicyChange {
    if ($script:PolicyChanges.Count -eq 0) { return '' }
    $failed = [System.Collections.Generic.List[string]]::new()
    $restored = 0
    for ($i = $script:PolicyChanges.Count - 1; $i -ge 0; $i--) {
        $change = $script:PolicyChanges[$i]
        $r = Invoke-FveValueRestore -Name $change.Name -Prior $change.PriorValue
        if ($r -like 'Failed:*' -or $change.PriorValue -eq 'unknown') { [void]$failed.Add("$($change.Name) (prior $($change.PriorValue))") } elseif ($r -eq 'Reverted') { $restored++ }
    }
    $script:PolicyChanges.Clear()
    if ($failed.Count -gt 0) { return " WARNING: restoring the FVE policy values failed for: $($failed -join ', '); put them back by hand." }
    " The FVE policy values written for the PIN were restored ($restored restored)."
}

# The ordered, all-or-nothing enable. Never returns or logs the recovery password or the PIN.
function Invoke-EnableOsVolume {
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    $mount = [string]$Item.Setting
    $protectorId = $null
    $keyFile = $null
    $password = $null
    try {
        $before = @()
        $existing = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop | Select-Object -First 1
        if ($existing) {
            $before = @(@(Get-OpsPropertyValue -InputObject $existing -Name 'KeyProtector') |
                    Where-Object { $_ } | ForEach-Object { [string]$_.KeyProtectorId })
        }

        # Step 1: recovery password protector.
        $added = Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPasswordProtector -ErrorAction Stop
        $candidates = @(Get-OpsPropertyValue -InputObject $added -Name 'KeyProtector')
        $fresh = @($candidates | Where-Object { $_ -and [string]$_.KeyProtectorType -eq 'RecoveryPassword' -and ([string]$_.KeyProtectorId) -notin $before })
        $new = $fresh | Select-Object -First 1
        if (-not $new) { throw 'Add-BitLockerKeyProtector did not return a new recovery password protector.' }
        $protectorId = [string]$new.KeyProtectorId
        $password = [string](Get-OpsPropertyValue -InputObject $new -Name 'RecoveryPassword')
        if ($script:KeyDest.Type -eq 'Folder') {
            if ([string]::IsNullOrWhiteSpace($password)) { throw 'The new recovery password protector carried no recovery password.' }

            # Step 2: write the key file, then Step 3: read it back. Neither message may contain the password.
            $keyFile = Get-RecoveryKeyFilePath -ProtectorId $protectorId
            if (Test-Path -LiteralPath $keyFile) { throw "Key file $keyFile already exists; refusing to overwrite it." }
            $content = Get-RecoveryKeyFileText -Mount $mount -ProtectorId $protectorId -KeyValue $password
            Set-Content -LiteralPath $keyFile -Value $content -Encoding ascii -ErrorAction Stop
            $readBack = Get-Content -LiteralPath $keyFile -Raw -ErrorAction Stop
            if ($null -eq $readBack -or -not $readBack.Contains($password)) {
                throw "Key file $keyFile was written but reading it back did not show the recovery password."
            }
        } else {
            # Steps 2 and 3 for an escrow destination: the backup must succeed (it throws otherwise) before encryption starts.
            Invoke-ProtectorEscrow -Mount $mount -ProtectorId $protectorId
        }

        # Step 4: only now start encryption.
        if ($script:UsePin) {
            # The SecureString goes straight to the cmdlet; it is never converted to text here.
            Enable-BitLocker -MountPoint $mount -TpmAndPinProtector -Pin $script:StartupPin -EncryptionMethod $script:EncryptionMethod -UsedSpaceOnly -ErrorAction Stop | Out-Null
        } else {
            Enable-BitLocker -MountPoint $mount -TpmProtector -EncryptionMethod $script:EncryptionMethod -UsedSpaceOnly -ErrorAction Stop | Out-Null
        }
    } catch {
        $message = $_.Exception.Message
        if ($password) { $message = $message.Replace($password, '[redacted]') }
        $cleanup = ''
        if ($protectorId) {
            try {
                Remove-BitLockerKeyProtector -MountPoint $mount -KeyProtectorId $protectorId -ErrorAction Stop | Out-Null
                $cleanup = " The recovery protector $protectorId was removed again."
            } catch {
                $cleanup = " WARNING: removing the recovery protector $protectorId failed; remove it by hand."
            }
            if ($keyFile -and (Test-Path -LiteralPath $keyFile)) {
                $cleanup += " Key file $keyFile refers to the removed protector and can be deleted."
            }
        }
        $cleanup += (Undo-FvePolicyChange)
        $script:StopReason = "enable failed: $message"
        if ($script:KeyDest.Type -ne 'Folder') { $script:StopReason = "enable failed (key backup to $($script:KeyDest.Location) or a later step): $message" }
        return "Failed: $message$cleanup BitLocker was not enabled."
    } finally {
        $password = $null
    }

    $Item.Detail = if ($script:KeyDest.Type -eq 'Folder') { "ProtectorId=$protectorId;KeyFile=$keyFile" } else { "ProtectorId=$protectorId;KeyBackup=$($script:KeyDest.Type);KeyBackupLocation=$($script:KeyDest.Location)" }
    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $script:EnableCategory; MountPoint = $mount; ProtectorId = $protectorId
            ScriptEnabledBitLocker = $true; EncryptionMethod = $script:EncryptionMethod
        })
    'Applied'
}

# Saves one existing recovery password protector to the key directory. Never returns or logs the password.
function Invoke-BackupRecoveryProtector {
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    $mount = [string]$script:ResolvedBackupVolume
    $protectorId = [string]$Item.Setting
    $password = $null
    if ($script:KeyDest.Type -ne 'Folder') {
        try {
            Invoke-ProtectorEscrow -Mount $mount -ProtectorId $protectorId
        } catch {
            $script:StopReason = "recovery protector backup failed: $($_.Exception.Message)"
            return "Failed: $($script:StopReason)"
        }
        $Item.Detail = "Volume=$mount;ProtectorId=$protectorId;KeyBackup=$($script:KeyDest.Type);KeyBackupLocation=$($script:KeyDest.Location)"
        return 'Applied'
    }
    $keyFile = Get-RecoveryKeyFilePath -ProtectorId $protectorId
    try {
        $volume = @(Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop | Select-Object -First 1)
        $protectors = @(Get-OpsPropertyValue -InputObject $volume[0] -Name 'KeyProtector')
        $match = $protectors | Where-Object { $_ -and [string]$_.KeyProtectorType -eq 'RecoveryPassword' -and [string]$_.KeyProtectorId -eq $protectorId } | Select-Object -First 1
        if (-not $match) { throw "protector $protectorId is no longer on $mount" }
        $password = [string](Get-OpsPropertyValue -InputObject $match -Name 'RecoveryPassword')
        if ([string]::IsNullOrWhiteSpace($password)) { throw "protector $protectorId carried no recovery password (is the session elevated?)" }
        if (Test-Path -LiteralPath $keyFile) {
            $existing = Get-Content -LiteralPath $keyFile -Raw -ErrorAction Stop
            if ($null -ne $existing -and $existing.Contains($password)) {
                $Item.Detail = "Volume=$mount;ProtectorId=$protectorId;KeyFile=$keyFile;AlreadyBackedUp=True"
                return 'NoChange'
            }
            throw "key file $keyFile already exists but does not hold this recovery password; refusing to overwrite it"
        }
        Set-Content -LiteralPath $keyFile -Value (Get-RecoveryKeyFileText -Mount $mount -ProtectorId $protectorId -KeyValue $password) -Encoding ascii -ErrorAction Stop
        $readBack = Get-Content -LiteralPath $keyFile -Raw -ErrorAction Stop
        if ($null -eq $readBack -or -not $readBack.Contains($password)) {
            throw "key file $keyFile was written but reading it back did not show the recovery password"
        }
    } catch {
        $message = $_.Exception.Message
        if ($password) { $message = $message.Replace($password, '[redacted]') }
        $script:StopReason = "recovery protector backup failed: $message"
        return "Failed: $($script:StopReason)"
    } finally {
        $password = $null
    }
    $Item.Detail = "Volume=$mount;ProtectorId=$protectorId;KeyFile=$keyFile"
    'Applied'
}

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Precondition') { return (Test-PreconditionItem -Item $Item) }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($script:StopReason) {
        # A policy row that failed earlier leaves the rows before it written: put those back when the enable is skipped.
        $undo = if ($Item.Category -eq $script:EnableCategory) { Undo-FvePolicyChange } else { '' }
        return "Skipped: precondition failed ($($script:StopReason))$undo"
    }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) {
        $undo = if ($Item.Category -eq $script:EnableCategory) { Undo-FvePolicyChange } else { '' }
        if ($undo) { return "Previewed:$undo" }
        return 'Previewed'
    }

    switch ($Item.Category) {
        { $_ -eq $script:EnableCategory } { return (Invoke-EnableOsVolume -Item $Item) }
        { $_ -eq $script:FveCategory } { return (Invoke-FvePolicySet -Item $Item) }
        { $_ -eq $script:FveRestoreCategory } { return (Invoke-FveValueRestore -Name $Item.Setting -Prior ([string]$Item.DesiredValue)) }
        { $_ -eq $script:BackupCategory } { return (Invoke-BackupRecoveryProtector -Item $Item) }
        'DisableOsVolume' {
            try {
                Disable-BitLocker -MountPoint $Item.Setting -ErrorAction Stop | Out-Null
            } catch {
                return "Failed: $($_.Exception.Message)"
            }
            return 'Reverted'
        }
    }
    "Failed: unknown category $($Item.Category)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not $Rollback) {
    $script:OrgSettings = Get-OpsOrgSettings
    $script:KeyDest = Resolve-KeyBackupDestination
    # A folder (the parameter or the settings value) gets the same validation; a bad one refuses before any change.
    if ($script:KeyDest.Type -eq 'Folder') {
        $script:ResolvedKeyDirectory = Resolve-RecoveryKeyDirectory -Path $script:KeyDest.Location
    }
}

$script:ResolvedBackupVolume = ([string]$env:SystemDrive).TrimEnd('\')
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$plan = @(if ($Rollback) { Get-RollbackPlan } else { Get-ForwardPlan })

$planPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-state-$timestamp.json"

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
        $rollbackNote = 'Rollback file left unconsumed: the step failed or was skipped, so -Rollback can be run again.'
    }
}

# Rollback record: only a live forward run that enabled BitLocker. Never holds the password or a key file path.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-rollback-$timestamp.json"
    $first = $script:ChangedSettings[0]
    [pscustomobject]@{
        Timestamp = $timestamp
        ComputerName = $env:COMPUTERNAME
        MountPoint = $first.MountPoint
        ProtectorId = $first.ProtectorId
        ScriptEnabledBitLocker = $true
        EncryptionMethod = $first.EncryptionMethod
        # The enable record first, then the prior value of each policy value written for the PIN (none without it).
        ChangedSettings = @(@($script:ChangedSettings) + @($script:PolicyChanges))
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$summary = [pscustomobject]@{
    Operation = "BitLockerOsVolume ($mode)"
    IsElevated = (Test-IsAdministrator)
    UseTpmAndPin = [bool]$script:UsePin
    RecoveryKeyDirectory = $script:ResolvedKeyDirectory
    KeyBackupDestination = $script:KeyDest.Type
    KeyBackupLocation = if ($script:KeyDest.Type -eq 'Folder') { $script:ResolvedKeyDirectory } else { $script:KeyDest.Location }
    KeyBackupSource = $script:KeyDest.Source
    KeyBackupNote = if ($script:KeyDest.IgnoredSettingsFolder) { "-RecoveryKeyDirectory was given, so the Folder value in the organisation settings ($($script:KeyDest.IgnoredSettingsFolder)) was ignored." } else { $null }
    KeyBackupProtectorIds = @($state | Where-Object { $_.Result -eq 'Applied' -and $_.Detail -match 'ProtectorId=' } | ForEach-Object { if ($_.Detail -match 'ProtectorId=(\{[0-9a-fA-F-]+\})') { $Matches[1] } })
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    OsVolumeStatus = $script:OsVolumeStatus
    OsProtectionStatus = $script:OsProtectionStatus
    RebootRequired = [bool](@($state | Where-Object { $_.Result -in @('Applied') -and $_.RequiresReboot }).Count)
    StoppedReason = $script:StopReason
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}

# A live run that stopped on a failed precondition or a failed step must not exit 0. The reports
# are already written; the message points at them. A -WhatIf run only previews, so it exits 0.
$failedItem = @($state | Where-Object { $_.Result -like 'Failed:*' }) | Select-Object -First 1
if (-not $WhatIfPreference -and (-not $script:AlreadyProtected -or $script:BackupPlanned) -and ($script:StopReason -or $failedItem)) {
    $why = if ($script:StopReason) { $script:StopReason } else { $failedItem.Result }
    throw "BitLocker change did not complete: $why. Reports: $resolvedReportDirectory"
}

$summary
