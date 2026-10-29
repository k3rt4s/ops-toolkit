<#
.SYNOPSIS
Plan, apply, and roll back BitLocker encryption of the operating-system volume with a TPM protector, saving a recovery password to a directory the operator names before encryption starts.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON. The plan lists every
  precondition and the ordered steps.
- -RecoveryKeyDirectory is mandatory and must be a directory that already exists on a volume
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
  Reports hold only the protector ID and the key file path. The key file itself holds the
  password in clear text: move it off the machine to a password manager or sealed storage, and
  restrict who can read the directory.
- Enable-BitLocker without -SkipHardwareTest runs a hardware test at the next restart, and
  encryption begins after it. Restart when convenient; the summary reports RebootRequired.
- -Rollback runs Disable-BitLocker on the volume recorded in the latest rollback file, and only
  if that file shows this script enabled it. Decryption takes hours, proportional to disk size,
  and is not a quick undo. Keep the recovery key file until decryption completes.
- There is no PIN option in this build. TPM plus a pre-boot PIN is the stronger posture because
  a TPM-only volume unlocks for anyone who can boot the machine; it is a later item.

Purpose:
Without BitLocker, physical access to the machine or its drive gives full access to the data
whatever the account controls say. This enables it on the operating-system volume in the one
order that cannot leave the machine encrypted with a recovery key that exists nowhere else.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -RecoveryKeyDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -RecoveryKeyDirectory <dir>      # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Enable-BitLockerOsVolume.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, plus on a live run that enabled
BitLocker a rollback JSON holding the protector ID, key file path and volume (never the
password). Returns a summary object.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Export-BitLockerEscrowStatus.ps1, which
reports whether a recovery key exists after this has run.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Enable')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')]
    [ValidateNotNullOrEmpty()]
    [string]$RecoveryKeyDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$script:Prefix = 'bitlocker-enable'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:StopReason = $null
$script:AlreadyProtected = $false
$script:ResolvedKeyDirectory = $null

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

function Get-ForwardPlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $mount = [string]$env:SystemDrive
    $keyDir = $script:ResolvedKeyDirectory

    $os = Get-OsVolumeState
    $volStatus = 'unknown'
    $protStatus = 'unknown'
    if ($os.Readable) {
        $volStatus = [string](Get-OpsPropertyValue -InputObject $os.Volume -Name 'VolumeStatus')
        $protStatus = [string](Get-OpsPropertyValue -InputObject $os.Volume -Name 'ProtectionStatus')
        # A TPM protector on a still-decrypted volume is an enable already done and waiting on the
        # hardware-test restart; a second run must not add another recovery protector.
        $tpmProtector = @(@(Get-OpsPropertyValue -InputObject $os.Volume -Name 'KeyProtector') |
                Where-Object { $_ -and [string]$_.KeyProtectorType -like 'Tpm*' })
        if ($tpmProtector.Count -gt 0 -and $volStatus -eq 'FullyDecrypted') { $volStatus = 'FullyDecrypted (enable pending restart)' }
        if ($volStatus -in @('FullyEncrypted', 'EncryptionInProgress', 'FullyEncryptedWipeInProgress', 'EncryptionSuspended') -or $protStatus -eq 'On' -or $tpmProtector.Count -gt 0) {
            $script:AlreadyProtected = $true
        }
    }

    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'RecoveryKeyDirectory' -RequiresAdmin $false `
                -CurrentValue $keyDir -DesiredValue 'existing directory off the OS volume' `
                -Action "Precondition: recovery key directory $keyDir exists and is not on $mount"))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'KeyDirectoryWritable' -RequiresAdmin $false `
                -CurrentValue 'not tested under -WhatIf' -DesiredValue 'writable' `
                -Action 'Precondition: recovery key directory is writable (a probe file is written and deleted on a live run)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false `
                -CurrentValue (Test-IsAdministrator) -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Tpm' -RequiresAdmin $false `
                -CurrentValue 'unread' -DesiredValue 'TpmPresent and TpmReady' -Action 'Precondition: TPM is present and ready (Get-Tpm)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'SecureBoot' -RequiresAdmin $false `
                -CurrentValue 'unread' -DesiredValue 'True' -Action 'Precondition: Secure Boot is on (Confirm-SecureBootUEFI)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'OsVolumeNotProtected' -RequiresAdmin $false `
                -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus" -DesiredValue 'FullyDecrypted;Off' `
                -Action 'Precondition: OS volume is not already encrypted or encrypting'))

    $action = if ($script:AlreadyProtected) {
        "No change (OS volume $mount is already encrypted or encrypting: $volStatus, protection $protStatus)"
    } else {
        "Protect ${mount}: add recovery password protector, save it to $keyDir, read it back, then enable BitLocker (TPM protector, XtsAes256, used space only)"
    }
    $items.Add((Get-PlanItem -Category 'EnableOsVolume' -Setting $mount -RequiresAdmin $true -RequiresReboot $true `
                -CurrentValue "VolumeStatus=$volStatus;ProtectionStatus=$protStatus" -DesiredValue 'TPM protector plus recovery password, XtsAes256' `
                -Action $action))
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # Exact name: the wildcard form would also match the rollback-plan file a -Rollback run writes.
    $pattern = '^' + [regex]::Escape($script:Prefix) + '-rollback-\d{8}_\d{6}\.json$'
    Get-ChildItem -LiteralPath $ReportDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Sort-Object LastWriteTime, Name -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:Prefix)-rollback-<timestamp>.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $enabled = Get-OpsPropertyValue -InputObject $data -Name 'ScriptEnabledBitLocker'
    $mount = [string](Get-OpsPropertyValue -InputObject $data -Name 'MountPoint')
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($enabled -ne $true -or -not $mount) {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'RollbackFile' -RequiresAdmin $false `
                    -CurrentValue $file.Name -DesiredValue 'ScriptEnabledBitLocker = true' `
                    -Action "Precondition: rollback file $($file.Name) shows this script enabled BitLocker"))
        return $items
    }
    $items.Add((Get-PlanItem -Category 'DisableOsVolume' -Setting $mount -RequiresAdmin $true `
                -CurrentValue 'encrypted by this script' -DesiredValue 'decrypted' `
                -Action "Disable BitLocker on $mount (decryption takes hours and is not a quick undo; keep recovery key file $([string](Get-OpsPropertyValue -InputObject $data -Name 'KeyFilePath')) until it completes)"))
    $items
}

# Applies the precondition named by the item. Returns the result string; sets StopReason on a real failure.
function Test-PreconditionItem {
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    # An already-protected volume makes the whole run NoChange; the other checks are moot.
    if ($script:AlreadyProtected -and $Item.Setting -in @('KeyDirectoryWritable', 'Tpm', 'SecureBoot')) { return 'NoChange' }

    switch ($Item.Setting) {
        'RecoveryKeyDirectory' { return 'Met' }
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
            if (-not $WhatIfPreference -and -not $script:AlreadyProtected) {
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
        'OsVolumeNotProtected' {
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
        'RollbackFile' {
            $script:StopReason = 'rollback file does not show this script enabled BitLocker'
            return "Failed: $($script:StopReason)"
        }
    }
    "Failed: unknown precondition $($Item.Setting)"
}

# The ordered, all-or-nothing enable. Never returns or logs the recovery password.
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
        if ([string]::IsNullOrWhiteSpace($password)) { throw 'The new recovery password protector carried no recovery password.' }

        # Step 2: write the key file, then Step 3: read it back. Neither message may contain the password.
        $idForName = $protectorId.Trim('{', '}')
        $keyFile = Join-Path $script:ResolvedKeyDirectory "BitLocker-Recovery-$($env:COMPUTERNAME)-$idForName.txt"
        if (Test-Path -LiteralPath $keyFile) { throw "Key file $keyFile already exists; refusing to overwrite it." }
        $content = @(
            'BitLocker recovery key'
            "Computer: $($env:COMPUTERNAME)"
            "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "Volume: $mount"
            "Protector ID: $protectorId"
            "Recovery password: $password"
        ) -join [Environment]::NewLine
        Set-Content -LiteralPath $keyFile -Value $content -Encoding ascii -ErrorAction Stop
        $readBack = Get-Content -LiteralPath $keyFile -Raw -ErrorAction Stop
        if ($null -eq $readBack -or -not $readBack.Contains($password)) {
            throw "Key file $keyFile was written but reading it back did not show the recovery password."
        }

        # Step 4: only now start encryption.
        Enable-BitLocker -MountPoint $mount -TpmProtector -EncryptionMethod XtsAes256 -UsedSpaceOnly -ErrorAction Stop | Out-Null
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
        $script:StopReason = "enable failed: $message"
        return "Failed: $message$cleanup BitLocker was not enabled."
    } finally {
        $password = $null
    }

    $Item.Detail = "ProtectorId=$protectorId;KeyFile=$keyFile"
    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; MountPoint = $mount; ProtectorId = $protectorId; KeyFilePath = $keyFile
            ScriptEnabledBitLocker = $true; EncryptionMethod = 'XtsAes256'
        })
    'Applied'
}

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Precondition') { return (Test-PreconditionItem -Item $Item) }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($script:StopReason) { return "Skipped: precondition failed ($($script:StopReason))" }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    switch ($Item.Category) {
        'EnableOsVolume' { return (Invoke-EnableOsVolume -Item $Item) }
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
    $script:ResolvedKeyDirectory = Resolve-RecoveryKeyDirectory -Path $RecoveryKeyDirectory
}

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

# Rollback record: only a live forward run that enabled BitLocker. Never holds the password.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-rollback-$timestamp.json"
    $first = $script:ChangedSettings[0]
    [pscustomobject]@{
        Timestamp = $timestamp
        ComputerName = $env:COMPUTERNAME
        MountPoint = $first.MountPoint
        ProtectorId = $first.ProtectorId
        KeyFilePath = $first.KeyFilePath
        ScriptEnabledBitLocker = $true
        EncryptionMethod = $first.EncryptionMethod
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$summary = [pscustomobject]@{
    Operation = "BitLockerOsVolume ($mode)"
    IsElevated = (Test-IsAdministrator)
    RecoveryKeyDirectory = $script:ResolvedKeyDirectory
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
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
if (-not $WhatIfPreference -and -not $script:AlreadyProtected -and ($script:StopReason -or $failedItem)) {
    $why = if ($script:StopReason) { $script:StopReason } else { $failedItem.Result }
    throw "BitLocker change did not complete: $why. Reports: $resolvedReportDirectory"
}

$summary
