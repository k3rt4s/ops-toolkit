<#
.SYNOPSIS
Report BitLocker protection and whether a recovery key exists and is escrowed where it can be recovered from.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads volume state, key protector metadata, and policy registry
  values. It never enables, disables, or rotates anything.
- Run elevated. Without elevation the BitLocker cmdlets return partial data and
  every volume reports Undetermined rather than a false pass.
- Recovery key values are never written to a report. Only protector types, key IDs,
  and escrow configuration are exported.
- -VerifyAdEscrow confirms a recovery key actually exists in Active Directory rather
  than only that policy requires it. It needs the ActiveDirectory module and rights
  to read msFVE-RecoveryInformation on the computer object.
- Generated reports are written under reports\it-operations by default.

Purpose:
"Is BitLocker on" is the question people ask; "can we get the data back" is the
question that matters, and cyber insurers now verify the second. A volume can be
fully encrypted with a recovery password that exists nowhere but on the machine that
is refusing to boot. This separates protection state from recoverability and reports
them independently, because a machine that is encrypted and unrecoverable is worse
than one that is not encrypted at all.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1 -VerifyAdEscrow
pwsh -File .\scripts\it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1 -ComputerName pc01,pc02

.OUTPUTS
Writes a per-volume status set, a per-machine rollup, and a run summary as CSV and
JSON under reports\it-operations by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [switch]$VerifyAdEscrow,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'bitlocker-escrow-status'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$bitlockerProbe = {
    function Get-RegValue {
        param($Path, $Name)
        try {
            return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        } catch {
            return $null
        }
    }

    $isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    # Policy that requires escrow. Present policy means new keys get backed up; it
    # says nothing about keys created before the policy landed.
    $fve = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $policy = [pscustomobject]@{
        OSActiveDirectoryBackup = Get-RegValue $fve 'OSActiveDirectoryBackup'
        OSRequireActiveDirectoryBackup = Get-RegValue $fve 'OSRequireActiveDirectoryBackup'
        OSActiveDirectoryInfoToStore = Get-RegValue $fve 'OSActiveDirectoryInfoToStore'
        FDVActiveDirectoryBackup = Get-RegValue $fve 'FDVActiveDirectoryBackup'
        RDVActiveDirectoryBackup = Get-RegValue $fve 'RDVActiveDirectoryBackup'
        RequireDeviceEncryption = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker' 'RequireDeviceEncryption'
        BackupToAad = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker' 'BackupRecoveryPasswordsToAzureAD'
    }

    # Join state decides where a key can be escrowed to at all.
    $joinState = [pscustomobject]@{ AzureAdJoined = $null; DomainJoined = $null; Workplace = $null }
    try {
        $dsreg = & dsregcmd.exe /status 2>&1
        $joinState.AzureAdJoined = [bool]($dsreg | Select-String -Pattern 'AzureAdJoined\s*:\s*YES' -Quiet)
        $joinState.DomainJoined = [bool]($dsreg | Select-String -Pattern 'DomainJoined\s*:\s*YES' -Quiet)
        $joinState.Workplace = [bool]($dsreg | Select-String -Pattern 'WorkplaceJoined\s*:\s*YES' -Quiet)
    } catch {
        $joinState.DomainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    }

    $volumes = @()
    $probeError = ''
    try {
        $volumes = @(Get-BitLockerVolume -ErrorAction Stop)
    } catch {
        $probeError = $_.Exception.Message
    }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($volume in $volumes) {
        $protectors = @($volume.KeyProtector)
        $protectorTypes = @($protectors | ForEach-Object { [string]$_.KeyProtectorType })
        $recoveryProtectors = @($protectors | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' })

        $records.Add([pscustomobject]@{
                MountPoint = [string]$volume.MountPoint
                VolumeType = [string]$volume.VolumeType
                ProtectionStatus = [string]$volume.ProtectionStatus
                VolumeStatus = [string]$volume.VolumeStatus
                EncryptionMethod = [string]$volume.EncryptionMethod
                EncryptionPercentage = $volume.EncryptionPercentage
                AutoUnlockEnabled = $volume.AutoUnlockEnabled
                KeyProtectorTypes = ($protectorTypes -join ';')
                RecoveryPasswordCount = $recoveryProtectors.Count
                RecoveryKeyIds = (@($recoveryProtectors | ForEach-Object { [string]$_.KeyProtectorId }) -join ';')
            })
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Elevated = $isElevated
        ProbeError = $probeError
        Policy = $policy
        JoinState = $joinState
        Volumes = @($records)
    }
}

$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$volumeRecords = [System.Collections.Generic.List[object]]::new()
$machineRecords = [System.Collections.Generic.List[object]]::new()

$adAvailable = $false
if ($VerifyAdEscrow) {
    $adAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
    if (-not $adAvailable) {
        Write-Warning 'VerifyAdEscrow was requested but the ActiveDirectory module is not available. Escrow will be reported from policy only.'
    } else {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

foreach ($target in $targets) {
    $probe = $null
    try {
        if ($target -eq $env:COMPUTERNAME) {
            $probe = & $bitlockerProbe
        } else {
            $probe = Invoke-Command -ComputerName $target -ScriptBlock $bitlockerProbe -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $machineRecords.Add([pscustomobject]@{
                ComputerName = $target
                Verdict = 'Unreachable'
                Elevated = $null
                EncryptedVolumeCount = 0
                UnprotectedVolumeCount = 0
                VolumesWithoutRecoveryKey = 0
                EscrowConfigured = ''
                AdEscrowVerified = ''
                Note = $_.Exception.Message
            })
        continue
    }

    $policy = Get-OpsPropertyValue -InputObject $probe -Name 'Policy'
    $joinState = Get-OpsPropertyValue -InputObject $probe -Name 'JoinState'
    $volumes = @(Get-OpsPropertyValue -InputObject $probe -Name 'Volumes')

    $escrowTargets = @()
    if ((Get-OpsPropertyValue -InputObject $policy -Name 'OSActiveDirectoryBackup')) { $escrowTargets += 'ActiveDirectory (policy)' }
    if ((Get-OpsPropertyValue -InputObject $policy -Name 'BackupToAad')) { $escrowTargets += 'EntraID (policy)' }

    # Verify rather than infer, when we can. Policy says what happens to new keys.
    $adEscrowVerified = 'NotChecked'
    $adRecoveryObjectCount = $null
    if ($VerifyAdEscrow -and $adAvailable) {
        try {
            $computer = Get-ADComputer -Identity $probe.ComputerName -ErrorAction Stop
            $recoveryObjects = @(Get-ADObject -SearchBase $computer.DistinguishedName -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -ErrorAction Stop)
            $adRecoveryObjectCount = $recoveryObjects.Count
            $adEscrowVerified = if ($recoveryObjects.Count -gt 0) { 'Present' } else { 'Absent' }
        } catch {
            $adEscrowVerified = 'Unreadable'
            Write-Warning "Could not verify AD escrow for $($probe.ComputerName): $($_.Exception.Message)"
        }
    }

    foreach ($volume in $volumes) {
        $protected = [string]$volume.ProtectionStatus -eq 'On'
        $hasRecoveryKey = [int]$volume.RecoveryPasswordCount -gt 0

        $status = if (-not $probe.Elevated) {
            'Undetermined'
        } elseif (-not $protected) {
            'Unprotected'
        } elseif (-not $hasRecoveryKey) {
            'EncryptedNoRecoveryKey'
        } elseif ($adEscrowVerified -eq 'Absent') {
            'EncryptedNotEscrowed'
        } elseif ($escrowTargets.Count -eq 0 -and $adEscrowVerified -eq 'NotChecked') {
            'EncryptedEscrowUnknown'
        } else {
            'Recoverable'
        }

        $volumeRecords.Add([pscustomobject]@{
                ComputerName = $probe.ComputerName
                MountPoint = $volume.MountPoint
                Status = $status
                VolumeType = $volume.VolumeType
                ProtectionStatus = $volume.ProtectionStatus
                VolumeStatus = $volume.VolumeStatus
                EncryptionMethod = $volume.EncryptionMethod
                EncryptionPercentage = $volume.EncryptionPercentage
                KeyProtectorTypes = $volume.KeyProtectorTypes
                RecoveryPasswordCount = $volume.RecoveryPasswordCount
                RecoveryKeyIds = $volume.RecoveryKeyIds
                EscrowConfigured = ($escrowTargets -join ';')
                AdEscrowVerified = $adEscrowVerified
                AdRecoveryObjectCount = $adRecoveryObjectCount
            })
    }

    $unprotected = @($volumeRecords | Where-Object { $_.ComputerName -eq $probe.ComputerName -and $_.Status -eq 'Unprotected' })
    $noKey = @($volumeRecords | Where-Object { $_.ComputerName -eq $probe.ComputerName -and $_.Status -in @('EncryptedNoRecoveryKey', 'EncryptedNotEscrowed') })
    $encrypted = @($volumeRecords | Where-Object { $_.ComputerName -eq $probe.ComputerName -and $_.ProtectionStatus -eq 'On' })

    $verdict = if (-not $probe.Elevated) {
        'Undetermined'
    } elseif ($noKey.Count -gt 0) {
        'AtRisk'
    } elseif ($unprotected.Count -gt 0) {
        'PartiallyProtected'
    } elseif ($encrypted.Count -gt 0) {
        'Protected'
    } else {
        'NotEncrypted'
    }

    $machineRecords.Add([pscustomobject]@{
            ComputerName = $probe.ComputerName
            Verdict = $verdict
            Elevated = $probe.Elevated
            AzureAdJoined = Get-OpsPropertyValue -InputObject $joinState -Name 'AzureAdJoined'
            DomainJoined = Get-OpsPropertyValue -InputObject $joinState -Name 'DomainJoined'
            VolumeCount = @($volumes).Count
            EncryptedVolumeCount = $encrypted.Count
            UnprotectedVolumeCount = $unprotected.Count
            VolumesWithoutRecoveryKey = $noKey.Count
            EscrowConfigured = ($escrowTargets -join ';')
            AdEscrowVerified = $adEscrowVerified
            RequireAdBackupPolicy = Get-OpsPropertyValue -InputObject $policy -Name 'OSRequireActiveDirectoryBackup'
            Note = if (-not $probe.Elevated) { 'Re-run elevated. BitLocker state cannot be read reliably without it.' } else { [string](Get-OpsPropertyValue -InputObject $probe -Name 'ProbeError') }
        })
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'bitlocker-volumes' -Record @($volumeRecords) -Directory $runDirectory
    Export-OpsReport -Name 'bitlocker-machines' -Record @($machineRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    ComputersQueried = @($targets).Count
    VerifyAdEscrowRequested = [bool]$VerifyAdEscrow
    AdModuleAvailable = $adAvailable
    ProtectedCount = @($machineRecords | Where-Object { $_.Verdict -eq 'Protected' }).Count
    AtRiskCount = @($machineRecords | Where-Object { $_.Verdict -eq 'AtRisk' }).Count
    PartiallyProtectedCount = @($machineRecords | Where-Object { $_.Verdict -eq 'PartiallyProtected' }).Count
    NotEncryptedCount = @($machineRecords | Where-Object { $_.Verdict -eq 'NotEncrypted' }).Count
    UndeterminedCount = @($machineRecords | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    UnreachableCount = @($machineRecords | Where-Object { $_.Verdict -eq 'Unreachable' }).Count
    VolumesWithoutRecoveryKey = @($volumeRecords | Where-Object { $_.Status -eq 'EncryptedNoRecoveryKey' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
