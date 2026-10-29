<#
.SYNOPSIS
Stand-in for the BitLocker module so scripts that protect or decrypt a volume never change real encryption.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_BL_VOLUMES_JSON to a JSON array describing the pretend volumes. Each
  entry may carry MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionMethod,
  EncryptionPercentage, AutoUnlockEnabled and KeyProtector (an array of objects with
  KeyProtectorType and KeyProtectorId). Unset or empty means no volumes are readable.
- Set OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD to the recovery password Add-BitLockerKeyProtector
  hands back for a new RecoveryPassword protector, so a test can search reports for it.
- Set OPSTOOLKIT_TEST_BL_PROTECTORID to the protector ID that call returns.
- Set OPSTOOLKIT_TEST_BL_READERROR to any value to make Get-BitLockerVolume throw, the way an
  unelevated session does.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Encrypting or decrypting the operating-system volume is the most disruptive change this
repository's scripts can make. The real module is never loaded under test because this one is
found first, and it holds no state: every call answers from the fixture and records itself.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeBlMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-FakeBlField {
    param($Object, [string]$Name, $Default)
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    $p.Value
}

function Get-BitLockerVolume {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$MountPoint)

    if ($env:OPSTOOLKIT_TEST_BL_READERROR) { throw 'Access is denied (fake BitLocker read error).' }
    if (-not $env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON) { return }

    $volumes = @($env:OPSTOOLKIT_TEST_BL_VOLUMES_JSON | ConvertFrom-Json)
    foreach ($v in $volumes) {
        $mount = [string](Get-FakeBlField $v 'MountPoint' 'C:')
        if ($MountPoint -and -not ($MountPoint | Where-Object { $_.TrimEnd('\') -ieq $mount.TrimEnd('\') })) { continue }
        [pscustomobject]@{
            MountPoint = $mount
            VolumeType = [string](Get-FakeBlField $v 'VolumeType' 'OperatingSystem')
            VolumeStatus = [string](Get-FakeBlField $v 'VolumeStatus' 'FullyDecrypted')
            ProtectionStatus = [string](Get-FakeBlField $v 'ProtectionStatus' 'Off')
            EncryptionMethod = [string](Get-FakeBlField $v 'EncryptionMethod' 'None')
            EncryptionPercentage = (Get-FakeBlField $v 'EncryptionPercentage' 0)
            AutoUnlockEnabled = (Get-FakeBlField $v 'AutoUnlockEnabled' $null)
            KeyProtector = @(Get-FakeBlField $v 'KeyProtector' @())
        }
    }
}

function Add-BitLockerKeyProtector {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$MountPoint,
        [switch]$RecoveryPasswordProtector,
        [switch]$TpmProtector,
        [switch]$TpmAndPinProtector,
        $Pin
    )

    $kind = if ($RecoveryPasswordProtector) { 'RecoveryPassword' } elseif ($TpmAndPinProtector) { 'TpmPin' } elseif ($TpmProtector) { 'Tpm' } else { 'Other' }
    Write-FakeBlMutation -Command 'Add-BitLockerKeyProtector' -Target $MountPoint -Detail $kind

    $id = if ($env:OPSTOOLKIT_TEST_BL_PROTECTORID) { $env:OPSTOOLKIT_TEST_BL_PROTECTORID } else { '{00000000-0000-4000-8000-00000000F4CE}' }
    $password = if ($env:OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD) { $env:OPSTOOLKIT_TEST_BL_RECOVERYPASSWORD } else { '111111-222222-333333-444444-555555-666666-777777-888888' }
    $protector = [pscustomobject]@{ KeyProtectorType = $kind; KeyProtectorId = $id; RecoveryPassword = $(if ($RecoveryPasswordProtector) { $password } else { '' }) }
    [pscustomobject]@{ MountPoint = $MountPoint; KeyProtector = @($protector) }
}

function Remove-BitLockerKeyProtector {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$MountPoint, [string]$KeyProtectorId)
    Write-FakeBlMutation -Command 'Remove-BitLockerKeyProtector' -Target $MountPoint -Detail $KeyProtectorId
    [pscustomobject]@{ MountPoint = $MountPoint; KeyProtector = @() }
}

function Enable-BitLocker {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$MountPoint,
        [string]$EncryptionMethod,
        [switch]$TpmProtector,
        [switch]$UsedSpaceOnly,
        [switch]$SkipHardwareTest
    )
    Write-FakeBlMutation -Command 'Enable-BitLocker' -Target $MountPoint -Detail "$EncryptionMethod;tpm=$([bool]$TpmProtector);usedspace=$([bool]$UsedSpaceOnly)"
    [pscustomobject]@{ MountPoint = $MountPoint }
}

function Disable-BitLocker {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$MountPoint)
    Write-FakeBlMutation -Command 'Disable-BitLocker' -Target $MountPoint
    [pscustomobject]@{ MountPoint = $MountPoint }
}

function Suspend-BitLocker {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$MountPoint, [int]$RebootCount)
    Write-FakeBlMutation -Command 'Suspend-BitLocker' -Target $MountPoint
    [pscustomobject]@{ MountPoint = $MountPoint }
}

function Resume-BitLocker {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$MountPoint)
    Write-FakeBlMutation -Command 'Resume-BitLocker' -Target $MountPoint
    [pscustomobject]@{ MountPoint = $MountPoint }
}

Export-ModuleMember -Function 'Get-BitLockerVolume', 'Add-BitLockerKeyProtector', 'Remove-BitLockerKeyProtector', 'Enable-BitLocker', 'Disable-BitLocker', 'Suspend-BitLocker', 'Resume-BitLocker'
