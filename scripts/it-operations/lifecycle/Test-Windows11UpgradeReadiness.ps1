<#
.SYNOPSIS
Check whether a machine meets the Windows 11 hardware requirements and report the exact blocker when it does not.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It queries CIM, TPM, and firmware state and writes reports. It changes
  nothing and needs no -WhatIf.
- Some checks need elevation. Without it those checks report Undetermined rather
  than guessing, and the overall verdict becomes Undetermined rather than Ready.
- -ComputerName needs WinRM and local administrator rights on each target.
- CPU model compatibility is not checked. Microsoft publishes that as a list of
  supported processors, not as a rule, so this reports the CPU for a manual check
  instead of inventing a threshold.
- Generated reports are written under reports\it-operations by default.

Purpose:
With Windows 10 consumer ESU ending 13 October 2026, the question on every remaining
Windows 10 machine is not whether to move but whether it can. Hardware eligibility is
the real gate. This says Ready, Blocked, or Undetermined per machine and names the
specific requirement that fails, so the estate splits into upgrade, remediate, and
replace instead of one undifferentiated pile.

Required syntax:
pwsh -File .\scripts\it-operations\lifecycle\Test-Windows11UpgradeReadiness.ps1
pwsh -File .\scripts\it-operations\lifecycle\Test-Windows11UpgradeReadiness.ps1 -ComputerName pc01,pc02
pwsh -File .\scripts\it-operations\lifecycle\Test-Windows11UpgradeReadiness.ps1 -MinimumFreeDiskGb 64

.OUTPUTS
Writes a per-machine verdict, a per-check detail set, and a run summary as CSV and
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
    [ValidateRange(1, 1024)]
    [int]$MinimumMemoryGb = 4,

    [Parameter()]
    [ValidateRange(1, 4096)]
    [int]$MinimumFreeDiskGb = 64,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$MinimumProcessorCore = 2,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$MinimumProcessorMhz = 1000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'windows11-upgrade-readiness'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$readinessProbe = {
    param($MinMemoryGb, $MinDiskGb, $MinCore, $MinMhz)

    $result = [System.Collections.Generic.List[object]]::new()

    function Add-Check {
        param($List, $Name, $Status, $Actual, $Required, $Note = '')
        $List.Add([pscustomobject]@{
                Check = $Name
                Status = $Status
                Actual = "$Actual"
                Required = "$Required"
                Note = $Note
            })
    }

    $isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu = @(Get-CimInstance -ClassName Win32_Processor)[0]

    $memoryGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    Add-Check $result 'Memory' $(if ($memoryGb -ge $MinMemoryGb) { 'Pass' } else { 'Fail' }) "$memoryGb GB" "$MinMemoryGb GB"

    $systemDrive = ($os.SystemDrive)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    $freeGb = [math]::Round($disk.FreeSpace / 1GB, 2)
    $sizeGb = [math]::Round($disk.Size / 1GB, 2)
    Add-Check $result 'SystemDiskSize' $(if ($sizeGb -ge $MinDiskGb) { 'Pass' } else { 'Fail' }) "$sizeGb GB" "$MinDiskGb GB" "System drive $systemDrive"
    Add-Check $result 'SystemDiskFree' $(if ($freeGb -ge 20) { 'Pass' } else { 'Warn' }) "$freeGb GB free" '20 GB free' 'Upgrade staging needs free space beyond the disk size requirement.'

    Add-Check $result 'ProcessorCores' $(if ($cpu.NumberOfCores -ge $MinCore) { 'Pass' } else { 'Fail' }) $cpu.NumberOfCores $MinCore
    Add-Check $result 'ProcessorSpeed' $(if ($cpu.MaxClockSpeed -ge $MinMhz) { 'Pass' } else { 'Fail' }) "$($cpu.MaxClockSpeed) MHz" "$MinMhz MHz"
    Add-Check $result 'Processor64Bit' $(if ($cpu.AddressWidth -eq 64) { 'Pass' } else { 'Fail' }) "$($cpu.AddressWidth)-bit" '64-bit'
    Add-Check $result 'ProcessorModel' 'Review' $cpu.Name 'On the Microsoft supported processor list' 'Microsoft publishes a model list, not a rule. Check this model against it manually.'

    # Secure Boot. Get-SecureBootUEFI throws on a legacy BIOS machine, which is
    # itself the answer, so the throw is interpreted rather than swallowed.
    $secureBootStatus = 'Undetermined'
    $secureBootActual = 'unknown'
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        $secureBootStatus = if ($secureBoot) { 'Pass' } else { 'Fail' }
        $secureBootActual = "$secureBoot"
    } catch [System.PlatformNotSupportedException] {
        $secureBootStatus = 'Fail'
        $secureBootActual = 'Legacy BIOS, not UEFI'
    } catch {
        $secureBootStatus = if ($isElevated) { 'Undetermined' } else { 'Undetermined' }
        $secureBootActual = $_.Exception.Message
    }
    Add-Check $result 'SecureBoot' $secureBootStatus $secureBootActual 'Enabled on UEFI firmware'

    $tpmStatus = 'Undetermined'
    $tpmActual = 'not read'
    $tpmNote = ''
    try {
        $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        if (-not $tpm) {
            $tpmStatus = 'Fail'
            $tpmActual = 'No TPM present'
        } else {
            $specVersion = ([string]$tpm.SpecVersion -split ',')[0].Trim()
            $major = 0
            [void][double]::TryParse($specVersion, [ref]$major)
            $tpmActual = "spec $specVersion, enabled=$($tpm.IsEnabled_InitialValue), activated=$($tpm.IsActivated_InitialValue)"
            $tpmStatus = if ($major -ge 2.0 -and $tpm.IsEnabled_InitialValue) { 'Pass' } else { 'Fail' }
            if ($major -ge 2.0 -and -not $tpm.IsEnabled_InitialValue) {
                $tpmNote = 'TPM 2.0 is present but disabled. This is a firmware setting, not a hardware replacement.'
            }
        }
    } catch {
        $tpmActual = $_.Exception.Message
        $tpmNote = if ($isElevated) { 'TPM namespace unreadable.' } else { 'Reading the TPM needs an elevated shell.' }
    }
    Add-Check $result 'Tpm2' $tpmStatus $tpmActual 'TPM 2.0 present and enabled' $tpmNote

    $partitionStyle = 'Undetermined'
    try {
        $systemDisk = Get-Disk -ErrorAction Stop | Where-Object { $_.IsBoot } | Select-Object -First 1
        if ($systemDisk) {
            $partitionStyle = [string]$systemDisk.PartitionStyle
        }
    } catch {
        $partitionStyle = 'Undetermined'
    }
    Add-Check $result 'PartitionStyle' $(if ($partitionStyle -eq 'GPT') { 'Pass' } elseif ($partitionStyle -eq 'Undetermined') { 'Undetermined' } else { 'Fail' }) $partitionStyle 'GPT'

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Elevated = $isElevated
        Caption = $os.Caption
        Build = [int]$os.BuildNumber
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        Checks = @($result)
    }
}

$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$verdicts = [System.Collections.Generic.List[object]]::new()
$details = [System.Collections.Generic.List[object]]::new()

foreach ($target in $targets) {
    $probe = $null
    try {
        if ($target -eq $env:COMPUTERNAME) {
            $probe = & $readinessProbe $MinimumMemoryGb $MinimumFreeDiskGb $MinimumProcessorCore $MinimumProcessorMhz
        } else {
            $probe = Invoke-Command -ComputerName $target -ScriptBlock $readinessProbe `
                -ArgumentList $MinimumMemoryGb, $MinimumFreeDiskGb, $MinimumProcessorCore, $MinimumProcessorMhz -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $verdicts.Add([pscustomobject]@{
                ComputerName = $target
                Verdict = 'Unreachable'
                Caption = ''
                Build = $null
                Manufacturer = ''
                Model = ''
                Elevated = $null
                FailedChecks = ''
                UndeterminedChecks = ''
                Note = $_.Exception.Message
            })
        continue
    }

    $checks = @(Get-OpsPropertyValue -InputObject $probe -Name 'Checks')
    foreach ($check in $checks) {
        $details.Add([pscustomobject]@{
                ComputerName = $probe.ComputerName
                Check = $check.Check
                Status = $check.Status
                Actual = $check.Actual
                Required = $check.Required
                Note = $check.Note
            })
    }

    $failed = @($checks | Where-Object { $_.Status -eq 'Fail' })
    $undetermined = @($checks | Where-Object { $_.Status -eq 'Undetermined' })

    # Undetermined is never folded into Ready. An unread TPM is not an absent TPM,
    # and reporting it as ready is how a rollout discovers the blocker at deploy time.
    $verdict = if ($failed.Count -gt 0) {
        'Blocked'
    } elseif ($undetermined.Count -gt 0) {
        'Undetermined'
    } else {
        'Ready'
    }

    $verdicts.Add([pscustomobject]@{
            ComputerName = $probe.ComputerName
            Verdict = $verdict
            Caption = $probe.Caption
            Build = $probe.Build
            Manufacturer = $probe.Manufacturer
            Model = $probe.Model
            Elevated = $probe.Elevated
            FailedChecks = (@($failed | ForEach-Object { $_.Check }) -join ';')
            UndeterminedChecks = (@($undetermined | ForEach-Object { $_.Check }) -join ';')
            Note = if (-not $probe.Elevated -and $undetermined.Count -gt 0) { 'Re-run elevated. Some checks could not be read without it.' } else { '' }
        })
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'readiness-verdict' -Record @($verdicts) -Directory $runDirectory
    Export-OpsReport -Name 'readiness-checks' -Record @($details) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    ComputersQueried = @($targets).Count
    ReadyCount = @($verdicts | Where-Object { $_.Verdict -eq 'Ready' }).Count
    BlockedCount = @($verdicts | Where-Object { $_.Verdict -eq 'Blocked' }).Count
    UndeterminedCount = @($verdicts | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    UnreachableCount = @($verdicts | Where-Object { $_.Verdict -eq 'Unreachable' }).Count
    MostCommonBlocker = (@($details | Where-Object { $_.Status -eq 'Fail' } | Group-Object Check | Sort-Object Count -Descending | Select-Object -First 1 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join '')
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
