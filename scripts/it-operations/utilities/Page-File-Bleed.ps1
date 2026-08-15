<#
.SYNOPSIS
Force Windows to release page-file backed memory by removing and immediately restoring the page-file configuration.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- State-changing and disruptive. It removes every page file, waits, then restores
  the exact configuration it captured first. Do not run it on a machine doing
  anything that matters.
- Run from an elevated shell. The script exits with an error if it is not elevated.
- Nothing happens without -Execute. Without it the script prints what it would do
  and exits 0. This gate predates the repo's -WhatIf convention; -WhatIf is also
  honoured through ShouldProcess, so either will stop it.
- Requires a reboot afterwards only if the restore step fails. The restore runs in a
  finally block precisely so an error mid-operation still puts the configuration back.
- If no Win32_PageFileSetting rows exist, the machine is on an automatically managed
  page file and the script exits without changing anything.

Purpose:
Windows will leave memory paged out long after the pressure that caused it has gone,
which shows up as a machine that feels slow with plenty of free RAM. Removing the
page file forces the contents back into memory or discards them, and restoring it
immediately puts the configuration back. This is a deliberate blunt instrument for a
workstation after a heavy batch job, not maintenance to schedule.

The original configuration is snapshotted before any change and restored in a finally
block, so an interruption cannot leave the machine with no page file.

Required syntax:
pwsh -File .\scripts\it-operations\utilities\Page-File-Bleed.ps1
pwsh -File .\scripts\it-operations\utilities\Page-File-Bleed.ps1 -Execute
pwsh -File .\scripts\it-operations\utilities\Page-File-Bleed.ps1 -Execute -WhatIf

.OUTPUTS
Writes progress to the information stream. No report files.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Legacy shape: it gates on
-Execute rather than on -WhatIf alone, and it writes no plan or state report, unlike
the newer state-changing scripts in this repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Execute
)

if (-not $Execute) {
    Write-Information "Dry run only. Pass -Execute to modify page-file configuration." -InformationAction Continue
    Exit 0
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    Exit 1
}

Write-Information "Checking current memory state..." -InformationAction Continue
$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$CurrentAutomatic = $ComputerSystem.AutomaticManagedPagefile

# Snapshot every configured page file before changing anything.
$PageSettings = @(Get-CimInstance Win32_PageFileSetting)
if ($PageSettings.Count -eq 0) {
    Write-Warning "No Win32_PageFileSetting rows exist. AutomaticManagedPagefile=$CurrentAutomatic. No changes made."
    Exit 0
}

$OriginalSettings = @(
    $PageSettings | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            InitialSize = $_.InitialSize
            MaximumSize = $_.MaximumSize
        }
    }
)
$TargetDescription = ($OriginalSettings.Name -join ", ")

if (-not $PSCmdlet.ShouldProcess($TargetDescription, "Temporarily remove and restore page-file configuration")) {
    Exit 0
}

try {
    Set-CimInstance -Query 'Select * from Win32_ComputerSystem' -Property @{ AutomaticManagedPagefile = $false }
    Write-Information "Temporarily removing page-file configuration..." -InformationAction Continue
    $PageSettings | Remove-CimInstance
    Start-Sleep -Seconds 5
}
finally {
    Write-Information "Restoring original page-file configuration..." -InformationAction Continue
    foreach ($Setting in $OriginalSettings) {
        $Existing = Get-CimInstance Win32_PageFileSetting | Where-Object { $_.Name -eq $Setting.Name }
        if ($null -eq $Existing) {
            New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                Name = $Setting.Name
                InitialSize = $Setting.InitialSize
                MaximumSize = $Setting.MaximumSize
            }
        } elseif (
            $Existing.InitialSize -ne $Setting.InitialSize -or
            $Existing.MaximumSize -ne $Setting.MaximumSize
        ) {
            Set-CimInstance -InputObject $Existing -Property @{
                InitialSize = $Setting.InitialSize
                MaximumSize = $Setting.MaximumSize
            }
        }
    }
    $RestoredBeforeAutomatic = @(Get-CimInstance Win32_PageFileSetting)
    $RestoreProblems = @(
        foreach ($Setting in $OriginalSettings) {
            $Actual = $RestoredBeforeAutomatic | Where-Object { $_.Name -eq $Setting.Name }
            if (
                $null -eq $Actual -or
                $Actual.InitialSize -ne $Setting.InitialSize -or
                $Actual.MaximumSize -ne $Setting.MaximumSize
            ) {
                $Setting.Name
            }
        }
    )
    Set-CimInstance -Query "Select * from Win32_ComputerSystem" -Property @{
        AutomaticManagedPagefile = $CurrentAutomatic
    }
    if ($RestoreProblems.Count -gt 0) {
        throw "Page-file restore validation failed for: $($RestoreProblems -join ', ')"
    }
}

$RestoredAutomatic = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
if ($RestoredAutomatic -ne $CurrentAutomatic) {
    Write-Error "AutomaticManagedPagefile restore validation failed."
    Exit 1
}
Write-Information "Operation complete. Page-file configuration restored and validated." -InformationAction Continue
