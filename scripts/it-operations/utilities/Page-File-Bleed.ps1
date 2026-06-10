[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [switch]$Execute
)

if (-not $Execute) {
    Write-Host "Dry run only. Pass -Execute to modify page-file configuration."
    Exit 0
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    Exit 1
}

Write-Host "Checking current memory state..." -ForegroundColor Cyan
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
    Set-CimInstance -Query "Select * from Win32_ComputerSystem" -Property @{AutomaticManagedPagefile=$False}
    Write-Host "Temporarily removing page-file configuration..." -ForegroundColor Yellow
    $PageSettings | Remove-CimInstance
    Start-Sleep -Seconds 5
}
finally {
    Write-Host "Restoring original page-file configuration..." -ForegroundColor Green
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
Write-Host "Operation complete. Page-file configuration restored and validated." -ForegroundColor Cyan
