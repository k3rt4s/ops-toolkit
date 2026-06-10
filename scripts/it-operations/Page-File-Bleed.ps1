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

# Query existing pagefile settings before changing anything.
$PageSetting = Get-CimInstance Win32_PageFileSetting
if ($null -eq $PageSetting) {
    Write-Warning "No active page file detected or already managed dynamically by OS."
    Exit 0
}

$OriginalInitial = $PageSetting.InitialSize
$OriginalMaximum = $PageSetting.MaximumSize
$OriginalName = $PageSetting.Name

if (-not $PSCmdlet.ShouldProcess($OriginalName, "Temporarily remove and restore page-file configuration")) {
    Exit 0
}

try {
    if ($CurrentAutomatic) {
        Set-CimInstance -Query "Select * from Win32_ComputerSystem" -Property @{AutomaticManagedPagefile=$False}
    }

    Write-Host "Temporarily removing page-file configuration..." -ForegroundColor Yellow
    $PageSetting | Remove-CimInstance
    Start-Sleep -Seconds 5
}
finally {
    Write-Host "Restoring original page-file configuration..." -ForegroundColor Green
    if ($CurrentAutomatic) {
        Set-CimInstance -Query "Select * from Win32_ComputerSystem" -Property @{AutomaticManagedPagefile=$True}
    } else {
        New-CimInstance -ClassName Win32_PageFileSetting -Property @{
            Name = $OriginalName
            InitialSize = $OriginalInitial
            MaximumSize = $OriginalMaximum
        }
    }
}

Write-Host "Operation complete. Virtual memory state normalized." -ForegroundColor Cyan
