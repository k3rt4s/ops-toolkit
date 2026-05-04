<#
.SYNOPSIS
Remove Windows printer connections.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Remove-WindowsPrinterConnections.ps1 -Full.
- Run with -WhatIf first before removing printer connections.

.STATUS
Active PowerShell replacement for Remove-LegacyPrinterConnection.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$PrinterName,

    [Parameter()]
    [switch]$AllConnectionPrinters
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$printers = if ($AllConnectionPrinters) {
    Get-Printer | Where-Object { $_.Type -eq 'Connection' }
} elseif ($PrinterName) {
    foreach ($name in $PrinterName) {
        Get-Printer -Name $name -ErrorAction Stop
    }
} else {
    throw 'Specify -PrinterName or -AllConnectionPrinters.'
}

foreach ($printer in $printers) {
    if ($PSCmdlet.ShouldProcess($printer.Name, 'Remove printer')) {
        Remove-Printer -Name $printer.Name
    }
}
