<#
.SYNOPSIS
Add one or more Windows printer connections.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Add-WindowsPrinterConnections.ps1 -Full.
- Run with -WhatIf first before adding printer connections.

.STATUS
Active PowerShell replacement for Add-LegacyPrinterConnections.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$PrinterPath = @(
        '\\10.0.0.22\4050b',
        '\\10.0.0.22\AccountingSharp',
        '\\10.0.0.22\AD - SHARP Fax',
        '\\10.0.0.22\ADPrinter - Black',
        '\\10.0.0.22\ADPrinter - Color',
        '\\10.0.0.22\BranchOffice4 - Black',
        '\\10.0.0.22\BranchOffice4 - Color',
        '\\10.0.0.22\BranchOffice4 - Sharp Fax',
        '\\10.0.0.22\BranchOffice1-HP4050A',
        '\\10.0.0.22\CertificatePrinter',
        '\\10.0.0.22\DellColorLaser',
        '\\10.0.0.22\BranchOffice3 - Black',
        '\\10.0.0.22\BranchOffice3 - HP Color CP4005-PCL6',
        '\\10.0.0.22\BranchOffice2 - Black',
        '\\10.0.0.22\BranchOffice2 - Color'
    )
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

foreach ($printer in $PrinterPath) {
    if ($PSCmdlet.ShouldProcess($printer, 'Add printer connection')) {
        Add-Printer -ConnectionName $printer
    }
}
