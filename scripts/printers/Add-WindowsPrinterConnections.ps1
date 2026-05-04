<#
.SYNOPSIS
Add one or more Windows printer connections.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass printer UNC paths with -PrinterPath or provide a text file with -PrinterListPath.
- Use one printer UNC path per line in the list file; blank lines and # comments are ignored.
- Run with -WhatIf first before adding printer connections.

.STATUS
Active PowerShell replacement for Add-LegacyPrinterConnections.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$PrinterPath,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PrinterListPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\printers\Add-WindowsPrinterConnections.ps1 -PrinterPath "\\print01\Accounting","\\print01\Warehouse" -WhatIf
  pwsh -File .\scripts\printers\Add-WindowsPrinterConnections.ps1 -PrinterListPath .\data\printers\printers.example.txt -WhatIf

Options:
  -PrinterPath      One or more printer UNC paths.
  -PrinterListPath  Text file containing one printer UNC path per line.
  -WhatIf           Preview printer connections without adding them.
'@
}

if (-not $PrinterPath -and -not $PrinterListPath) {
    Show-Usage
    exit 2
}

$printers = @()
if ($PrinterPath) {
    $printers += $PrinterPath
}

if ($PrinterListPath) {
    $printers += Get-Content -LiteralPath $PrinterListPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_.TrimStart() -notlike '#*' }
}

$printers = $printers | Select-Object -Unique
if (-not $printers) {
    throw 'No printer paths were provided after reading the supplied arguments.'
}

foreach ($printer in $printers) {
    if ($PSCmdlet.ShouldProcess($printer, 'Add printer connection')) {
        Add-Printer -ConnectionName $printer
    }
}
