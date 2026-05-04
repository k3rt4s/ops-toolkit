<#
.SYNOPSIS
Clear user temp and common drive temp folders.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Clear-TempFolders.ps1 -Full.
- Run with -WhatIf first before deleting temp content.

.STATUS
Active PowerShell replacement for Clear-UserAndDriveTempFolders.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$TempPath = @(
        $env:TEMP,
        'C:\temp',
        'D:\temp',
        'E:\temp',
        'I:\temp'
    )
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

foreach ($path in $TempPath | Where-Object { $_ }) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        continue
    }

    Get-ChildItem -LiteralPath $path -Force -ErrorAction Continue | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove temp item')) {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Continue
        }
    }
}
