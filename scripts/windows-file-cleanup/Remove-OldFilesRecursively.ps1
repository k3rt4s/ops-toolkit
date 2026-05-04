<#
.SYNOPSIS
Delete files older than a supplied day threshold from a folder tree.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Remove-OldFilesRecursively.ps1 -Full.
- Run with -WhatIf first before deleting files.

.STATUS
Active PowerShell replacement for Remove-OldFilesRecursively.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Path,

    [Parameter(Mandatory)]
    [ValidateRange(1, 3650)]
    [int]$OlderThanDays
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$cutoff = (Get-Date).AddDays(-$OlderThanDays)
Get-ChildItem -LiteralPath $Path -Recurse -File -Force | Where-Object {
    $_.LastWriteTime -lt $cutoff
} | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.FullName, "Remove file older than $OlderThanDays days")) {
        Remove-Item -LiteralPath $_.FullName -Force
    }
}
