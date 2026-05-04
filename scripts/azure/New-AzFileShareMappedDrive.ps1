<#
.SYNOPSIS
Create a persistent Windows mapped drive for an Azure file share.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\New-AzFileShareMappedDrive.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Z]$')]
    [string]$DriveLetter,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$StorageAccountName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ShareName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$StorageAccountKey
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$root = "\\$StorageAccountName.file.core.windows.net\$ShareName"
$userName = "Azure\$StorageAccountName"
$target = "$DriveLetter`:"

if (Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($target, 'Remove existing mapped drive')) {
        Remove-PSDrive -Name $DriveLetter -Force
    }
}

if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Store Azure Files credential in Windows Credential Manager')) {
    cmdkey.exe /add:"$StorageAccountName.file.core.windows.net" /user:$userName /pass:$StorageAccountKey | Out-Null
}

if ($PSCmdlet.ShouldProcess($target, "Map Azure file share $root")) {
    New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $root -Persist | Out-Null
}

Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue

