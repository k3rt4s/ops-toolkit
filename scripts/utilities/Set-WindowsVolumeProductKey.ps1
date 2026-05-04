<#
.SYNOPSIS
Set a Windows volume product key.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-WindowsVolumeProductKey.ps1 -Full.
- Run from an elevated shell.
- Run with -WhatIf first before applying a product key.

.STATUS
Active PowerShell replacement for Set-WindowsVolumeProductKey.vbs.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Z0-9]{5}(-?[A-Z0-9]{5}){4}$')]
    [string]$ProductKey
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$normalizedKey = $ProductKey.ToUpperInvariant()
if ($PSCmdlet.ShouldProcess('SoftwareLicensingService', 'Install Windows product key')) {
    Invoke-CimMethod -ClassName SoftwareLicensingService -MethodName InstallProductKey -Arguments @{
        ProductKey = $normalizedKey
    } | Out-Null

    Invoke-CimMethod -ClassName SoftwareLicensingService -MethodName RefreshLicenseStatus | Out-Null
}
