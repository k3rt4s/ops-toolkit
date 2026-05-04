<#
.SYNOPSIS
Set one custom HTTP response header on one IIS site.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-IisCustomHeaderForSite.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- Run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules WebAdministration
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SiteName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderValue
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction Stop

$sitePath = "IIS:\Sites\$SiteName"
if (-not (Test-Path -LiteralPath $sitePath)) {
    throw "IIS site '$SiteName' was not found."
}

$filter = 'system.webServer/httpProtocol/customHeaders'
$existing = Get-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection |
    Where-Object { $_.name -eq $HeaderName }

if ($existing) {
    if ($PSCmdlet.ShouldProcess($SiteName, "Update HTTP response header $HeaderName")) {
        Set-WebConfigurationProperty -PSPath $sitePath -Filter "$filter/add[@name='$HeaderName']" -Name value -Value $HeaderValue
    }
} elseif ($PSCmdlet.ShouldProcess($SiteName, "Add HTTP response header $HeaderName")) {
    Add-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection -Value @{
        name = $HeaderName
        value = $HeaderValue
    }
}
