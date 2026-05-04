<#
.SYNOPSIS
Set one custom HTTP response header on all IIS sites.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-IisCustomHeaderForAllSites.ps1 -Full or by opening the script.
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
    [string]$HeaderName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderValue
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction Stop

$filter = 'system.webServer/httpProtocol/customHeaders'

foreach ($site in Get-ChildItem -Path IIS:\Sites) {
    $sitePath = "IIS:\Sites\$($site.Name)"
    $existing = Get-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection |
        Where-Object { $_.name -eq $HeaderName }

    if ($existing) {
        if ($PSCmdlet.ShouldProcess($site.Name, "Update HTTP response header $HeaderName")) {
            Set-WebConfigurationProperty -PSPath $sitePath -Filter "$filter/add[@name='$HeaderName']" -Name value -Value $HeaderValue
        }
    } elseif ($PSCmdlet.ShouldProcess($site.Name, "Add HTTP response header $HeaderName")) {
        Add-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection -Value @{
            name = $HeaderName
            value = $HeaderValue
        }
    }
}
