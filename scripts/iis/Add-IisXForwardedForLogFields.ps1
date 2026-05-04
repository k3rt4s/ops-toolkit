<#
.SYNOPSIS
Add X-Forwarded-For and custom log fields to IIS site defaults.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Add-IisXForwardedForLogFields.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- Run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules WebAdministration
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [hashtable[]]$CustomField = @(
        @{
            logFieldName = 'X-Forwarded-For'
            sourceName = 'X-Forwarded-For'
            sourceType = 'RequestHeader'
        }
    )
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction Stop

$filter = 'system.applicationHost/sites/siteDefaults/logFile/customFields'
foreach ($field in $CustomField) {
    $name = [string]$field.logFieldName
    if ($PSCmdlet.ShouldProcess('IIS siteDefaults', "Add custom log field $name")) {
        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $filter -Name '.' -Value $field
    }
}
