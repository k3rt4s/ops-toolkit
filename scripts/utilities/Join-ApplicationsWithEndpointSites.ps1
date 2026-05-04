<#
.SYNOPSIS
Join application inventory rows with matching endpoint site data.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Join-ApplicationsWithEndpointSites.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ })]
    [string]$ApplicationsPath = '.\applications.csv',

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ })]
    [string]$EndpointsPath = '.\endpoints.csv',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = '.\new_list.csv'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$applications = Import-Csv -LiteralPath $ApplicationsPath
$endpoints = Import-Csv -LiteralPath $EndpointsPath
$endpointByName = @{}

foreach ($endpoint in $endpoints) {
    if ($endpoint.'Endpoint Name') {
        $endpointByName[$endpoint.'Endpoint Name'] = $endpoint
    }
}

$results = foreach ($application in $applications) {
    $agentName = $application.'Agent Name'
    if ($agentName -and $endpointByName.ContainsKey($agentName)) {
        $endpoint = $endpointByName[$agentName]
        [pscustomobject]@{
            'App Name' = $application.Name
            'Endpoint Name' = $agentName
            Site = $endpoint.Site
            'Machine Type' = $application.'Machine Type'
        }
    }
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
Write-Information "Matched $(@($results).Count) application endpoints. Output: $OutputPath" -InformationAction Continue


