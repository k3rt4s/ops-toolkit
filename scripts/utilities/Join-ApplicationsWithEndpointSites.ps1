<#
.SYNOPSIS
Join application inventory rows with endpoint site data and write matched/unmatched reports.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Confirm the input CSV column names before running.
- Use -IncludeUnmatchedApplications when review needs to show missing endpoint-site matches.
- Generated reports are written under reports\utilities by default.

Purpose:
Use this report-only utility to join application inventory rows to endpoint
site data. By default it joins application "Agent Name" to endpoint "Endpoint
Name" and writes matched rows, optional unmatched rows, and a summary JSON file.

Required syntax:
pwsh -File .\scripts\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv
pwsh -File .\scripts\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv -IncludeUnmatchedApplications

.OUTPUTS
Writes matched CSV and summary JSON reports under reports\utilities by default.
Optionally writes unmatched application rows. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ApplicationsPath = '.\applications.csv',

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EndpointsPath = '.\endpoints.csv',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationJoinColumn = 'Agent Name',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EndpointJoinColumn = 'Endpoint Name',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationNameColumn = 'Name',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EndpointSiteColumn = 'Site',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MachineTypeColumn = 'Machine Type',

    [Parameter()]
    [switch]$CaseSensitive,

    [Parameter()]
    [switch]$IncludeUnmatchedApplications,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\utilities'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'applications-endpoint-sites'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Assert-CsvColumn {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Row,

        [Parameter(Mandatory = $true)]
        [string[]]$ColumnName,

        [Parameter(Mandatory = $true)]
        [string]$InputName
    )

    if ($Row.Count -eq 0) {
        return
    }

    $properties = @($Row[0].PSObject.Properties.Name)
    foreach ($column in $ColumnName) {
        if ($column -notin $properties) {
            throw "$InputName is missing required column '$column'. Found columns: $($properties -join ', ')"
        }
    }
}

function Get-JoinKey {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $key = ([string]$Value).Trim()
    if ($CaseSensitive) {
        return $key
    }

    $key.ToLowerInvariant()
}

$applications = @(Import-Csv -LiteralPath $ApplicationsPath)
$endpoints = @(Import-Csv -LiteralPath $EndpointsPath)
Assert-CsvColumn -Row $applications -ColumnName @($ApplicationJoinColumn, $ApplicationNameColumn, $MachineTypeColumn) -InputName 'Applications CSV'
Assert-CsvColumn -Row $endpoints -ColumnName @($EndpointJoinColumn, $EndpointSiteColumn) -InputName 'Endpoints CSV'

$endpointByName = @{}
$duplicateEndpointKeys = [System.Collections.Generic.List[string]]::new()
foreach ($endpoint in $endpoints) {
    $key = Get-JoinKey -Value $endpoint.$EndpointJoinColumn
    if (-not $key) {
        continue
    }

    if ($endpointByName.ContainsKey($key)) {
        $duplicateEndpointKeys.Add($key)
        continue
    }

    $endpointByName[$key] = $endpoint
}

$matched = [System.Collections.Generic.List[object]]::new()
$unmatched = [System.Collections.Generic.List[object]]::new()
foreach ($application in $applications) {
    $agentName = [string]$application.$ApplicationJoinColumn
    $key = Get-JoinKey -Value $agentName
    if ($key -and $endpointByName.ContainsKey($key)) {
        $endpoint = $endpointByName[$key]
        $matched.Add([pscustomobject]@{
                'App Name' = $application.$ApplicationNameColumn
                'Endpoint Name' = $agentName
                Site = $endpoint.$EndpointSiteColumn
                'Machine Type' = $application.$MachineTypeColumn
                MatchKey = $key
            })
    } else {
        $unmatched.Add([pscustomobject]@{
                'App Name' = $application.$ApplicationNameColumn
                'Endpoint Name' = $agentName
                'Machine Type' = $application.$MachineTypeColumn
                MatchKey = $key
                Reason = if ($key) { 'No endpoint row matched the application join key.' } else { 'Application join key was empty.' }
            })
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix

# Unmatched is always written, even when it was not requested and is therefore empty.
# A report that exists and is empty proves the join ran and found nothing left over;
# a missing file cannot be told apart from a run that never happened.
$exports = @(
    Export-OpsReport -Name 'matched' -Record @($matched) -Directory $runDirectory
    Export-OpsReport -Name 'unmatched' -Record @(if ($IncludeUnmatchedApplications) { $unmatched } else { @() }) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    ApplicationsPath = (Resolve-Path -LiteralPath $ApplicationsPath).Path
    EndpointsPath = (Resolve-Path -LiteralPath $EndpointsPath).Path
    CaseSensitive = [bool]$CaseSensitive
    IncludedUnmatched = [bool]$IncludeUnmatchedApplications
    ApplicationCount = @($applications).Count
    EndpointCount = @($endpoints).Count
    MatchedCount = $matched.Count
    UnmatchedCount = $unmatched.Count
    DuplicateEndpointKeyCount = $duplicateEndpointKeys.Count
    DuplicateEndpointKeys = @($duplicateEndpointKeys)
    Exports = @($exports)
}

Write-Information "Matched $($matched.Count) application endpoints. Output: $runDirectory" -InformationAction Continue
Export-OpsSummary -Summary $summary -Directory $runDirectory
