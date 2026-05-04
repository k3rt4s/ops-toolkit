<#
.SYNOPSIS
Export AD user distinguished names to CSV.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Review parameters with Get-Help .\Export-AdUserDistinguishedNamesToCsv.ps1 -Full.

.STATUS
Active PowerShell replacement for Export-AdUserDistinguishedNamesToExcel.vbs.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\reports\active-directory\ad-user-distinguished-names.csv'),

    [Parameter()]
    [string]$SearchBase
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$params = @{
    Filter = '*'
    Properties = 'DistinguishedName'
}
if ($SearchBase) {
    $params.SearchBase = $SearchBase
}

$directory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $directory -Force | Out-Null

Get-ADUser @params |
    Select-Object -Property Name, SamAccountName, DistinguishedName |
    Sort-Object -Property Name |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

Write-Information "Report written to $OutputPath" -InformationAction Continue
