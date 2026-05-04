<#
.SYNOPSIS
Export commonly used AD user attributes to CSV.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Review parameters with Get-Help .\Export-AdUserAttributesToCsv.ps1 -Full.

.STATUS
Active PowerShell replacement for Export-AdUserAttributesToExcel.vbs.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\reports\active-directory\ad-user-attributes.csv'),

    [Parameter()]
    [string]$SearchBase
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$properties = @(
    'GivenName',
    'Surname',
    'Initials',
    'Description',
    'Office',
    'OfficePhone',
    'EmailAddress',
    'HomePage',
    'StreetAddress',
    'City',
    'State',
    'PostalCode',
    'Title',
    'Department',
    'Company',
    'Manager',
    'ProfilePath',
    'ScriptPath',
    'HomeDirectory',
    'HomeDrive',
    'LastLogonDate',
    'ProxyAddresses'
)

$params = @{
    Filter = '*'
    Properties = $properties
}
if ($SearchBase) {
    $params.SearchBase = $SearchBase
}

$directory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $directory -Force | Out-Null

Get-ADUser @params | Select-Object `
    SamAccountName,
Name,
GivenName,
Surname,
Initials,
Description,
Office,
OfficePhone,
EmailAddress,
HomePage,
StreetAddress,
City,
State,
PostalCode,
Title,
Department,
Company,
Manager,
ProfilePath,
ScriptPath,
HomeDirectory,
HomeDrive,
LastLogonDate,
DistinguishedName,
@{ Name = 'PrimarySmtpAddress'; Expression = { ($_.ProxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1) -replace '^SMTP:', '' } },
@{ Name = 'SecondarySmtpAddresses'; Expression = { (($_.ProxyAddresses | Where-Object { $_ -cmatch '^smtp:' }) -replace '^smtp:', '') -join ';' } } |
    Sort-Object -Property Name |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

Write-Information "Report written to $OutputPath" -InformationAction Continue
