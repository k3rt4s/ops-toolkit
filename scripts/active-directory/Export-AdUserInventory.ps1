<#
.SYNOPSIS
Export Active Directory user inventory reports to CSV.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Use -SearchBase and -Server to scope large domains.
- Use -ReportType Attributes for full user attributes, DistinguishedNames for a compact DN report, or All for both.
- Generated reports are written under reports\active-directory by default.

.PURPOSE
This script replaces the separate AD user attribute and distinguished-name CSV
exports with one report-driven inventory command.

.REQUIRED SYNTAX
pwsh -File .\scripts\active-directory\Export-AdUserInventory.ps1 -ReportType Attributes
pwsh -File .\scripts\active-directory\Export-AdUserInventory.ps1 -ReportType DistinguishedNames -SearchBase "OU=Users,DC=example,DC=com"
pwsh -File .\scripts\active-directory\Export-AdUserInventory.ps1 -ReportType All -OutputDirectory .\reports\active-directory

.OUTPUTS
Writes one or more CSV reports and returns a summary object with output paths
and row counts.

.STATUS
Active PowerShell replacement for Export-AdUserAttributesToExcel.vbs,
Export-AdUserDistinguishedNamesToExcel.vbs, and the previous split PowerShell
export scripts.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Attributes', 'DistinguishedNames', 'All')]
    [string]$ReportType = 'Attributes',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [Parameter()]
    [string]$LdapFilter = '(objectClass=user)'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-AdUserQueryParameter {
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
        'ProxyAddresses',
        'UserPrincipalName',
        'Enabled',
        'DistinguishedName'
    )

    $queryParameters = @{
        LDAPFilter = $LdapFilter
        Properties = $properties
    }

    if ($SearchBase) {
        $queryParameters.SearchBase = $SearchBase
        $queryParameters.SearchScope = $SearchScope
    }
    if ($Server) {
        $queryParameters.Server = $Server
    }

    $queryParameters
}

function Select-AdUserAttributeReport {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$User
    )

    $User | Select-Object `
        SamAccountName,
    Name,
    Enabled,
    UserPrincipalName,
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
    @{ Name = 'SecondarySmtpAddresses'; Expression = { (($_.ProxyAddresses | Where-Object { $_ -cmatch '^smtp:' }) -replace '^smtp:', '') -join ';' } }
}

function Select-AdUserDistinguishedNameReport {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$User
    )

    $User | Select-Object -Property Name, SamAccountName, UserPrincipalName, Enabled, DistinguishedName
}

function Export-Report {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $Directory "ad-user-$Name-$timestamp.csv"
    $Rows | Export-Csv -Path $path -NoTypeInformation -Encoding utf8

    [pscustomobject]@{
        ReportName = $Name
        OutputPath = (Resolve-Path -LiteralPath $path).Path
        RowCount = @($Rows).Count
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$queryParameters = Get-AdUserQueryParameter
$users = @(Get-ADUser @queryParameters | Sort-Object -Property Name)
$exports = [System.Collections.Generic.List[object]]::new()

if ($ReportType -in @('Attributes', 'All')) {
    $rows = @(Select-AdUserAttributeReport -User $users)
    $exports.Add((Export-Report -Name 'attributes' -Rows $rows -Directory $resolvedOutputDirectory))
}

if ($ReportType -in @('DistinguishedNames', 'All')) {
    $rows = @(Select-AdUserDistinguishedNameReport -User $users)
    $exports.Add((Export-Report -Name 'distinguished-names' -Rows $rows -Directory $resolvedOutputDirectory))
}

[pscustomobject]@{
    ReportType = $ReportType
    SearchBase = $SearchBase
    SearchScope = if ($SearchBase) { $SearchScope } else { $null }
    Server = $Server
    LdapFilter = $LdapFilter
    UserCount = @($users).Count
    Reports = @($exports)
}
