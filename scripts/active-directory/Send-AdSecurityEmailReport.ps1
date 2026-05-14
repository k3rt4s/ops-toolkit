<#
.SYNOPSIS
Generate and optionally email Active Directory security reports.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Report generation is the default. Email is sent only when -SendEmail is supplied.
- Pass SMTP settings explicitly when using -SendEmail.
- Use -ReportType PrivilegedGroupMembership for AD group membership reports.
- Use -ReportType PasswordNeverExpires for user accounts whose passwords never expire.

.PURPOSE
This script replaces the separate Domain Admins membership and password-never-
expires email reports with one AD security report command.

.REQUIRED SYNTAX
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PrivilegedGroupMembership -GroupName "Domain Admins"
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires -SendEmail -SmtpServer smtp.example.com -From secops@example.com -To admins@example.com

.OUTPUTS
Writes HTML, CSV, and JSON reports under reports\active-directory by default.
Returns a summary object with output paths and row counts.

.STATUS
Active script kept in the reorganized ops-toolkit repo. Replaces
Send-AdDomainAdminsEmailReport.ps1 and Send-AdPasswordNeverExpiresEmailReport.ps1.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('PrivilegedGroupMembership', 'PasswordNeverExpires')]
    [string]$ReportType = 'PrivilegedGroupMembership',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName = 'Domain Admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [switch]$SendEmail,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$From,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$To,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ContactEmail
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PrivilegedGroupMembership -GroupName "Domain Admins"
  pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires
  pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires -SendEmail -SmtpServer smtp.example.com -From secops@example.com -To admins@example.com

Options:
  -ReportType       PrivilegedGroupMembership or PasswordNeverExpires.
  -GroupName        AD group to report. Defaults to Domain Admins.
  -OutputDirectory  Report output directory.
  -SendEmail        Send the HTML report by email.
  -SmtpServer       SMTP server required with -SendEmail.
  -From             Sender address required with -SendEmail.
  -To               Recipient address list required with -SendEmail.
  -ContactEmail     Optional contact mailbox included in the report text.
'@
}

if ($SendEmail -and (-not $SmtpServer -or -not $From -or -not $To)) {
    Show-Usage
    exit 2
}

function Get-PrivilegedGroupMembershipReport {
    @(Get-ADGroupMember -Identity $GroupName -Recursive |
            Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
            Sort-Object Name)
}

function Get-PasswordNeverExpiresReport {
    @(Search-ADAccount -PasswordNeverExpires -UsersOnly |
            Select-Object Name, SamAccountName, Enabled, DistinguishedName |
            Sort-Object Name)
}

function Format-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedAt,

        [Parameter()]
        [string]$ReportContactEmail
    )

    $contactLine = if ($ReportContactEmail) { "<p>Contact <a href=`"mailto:$ReportContactEmail`">$ReportContactEmail</a> with questions or concerns.</p>" } else { '' }
    @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>$Title</title>
</head>
<body>
  <h1>$Title</h1>
  <p>Generated on $GeneratedAt.</p>
  $contactLine
  $($Rows | ConvertTo-Html -Fragment)
</body>
</html>
"@
}

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$generatedAt = Get-Date

$rows = if ($ReportType -eq 'PrivilegedGroupMembership') {
    Get-PrivilegedGroupMembershipReport
} else {
    Get-PasswordNeverExpiresReport
}

$slug = if ($ReportType -eq 'PrivilegedGroupMembership') { "group-$($GroupName -replace '[^A-Za-z0-9]+', '-')" } else { 'password-never-expires' }
$title = if ($ReportType -eq 'PrivilegedGroupMembership') { "$GroupName membership report" } else { 'Password never expires report' }
$htmlPath = Join-Path $resolvedOutputDirectory "ad-security-$slug-$timestamp.html"
$csvPath = Join-Path $resolvedOutputDirectory "ad-security-$slug-$timestamp.csv"
$jsonPath = Join-Path $resolvedOutputDirectory "ad-security-$slug-$timestamp.json"
$html = Format-HtmlReport -Title $title -Rows $rows -GeneratedAt $generatedAt -ReportContactEmail $ContactEmail

$html | Set-Content -LiteralPath $htmlPath -Encoding utf8
$rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
Set-Content -LiteralPath $jsonPath -Value (@($rows) | ConvertTo-Json -Depth 4) -Encoding utf8

if ($SendEmail) {
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject "$title $generatedAt" -Body $html -BodyAsHtml
}

[pscustomobject]@{
    ReportType = $ReportType
    GroupName = if ($ReportType -eq 'PrivilegedGroupMembership') { $GroupName } else { $null }
    RowCount = @($rows).Count
    HtmlPath = (Resolve-Path -LiteralPath $htmlPath).Path
    CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
    JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    EmailSent = [bool]$SendEmail
}
