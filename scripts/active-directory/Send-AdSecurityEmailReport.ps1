<#
.SYNOPSIS
Generate and optionally email Active Directory security reports.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Report generation is the default. Email is sent only when -SendEmail is supplied.
- Pass SMTP settings explicitly when using -SendEmail.
- Run with -WhatIf first when sending. Reports are still written on a preview run;
  only the message is withheld.
- Use -ReportType PrivilegedGroupMembership for AD group membership reports.
- Use -ReportType PasswordNeverExpires for user accounts whose passwords never expire.

Purpose:
This script replaces the separate Domain Admins membership and password-never-
expires email reports with one AD security report command.

Required syntax:
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PrivilegedGroupMembership -GroupName "Domain Admins"
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PasswordNeverExpires -SendEmail -SmtpServer smtp.example.com -From secops@example.com -To admins@example.com

.OUTPUTS
Writes HTML, CSV, and JSON reports under reports\active-directory by default.
Returns a summary object with output paths and row counts.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Replaces
Send-AdDomainAdminsEmailReport.ps1 and Send-AdPasswordNeverExpiresEmailReport.ps1.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding(SupportsShouldProcess = $true)]
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
  -WhatIf           Write the reports but do not send the message.
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

# -WhatIf:$false throughout the reporting path. Sending the mail is the change being
# previewed; writing the report is the preview itself, and the summary below resolves
# these paths. Without this a preview run creates no directory and the Resolve-Path
# immediately below throws.
New-Item -ItemType Directory -Path $OutputDirectory -Force -WhatIf:$false | Out-Null
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

$html | Set-Content -LiteralPath $htmlPath -Encoding utf8 -WhatIf:$false
$rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $jsonPath -Value (@($rows) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

$emailResult = if (-not $SendEmail) {
    'NotRequested'
} elseif ($PSCmdlet.ShouldProcess(($To -join ', '), "Send $title")) {
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject "$title $generatedAt" -Body $html -BodyAsHtml
    'Sent'
} else {
    'Previewed'
}

[pscustomobject]@{
    ReportType = $ReportType
    GroupName = if ($ReportType -eq 'PrivilegedGroupMembership') { $GroupName } else { $null }
    RowCount = @($rows).Count
    HtmlPath = (Resolve-Path -LiteralPath $htmlPath).Path
    CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
    JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    # EmailSent stays a boolean for anything already reading it, and is only true when
    # a message really went out. EmailResult tells the three cases apart.
    EmailSent = ($emailResult -eq 'Sent')
    EmailResult = $emailResult
}
