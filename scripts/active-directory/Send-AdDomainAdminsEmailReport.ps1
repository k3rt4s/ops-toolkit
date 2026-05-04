<#
.SYNOPSIS
Generate or email an HTML report of privileged AD group membership.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass mail settings on the command line only when using -SendEmail.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName = 'Domain Admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = '.\reports\active-directory\domain-admins.html',

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
  pwsh -File .\scripts\active-directory\Send-AdDomainAdminsEmailReport.ps1
  pwsh -File .\scripts\active-directory\Send-AdDomainAdminsEmailReport.ps1 -GroupName "Domain Admins" -OutputPath .\reports\active-directory\domain-admins.html
  pwsh -File .\scripts\active-directory\Send-AdDomainAdminsEmailReport.ps1 -SendEmail -SmtpServer smtp.example.com -From secops@example.com -To admins@example.com

Options:
  -GroupName     AD group to report. Defaults to Domain Admins.
  -OutputPath    HTML report path.
  -SendEmail     Send the report by email.
  -SmtpServer    SMTP server required with -SendEmail.
  -From          Sender address required with -SendEmail.
  -To            Recipient address list required with -SendEmail.
  -ContactEmail  Optional contact mailbox included in the report text.
'@
}

if ($SendEmail -and (-not $SmtpServer -or -not $From -or -not $To)) {
    Show-Usage
    exit 2
}

$members = Get-ADGroupMember -Identity $GroupName -Recursive |
    Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
    Sort-Object Name

$generatedAt = Get-Date
$contactLine = if ($ContactEmail) { "<p>Contact <a href=`"mailto:$ContactEmail`">$ContactEmail</a> with questions or concerns.</p>" } else { '' }
$html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>$GroupName membership report</title>
</head>
<body>
  <h1>$GroupName membership report</h1>
  <p>Generated on $generatedAt.</p>
  $contactLine
  $($members | ConvertTo-Html -Fragment)
</body>
</html>
"@

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$html | Set-Content -LiteralPath $OutputPath -Encoding utf8

if ($SendEmail) {
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject "$GroupName membership report $generatedAt" -Body $html -BodyAsHtml
}

[pscustomobject]@{
    GroupName = $GroupName
    MemberCount = @($members).Count
    OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    EmailSent = [bool]$SendEmail
}
