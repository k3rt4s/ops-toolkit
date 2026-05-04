<#
.SYNOPSIS
Generate a password-expiry report and optionally email users or administrators.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass SMTP values explicitly when using -SendUserEmails or -SendAdminReport.
- Use -WhatIf first before sending reminder emails.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBeforeExpiry = 7,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = '.\reports\active-directory\password-expiry.html',

    [Parameter()]
    [switch]$SendUserEmails,

    [Parameter()]
    [switch]$SendAdminReport,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$From,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$AdminTo,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResetUrl
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -DaysBeforeExpiry 14 -OutputPath .\reports\active-directory\password-expiry.html
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -SendAdminReport -SmtpServer smtp.example.com -From secops@example.com -AdminTo admins@example.com -WhatIf
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -SendUserEmails -SmtpServer smtp.example.com -From secops@example.com -AdminTo admins@example.com -ResetUrl https://password.example.com -WhatIf

Options:
  -DaysBeforeExpiry  Include passwords expiring within this many days. Defaults to 7.
  -OutputPath        HTML report path.
  -SendUserEmails    Email users with mail attributes.
  -SendAdminReport   Email the admin summary report.
  -SmtpServer        SMTP server required when sending email.
  -From              Sender address required when sending email.
  -AdminTo           Admin recipient list required when sending email or when users have no email.
  -ResetUrl          Optional reset URL included in user reminders.
  -WhatIf            Preview email sends without sending messages.
'@
}

$willSendEmail = $SendUserEmails -or $SendAdminReport
if ($willSendEmail -and (-not $SmtpServer -or -not $From -or -not $AdminTo)) {
    Show-Usage
    exit 2
}

function Send-HtmlMail {
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Recipient,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Body
    )

    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $Recipient -Subject $Subject -Body $Body -BodyAsHtml
}

$today = Get-Date
$users = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } -Properties mail, givenName, SamAccountName, 'msDS-UserPasswordExpiryTimeComputed' |
    ForEach-Object {
        $rawExpiry = $_.'msDS-UserPasswordExpiryTimeComputed'
        if (-not $rawExpiry -or $rawExpiry -eq 0 -or $rawExpiry -eq 9223372036854775807) {
            return
        }

        $expiry = [datetime]::FromFileTime($rawExpiry)
        $daysRemaining = [int][math]::Floor(($expiry - $today).TotalDays)
        if ($daysRemaining -le $DaysBeforeExpiry) {
            [pscustomobject]@{
                Name = $_.Name
                SamAccountName = $_.SamAccountName
                Mail = $_.mail
                GivenName = $_.givenName
                PasswordExpires = $expiry
                DaysRemaining = $daysRemaining
                Status = if ($daysRemaining -lt 0) { 'Expired' } else { 'Expiring' }
            }
        }
    } |
    Sort-Object DaysRemaining, Name

$generatedAt = Get-Date
$html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Password expiry report</title>
</head>
<body>
  <h1>Password expiry report</h1>
  <p>Generated on $generatedAt. Threshold: $DaysBeforeExpiry days.</p>
  $($users | ConvertTo-Html -Fragment)
</body>
</html>
"@

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$html | Set-Content -LiteralPath $OutputPath -Encoding utf8

if ($SendUserEmails) {
    foreach ($user in $users) {
        $recipient = if ($user.Mail) { @($user.Mail) } else { $AdminTo }
        $displayName = if ($user.GivenName) { $user.GivenName } else { $user.Name }
        $resetLine = if ($ResetUrl) { "<p>You can reset your password here: <a href=`"$ResetUrl`">$ResetUrl</a></p>" } else { '' }
        $subject = if ($user.DaysRemaining -lt 0) {
            "Password expired for $($user.SamAccountName)"
        } else {
            "Password expires in $($user.DaysRemaining) day(s)"
        }

        $body = @"
<html>
<body>
  <p>Hello $displayName,</p>
  <p>The password for account <strong>$($user.SamAccountName)</strong> is $($user.Status.ToLowerInvariant()). Expiration date: $($user.PasswordExpires).</p>
  $resetLine
</body>
</html>
"@

        if ($PSCmdlet.ShouldProcess(($recipient -join ', '), "Send password expiry reminder for $($user.SamAccountName)")) {
            Send-HtmlMail -Recipient $recipient -Subject $subject -Body $body
        }
    }
}

if ($SendAdminReport -and $PSCmdlet.ShouldProcess(($AdminTo -join ', '), 'Send password expiry admin report')) {
    Send-HtmlMail -Recipient $AdminTo -Subject "Password expiry report $generatedAt" -Body $html
}

[pscustomobject]@{
    DaysBeforeExpiry = $DaysBeforeExpiry
    AccountCount = @($users).Count
    OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    UserEmailsEnabled = [bool]$SendUserEmails
    AdminReportEnabled = [bool]$SendAdminReport
}
