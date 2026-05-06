<#
.SYNOPSIS
Generate password-expiry reminder plans and optionally email users or administrators.

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
- Report generation is the default. Email is sent only with -SendUserEmails or -SendAdminReport.
- Always run with -WhatIf first before sending reminder emails.
- Pass SMTP values explicitly when using -SendUserEmails or -SendAdminReport.
- Generated reports are written under reports\active-directory by default.

.PURPOSE
Use this to identify enabled AD users whose passwords are expired or expiring
soon, write report artifacts, and optionally send user reminder emails and/or
an admin summary.

.REQUIRED SYNTAX
pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1
pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -DaysBeforeExpiry 14 -OutputDirectory .\reports\active-directory
pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -SendUserEmails -SmtpServer smtp.example.com -From secops@example.com -AdminTo admins@example.com -ResetUrl https://password.example.com -WhatIf

.OUTPUTS
Writes HTML, CSV, JSON, plan, and state files under reports\active-directory by
default. Returns a summary object with output paths and send counts.

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
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

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
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -DaysBeforeExpiry 14 -OutputDirectory .\reports\active-directory
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -SendAdminReport -SmtpServer smtp.example.com -From secops@example.com -AdminTo admins@example.com -WhatIf
  pwsh -File .\scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1 -SendUserEmails -SmtpServer smtp.example.com -From secops@example.com -AdminTo admins@example.com -ResetUrl https://password.example.com -WhatIf

Options:
  -DaysBeforeExpiry  Include passwords expiring within this many days. Defaults to 7.
  -OutputDirectory   Report output directory.
  -SendUserEmails    Email users with mail attributes; AdminTo receives fallback notices.
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Recipient,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($PSCmdlet.ShouldProcess(($Recipient -join ', '), $Description)) {
        Send-MailMessage -SmtpServer $SmtpServer -From $From -To $Recipient -Subject $Subject -Body $Body -BodyAsHtml
        return 'Sent'
    }

    'Previewed'
}

function Get-PasswordExpiryUser {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Today
    )

    @(Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } -Properties mail, givenName, SamAccountName, 'msDS-UserPasswordExpiryTimeComputed' |
            ForEach-Object {
                $rawExpiry = $_.'msDS-UserPasswordExpiryTimeComputed'
                if (-not $rawExpiry -or $rawExpiry -eq 0 -or $rawExpiry -eq 9223372036854775807) {
                    return
                }

                $expiry = [datetime]::FromFileTime($rawExpiry)
                $daysRemaining = [int][math]::Floor(($expiry - $Today).TotalDays)
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
            Sort-Object DaysRemaining, Name)
}

function Format-AdminHtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$User,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedAt
    )

    @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Password expiry report</title>
</head>
<body>
  <h1>Password expiry report</h1>
  <p>Generated on $GeneratedAt. Threshold: $DaysBeforeExpiry days.</p>
  $($User | ConvertTo-Html -Fragment)
</body>
</html>
"@
}

function Format-UserReminderHtml {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$User,

        [Parameter()]
        [string]$SelfServiceUrl
    )

    $displayName = if ($User.GivenName) { $User.GivenName } else { $User.Name }
    $resetLine = if ($SelfServiceUrl) { "<p>You can reset your password here: <a href=`"$SelfServiceUrl`">$SelfServiceUrl</a></p>" } else { '' }
    @"
<html>
<body>
  <p>Hello $displayName,</p>
  <p>The password for account <strong>$($User.SamAccountName)</strong> is $($User.Status.ToLowerInvariant()). Expiration date: $($User.PasswordExpires).</p>
  $resetLine
</body>
</html>
"@
}

function Get-EmailPlan {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$User,

        [Parameter(Mandatory = $true)]
        [string]$AdminReportBody,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedAt,

        [Parameter()]
        [string]$ReminderResetUrl
    )

    foreach ($user in $User) {
        if ($SendUserEmails) {
            $recipient = if ($user.Mail) { @($user.Mail) } else { $AdminTo }
            $subject = if ($user.DaysRemaining -lt 0) {
                "Password expired for $($user.SamAccountName)"
            } else {
                "Password expires in $($user.DaysRemaining) day(s)"
            }

            [pscustomobject]@{
                PlanType = 'UserReminder'
                SamAccountName = $user.SamAccountName
                Recipient = $recipient -join ';'
                Subject = $subject
                Body = Format-UserReminderHtml -User $user -SelfServiceUrl $ReminderResetUrl
                Reason = if ($user.Mail) { 'User reminder email.' } else { 'User has no mail attribute; sending fallback notice to admins.' }
            }
        }
    }

    if ($SendAdminReport) {
        [pscustomobject]@{
            PlanType = 'AdminReport'
            SamAccountName = ''
            Recipient = $AdminTo -join ';'
            Subject = "Password expiry report $GeneratedAt"
            Body = $AdminReportBody
            Reason = 'Admin summary report.'
        }
    }
}

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$generatedAt = Get-Date
$today = Get-Date

$users = @(Get-PasswordExpiryUser -Today $today)
$html = Format-AdminHtmlReport -User $users -GeneratedAt $generatedAt
$htmlPath = Join-Path $resolvedOutputDirectory "ad-password-expiry-$timestamp.html"
$csvPath = Join-Path $resolvedOutputDirectory "ad-password-expiry-$timestamp.csv"
$jsonPath = Join-Path $resolvedOutputDirectory "ad-password-expiry-$timestamp.json"
$planPath = Join-Path $resolvedOutputDirectory "ad-password-expiry-email-plan-$timestamp.csv"
$statePath = Join-Path $resolvedOutputDirectory "ad-password-expiry-email-state-$timestamp.csv"

$html | Set-Content -LiteralPath $htmlPath -Encoding utf8
$users | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
Set-Content -LiteralPath $jsonPath -Value (@($users) | ConvertTo-Json -Depth 4) -Encoding utf8

$emailPlan = @(Get-EmailPlan -User $users -AdminReportBody $html -GeneratedAt $generatedAt -ReminderResetUrl $ResetUrl)
$emailPlanForReport = @($emailPlan | Select-Object PlanType, SamAccountName, Recipient, Subject, Reason)
$emailPlanForReport | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8

$emailState = foreach ($item in $emailPlan) {
    $result = try {
        Send-HtmlMail -Recipient ($item.Recipient -split ';') -Subject $item.Subject -Body $item.Body -Description $item.Reason -WhatIf:$WhatIfPreference
    } catch {
        "Failed: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        PlanType = $item.PlanType
        SamAccountName = $item.SamAccountName
        Recipient = $item.Recipient
        Subject = $item.Subject
        Reason = $item.Reason
        Result = $result
    }
}
$emailState | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8

[pscustomobject]@{
    DaysBeforeExpiry = $DaysBeforeExpiry
    AccountCount = @($users).Count
    HtmlPath = (Resolve-Path -LiteralPath $htmlPath).Path
    CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
    JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    EmailPlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    EmailStateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    UserEmailsEnabled = [bool]$SendUserEmails
    AdminReportEnabled = [bool]$SendAdminReport
    PlannedEmailCount = @($emailPlan).Count
    SentCount = @($emailState | Where-Object Result -eq 'Sent').Count
    PreviewedCount = @($emailState | Where-Object Result -eq 'Previewed').Count
    FailedCount = @($emailState | Where-Object { $_.Result -like 'Failed:*' }).Count
    EmailResults = @($emailState)
}
