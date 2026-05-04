<#
.SYNOPSIS
Disable stale AD computer accounts and move them to a disabled-computers OU.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass -TargetOu explicitly; do not store environment-specific distinguished names in this script.
- Run with -WhatIf first before disabling or moving computer accounts.
- Use -SendEmail only when SMTP settings are supplied on the command line.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOu,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = '.\reports\active-directory\stale-computers.html',

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
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -TargetOu "OU=DisabledComputers,DC=example,DC=com" -WhatIf
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -TargetOu "OU=DisabledComputers,DC=example,DC=com" -OutputPath .\reports\active-directory\stale-computers.html -WhatIf
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -TargetOu "OU=DisabledComputers,DC=example,DC=com" -SendEmail -SmtpServer smtp.example.com -From secops@example.com -To admins@example.com -WhatIf

Options:
  -InactiveDays  Minimum days since last logon. Defaults to 30.
  -TargetOu      Distinguished name of the OU where stale computers are moved.
  -OutputPath    HTML report path.
  -SendEmail     Send the report by email after processing.
  -SmtpServer    SMTP server required with -SendEmail.
  -From          Sender address required with -SendEmail.
  -To            Recipient address list required with -SendEmail.
  -ContactEmail  Optional contact mailbox included in the report text.
  -WhatIf        Preview disables and moves without changing AD.
'@
}

if (-not $TargetOu -or ($SendEmail -and (-not $SmtpServer -or -not $From -or -not $To))) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$InactiveDays)
$computers = Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } -Properties LastLogonDate |
    Select-Object Name, DistinguishedName, LastLogonDate |
    Sort-Object Name

$generatedAt = Get-Date
$contactLine = if ($ContactEmail) { "<p>Contact <a href=`"mailto:$ContactEmail`">$ContactEmail</a> if an account was disabled in error.</p>" } else { '' }
$html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Stale AD computer report</title>
</head>
<body>
  <h1>Stale AD computer report</h1>
  <p>Generated on $generatedAt. Threshold: no logon since $cutoff.</p>
  $contactLine
  $($computers | ConvertTo-Html -Fragment)
</body>
</html>
"@

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$html | Set-Content -LiteralPath $OutputPath -Encoding utf8

foreach ($computer in $computers) {
    if ($PSCmdlet.ShouldProcess($computer.Name, 'Disable AD computer account')) {
        Disable-ADAccount -Identity $computer.DistinguishedName
    }

    if ($PSCmdlet.ShouldProcess($computer.Name, "Move AD computer account to $TargetOu")) {
        Move-ADObject -Identity $computer.DistinguishedName -TargetPath $TargetOu
    }
}

if ($SendEmail) {
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject "Stale AD computer report $generatedAt" -Body $html -BodyAsHtml
}

[pscustomobject]@{
    InactiveDays = $InactiveDays
    ComputerCount = @($computers).Count
    TargetOu = $TargetOu
    OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    EmailSent = [bool]$SendEmail
}
