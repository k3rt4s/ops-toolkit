<#
.SYNOPSIS
Export distribution group usage based on Exchange Online message trace recipients.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Export-M365DistributionGroupMessageTraceUsage.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$DaysBack = 10,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\reports\microsoft-365\distribution-group-usage.csv'),

    [Parameter()]
    [switch]$Connect
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ($Connect) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$endDate = Get-Date
$startDate = $endDate.AddDays(-$DaysBack)
$page = 1
$messages = do {
    $pageOfMessages = Get-MessageTrace -Status Expanded -PageSize 5000 -Page $page -StartDate $startDate -EndDate $endDate |
        Select-Object -Property Received, RecipientAddress
    $page++
    $pageOfMessages
} while ($pageOfMessages)

$activeRecipients = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($message in $messages) {
    if ($message.RecipientAddress) {
        [void]$activeRecipients.Add([string]$message.RecipientAddress)
    }
}

$results = foreach ($group in Get-DistributionGroup -ResultSize Unlimited) {
    $address = [string]$group.PrimarySmtpAddress
    [pscustomobject]@{
        DisplayName = $group.DisplayName
        PrimarySmtpAddress = $address
        Active = $activeRecipients.Contains($address)
        LookbackDays = $DaysBack
    }
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$results | Sort-Object DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
Write-Information "Report written to $OutputPath" -InformationAction Continue


