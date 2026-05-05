<#
.SYNOPSIS
Export distribution group usage based on Exchange Online expanded-recipient message traces.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Install and import ExchangeOnlineManagement before running, or use -Connect.
- Get-MessageTraceV2 can search up to 90 days, but each query can cover only 10 days.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 10,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$ChunkDays = 10,

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]$ResultSize = 5000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\reports\microsoft-365\distribution-group-usage.csv'),

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Organization
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Assert-ExchangeCommand {
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName
    )

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName is not available. Connect to Exchange Online with -Connect or update the ExchangeOnlineManagement module."
    }
}

function Get-TraceWindow {
    param(
        [Parameter()]
        [datetime]$StartDate,

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [int]$ResultSize
    )

    $queryEndDate = $EndDate
    $startingRecipientAddress = $null
    $seenPageKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    do {
        $traceParameters = @{
            StartDate = $StartDate
            EndDate = $queryEndDate
            Status = 'Expanded'
            ResultSize = $ResultSize
        }
        if ($startingRecipientAddress) {
            $traceParameters.StartingRecipientAddress = $startingRecipientAddress
        }

        $page = @(Get-MessageTraceV2 @traceParameters | Select-Object Received, RecipientAddress, SenderAddress, Subject, Status)
        foreach ($message in $page) {
            $message
        }

        if ($page.Count -lt $ResultSize) {
            break
        }

        $lastMessage = $page[-1]
        if (-not $lastMessage.RecipientAddress -or -not $lastMessage.Received) {
            Write-Warning 'Stopping message trace paging because the last result did not include RecipientAddress and Received.'
            break
        }

        $pageKey = '{0}|{1:o}' -f $lastMessage.RecipientAddress, ([datetime]$lastMessage.Received)
        if (-not $seenPageKeys.Add($pageKey)) {
            Write-Warning 'Stopping message trace paging because the next page key repeated.'
            break
        }

        $startingRecipientAddress = [string]$lastMessage.RecipientAddress
        $queryEndDate = [datetime]$lastMessage.Received
    } while ($true)
}

function Get-TraceWindows {
    param(
        [Parameter()]
        [datetime]$StartDate,

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [int]$ChunkDays
    )

    $windowStart = $StartDate
    while ($windowStart -lt $EndDate) {
        $windowEnd = $windowStart.AddDays($ChunkDays)
        if ($windowEnd -gt $EndDate) {
            $windowEnd = $EndDate
        }

        [pscustomobject]@{
            StartDate = $windowStart
            EndDate = $windowEnd
        }

        $windowStart = $windowEnd
    }
}

if ($Connect) {
    $connectParameters = @{
        ShowBanner = $false
    }
    if ($Organization) {
        $connectParameters.Organization = $Organization
    }

    Connect-ExchangeOnline @connectParameters
}
Assert-ExchangeCommand -CommandName Get-MessageTraceV2
Assert-ExchangeCommand -CommandName Get-DistributionGroup

$startDate = $EndDate.AddDays(-$DaysBack)
$windows = @(Get-TraceWindows -StartDate $startDate -EndDate $EndDate -ChunkDays $ChunkDays)
$traceStats = @{}

foreach ($window in $windows) {
    Write-Information "Querying expanded distribution group traces from $($window.StartDate) to $($window.EndDate)." -InformationAction Continue

    foreach ($message in Get-TraceWindow -StartDate $window.StartDate -EndDate $window.EndDate -ResultSize $ResultSize) {
        if (-not $message.RecipientAddress) {
            continue
        }

        $address = ([string]$message.RecipientAddress).ToLowerInvariant()
        if (-not $traceStats.ContainsKey($address)) {
            $traceStats[$address] = [pscustomobject]@{
                TraceCount = 0
                FirstSeenUtc = $null
                LastSeenUtc = $null
            }
        }

        $stats = $traceStats[$address]
        $received = [datetime]$message.Received
        $stats.TraceCount++
        if (-not $stats.FirstSeenUtc -or $received -lt $stats.FirstSeenUtc) {
            $stats.FirstSeenUtc = $received
        }
        if (-not $stats.LastSeenUtc -or $received -gt $stats.LastSeenUtc) {
            $stats.LastSeenUtc = $received
        }
    }
}

$results = foreach ($group in Get-DistributionGroup -ResultSize Unlimited) {
    $address = [string]$group.PrimarySmtpAddress
    $key = if ($address) { $address.ToLowerInvariant() } else { $null }
    $stats = if ($key -and $traceStats.ContainsKey($key)) { $traceStats[$key] } else { $null }

    [pscustomobject]@{
        DisplayName = $group.DisplayName
        PrimarySmtpAddress = $address
        Active = [bool]$stats
        TraceCount = if ($stats) { $stats.TraceCount } else { 0 }
        FirstSeenUtc = if ($stats) { $stats.FirstSeenUtc } else { $null }
        LastSeenUtc = if ($stats) { $stats.LastSeenUtc } else { $null }
        LookbackDays = $DaysBack
        QueryStart = $startDate
        QueryEnd = $EndDate
    }
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$results |
    Sort-Object @{ Expression = 'Active'; Descending = $true }, @{ Expression = 'TraceCount'; Descending = $true }, DisplayName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

Write-Information "Report written to $OutputPath" -InformationAction Continue
