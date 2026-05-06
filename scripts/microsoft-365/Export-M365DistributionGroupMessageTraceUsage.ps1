<#
.SYNOPSIS
Export Microsoft 365 distribution group usage from Exchange Online expanded-recipient message traces.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\ops-toolkit\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ExchangeOnlineManagement PowerShell module and Exchange Online permissions.
- Use -Connect when the shell is not already connected to Exchange Online.
- Get-MessageTraceV2 can search the last 90 days, but each query window can cover only 10 days.
- Generated reports are written under reports\microsoft-365 by default.

.PURPOSE
Use this report-only script to find distribution groups with expanded-recipient
message trace activity. It chunks the requested lookback period into compliant
10-day-or-smaller windows, handles Get-MessageTraceV2 continuation keys, joins
the trace counts to distribution group inventory, and writes CSV/JSON/summary
artifacts for review.

.REQUIRED SYNTAX
pwsh -File .\scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1 -Connect -Organization "<tenant-domain>"
pwsh -File .\scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1 -DaysBack 30 -ChunkDays 5 -OutputDirectory .\reports\microsoft-365

.OUTPUTS
Writes CSV, JSON, and summary JSON reports under reports\microsoft-365 by
default. Returns a summary object with output paths and group counts.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
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
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\microsoft-365'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'distribution-group-message-trace-usage',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$GroupPrimarySmtpAddress,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [switch]$DisconnectWhenFinished,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Organization
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-OutputDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Assert-ExchangeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName
    )

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName is not available. Connect to Exchange Online with -Connect or update the ExchangeOnlineManagement module."
    }
}

function Get-TraceWindow {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [int]$PageSize
    )

    $queryEndDate = $EndDate
    $startingRecipientAddress = $null
    $seenPageKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    do {
        $traceParameters = @{
            StartDate = $StartDate
            EndDate = $queryEndDate
            Status = 'Expanded'
            ResultSize = $PageSize
        }
        if ($startingRecipientAddress) {
            $traceParameters.StartingRecipientAddress = $startingRecipientAddress
        }

        $page = @(Get-MessageTraceV2 @traceParameters | Select-Object Received, RecipientAddress, SenderAddress, Subject, Status)
        foreach ($message in $page) {
            $message
        }

        if ($page.Count -lt $PageSize) {
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
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [int]$WindowDays
    )

    $windowStart = $StartDate
    while ($windowStart -lt $EndDate) {
        $windowEnd = $windowStart.AddDays($WindowDays)
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

function Get-DistributionGroupUsageRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group,

        [Parameter(Mandatory = $true)]
        [hashtable]$TraceStatistic,

        [Parameter(Mandatory = $true)]
        [datetime]$QueryStart,

        [Parameter(Mandatory = $true)]
        [datetime]$QueryEnd
    )

    $address = [string]$Group.PrimarySmtpAddress
    $key = if ($address) { $address.ToLowerInvariant() } else { $null }
    $stats = if ($key -and $TraceStatistic.ContainsKey($key)) { $TraceStatistic[$key] } else { $null }

    [pscustomobject]@{
        DisplayName = $Group.DisplayName
        PrimarySmtpAddress = $address
        Alias = $Group.Alias
        RecipientTypeDetails = $Group.RecipientTypeDetails
        Active = [bool]$stats
        TraceCount = if ($stats) { $stats.TraceCount } else { 0 }
        FirstSeenUtc = if ($stats) { $stats.FirstSeenUtc } else { $null }
        LastSeenUtc = if ($stats) { $stats.LastSeenUtc } else { $null }
        LookbackDays = $DaysBack
        QueryStart = $QueryStart
        QueryEnd = $QueryEnd
    }
}

if ($Connect) {
    $connectParameters = @{ ShowBanner = $false }
    if ($Organization) {
        $connectParameters.Organization = $Organization
    }

    Connect-ExchangeOnline @connectParameters
}

try {
    Assert-ExchangeCommand -CommandName Get-MessageTraceV2
    Assert-ExchangeCommand -CommandName Get-DistributionGroup

    $resolvedOutputDirectory = Resolve-OutputDirectory -Path $OutputDirectory
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvPath = Join-Path $resolvedOutputDirectory "$OutputPrefix-$timestamp.csv"
    $jsonPath = Join-Path $resolvedOutputDirectory "$OutputPrefix-$timestamp.json"
    $summaryPath = Join-Path $resolvedOutputDirectory "$OutputPrefix-summary-$timestamp.json"

    $startDate = $EndDate.AddDays(-$DaysBack)
    $windows = @(Get-TraceWindows -StartDate $startDate -EndDate $EndDate -WindowDays $ChunkDays)
    $traceStats = @{}

    foreach ($window in $windows) {
        Write-Information "Querying expanded distribution group traces from $($window.StartDate) to $($window.EndDate)." -InformationAction Continue

        foreach ($message in Get-TraceWindow -StartDate $window.StartDate -EndDate $window.EndDate -PageSize $ResultSize) {
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

    $groups = @(Get-DistributionGroup -ResultSize Unlimited)
    if ($GroupPrimarySmtpAddress) {
        $filter = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($address in $GroupPrimarySmtpAddress) {
            [void]$filter.Add($address)
        }
        $groups = @($groups | Where-Object { $filter.Contains([string]$_.PrimarySmtpAddress) })
    }

    $results = @(
        foreach ($group in $groups) {
            Get-DistributionGroupUsageRecord -Group $group -TraceStatistic $traceStats -QueryStart $startDate -QueryEnd $EndDate
        }
    ) | Sort-Object @{ Expression = 'Active'; Descending = $true }, @{ Expression = 'TraceCount'; Descending = $true }, DisplayName

    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    Set-Content -LiteralPath $jsonPath -Value (@($results) | ConvertTo-Json -Depth 5) -Encoding utf8

    $summary = [pscustomobject]@{
        GeneratedAt = Get-Date
        DaysBack = $DaysBack
        ChunkDays = $ChunkDays
        ResultSize = $ResultSize
        QueryStart = $startDate
        QueryEnd = $EndDate
        QueryWindowCount = @($windows).Count
        GroupCount = @($results).Count
        ActiveGroupCount = @($results | Where-Object Active).Count
        InactiveGroupCount = @($results | Where-Object { -not $_.Active }).Count
        CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
        JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
        SummaryPath = (Resolve-Path -LiteralPath $summaryPath).Path
    }
    Set-Content -LiteralPath $summaryPath -Value ($summary | ConvertTo-Json -Depth 5) -Encoding utf8
    Write-Information "Reports written to $resolvedOutputDirectory" -InformationAction Continue
    $summary
} finally {
    if ($DisconnectWhenFinished) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
}
