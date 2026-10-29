<#
.SYNOPSIS
Report Windows Defender Application Control audit events from the Code Integrity log, grouped by file path and by publisher, so a policy can be judged before it is enforced.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads the Microsoft-Windows-CodeIntegrity/Operational log. It changes no
  policy and no setting.
- Run elevated if the log is not readable by your account. A log that cannot be read is
  reported as Unreadable with the reason, never as zero events.
- Event 3076 means a file would have been blocked by a policy in audit mode. Event 3089 carries
  the signature (publisher and issuer) details for a file named by a nearby 3076 or 3077 event.
  Event 3077 means a file WAS blocked by an enforced policy; it is included so an enforced
  policy cannot hide in an audit review. Events 8028 and 8029 (script and installer enforcement)
  are not read by this script.
- -Days sets the look-back window, 1 to 365, default 7. Review a period that includes the
  monthly patch cycle and the tools the machine is actually used for before drawing a conclusion
  from a quiet log.
- The by-file and by-publisher reports are the review surface: a publisher that signs many
  audit events is a candidate for a rule, an unsigned path that keeps appearing is the thing to
  investigate.

Purpose:
Enforcing an application control policy blind blocks things people need. Audit mode records what
would have been blocked; this turns that record into a short list a person can decide on.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Export-WdacAuditEvent.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Export-WdacAuditEvent.ps1 -Days 30 -OutputDirectory <dir>

.OUTPUTS
Writes the individual events, a by-file rollup, and a by-publisher rollup as CSV and JSON in a
timestamped run folder under reports\it-operations by default, plus summary.json. Returns a
summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Companion to Set-WdacAuditPolicy.ps1.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$Days = 7,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'wdac-audit-events'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$logName = 'Microsoft-Windows-CodeIntegrity/Operational'
$eventIds = @(3076, 3077, 3089)
$since = (Get-Date).AddDays(-$Days)

function Get-EventDataValue {
    param($DataNode, [string[]]$Name)
    foreach ($node in @($DataNode)) {
        if ($null -eq $node) { continue }
        $attr = [string]$node.GetAttribute('Name')
        if ($attr -in $Name) { return [string]$node.InnerText }
    }
    ''
}

$readError = ''
$events = @()
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eventIds; StartTime = $since } -ErrorAction Stop)
} catch {
    # "No events were found" is an answer; anything else (log missing, access denied) is not.
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*') {
        $events = @()
    } else {
        $readError = $_.Exception.Message
    }
}

$rows = [System.Collections.Generic.List[object]]::new()
foreach ($evt in $events) {
    $id = [int]$evt.Id
    $xml = $null
    try { $xml = [xml]$evt.ToXml() } catch { $xml = $null }
    $data = @()
    if ($null -ne $xml) { $data = @($xml.SelectNodes("//*[local-name()='Data']")) }

    $rows.Add([pscustomobject]@{
            TimeCreated = $evt.TimeCreated
            EventId = $id
            Meaning = switch ($id) { 3076 { 'AuditWouldBlock' } 3077 { 'Blocked' } 3089 { 'SignatureInfo' } default { 'Other' } }
            FilePath = Get-EventDataValue -DataNode $data -Name @('File Name', 'FileName')
            ProcessName = Get-EventDataValue -DataNode $data -Name @('Process Name', 'ProcessName')
            PolicyName = Get-EventDataValue -DataNode $data -Name @('PolicyName', 'Policy Name')
            Publisher = Get-EventDataValue -DataNode $data -Name @('PublisherName', 'Publisher Name')
            Issuer = Get-EventDataValue -DataNode $data -Name @('IssuerName', 'Issuer Name')
            ComputerName = [string]$evt.MachineName
        })
}

# Publisher by file, from the 3089 signature events.
$publisherByFile = @{}
foreach ($row in $rows) {
    if ($row.EventId -eq 3089 -and $row.FilePath -and $row.Publisher) {
        if (-not $publisherByFile.ContainsKey($row.FilePath)) { $publisherByFile[$row.FilePath] = [System.Collections.Generic.List[string]]::new() }
        if (-not $publisherByFile[$row.FilePath].Contains($row.Publisher)) { $publisherByFile[$row.FilePath].Add($row.Publisher) }
    }
}

$decisionRows = @($rows | Where-Object { $_.EventId -in @(3076, 3077) })
$byFile = @($decisionRows | Group-Object -Property FilePath | ForEach-Object {
        $group = @($_.Group)
        $publishers = if ($publisherByFile.ContainsKey([string]$_.Name)) { @($publisherByFile[[string]$_.Name]) } else { @() }
        [pscustomobject]@{
            FilePath = [string]$_.Name
            AuditWouldBlockCount = @($group | Where-Object EventId -eq 3076).Count
            BlockedCount = @($group | Where-Object EventId -eq 3077).Count
            Publisher = ($publishers -join ';')
            PolicyName = (@($group | ForEach-Object { $_.PolicyName } | Where-Object { $_ } | Select-Object -Unique) -join ';')
            ProcessName = (@($group | ForEach-Object { $_.ProcessName } | Where-Object { $_ } | Select-Object -Unique) -join ';')
            FirstSeen = ($group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastSeen = ($group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        }
    } | Sort-Object -Property @{ Expression = 'AuditWouldBlockCount'; Descending = $true }, FilePath)

$byPublisher = @($rows | Where-Object { $_.EventId -eq 3089 -and $_.Publisher } | Group-Object -Property Publisher | ForEach-Object {
        $group = @($_.Group)
        [pscustomobject]@{
            Publisher = [string]$_.Name
            Issuer = (@($group | ForEach-Object { $_.Issuer } | Where-Object { $_ } | Select-Object -Unique) -join ';')
            EventCount = $group.Count
            DistinctFileCount = @($group | ForEach-Object { $_.FilePath } | Where-Object { $_ } | Select-Object -Unique).Count
        }
    } | Sort-Object -Property @{ Expression = 'EventCount'; Descending = $true }, Publisher)

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'wdac-audit-events' -Record @($rows) -Directory $runDirectory
    Export-OpsReport -Name 'wdac-audit-by-file' -Record $byFile -Directory $runDirectory
    Export-OpsReport -Name 'wdac-audit-by-publisher' -Record $byPublisher -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    LogName = $logName
    Days = $Days
    Status = if ($readError) { 'Unreadable' } elseif ($rows.Count -eq 0) { 'NoEvents' } else { 'Events' }
    ReadError = $readError
    EventCount = $rows.Count
    AuditWouldBlockCount = @($rows | Where-Object EventId -eq 3076).Count
    BlockedCount = @($rows | Where-Object EventId -eq 3077).Count
    DistinctFileCount = $byFile.Count
    DistinctPublisherCount = $byPublisher.Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
