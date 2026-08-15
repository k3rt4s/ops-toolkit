<#
.SYNOPSIS
Compare the two most recent runs of a collector and report what changed since last time.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads report folders that collectors already wrote and writes a
  change report. It runs no collector and touches no system.
- Point -Path at a report root such as reports\entra. It finds the run folders,
  picks the two most recent, and compares them. Use -Prefix when a root holds runs
  from more than one collector.
- Records are matched on key columns. Known reports have sensible keys built in;
  anything else falls back to the first column and says so in the output. Override
  with -KeyColumn when the fallback is wrong.
- Columns whose value changes every run by arithmetic, ages and generation
  timestamps, are excluded by default. The facts they are derived from are compared
  instead. Use -IncludeVolatileColumn to see them anyway.
- Generated reports are written under reports\comparisons by default.

Purpose:
Every collector in this toolkit writes a timestamped folder and nothing reads the
previous one, so each run is an island and the question people actually ask, what
changed since last time, has no answer. A finding that has been there for a year and
a finding that appeared this morning need different responses, and a list sorted by
severity cannot tell them apart.

The interesting part is deciding what counts as a change. Days-to-expiry moves every
day without anything happening, so comparing it marks every record changed and
buries the real differences. The underlying dates are compared instead, which is the
same reasoning that makes the Conditional Access baseline ignore modifiedDateTime.

Required syntax:
pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path .\reports\entra
pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path .\reports\active-directory -Prefix ad-privileged-access-audit
pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path .\reports\entra -ReportName credentials -KeyColumn KeyId

.OUTPUTS
Writes per-record changes, a per-report rollup, and a run summary as CSV and JSON
under reports\comparisons by default. Returns a summary object. Exits 1 with
-FailOnNewFinding when anything was added.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Prefix,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ReportName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$KeyColumn,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$IgnoreColumn = @(),

    [Parameter()]
    [switch]$IncludeVolatileColumn,

    [Parameter()]
    [switch]$FailOnNewFinding,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\comparisons'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'run-comparison'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

if (-not $Path) {
    @(
        'Compare-OpsToolkitRun.ps1 compares the two most recent runs of a collector.'
        ''
        'Usage:'
        '  pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path <report root>'
        '                                                          [-Prefix <run prefix>]'
        '                                                          [-ReportName credentials]'
        '                                                          [-KeyColumn KeyId]'
        '                                                          [-IncludeVolatileColumn] [-FailOnNewFinding]'
        ''
        '-Path is required. Point it at a report root such as reports\entra.'
    ) | Write-Output
    exit 2
}

# Keys for the reports this repo produces. A report not listed here still compares,
# using its first column, and the fallback is reported rather than assumed correct.
$script:ReportKey = @{
    'credentials' = @('ObjectType', 'ObjectId', 'KeyId')
    'credentials-needing-attention' = @('ObjectType', 'ObjectId', 'KeyId')
    'application-rollup' = @('ObjectType', 'ObjectId')
    'objects-without-credentials' = @('ObjectType', 'ObjectId')
    'findings' = @('FindingId', 'DistinguishedName', 'SamAccountName')
    'finding-rollup' = @('FindingId')
    'tier0-membership' = @('GroupKey', 'DistinguishedName')
    'tier0-groups' = @('GroupKey')
    'acl-findings' = @('Right', 'Principal', 'TargetDistinguishedName')
    'principal-rollup' = @('Principal')
    'certificates' = @('Source', 'Location', 'Thumbprint')
    'certificates-needing-attention' = @('Source', 'Location', 'Thumbprint')
    'lifecycle-inventory' = @('ComputerName')
    'readiness-verdict' = @('ComputerName')
    'readiness-checks' = @('ComputerName', 'Check')
    'update-health-verdict' = @('ComputerName')
    'update-health-signals' = @('ComputerName', 'Signal')
    'bitlocker-volumes' = @('ComputerName', 'MountPoint')
    'bitlocker-machines' = @('ComputerName')
    'local-admin-members' = @('ComputerName', 'MemberName')
    'admin-posture' = @('ComputerName')
    'hardening-compliance' = @('Target', 'Item')
    'tls-handshakes' = @('Endpoint', 'Protocol')
    'control-assessment' = @('ControlId')
    'conditional-access-policies' = @('Id')
    'gap-analysis' = @('Control')
    'auth-method-readiness' = @('UserId')
    'telephony-only-users' = @('UserId')
    'mailbox-posture' = @('PrimarySmtpAddress')
    'forwarding-findings' = @('Kind', 'PrimarySmtpAddress', 'Destination')
    'inbox-rule-forwarding' = @('UserPrincipalName', 'RuleName', 'Destination')
    'protocol-exposure' = @('Protocol', 'PrimarySmtpAddress')
    'orphaned-resources' = @('ResourceId')
    'findings-legacy' = @('RuleId', 'File', 'LineNumber')
}

# Reports whose records are findings. A new row here is a new problem, which is a
# different thing from a new row in an inventory.
$script:FindingReport = @(
    'findings', 'acl-findings', 'certificates-needing-attention', 'credentials-needing-attention'
    'forwarding-findings', 'inbox-rule-forwarding', 'protocol-exposure', 'gap-analysis'
    'orphaned-resources', 'telephony-only-users'
)

function Resolve-KeyColumn {
    <#
    .SYNOPSIS
    Work out which columns identify a record in a report, and say how it was decided.

    .PARAMETER Name
    The report name, without extension.

    .PARAMETER AvailableColumn
    Columns present in the report.

    .PARAMETER OverrideColumn
    Operator-supplied key columns, which win over everything else. Passed rather than
    captured from script scope so the precedence is visible at the call site.

    .OUTPUTS
    PSCustomObject with Column and Source.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$AvailableColumn,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$OverrideColumn = @()
    )

    if ($OverrideColumn.Count -gt 0) {
        return [pscustomobject]@{ Column = @($OverrideColumn); Source = 'Parameter' }
    }

    if ($script:ReportKey.ContainsKey($Name)) {
        # Only keep the configured columns the report actually has, so a report that
        # gained or lost a column still compares instead of failing.
        $usable = @($script:ReportKey[$Name] | Where-Object { $AvailableColumn -contains $_ })
        if ($usable.Count -gt 0) {
            return [pscustomobject]@{ Column = $usable; Source = 'KnownReport' }
        }
    }

    if ($AvailableColumn.Count -gt 0) {
        return [pscustomobject]@{ Column = @($AvailableColumn[0]); Source = 'FirstColumnFallback' }
    }

    [pscustomobject]@{ Column = @(); Source = 'None' }
}

$asOf = Get-Date
$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$runs = @(Get-OpsRunDirectory -Path $resolvedPath -Prefix $Prefix)

if ($runs.Count -lt 2) {
    throw "Found $($runs.Count) run folder(s) under $resolvedPath$(if ($Prefix) { " with prefix $Prefix" }). Two are needed to compare. Run the collector again, or point -Path at a root that holds run history."
}

$current = $runs[0]
$previous = $runs[1]
Write-Verbose "Comparing $($previous.Path) with $($current.Path)."

$changeRecords = [System.Collections.Generic.List[object]]::new()
$reportRollup = [System.Collections.Generic.List[object]]::new()

function Invoke-ReportComparison {
    <#
    .SYNOPSIS
    Compare one report between two runs, adding to the change and rollup collections.

    .DESCRIPTION
    The per-report work lives in a function rather than inline in the loop so that
    skipping a report uses return rather than continue. A continue at script top
    level can bind to an enclosing loop in the caller's scope, which aborts a Pester
    run outright, and the same hazard applies to any host that invokes this script
    from inside its own loop.

    .PARAMETER Report
    The current run's report file.

    .PARAMETER PreviousRunPath
    Path of the previous run directory.

    .PARAMETER ChangeRecord
    Collection to add per-record changes to.

    .PARAMETER ReportRollup
    Collection to add the per-report summary to.

    .OUTPUTS
    None. Results are added to the supplied collections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PreviousRunPath,

        # AllowEmptyCollection is required: a Mandatory parameter typed as a list
        # rejects an empty one, and both of these are empty on the first report.
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$ChangeRecord,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$ReportRollup,

        # These three mirror the script parameters. Passing them rather than reading
        # them from script scope keeps the function's inputs visible at the call site,
        # which is the same reason the other scripts here stopped capturing scope.
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$OnlyReport = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$OverrideKeyColumn = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$ExcludeColumn = @(),

        [Parameter()]
        [switch]$CompareVolatile
    )

    $changeRecords = $ChangeRecord
    $reportRollup = $ReportRollup
    $name = [System.IO.Path]::GetFileNameWithoutExtension($Report.Name)
    if ($OnlyReport.Count -gt 0 -and $OnlyReport -notcontains $name) {
        return
    }

    $previousFile = Join-Path $PreviousRunPath $Report.Name
    if (-not (Test-Path -LiteralPath $previousFile)) {
        $reportRollup.Add([pscustomobject]@{
                Report = $name
                Status = 'NewReport'
                KeySource = ''
                KeyColumn = ''
                PreviousCount = 0
                CurrentCount = 0
                Added = 0
                Removed = 0
                Changed = 0
                Unchanged = 0
                Note = 'This report did not exist in the previous run, so there is nothing to compare it against.'
            })
        return
    }

    $previousRows = @(Import-Csv -LiteralPath $previousFile)
    $currentRows = @(Import-Csv -LiteralPath $Report.FullName)
    # Read the record's own properties. Wrapping in @() first and then reaching for
    # PSObject returns the array's members (Length, Rank, Count), which then get used
    # as column names and silently poison key resolution.
    $columns = @($currentRows | Select-Object -First 1 | ForEach-Object { $_.PSObject.Properties.Name })
    if ($columns.Count -eq 0) {
        $columns = @($previousRows | Select-Object -First 1 | ForEach-Object { $_.PSObject.Properties.Name })
    }

    # Filter nulls: @($null) is a one-element array containing null, which would pass
    # a count check and then fail validation inside Compare-OpsRecordSet.
    $key = Resolve-KeyColumn -Name $name -AvailableColumn $columns -OverrideColumn $OverrideKeyColumn
    if ($key.Column.Count -eq 0) {
        $reportRollup.Add([pscustomobject]@{
                Report = $name; Status = 'Empty'; KeySource = $key.Source; KeyColumn = ''
                PreviousCount = $previousRows.Count; CurrentCount = $currentRows.Count
                Added = 0; Removed = 0; Changed = 0; Unchanged = 0
                Note = 'Both runs of this report are empty, so no key could be determined.'
            })
        return
    }

    $comparison = Compare-OpsRecordSet -Previous $previousRows -Current $currentRows `
        -KeyColumn $key.Column -IgnoreColumn $ExcludeColumn -IncludeVolatileColumn:$CompareVolatile

    $isFindingReport = $script:FindingReport -contains $name

    foreach ($entry in $comparison.Added) {
        $changeRecords.Add([pscustomobject]@{
                Report = $name
                Change = 'Added'
                # A new finding is a new problem. A new inventory row is just a new thing.
                Significance = if ($isFindingReport) { 'NewFinding' } else { 'NewRecord' }
                Key = $entry.Key
                Column = ''
                Before = ''
                After = ''
                Detail = (Join-OpsValue -Value (@($key.Column | ForEach-Object { "$_=$(Get-OpsPropertyValue -InputObject $entry.Record -Name $_)" })))
            })
    }

    foreach ($entry in $comparison.Removed) {
        $changeRecords.Add([pscustomobject]@{
                Report = $name
                Change = 'Removed'
                Significance = if ($isFindingReport) { 'FindingResolved' } else { 'RecordGone' }
                Key = $entry.Key
                Column = ''
                Before = ''
                After = ''
                Detail = (Join-OpsValue -Value (@($key.Column | ForEach-Object { "$_=$(Get-OpsPropertyValue -InputObject $entry.Record -Name $_)" })))
            })
    }

    foreach ($entry in $comparison.Changed) {
        foreach ($difference in $entry.Differences) {
            $changeRecords.Add([pscustomobject]@{
                    Report = $name
                    Change = 'Changed'
                    Significance = 'FieldChanged'
                    Key = $entry.Key
                    Column = $difference.Column
                    Before = $difference.Before
                    After = $difference.After
                    Detail = ''
                })
        }
    }

    $note = ''
    if ($key.Source -eq 'FirstColumnFallback') {
        $note = "No key is configured for this report, so its first column ($($key.Column -join ',')) was used. Pass -KeyColumn if that is wrong."
    }
    if (-not $comparison.KeyIsUnique) {
        $note = (@($note, "The key does not uniquely identify a record, so rows are compared only as present or absent, never as changed. Duplicated keys: $(@($comparison.DuplicateKey | Select-Object -First 3) -join '; ')") | Where-Object { $_ }) -join ' '
    }

    $reportRollup.Add([pscustomobject]@{
            Report = $name
            Status = if ($isFindingReport) { 'FindingReport' } else { 'Inventory' }
            KeySource = $key.Source
            KeyColumn = ($key.Column -join ',')
            PreviousCount = $comparison.PreviousCount
            CurrentCount = $comparison.CurrentCount
            Added = @($comparison.Added).Count
            Removed = @($comparison.Removed).Count
            Changed = @($comparison.Changed).Count
            Unchanged = $comparison.UnchangedCount
            Note = $note
        })
}

$currentReports = @(Get-ChildItem -LiteralPath $current.Path -Filter '*.csv' -File)
foreach ($report in $currentReports) {
    Invoke-ReportComparison -Report $report -PreviousRunPath $previous.Path `
        -ChangeRecord $changeRecords -ReportRollup $reportRollup `
        -OnlyReport @($ReportName | Where-Object { $_ }) `
        -OverrideKeyColumn @($KeyColumn | Where-Object { $_ }) `
        -ExcludeColumn @($IgnoreColumn | Where-Object { $_ }) `
        -CompareVolatile:$IncludeVolatileColumn
}

# New findings first, then changes, then everything else. A finding that appeared
# this morning needs a different response from one that has been there a year.
$significanceRank = {
    switch ($_.Significance) {
        'NewFinding' { 0 }
        'FieldChanged' { 1 }
        'NewRecord' { 2 }
        'FindingResolved' { 3 }
        default { 4 }
    }
}

# Wrap the pipeline output, not just the input. With no changes at all, which is the
# ordinary case for a healthy estate, Sort-Object emits nothing and an unwrapped
# result is null rather than an empty array, so every count on it throws.
$sortedChanges = @(@($changeRecords) | Sort-Object -Property @{ Expression = $significanceRank }, Report, Key)

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'changes' -Record $sortedChanges -Directory $runDirectory
    Export-OpsReport -Name 'report-rollup' -Record @($reportRollup) -Directory $runDirectory
)

$newFindings = @($sortedChanges | Where-Object { $_.Significance -eq 'NewFinding' })
$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    ComparedPath = $resolvedPath
    PreviousRun = $previous.Path
    PreviousRunAt = $previous.Timestamp
    CurrentRun = $current.Path
    CurrentRunAt = $current.Timestamp
    ElapsedDays = [int][math]::Floor(($current.Timestamp - $previous.Timestamp).TotalDays)
    ReportsCompared = @($reportRollup | Where-Object { $_.Status -in @('FindingReport', 'Inventory') }).Count
    ReportsSkipped = @($reportRollup | Where-Object { $_.Status -notin @('FindingReport', 'Inventory') }).Count
    ChangeCount = $sortedChanges.Count
    NewFindingCount = $newFindings.Count
    ResolvedFindingCount = @($sortedChanges | Where-Object { $_.Significance -eq 'FindingResolved' }).Count
    FieldChangeCount = @($sortedChanges | Where-Object { $_.Significance -eq 'FieldChanged' }).Count
    NewRecordCount = @($sortedChanges | Where-Object { $_.Significance -eq 'NewRecord' }).Count
    FallbackKeyReports = @($reportRollup | Where-Object { $_.KeySource -eq 'FirstColumnFallback' } | ForEach-Object { $_.Report })
    VolatileColumnsExcluded = -not $IncludeVolatileColumn
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($FailOnNewFinding -and $newFindings.Count -gt 0) {
    Write-Warning "$($newFindings.Count) new finding(s) since the previous run."
    exit 1
}
