<#
.SYNOPSIS
Reconcile the systems that should each know about the same machine, and report what only some of them know about.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads exported CSV inventories and writes reports. It contacts no
  service and changes nothing.
- Each authority is a CSV plus the column holding the machine identity. Supply them
  with -Authority, or with -ManifestPath for a saved set that can be scheduled.
- Mark an authority Required when every machine is expected to appear in it. An
  authority that is not Required is reported but never produces a gap, which is how
  a partial source such as a subnet scan is included without inventing findings.
- An authority whose file is missing or unreadable is reported NotRead, is excluded
  from grading, and takes the run verdict to Undetermined. It is never treated as an
  authority that returned nothing.
- Names are normalised before matching. The default strips any DNS suffix and
  uppercases, so PC01 and pc01.contoso.com are one machine. Use -MatchOn Fqdn or Raw
  where that is wrong.
- Generated reports are written under reports\reporting by default.

Purpose:
Every system that tracks machines reports the machines it knows about, which is not
the same as the machines that exist. The gap is invisible from inside any one of them,
because a machine missing from a console does not appear in it to be counted. The only
way to see it is to ask several systems that should agree and look at where they do
not.

That is the whole method: query the directory, the EDR console, the asset system, and
the address space, then differential them. A machine in the directory with no EDR agent
is a coverage gap. An EDR agent on a machine no asset system lists is an unmanaged
device. Neither shows up as a problem in the system that is missing it.

Design rule, the one that makes the output usable as evidence: an authority that could
not be read is not an authority that returned nothing. Those two cases produce opposite
reports from identical-looking input, and quietly merging them turns an unread source
into a clean bill of health for every machine it would have flagged.

Required syntax:
pwsh -File .\scripts\reporting\Export-CoverageReconciliation.ps1 -Authority @{Name='ActiveDirectory';Path='.\ad-computers.csv';KeyColumn='Name';Required=$true},@{Name='Defender';Path='.\devices.csv';KeyColumn='ComputerDnsName';Required=$true}
pwsh -File .\scripts\reporting\Export-CoverageReconciliation.ps1 -ManifestPath .\authorities.json
pwsh -File .\scripts\reporting\Export-CoverageReconciliation.ps1 -ManifestPath .\authorities.json -MatchOn Fqdn

.OUTPUTS
Writes per-machine coverage across every authority, the gap subset, an authority read
log, and a run summary as CSV and JSON under reports\reporting by default. Returns a
summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#requires -Version 7
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [hashtable[]]$Authority,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ManifestPath,

    [Parameter()]
    [ValidateSet('ShortName', 'Fqdn', 'Raw')]
    [string]$MatchOn = 'ShortName',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\reporting'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'coverage-reconciliation'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function ConvertTo-CoverageKey {
    <#
    .SYNOPSIS
    Normalise a machine identity so the same machine matches across authorities.

    .DESCRIPTION
    Authorities disagree about naming: a directory holds the short name, an EDR
    console holds the FQDN, an asset system holds whatever was typed. Matching raw
    strings reports both as separate machines, which produces two coverage gaps out of
    one covered machine and makes the whole report worse than not running it.

    .PARAMETER Value
    The raw identity read from the authority.

    .PARAMETER MatchOn
    ShortName strips any DNS suffix and uppercases. Fqdn uppercases only. Raw trims
    only, for authorities keyed on something that is not a name at all.

    .OUTPUTS
    String. Empty when the value is null or blank.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ShortName', 'Fqdn', 'Raw')]
        [string]$MatchOn
    )

    $trimmed = ([string]$Value).Trim()
    if (-not $trimmed) {
        return ''
    }

    switch ($MatchOn) {
        'Raw' { $trimmed }
        'Fqdn' { $trimmed.ToUpperInvariant() }
        default {
            # A directory distinguished name and a trailing dollar on a computer
            # account are both common in exports and neither is part of the name.
            $name = $trimmed
            if ($name -match '^CN=([^,]+)') { $name = $Matches[1] }
            $name = $name.TrimEnd('$')
            $name.Split('.')[0].ToUpperInvariant()
        }
    }
}

function Get-CoverageStatus {
    <#
    .SYNOPSIS
    Grade one machine against the authorities that were actually read.

    .DESCRIPTION
    Undetermined outranks both other outcomes. A machine present everywhere that was
    read, while a required authority went unread, is not covered: the unread authority
    is exactly the one that might not have it, and the whole point of reconciling is
    that no single source can answer for the others.

    .PARAMETER MissingFromRequired
    Count of required authorities that were read and do not have this machine.

    .PARAMETER UnreadRequired
    Count of required authorities that could not be read at all.

    .PARAMETER ReadRequired
    Count of required authorities that were read.

    .OUTPUTS
    String. One of Covered, Gap, or Undetermined.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][int]$MissingFromRequired,
        [Parameter(Mandatory = $true)][int]$UnreadRequired,
        [Parameter(Mandatory = $true)][int]$ReadRequired
    )

    if ($MissingFromRequired -gt 0) {
        # A known gap is a finding even when something else went unread. It is true
        # regardless of what the unread source would have said.
        return 'Gap'
    }

    if ($UnreadRequired -gt 0 -or $ReadRequired -eq 0) {
        return 'Undetermined'
    }

    'Covered'
}

# ---------------------------------------------------------------------------
# Resolve the authority list.
# ---------------------------------------------------------------------------
$specs = [System.Collections.Generic.List[object]]::new()

if ($ManifestPath) {
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath. It should be a JSON array of objects with Name, Path, KeyColumn, and optionally Required."
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    # A manifest holding one object deserializes to an object, not an array, and
    # foreach over it would iterate its properties instead of the entry.
    foreach ($entry in @($manifest)) {
        $specs.Add($entry)
    }
}

foreach ($entry in @($Authority | Where-Object { $_ })) {
    $specs.Add([pscustomobject]$entry)
}

if ($specs.Count -eq 0) {
    throw 'No authorities supplied. Pass -Authority, -ManifestPath, or both. Nothing was read and no report was written.'
}

if ($specs.Count -eq 1) {
    # One authority cannot be reconciled against anything, and the report it would
    # produce says every machine is covered, which is meaningless and reads as good
    # news.
    throw 'Only one authority supplied. Reconciliation needs at least two independent sources to differential; a single source can only agree with itself.'
}

# ---------------------------------------------------------------------------
# Read each authority. A read failure is recorded, not thrown, because the other
# authorities still carry information and the failure has to appear in the report.
# ---------------------------------------------------------------------------
$asOf = Get-Date
$authorityRuns = [System.Collections.Generic.List[object]]::new()
$authorityKeys = @{}

foreach ($spec in $specs) {
    $name = [string](Get-OpsPropertyValue -InputObject $spec -Name 'Name')
    $path = [string](Get-OpsPropertyValue -InputObject $spec -Name 'Path')
    $keyColumn = [string](Get-OpsPropertyValue -InputObject $spec -Name 'KeyColumn')
    $requiredValue = Get-OpsPropertyValue -InputObject $spec -Name 'Required'
    # Absent Required defaults to true. An authority someone bothered to list is
    # expected to know about the estate unless they say otherwise.
    $required = if ($null -eq $requiredValue) { $true } else { [bool]$requiredValue }

    $run = [pscustomobject]@{
        Authority = $name
        Path = $path
        KeyColumn = $keyColumn
        Required = $required
        Status = 'NotRead'
        RowCount = 0
        DistinctKeys = 0
        BlankKeys = 0
        DuplicateKeys = 0
        Note = ''
    }

    if (-not $name -or -not $path -or -not $keyColumn) {
        $run.Note = 'Authority entry is missing Name, Path, or KeyColumn.'
        $authorityRuns.Add($run)
        continue
    }

    if (-not (Test-Path -LiteralPath $path)) {
        $run.Note = "File not found: $path"
        $authorityRuns.Add($run)
        continue
    }

    $rows = @()
    try {
        $rows = @(Import-Csv -LiteralPath $path)
    } catch {
        $run.Note = $_.Exception.Message
        $authorityRuns.Add($run)
        continue
    }

    # A CSV that parsed but has no such column is a misconfiguration, not an empty
    # authority. Grading against it would report every machine as missing from it.
    # Bind the row first. @($rows | Select-Object -First 1).PSObject.Properties.Name
    # reads the wrapping array's own members, so every column check would fail with
    # Length, Rank, SyncRoot as the columns it claims to have found.
    $firstRow = $rows | Select-Object -First 1
    $columns = @($firstRow.PSObject.Properties.Name)
    if ($rows.Count -gt 0 -and $keyColumn -notin $columns) {
        $run.Status = 'NotRead'
        $run.RowCount = $rows.Count
        $run.Note = "Column '$keyColumn' not found. Columns present: $($columns -join ', ')"
        $authorityRuns.Add($run)
        continue
    }

    $keys = [System.Collections.Generic.List[string]]::new()
    $blank = 0
    foreach ($row in $rows) {
        $key = ConvertTo-CoverageKey -Value ([string](Get-OpsPropertyValue -InputObject $row -Name $keyColumn)) -MatchOn $MatchOn
        if ($key) { $keys.Add($key) } else { $blank++ }
    }

    $distinct = @($keys | Sort-Object -Unique)
    $run.Status = 'Read'
    $run.RowCount = $rows.Count
    $run.DistinctKeys = $distinct.Count
    $run.BlankKeys = $blank
    $run.DuplicateKeys = $keys.Count - $distinct.Count
    if ($blank -gt 0) {
        $run.Note = "$blank row(s) had no value in '$keyColumn' and could not be matched."
    }

    $authorityKeys[$name] = [System.Collections.Generic.HashSet[string]]::new([string[]]$distinct, [System.StringComparer]::OrdinalIgnoreCase)
    $authorityRuns.Add($run)
}

$readAuthorities = @($authorityRuns | Where-Object { $_.Status -eq 'Read' })
if ($readAuthorities.Count -lt 2) {
    throw "Fewer than two authorities could be read, so there is nothing to reconcile. See the note on each: $((@($authorityRuns | ForEach-Object { "$($_.Authority): $($_.Status). $($_.Note)" })) -join ' | ')"
}

$requiredRuns = @($authorityRuns | Where-Object { $_.Required })
$unreadRequired = @($requiredRuns | Where-Object { $_.Status -ne 'Read' })
$readRequired = @($requiredRuns | Where-Object { $_.Status -eq 'Read' })

# ---------------------------------------------------------------------------
# Build the union and grade each machine.
# ---------------------------------------------------------------------------
$allKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($set in $authorityKeys.Values) {
    foreach ($key in $set) { $allKeys.Add($key) | Out-Null }
}

$coverageRecords = [System.Collections.Generic.List[object]]::new()
foreach ($key in (@($allKeys) | Sort-Object)) {
    $record = [ordered]@{ MachineKey = $key }
    $knownBy = 0
    $missingRequired = [System.Collections.Generic.List[string]]::new()

    foreach ($run in $authorityRuns) {
        if ($run.Status -ne 'Read') {
            # Not Absent. Nobody looked.
            $record["$($run.Authority)"] = 'NotAssessed'
            continue
        }

        if ($authorityKeys[$run.Authority].Contains($key)) {
            $record["$($run.Authority)"] = 'Present'
            $knownBy++
        } else {
            $record["$($run.Authority)"] = 'Absent'
            if ($run.Required) { $missingRequired.Add($run.Authority) }
        }
    }

    $record['KnownByCount'] = $knownBy
    $record['MissingFromRequired'] = ($missingRequired -join ';')
    $record['MissingFromRequiredCount'] = $missingRequired.Count
    $record['UnreadRequiredCount'] = $unreadRequired.Count
    $record['Status'] = Get-CoverageStatus -MissingFromRequired $missingRequired.Count `
        -UnreadRequired $unreadRequired.Count -ReadRequired $readRequired.Count

    $coverageRecords.Add([pscustomobject]$record)
}

$gaps = @($coverageRecords | Where-Object { $_.Status -eq 'Gap' })

$authorityRollup = foreach ($run in $authorityRuns) {
    $missing = if ($run.Status -eq 'Read') {
        @($coverageRecords | Where-Object { $_."$($run.Authority)" -eq 'Absent' }).Count
    } else {
        $null
    }

    [pscustomobject]@{
        Authority = $run.Authority
        Required = $run.Required
        Status = $run.Status
        KnownMachines = $run.DistinctKeys
        # How many machines some other authority knows about and this one does not.
        MissingFromThisAuthority = $missing
        CoveragePercent = if ($run.Status -eq 'Read' -and $allKeys.Count -gt 0) {
            [math]::Round(100 * $run.DistinctKeys / $allKeys.Count, 1)
        } else {
            $null
        }
        Note = $run.Note
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'device-coverage' -Record @($coverageRecords) -Directory $runDirectory
    Export-OpsReport -Name 'coverage-gaps' -Record @($gaps) -Directory $runDirectory
    Export-OpsReport -Name 'authority-runs' -Record @($authorityRuns) -Directory $runDirectory
    Export-OpsReport -Name 'authority-rollup' -Record @($authorityRollup) -Directory $runDirectory
)

$verdict = if ($unreadRequired.Count -gt 0) {
    'Undetermined'
} elseif ($gaps.Count -gt 0) {
    'GapsFound'
} elseif ($allKeys.Count -eq 0) {
    # Every authority read cleanly and none of them knows about a single machine.
    # That is not full coverage, it is an empty reconciliation.
    'Undetermined'
} else {
    'Reconciled'
}

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    Verdict = $verdict
    MatchOn = $MatchOn
    AuthorityCount = $authorityRuns.Count
    AuthoritiesRead = $readAuthorities.Count
    AuthoritiesNotRead = @($authorityRuns | Where-Object { $_.Status -ne 'Read' }).Count
    UnreadRequiredAuthorities = @($unreadRequired | ForEach-Object { $_.Authority })
    MachineCount = $allKeys.Count
    CoveredCount = @($coverageRecords | Where-Object { $_.Status -eq 'Covered' }).Count
    GapCount = $gaps.Count
    UndeterminedCount = @($coverageRecords | Where-Object { $_.Status -eq 'Undetermined' }).Count
    KnownByOneAuthorityOnly = @($coverageRecords | Where-Object { $_.KnownByCount -eq 1 }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
