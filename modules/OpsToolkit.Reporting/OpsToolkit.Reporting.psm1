<#
.SYNOPSIS
Shared report-writing helpers used by ops-toolkit scripts.

.DESCRIPTION
Instructions:
- Import with a path relative to the calling script, not by module name, because
  this module is not installed to a PSModulePath:
  Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force
- Every function here is side-effect free except the two directory resolvers, which
  create the directory they return.
- Do not add domain logic here. This module knows about files and shapes, not about
  Active Directory, Azure, or Windows.

Purpose:
Every report-first script in this repo had its own copy of the same three helpers:
resolve an output directory, make a timestamped run directory, write a record set
as CSV plus JSON and hand back a descriptor. Those copies drifted. This module is
the one implementation so a fix to report writing lands everywhere at once.

.NOTES
Status:
Active module kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Resolve-OpsOutputDirectory {
    <#
    .SYNOPSIS
    Create the output directory if it does not exist and return its absolute path.

    .PARAMETER Path
    Directory to create and resolve. Relative paths resolve against the caller's
    current location, so scripts should pass a path built from $PSScriptRoot.

    .OUTPUTS
    String. The absolute path of the directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-OpsRunDirectory {
    <#
    .SYNOPSIS
    Create a timestamped run directory under the output directory and return its path.

    .PARAMETER OutputDirectory
    Parent directory. Created if missing.

    .PARAMETER Prefix
    Run directory name prefix. The timestamp is appended as yyyyMMdd_HHmmss.

    .PARAMETER Timestamp
    Timestamp to use. Defaults to now. Pass an explicit value to make a run
    reproducible in a test.

    .OUTPUTS
    String. The absolute path of the run directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Prefix,

        [Parameter()]
        [datetime]$Timestamp = (Get-Date)
    )

    $parent = Resolve-OpsOutputDirectory -Path $OutputDirectory
    $runDirectory = Join-Path $parent "$Prefix-$($Timestamp.ToString('yyyyMMdd_HHmmss'))"
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    (Resolve-Path -LiteralPath $runDirectory).Path
}

function Export-OpsReport {
    <#
    .SYNOPSIS
    Write a record set as CSV and JSON and return a descriptor of what was written.

    .DESCRIPTION
    An empty record set still writes both files. A report that exists and is empty
    is evidence the check ran and found nothing; a missing file is ambiguous.

    .PARAMETER Name
    Base file name, without extension.

    .PARAMETER Record
    The records to write. May be empty.

    .PARAMETER Directory
    Directory to write into. Must already exist.

    .PARAMETER Depth
    JSON serialization depth.

    .OUTPUTS
    PSCustomObject with Name, Count, CsvPath, and JsonPath.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Record,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$Depth = 8
    )

    $records = @($Record | Where-Object { $null -ne $_ })
    $csvPath = Join-Path $Directory "$Name.csv"
    $jsonPath = Join-Path $Directory "$Name.json"

    if ($records.Count -gt 0) {
        $records | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    } else {
        # Export-Csv writes nothing at all for an empty set, which leaves no file and
        # no way to tell "ran and found nothing" from "never ran".
        Set-Content -LiteralPath $csvPath -Value '' -Encoding utf8
    }

    Set-Content -LiteralPath $jsonPath -Value ($records | ConvertTo-Json -Depth $Depth -AsArray) -Encoding utf8

    [pscustomobject]@{
        Name = $Name
        Count = $records.Count
        CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
        JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    }
}

function Export-OpsSummary {
    <#
    .SYNOPSIS
    Write the run summary as summary.json and return it with SummaryPath attached.

    .PARAMETER Summary
    The summary object to write.

    .PARAMETER Directory
    Run directory to write into.

    .OUTPUTS
    The same object, with a SummaryPath property added.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Summary,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory
    )

    $summaryPath = Join-Path $Directory 'summary.json'
    Set-Content -LiteralPath $summaryPath -Value ($Summary | ConvertTo-Json -Depth 10) -Encoding utf8
    $Summary | Add-Member -NotePropertyName SummaryPath -NotePropertyValue (Resolve-Path -LiteralPath $summaryPath).Path -Force
    $Summary
}

function Get-OpsPropertyValue {
    <#
    .SYNOPSIS
    Read a property that may not exist, without tripping Set-StrictMode.

    .DESCRIPTION
    Strict mode 3.0 throws on a reference to a property an object does not have.
    Directory objects, Graph responses, and CIM instances all vary in shape between
    versions, so reads that might miss go through here.

    .PARAMETER InputObject
    Object to read. May be null.

    .PARAMETER Name
    Property name. Matching is case-insensitive, as PowerShell property lookup is.

    .OUTPUTS
    The property value, or null when the object or property is absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    $property.Value
}

function Join-OpsValue {
    <#
    .SYNOPSIS
    Flatten a value to a single string suitable for a CSV cell.

    .DESCRIPTION
    Arrays join with a semicolon. Null becomes an empty string. Byte arrays are not
    handled here, because a byte array in a report is almost always a thumbprint and
    belongs in ConvertTo-OpsHexString.

    .PARAMETER Value
    Value to flatten.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    # A dictionary is IEnumerable but enumerates to DictionaryEntry objects, which
    # stringify as type names. Render it as key=value pairs in a stable order instead.
    if ($Value -is [System.Collections.IDictionary]) {
        return ((@($Value.Keys) | Sort-Object | ForEach-Object { "$_=$($Value[$_])" }) -join ';')
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return ((@($Value) | Where-Object { $null -ne $_ }) -join ';')
    }

    [string]$Value
}

function ConvertTo-OpsHexString {
    <#
    .SYNOPSIS
    Render a byte sequence as an uppercase hex string.

    .DESCRIPTION
    PowerShell unrolls an array returned from a function, so a [byte[]] read from an
    object arrives here as [object[]] and a [byte[]] type test would miss it. Any
    byte enumerable is accepted for that reason.

    .PARAMETER Value
    Byte sequence, or a string to pass through unchanged.

    .OUTPUTS
    String. Empty when the value is null or an empty sequence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    # A dictionary is never a thumbprint. Hand it to Join-OpsValue rather than letting
    # it fall through to [string], which yields "System.Collections.Hashtable".
    if ($Value -is [System.Collections.IDictionary]) {
        return (Join-OpsValue -Value $Value)
    }

    # Only a sequence of byte-convertible numbers is a thumbprint. Any other
    # enumerable falls back to a joined value rather than being coerced into hex.
    if ($Value -is [System.Collections.IEnumerable]) {
        $bytes = @($Value)
        if ($bytes.Count -eq 0) {
            return ''
        }

        $converted = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $bytes) {
            try {
                $converted.Add('{0:X2}' -f [byte]$item)
            } catch {
                return (Join-OpsValue -Value $Value)
            }
        }

        return ($converted -join '')
    }

    [string]$Value
}

function Get-OpsAge {
    <#
    .SYNOPSIS
    Return whole days between a timestamp and a reference point, or null if never set.

    .DESCRIPTION
    Windows and Active Directory write "never" as 0, as a negative file time, or as
    an early-1601 date rather than as a null. All three mean the same thing and all
    three return null here, because reporting a 155000-day age is worse than
    reporting nothing.

    .PARAMETER Timestamp
    A DateTime, or a Windows file time as a long.

    .PARAMETER AsOf
    Reference point.

    .OUTPUTS
    Int32 days, or null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Timestamp,

        [Parameter(Mandatory = $true)]
        [datetime]$AsOf
    )

    if ($null -eq $Timestamp) {
        return $null
    }

    $value = $Timestamp
    if ($value -is [long] -or $value -is [int]) {
        if ([long]$value -le 0) {
            return $null
        }

        try {
            $value = [datetime]::FromFileTimeUtc([long]$value)
        } catch {
            return $null
        }
    }

    if ($value -is [string]) {
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($value, [ref]$parsed)) {
            return $null
        }

        $value = $parsed
    }

    $value = [datetime]$value
    if ($value.Year -le 1601) {
        return $null
    }

    [int][math]::Floor(($AsOf - $value).TotalDays)
}

function Get-OpsSeverityRank {
    <#
    .SYNOPSIS
    Map a severity name to a sort rank, worst first.

    .PARAMETER Severity
    Critical, High, Medium, Low, or Informational.

    .OUTPUTS
    Int32 rank, 0 for Critical through 4 for Informational.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { 0 }
        'High' { 1 }
        'Medium' { 2 }
        'Low' { 3 }
        default { 4 }
    }
}

# Columns whose value changes on every run by arithmetic rather than by anything
# happening. Comparing them makes every record look changed and buries the real
# differences, which is the same failure as diffing a Conditional Access policy on
# its modifiedDateTime.
$script:OpsVolatileColumn = @(
    'GeneratedAt', 'AssessedAt', 'AsOfUtc', 'LastWriteTime', 'TimeCreated'
    'DaysToExpiry', 'DaysRemaining', 'AgeDays', 'UptimeDays', 'DaysSinceInstall'
    'LastLogonDays', 'PasswordAgeDays', 'PwdLastSetAgeDays', 'LapsPasswordAgeDays'
    'BuiltInAdminPasswordAgeDays', 'LifetimeDays', 'EncryptionPercentage'
    'DurationSeconds', 'FirstSeen', 'LastSeen', 'SizeGb', 'EstimatedMonthlyCost'
    # Paths into the run's own output folder differ on every run by construction.
    'OutputPath', 'OutputDirectory', 'PackDirectory', 'CsvPath', 'JsonPath', 'SummaryPath', 'RunDirectory'
)

function Get-OpsVolatileColumn {
    <#
    .SYNOPSIS
    Return the column names that change every run without anything having happened.

    .DESCRIPTION
    These are derived values, mostly ages and timestamps. The underlying facts they
    are computed from, such as EndDateTime or LastBootUpTime, are compared instead.

    .OUTPUTS
    String array.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $script:OpsVolatileColumn
}

function Get-OpsRunDirectory {
    <#
    .SYNOPSIS
    Return a collector's run directories, newest first.

    .DESCRIPTION
    Run directories are named prefix-yyyyMMdd_HHmmss. Sorting is done on the parsed
    timestamp rather than on the name or the file system time, because a copied or
    restored folder carries the wrong file system time and would reorder the history.

    .PARAMETER Path
    The report root to look under.

    .PARAMETER Prefix
    Optional run prefix. All prefixes are returned when omitted.

    .OUTPUTS
    PSCustomObject with Path, Prefix, and Timestamp, newest first.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Prefix
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    # Accumulate into a list rather than assigning the foreach as an expression. A
    # continue inside a foreach used as an expression can escape the loop entirely
    # and propagate into the caller's own loops, which aborts a Pester run outright.
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($directory in (Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue)) {
        $match = [regex]::Match($directory.Name, '^(?<prefix>.+)-(?<stamp>\d{8}_\d{6})$')
        if (-not $match.Success) {
            continue
        }

        if ($Prefix -and $match.Groups['prefix'].Value -ne $Prefix) {
            continue
        }

        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($match.Groups['stamp'].Value, 'yyyyMMdd_HHmmss', $null, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            continue
        }

        $results.Add([pscustomobject]@{
                Path = $directory.FullName
                Prefix = $match.Groups['prefix'].Value
                Timestamp = $parsed
            })
    }

    @($results) | Sort-Object Timestamp -Descending
}

function Compare-OpsRecordSet {
    <#
    .SYNOPSIS
    Compare two record sets by key and report what was added, removed, and changed.

    .DESCRIPTION
    Records are matched on the key columns. Non-key, non-ignored columns are compared
    value by value, and a changed record reports which fields differ and how.

    When the key does not uniquely identify a record, comparison by key would silently
    pick an arbitrary pair, so this reports the duplication and treats those records
    as set membership only: present or absent, never changed.

    .PARAMETER Previous
    The earlier record set.

    .PARAMETER Current
    The later record set.

    .PARAMETER KeyColumn
    Columns that together identify a record.

    .PARAMETER IgnoreColumn
    Columns to exclude from comparison, in addition to the volatile defaults.

    .PARAMETER IncludeVolatileColumn
    Compare the volatile columns too. Off by default.

    .OUTPUTS
    PSCustomObject with Added, Removed, Changed, UnchangedCount, KeyIsUnique, and
    DuplicateKey.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Previous,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Current,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$KeyColumn,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$IgnoreColumn = @(),

        [Parameter()]
        [switch]$IncludeVolatileColumn
    )

    $previousRecords = @($Previous | Where-Object { $null -ne $_ })
    $currentRecords = @($Current | Where-Object { $null -ne $_ })

    $ignored = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($column in $IgnoreColumn) { $ignored.Add($column) | Out-Null }
    if (-not $IncludeVolatileColumn) {
        foreach ($column in $script:OpsVolatileColumn) { $ignored.Add($column) | Out-Null }
    }
    foreach ($column in $KeyColumn) { $ignored.Add($column) | Out-Null }

    function Get-Key {
        param($Record)
        (@($KeyColumn | ForEach-Object { Join-OpsValue -Value (Get-OpsPropertyValue -InputObject $Record -Name $_) }) -join '|')
    }

    $previousByKey = @{}
    $duplicateKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($record in $previousRecords) {
        $key = Get-Key -Record $record
        if ($previousByKey.ContainsKey($key)) {
            $duplicateKeys.Add($key)
        } else {
            $previousByKey[$key] = $record
        }
    }

    $currentByKey = @{}
    foreach ($record in $currentRecords) {
        $key = Get-Key -Record $record
        if ($currentByKey.ContainsKey($key)) {
            $duplicateKeys.Add($key)
        } else {
            $currentByKey[$key] = $record
        }
    }

    $keyIsUnique = $duplicateKeys.Count -eq 0

    $added = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $changed = [System.Collections.Generic.List[object]]::new()
    $unchanged = 0

    foreach ($key in $currentByKey.Keys) {
        if (-not $previousByKey.ContainsKey($key)) {
            $added.Add([pscustomobject]@{ Key = $key; Record = $currentByKey[$key] })
            continue
        }

        if (-not $keyIsUnique) {
            # With a non-unique key any pairing is arbitrary, so claim only membership.
            $unchanged++
            continue
        }

        $before = $previousByKey[$key]
        $after = $currentByKey[$key]
        $columns = @(@($before.PSObject.Properties.Name) + @($after.PSObject.Properties.Name) | Select-Object -Unique | Where-Object { -not $ignored.Contains($_) })

        $differences = [System.Collections.Generic.List[object]]::new()
        foreach ($column in $columns) {
            $beforeValue = Join-OpsValue -Value (Get-OpsPropertyValue -InputObject $before -Name $column)
            $afterValue = Join-OpsValue -Value (Get-OpsPropertyValue -InputObject $after -Name $column)
            if ($beforeValue -ne $afterValue) {
                $differences.Add([pscustomobject]@{ Column = $column; Before = $beforeValue; After = $afterValue })
            }
        }

        if ($differences.Count -gt 0) {
            $changed.Add([pscustomobject]@{ Key = $key; Differences = @($differences); Record = $after })
        } else {
            $unchanged++
        }
    }

    foreach ($key in $previousByKey.Keys) {
        if (-not $currentByKey.ContainsKey($key)) {
            $removed.Add([pscustomobject]@{ Key = $key; Record = $previousByKey[$key] })
        }
    }

    [pscustomobject]@{
        Added = @($added)
        Removed = @($removed)
        Changed = @($changed)
        UnchangedCount = $unchanged
        PreviousCount = $previousRecords.Count
        CurrentCount = $currentRecords.Count
        KeyColumn = @($KeyColumn)
        KeyIsUnique = $keyIsUnique
        DuplicateKey = @($duplicateKeys | Select-Object -Unique)
        ComparedColumnsExclude = @($ignored | Sort-Object)
    }
}

Export-ModuleMember -Function @(
    'Resolve-OpsOutputDirectory'
    'Resolve-OpsRunDirectory'
    'Export-OpsReport'
    'Export-OpsSummary'
    'Get-OpsPropertyValue'
    'Join-OpsValue'
    'ConvertTo-OpsHexString'
    'Get-OpsAge'
    'Get-OpsSeverityRank'
    'Get-OpsVolatileColumn'
    'Get-OpsRunDirectory'
    'Compare-OpsRecordSet'
)
