<#
.SYNOPSIS
Report Windows edition, build, and remaining support life for the local machine or a list of computers.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It queries CIM and the registry and writes reports. It changes nothing.
- Runs against the local machine by default. Use -ComputerName for remote hosts,
  which needs WinRM and local administrator rights on each target.
- Support dates come from data\it-operations\lifecycle\windows-support-lifecycle.csv,
  not from the script. Microsoft moves these dates. Update the file, not the code.
- Each row carries VerifiedOn and Source. Staleness is measured from the oldest
  VerifiedOn date, not from the file timestamp, because git resets a checked-out
  file's timestamp and a fresh clone of stale data would otherwise look current.
  When you re-check a date against its Source, update its VerifiedOn.
- A machine whose build is not in the data file is reported as Unknown rather than
  guessed. Unknown is a prompt to update the data file, not a pass.
- Generated reports are written under reports\it-operations by default.

Purpose:
13 October 2026 is a convergence date: Windows 11 24H2 Home and Pro reach end of
updates, the Windows 10 consumer ESU bridge ends, and Office LTSC 2021 ends. Estates
that spread upgrades over a year need to know now which machines fall off support
and when, and hardware eligibility is the real gate rather than willingness. This
answers the first half; Test-Windows11UpgradeReadiness.ps1 answers the second.

Required syntax:
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1 -ComputerName pc01,pc02
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1 -WarnWithinDays 365

.OUTPUTS
Writes an inventory, a per-status rollup, and a run summary as CSV and JSON under
reports\it-operations by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$WarnWithinDays = 365,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DataMaxAgeDays = 180,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LifecycleDataPath = (Join-Path $PSScriptRoot '..\..\..\data\it-operations\lifecycle\windows-support-lifecycle.csv'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'windows-lifecycle-inventory'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

function Get-ProductLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Caption
    )

    if ($Caption -match '(?i)windows\s+server\s+(\d{4}\s*R2|\d{4})') {
        return @{ Line = 'Windows Server'; Version = ($Matches[1] -replace '\s+', ' ').Trim() }
    }

    if ($Caption -match '(?i)windows\s+11') {
        return @{ Line = 'Windows 11'; Version = '' }
    }

    if ($Caption -match '(?i)windows\s+10') {
        return @{ Line = 'Windows 10'; Version = '' }
    }

    @{ Line = 'Unknown'; Version = '' }
}

function Get-EditionClass {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Caption,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProductLine
    )

    if ($ProductLine -eq 'Windows Server') {
        return 'Server'
    }

    # Enterprise and Education client releases get roughly twelve months more
    # servicing than Home and Pro, so the edition decides the date, not the build.
    if ($Caption -match '(?i)\b(Enterprise|Education|IoT Enterprise)\b') {
        return 'Enterprise'
    }

    'Consumer'
}

function Get-MachineLifecycleFact {
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Target
    )

    $cimParameter = @{}
    if ($Target -and $Target -ne $env:COMPUTERNAME) {
        $cimParameter['ComputerName'] = $Target
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem @cimParameter
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem @cimParameter

    # DisplayVersion (25H2) lives only in the registry; CIM has the build number.
    $displayVersion = ''
    $ubr = $null
    try {
        if ($cimParameter.ContainsKey('ComputerName')) {
            $remote = Invoke-Command -ComputerName $Target -ScriptBlock {
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                [pscustomobject]@{
                    DisplayVersion = (Get-ItemProperty -Path $key -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
                    ReleaseId = (Get-ItemProperty -Path $key -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId
                    UBR = (Get-ItemProperty -Path $key -Name UBR -ErrorAction SilentlyContinue).UBR
                }
            } -ErrorAction Stop
            $displayVersion = if ($remote.DisplayVersion) { $remote.DisplayVersion } else { $remote.ReleaseId }
            $ubr = $remote.UBR
        } else {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $displayVersion = (Get-ItemProperty -Path $key -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
            if (-not $displayVersion) {
                $displayVersion = (Get-ItemProperty -Path $key -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId
            }
            $ubr = (Get-ItemProperty -Path $key -Name UBR -ErrorAction SilentlyContinue).UBR
        }
    } catch {
        Write-Warning "Could not read the release registry values on $Target : $($_.Exception.Message)"
    }

    [pscustomobject]@{
        ComputerName = $os.CSName
        Caption = $os.Caption
        DisplayVersion = Join-OpsValue $displayVersion
        Build = [int]($os.BuildNumber)
        UpdateBuildRevision = $ubr
        OsVersion = $os.Version
        InstallDate = $os.InstallDate
        LastBootUpTime = $os.LastBootUpTime
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        Domain = $cs.Domain
        PartOfDomain = $cs.PartOfDomain
    }
}

if (-not (Test-Path -LiteralPath $LifecycleDataPath)) {
    throw "Lifecycle data file not found: $LifecycleDataPath. It ships with the repo under data\it-operations\lifecycle\."
}

$lifecycleData = @(Import-Csv -LiteralPath $LifecycleDataPath)

# Staleness comes from the VerifiedOn column, not from the file timestamp. Git sets
# a checked-out file's mtime to the checkout time, so a fresh clone of two-year-old
# data would otherwise report itself as verified today.
$verifiedDates = foreach ($row in $lifecycleData) {
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string](Get-OpsPropertyValue -InputObject $row -Name 'VerifiedOn'), [ref]$parsed)) {
        $parsed
    }
}

$oldestVerified = @($verifiedDates) | Sort-Object | Select-Object -First 1
$dataAgeDays = if ($oldestVerified) { [int][math]::Floor(((Get-Date) - $oldestVerified).TotalDays) } else { $null }
$dataIsStale = $null -eq $dataAgeDays -or $dataAgeDays -gt $DataMaxAgeDays

if ($null -eq $dataAgeDays) {
    Write-Warning "The lifecycle data file has no usable VerifiedOn dates, so its age cannot be established. Treat every date in this report as unverified."
} elseif ($dataIsStale) {
    Write-Warning "The oldest lifecycle row was verified $dataAgeDays days ago, over the $DataMaxAgeDays day threshold. Microsoft moves these dates. Re-check them against the Source column before acting on this report."
}

$asOf = Get-Date
$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$records = [System.Collections.Generic.List[object]]::new()

foreach ($target in $targets) {
    $fact = $null
    try {
        $fact = Get-MachineLifecycleFact -Target $target
    } catch {
        Write-Warning "Could not query $target : $($_.Exception.Message)"
        $records.Add([pscustomobject]@{
                ComputerName = $target
                Status = 'Unreachable'
                Caption = ''
                DisplayVersion = ''
                Build = $null
                EditionClass = ''
                EndOfServicing = $null
                DaysRemaining = $null
                Note = $_.Exception.Message
            })
        continue
    }

    $product = Get-ProductLine -Caption ([string]$fact.Caption)
    $editionClass = Get-EditionClass -Caption ([string]$fact.Caption) -ProductLine $product.Line
    $version = if ($product.Version) { $product.Version } else { [string]$fact.DisplayVersion }

    $match = @($lifecycleData | Where-Object {
            $_.ProductLine -eq $product.Line -and
            $_.EditionClass -eq $editionClass -and
            ($_.Version -eq $version -or [int]$_.Build -eq [int]$fact.Build)
        })

    # Prefer a version match over a build match. Windows 11 24H2 and Windows Server
    # 2025 share build 26100, so build alone is not an identity.
    $exact = @($match | Where-Object { $_.Version -eq $version })
    if ($exact.Count -gt 0) {
        $match = $exact
    }

    $row = $match | Select-Object -First 1
    $endOfServicing = $null
    $daysRemaining = $null
    $status = 'Unknown'
    $note = ''

    if ($row) {
        $endOfServicing = [datetime]$row.EndOfServicing
        $daysRemaining = [int][math]::Floor(($endOfServicing - $asOf).TotalDays)
        $note = $row.Note
        $status = if ($daysRemaining -lt 0) {
            'OutOfSupport'
        } elseif ($daysRemaining -le $WarnWithinDays) {
            'EndingSoon'
        } else {
            'Supported'
        }
    } else {
        $note = "No lifecycle row for product line '$($product.Line)', version '$version', edition class '$editionClass', build $($fact.Build). Add a row to the data file."
    }

    $records.Add([pscustomobject]@{
            ComputerName = $fact.ComputerName
            Status = $status
            Caption = $fact.Caption
            ProductLine = $product.Line
            DisplayVersion = $version
            Build = $fact.Build
            UpdateBuildRevision = $fact.UpdateBuildRevision
            OsVersion = $fact.OsVersion
            EditionClass = $editionClass
            EndOfServicing = $endOfServicing
            DaysRemaining = $daysRemaining
            DateVerifiedOn = if ($row) { Get-OpsPropertyValue -InputObject $row -Name 'VerifiedOn' } else { '' }
            DateSource = if ($row) { Get-OpsPropertyValue -InputObject $row -Name 'Source' } else { '' }
            Manufacturer = $fact.Manufacturer
            Model = $fact.Model
            Domain = $fact.Domain
            PartOfDomain = $fact.PartOfDomain
            InstallDate = $fact.InstallDate
            LastBootUpTime = $fact.LastBootUpTime
            Note = $note
        })
}

$inventory = @($records) | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysRemaining) { [int]::MaxValue } else { $_.DaysRemaining } } }, ComputerName

$statusRollup = foreach ($group in (@($inventory) | Group-Object -Property Status)) {
    [pscustomobject]@{
        Status = $group.Name
        Count = $group.Count
        Computers = (@($group.Group | ForEach-Object { $_.ComputerName }) | Sort-Object) -join ';'
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'lifecycle-inventory' -Record $inventory -Directory $runDirectory
    Export-OpsReport -Name 'status-rollup' -Record @($statusRollup) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    LifecycleDataPath = (Resolve-Path -LiteralPath $LifecycleDataPath).Path
    LifecycleDataOldestVerifiedOn = $oldestVerified
    LifecycleDataAgeDays = $dataAgeDays
    LifecycleDataIsStale = $dataIsStale
    WarnWithinDays = $WarnWithinDays
    ComputersQueried = @($targets).Count
    OutOfSupportCount = @($inventory | Where-Object { $_.Status -eq 'OutOfSupport' }).Count
    EndingSoonCount = @($inventory | Where-Object { $_.Status -eq 'EndingSoon' }).Count
    SupportedCount = @($inventory | Where-Object { $_.Status -eq 'Supported' }).Count
    UnknownCount = @($inventory | Where-Object { $_.Status -eq 'Unknown' }).Count
    UnreachableCount = @($inventory | Where-Object { $_.Status -eq 'Unreachable' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
