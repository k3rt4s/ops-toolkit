#Requires -Version 7.0

<#
.SYNOPSIS
Run the read-only collectors and assemble a dated evidence pack answering the security control questions insurers and assessors ask.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It runs only collectors that change nothing, and writes a bundle. No
  control is remediated, enabled, or altered by this script.
- Run elevated for complete results. Several collectors report Undetermined without
  elevation, and Undetermined is reported as such rather than folded into a pass.
- Without -ComputerName or -TargetListPath the pack covers this machine only, and
  says so on every endpoint control. Estate scope needs WinRM and local
  administrator rights on each target.
- Not every collector can reach a remote machine. The pack detects which ones accept
  -ComputerName by reading their parameter blocks, passes the target list only to
  those, and records the rest as local-only in the collector run log, so a
  machine-scoped claim is never made from a single-machine reading.
- -ScopeExclusion removes a named target only when a reason is supplied. The target
  and reason remain in every endpoint control's scope fields.
- -DefenderDeviceInventoryPath accepts the devices.csv written by
  Export-DefenderEndpointDeviceInventory.ps1. Pair it with -CoverageManifestPath to
  grade estate-wide endpoint protection against independent required authorities.
- -IncludeEntra and -IncludeActiveDirectory are off by default because they need
  credentials and modules that a workstation may not have. Controls whose collector
  did not run are reported NotAssessed, never Met.
- The pack contains configuration state, not secrets. No password, key, recovery
  value, or certificate private key is collected or written.
- Review the pack before sending it anywhere. It describes your security posture,
  which makes it sensitive in its own right.
- Generated packs are written under reports\evidence by default.

Purpose:
Cyber insurers moved during 2026 from questionnaires to technical verification, and
CMMC assessors ask the same questions with more paperwork. Both want evidence rather
than assertions, and the evidence is scattered across a dozen consoles that each
answer part of one question. This runs the collectors already in this repo, maps
their output to the questions actually asked, and produces one dated bundle with the
raw output attached.

The design rule that makes it usable as evidence: a control whose collector did not
run, or ran and could not read what it needed, is reported NotAssessed. It is never
reported as Met, and the summary counts NotAssessed separately from NotMet, because
an evidence pack that quietly converts "we did not check" into "we are fine" is
worse than no pack at all.

Required syntax:
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -IncludeEntra -IncludeActiveDirectory
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -Organization "Example Ltd" -OutputDirectory D:\evidence
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -DefenderDeviceInventoryPath .\devices.csv -CoverageManifestPath .\authorities.json

.OUTPUTS
Writes a control assessment, a collector run log, a readable summary.md, and every
collector's own reports into one dated pack directory. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Organization = $env:USERDOMAIN,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetListPath,

    [Parameter()]
    [AllowEmptyCollection()]
    [hashtable[]]$ScopeExclusion,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DefenderDeviceInventoryPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CoverageManifestPath,

    [Parameter()]
    [switch]$IncludeEntra,

    [Parameter()]
    [switch]$IncludeActiveDirectory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdServer,

    [Parameter()]
    [ValidateRange(60, 3600)]
    [int]$CollectorTimeoutSeconds = 900,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\evidence'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'security-control-evidence'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

$scriptsRoot = Join-Path $PSScriptRoot '..'
$asOf = Get-Date
$packDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$collectorRoot = Join-Path $packDirectory 'collectors'
$inputsRoot = Join-Path $packDirectory 'inputs'
New-Item -ItemType Directory -Path $collectorRoot -Force | Out-Null
New-Item -ItemType Directory -Path $inputsRoot -Force | Out-Null

$isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$pwshPath = (Get-Process -Id $PID).Path

Write-Verbose "Assembling evidence pack in $packDirectory. Per-collector timeout: $CollectorTimeoutSeconds seconds. Elevated: $isElevated."
if (-not $isElevated) {
    Write-Warning 'Not running elevated. Several collectors will report Undetermined, and those controls will be reported NotAssessed rather than Met.'
}

$collectorRuns = [System.Collections.Generic.List[object]]::new()
$controls = [System.Collections.Generic.List[object]]::new()
$inputSources = [System.Collections.Generic.List[object]]::new()

# Resolve the target list. A file wins nothing over -ComputerName; the two combine,
# because an operator will keep a standing list and add a machine for one run.
$targets = [System.Collections.Generic.List[string]]::new()
foreach ($name in @($ComputerName)) {
    if ($name) { $targets.Add($name) }
}

if ($TargetListPath) {
    if (-not (Test-Path -LiteralPath $TargetListPath)) {
        throw "Target list not found: $TargetListPath. One computer name per line; blank lines and lines starting with # are ignored."
    }

    foreach ($line in [System.IO.File]::ReadAllLines($TargetListPath)) {
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#')) {
            $targets.Add($trimmed)
        }
    }
}

$requestedTargets = @($targets | Sort-Object -Unique)
$exclusions = [System.Collections.Generic.List[object]]::new()
$seenExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($ScopeExclusion | Where-Object { $_ })) {
    $target = ([string](Get-OpsPropertyValue -InputObject $entry -Name 'Target')).Trim()
    $reason = ([string](Get-OpsPropertyValue -InputObject $entry -Name 'Reason')).Trim()
    if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($reason)) {
        throw 'Every -ScopeExclusion entry needs non-empty Target and Reason values.'
    }
    if ($target -notin $requestedTargets) {
        throw "Scope exclusion '$target' is not in -ComputerName or -TargetListPath. An exclusion cannot widen or invent the requested scope."
    }
    if (-not $seenExclusions.Add($target)) {
        throw "Scope exclusion '$target' was supplied more than once. Each excluded endpoint needs one unambiguous reason."
    }
    $exclusions.Add([pscustomobject]@{ Target = $target; Reason = $reason })
}

$excludedNames = @($exclusions | ForEach-Object { $_.Target })
$resolvedTargets = @($requestedTargets | Where-Object { $_ -notin $excludedNames })
$isEstateScope = $requestedTargets.Count -gt 0
if ($isEstateScope -and $resolvedTargets.Count -eq 0) {
    throw 'Every requested target was excluded. Nothing remains to assess.'
}

$scopeText = if ($isEstateScope) {
    "$($resolvedTargets.Count) attempted machine(s), $($exclusions.Count) excluded"
} else {
    'this machine only'
}
Write-Verbose "Endpoint scope: $scopeText."

function Test-CollectorSupportsComputerName {
    <#
    .SYNOPSIS
    Return true when a collector script declares a ComputerName parameter.

    .DESCRIPTION
    Read from the script's own parameter block rather than from a maintained list, so
    a collector that gains remote support starts being fanned out without anyone
    remembering to update this script.

    .PARAMETER Path
    Path to the collector script.

    .OUTPUTS
    Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    if (-not $ast.ParamBlock) {
        return $false
    }

    foreach ($parameter in $ast.ParamBlock.Parameters) {
        if ($parameter.Name.VariablePath.UserPath -eq 'ComputerName') {
            return $true
        }
    }

    $false
}

function Invoke-Collector {
    <#
    .SYNOPSIS
    Run one collector in a child process and record whether it produced output.

    .DESCRIPTION
    Each collector runs isolated so that one failing does not abort the pack, and so
    a collector that hangs cannot hold the whole run open indefinitely.

    .PARAMETER Name
    Short collector name, used as its output folder.

    .PARAMETER RelativePath
    Path to the collector script, relative to the scripts root.

    .PARAMETER Argument
    Extra arguments for the collector.

    .OUTPUTS
    PSCustomObject describing the run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Argument = @(),

        [Parameter()]
        [switch]$InputDefinedScope,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$WorkingDirectory,

        # Passed rather than captured from script scope so the timeout is visible
        # where the wait actually happens.
        [Parameter()]
        [int]$TimeoutSeconds = $CollectorTimeoutSeconds
    )

    $scriptPath = Join-Path $scriptsRoot $RelativePath
    $outputPath = Join-Path $collectorRoot $Name
    $result = [pscustomobject]@{
        Collector = $Name
        ScriptPath = $scriptPath
        Status = 'NotRun'
        ExitCode = $null
        OutputPath = $outputPath
        DurationSeconds = 0
        Scope = 'LocalMachine'
        Note = ''
    }

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        $result.Status = 'Missing'
        $result.Note = "Collector script not found at $scriptPath."
        $collectorRuns.Add($result)
        return $result
    }

    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    $stdout = Join-Path $outputPath 'run.log'
    $stderr = Join-Path $outputPath 'run.err.log'
    $started = Get-Date

    # Fan out only to collectors that can actually reach a remote machine. A
    # collector that cannot is recorded as local-only so no estate-wide claim is
    # made from a reading of one machine.
    $targetArgument = @()
    if ($InputDefinedScope) {
        $result.Scope = 'InputDefined'
    } elseif ($isEstateScope) {
        if (Test-CollectorSupportsComputerName -Path $scriptPath) {
            $targetArgument = @('-ComputerName') + $resolvedTargets
            $result.Scope = "$($resolvedTargets.Count) machine(s)"
        } else {
            $result.Scope = 'LocalMachineOnly'
            $result.Note = 'This collector has no -ComputerName parameter, so it covers only the machine the pack ran on.'
        }
    }

    try {
        $arguments = @('-NoProfile', '-NonInteractive', '-File', $scriptPath, '-OutputDirectory', $outputPath) + $targetArgument + $Argument
        $startParameters = @{
            FilePath = $pwshPath
            ArgumentList = $arguments
            NoNewWindow = $true
            PassThru = $true
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
        }
        if ($WorkingDirectory) {
            $startParameters['WorkingDirectory'] = $WorkingDirectory
        }
        $process = Start-Process @startParameters

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $result.Status = 'TimedOut'
            $result.Note = "Exceeded $TimeoutSeconds seconds and was stopped."
        } else {
            $result.ExitCode = $process.ExitCode
            $result.Status = if ($process.ExitCode -eq 0) { 'Completed' } else { 'Failed' }
            if ($process.ExitCode -ne 0) {
                $errorText = if (Test-Path -LiteralPath $stderr) { (Get-Content -LiteralPath $stderr -Raw) } else { '' }
                $result.Note = ($errorText -replace '\s+', ' ').Trim()
            }
        }
    } catch {
        $result.Status = 'Failed'
        $result.Note = $_.Exception.Message
    }

    $result.DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)

    # Record where the output sits relative to the pack, not as an absolute path. The
    # pack should survive being zipped and read somewhere else, and an absolute path
    # also makes every run-over-run comparison show a change that is not one.
    $result | Add-Member -NotePropertyName RelativeOutputPath -NotePropertyValue "collectors\$Name" -Force
    $collectorRuns.Add($result)
    $result
}

function Get-CollectorSummary {
    <#
    .SYNOPSIS
    Read the summary.json a collector wrote, or return null when it produced none.

    .PARAMETER Run
    The collector run record.

    .OUTPUTS
    The parsed summary object, or null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Run
    )

    if ($Run.Status -ne 'Completed') {
        return $null
    }

    $summaryFile = Get-ChildItem -LiteralPath $Run.OutputPath -Filter 'summary.json' -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $summaryFile) {
        return $null
    }

    try {
        Get-Content -LiteralPath $summaryFile.FullName -Raw | ConvertFrom-Json
    } catch {
        $null
    }
}

function Copy-OpsEvidenceInput {
    <#
    .SYNOPSIS
    Snapshot one operator-supplied evidence file into the pack and record its read status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DestinationName
    )

    $record = [pscustomobject]@{
        Name = $Name
        SourcePath = [System.IO.Path]::GetFileName($Path)
        Status = 'NotRead'
        SnapshotPath = ''
        SourceSHA256 = ''
        SHA256 = ''
        ObservedAt = $null
        Note = ''
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $record.Note = "File not found: $([System.IO.Path]::GetFileName($Path))"
        $inputSources.Add($record)
        return $record
    }

    try {
        $source = Get-Item -LiteralPath $Path
        $destination = Join-Path $inputsRoot $DestinationName
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $Path -Destination $destination -Force
        $snapshot = Get-Item -LiteralPath $destination
        $record.Status = 'Read'
        $record.SourcePath = $source.Name
        $record.SourceSHA256 = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
        $record.SnapshotPath = [System.IO.Path]::GetRelativePath($packDirectory, $snapshot.FullName)
        $record.SHA256 = (Get-FileHash -LiteralPath $snapshot.FullName -Algorithm SHA256).Hash
        $record.ObservedAt = $snapshot.LastWriteTimeUtc
    } catch {
        $record.Note = $_.Exception.Message
    }

    $inputSources.Add($record)
    $record
}

function ConvertTo-OpsEndpointKey {
    <#
    .SYNOPSIS
    Normalize an endpoint name to the short, case-insensitive key used by reconciliation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowEmptyString()][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    $Name.Trim().Split('.')[0].ToUpperInvariant()
}

function Get-OpsEndpointCoverageStatus {
    <#
    .SYNOPSIS
    Grade estate endpoint protection from management-plane and reconciliation evidence.

    .DESCRIPTION
    A known agent or inventory gap outranks an unread source because the gap remains
    true regardless of what the unread source would have said. With no known gap, an
    unread required authority or an undetermined device makes the result NotAssessed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][bool]$InventoryReadable,
        [Parameter(Mandatory = $true)][int]$DeviceCount,
        [Parameter(Mandatory = $true)][bool]$CoverageReadable,
        [Parameter(Mandatory = $true)][int]$ReconciledPopulationCount,
        [Parameter(Mandatory = $true)][int]$RequiredAuthoritiesRead,
        [Parameter(Mandatory = $true)][bool]$DefenderAuthorityIncluded,
        [Parameter(Mandatory = $true)][int]$AttentionCount,
        [Parameter(Mandatory = $true)][int]$CoverageGapCount,
        [Parameter(Mandatory = $true)][int]$UnreadRequiredCount,
        [Parameter(Mandatory = $true)][int]$UndeterminedCount
    )

    if ($AttentionCount -gt 0 -or $CoverageGapCount -gt 0) {
        return 'NotMet'
    }
    if (-not $InventoryReadable -or $DeviceCount -eq 0 -or -not $CoverageReadable -or
        $ReconciledPopulationCount -eq 0 -or $RequiredAuthoritiesRead -lt 2 -or
        -not $DefenderAuthorityIncluded -or
        $UnreadRequiredCount -gt 0 -or $UndeterminedCount -gt 0) {
        return 'NotAssessed'
    }
    'Met'
}

function Get-OpsControlConclusion {
    <#
    .SYNOPSIS
    Render a control status as evidence language that does not imply framework conformance.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Met', 'NotMet', 'Partial', 'NotAssessed')]
        [string]$Status
    )

    switch ($Status) {
        'Met' { 'Observed evidence supports the question within the stated scope.' }
        'NotMet' { 'Observed evidence shows a gap within the stated scope.' }
        'Partial' { 'Observed evidence supports only part of the question or population.' }
        default { 'No sufficient evidence was produced for this question in this run.' }
    }
}

function Get-OpsControlScopeKind {
    <#
    .SYNOPSIS
    Classify a custom evidence-pack control by the population its evidence observes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$ControlId
    )

    if ($ControlId -eq 'EDR-02') { return 'LocalEndpoint' }
    if ($ControlId -match '^(EDR-01|ENC-|PATCH-|CFG-|LOG-|PRIV-0[12])') { return 'EndpointPopulation' }
    if ($ControlId -match '^(MFA-|IAM-)') { return 'EntraTenant' }
    if ($ControlId -eq 'PRIV-03') { return 'ActiveDirectoryDomain' }
    'Organization'
}

function Get-OpsEvidenceFile {
    <#
    .SYNOPSIS
    Resolve the files behind a semicolon-separated evidence path list inside a pack.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter()][AllowEmptyString()][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$PackDirectory
    )

    foreach ($entry in @($Evidence -split ';' | Where-Object { $_ })) {
        $candidate = Join-Path $PackDirectory $entry
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Get-Item -LiteralPath $candidate
        } elseif (Test-Path -LiteralPath $candidate -PathType Container) {
            Get-ChildItem -LiteralPath $candidate -File -Recurse | Sort-Object FullName
        }
    }
}

function Add-Control {
    <#
    .SYNOPSIS
    Record one control assessment.

    .DESCRIPTION
    Status must be one of Met, NotMet, Partial, or NotAssessed. NotAssessed is a
    first-class outcome: it means nobody checked, and it must never be presented as
    a pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Question,
        [Parameter(Mandatory = $true)][ValidateSet('Met', 'NotMet', 'Partial', 'NotAssessed')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Finding,
        [Parameter()][AllowEmptyString()][string]$Evidence = '',
        [Parameter()][AllowEmptyString()][string]$Collector = '',
        [Parameter()][AllowEmptyString()][string]$Limitations = ''
    )

    $controls.Add([pscustomobject]@{
            ControlId = $Id
            Question = $Question
            Status = $Status
            Finding = $Finding
            Evidence = $Evidence
            Collector = $Collector
            Conclusion = Get-OpsControlConclusion -Status $Status
            IntendedScope = ''
            IntendedCount = 0
            AttemptedPopulation = ''
            AttemptedCount = 0
            ObservedCount = 0
            FailedCount = 0
            FailedReads = ''
            ExcludedPopulation = ''
            ExcludedCount = 0
            ExclusionReasons = ''
            EvidenceArtifacts = ''
            EvidenceHashes = ''
            EvidenceObservedAt = $null
            EvidenceAgeDays = $null
            Limitations = $Limitations
            AssessedAt = Get-Date
        })
}

# ---------------------------------------------------------------------------
# Optional operator-supplied management-plane and reconciliation evidence.
# ---------------------------------------------------------------------------
$defenderInput = $null
$defenderRecords = @()
$defenderSourceFullPath = ''
if ($DefenderDeviceInventoryPath) {
    $defenderInput = Copy-OpsEvidenceInput -Name 'DefenderDeviceInventory' `
        -Path $DefenderDeviceInventoryPath -DestinationName 'defender-device-inventory.csv'
    if ($defenderInput.Status -eq 'Read') {
        try {
            $defenderSourceFullPath = (Resolve-Path -LiteralPath $DefenderDeviceInventoryPath).Path
            $defenderSnapshot = Join-Path $packDirectory $defenderInput.SnapshotPath
            $defenderRecords = @(Import-Csv -LiteralPath $defenderSnapshot)
            $firstDevice = $defenderRecords | Select-Object -First 1
            $columns = if ($null -eq $firstDevice) { @() } else { @($firstDevice.PSObject.Properties.Name) }
            foreach ($requiredColumn in @('ComputerDnsName', 'Verdict', 'CoverageStatus', 'ContactStatus')) {
                if ($defenderRecords.Count -gt 0 -and $requiredColumn -notin $columns) {
                    throw "Column '$requiredColumn' not found in the Defender device inventory."
                }
            }
        } catch {
            $defenderInput.Status = 'NotRead'
            $defenderInput.Note = $_.Exception.Message
            $defenderRecords = @()
        }
    }
}

$coverageInput = $null
$coverageRun = $null
$coverage = $null
$manifestIncludesDefenderInventory = $false
$defenderAuthorityName = ''
if ($CoverageManifestPath) {
    $coverageInput = Copy-OpsEvidenceInput -Name 'CoverageManifest' `
        -Path $CoverageManifestPath -DestinationName 'coverage-manifest.json'
    if ($coverageInput.Status -eq 'Read') {
        $coverageSnapshot = Join-Path $packDirectory $coverageInput.SnapshotPath
        try {
            $manifestSpecs = @(Get-Content -LiteralPath $CoverageManifestPath -Raw | ConvertFrom-Json)
            if ($manifestSpecs.Count -eq 0) {
                throw 'Coverage manifest contains no authorities.'
            }

            $sanitizedSpecs = [System.Collections.Generic.List[object]]::new()
            $authorityIndex = 0
            foreach ($spec in $manifestSpecs) {
                $authorityIndex++
                $authorityName = [string](Get-OpsPropertyValue -InputObject $spec -Name 'Name')
                $authorityPath = [string](Get-OpsPropertyValue -InputObject $spec -Name 'Path')
                $keyColumn = [string](Get-OpsPropertyValue -InputObject $spec -Name 'KeyColumn')
                $requiredValue = Get-OpsPropertyValue -InputObject $spec -Name 'Required'
                $required = if ($null -eq $requiredValue) { $true } else { [bool]$requiredValue }

                $safeName = ($authorityName -replace '[^A-Za-z0-9._-]', '_').Trim('_')
                if (-not $safeName) { $safeName = "authority-$authorityIndex" }
                $extension = [System.IO.Path]::GetExtension($authorityPath)
                if (-not $extension) { $extension = '.csv' }
                $destinationName = 'authorities\{0:D2}-{1}{2}' -f $authorityIndex, $safeName, $extension
                $resolvedAuthorityPath = if ($authorityPath) {
                    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($authorityPath)
                } else {
                    "missing-authority-$authorityIndex.csv"
                }
                $authorityInput = Copy-OpsEvidenceInput -Name "CoverageAuthority:$authorityName" `
                    -Path $resolvedAuthorityPath -DestinationName $destinationName
                $relativeAuthorityPath = if ($authorityInput.SnapshotPath) {
                    $authorityInput.SnapshotPath
                } else {
                    Join-Path 'inputs' $destinationName
                }

                if ($defenderSourceFullPath -and
                    $resolvedAuthorityPath.Equals($defenderSourceFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $manifestIncludesDefenderInventory = $true
                    $defenderAuthorityName = $authorityName
                }

                $sanitizedSpecs.Add([pscustomobject][ordered]@{
                        Name = $authorityName
                        Path = $relativeAuthorityPath
                        KeyColumn = $keyColumn
                        Required = $required
                    })
            }

            Set-Content -LiteralPath $coverageSnapshot -Encoding utf8 `
                -Value (@($sanitizedSpecs) | ConvertTo-Json -Depth 5 -AsArray)
            $coverageSnapshotItem = Get-Item -LiteralPath $coverageSnapshot
            $coverageInput.SHA256 = (Get-FileHash -LiteralPath $coverageSnapshot -Algorithm SHA256).Hash
            $coverageInput.ObservedAt = $coverageSnapshotItem.LastWriteTimeUtc

            $coverageRun = Invoke-Collector -Name 'coverage-reconciliation' `
                -RelativePath 'reporting\Export-CoverageReconciliation.ps1' `
                -Argument @('-ManifestPath', $coverageInput.SnapshotPath) `
                -InputDefinedScope -WorkingDirectory $packDirectory
            $coverage = Get-CollectorSummary -Run $coverageRun
        } catch {
            $coverageInput.Status = 'NotRead'
            $coverageInput.Note = $_.Exception.Message -replace [regex]::Escape($CoverageManifestPath), [System.IO.Path]::GetFileName($CoverageManifestPath)
            Set-Content -LiteralPath $coverageSnapshot -Encoding utf8 -Value '[]'
            $coverageInput.SHA256 = (Get-FileHash -LiteralPath $coverageSnapshot -Algorithm SHA256).Hash
        }
    }
}

# ---------------------------------------------------------------------------
# Endpoint protection. Estate coverage uses management-plane and reconciliation
# evidence when supplied. The local Defender read remains useful for one machine and
# for tamper protection, but it cannot establish coverage of an estate.
# ---------------------------------------------------------------------------
$defenderStatus = $null
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
} catch {
    $defenderStatus = $null
}

$inlineObservations = [System.Collections.Generic.List[object]]::new()
if ($null -ne $defenderStatus) {
    $inlineObservations.Add([pscustomobject]@{
            Observation = 'LocalMicrosoftDefender'
            ComputerName = $env:COMPUTERNAME
            ObservedAt = Get-Date
            RealTimeProtectionEnabled = Get-OpsPropertyValue -InputObject $defenderStatus -Name 'RealTimeProtectionEnabled'
            AntivirusSignatureAgeDays = Get-OpsPropertyValue -InputObject $defenderStatus -Name 'AntivirusSignatureAge'
            IsTamperProtected = Get-OpsPropertyValue -InputObject $defenderStatus -Name 'IsTamperProtected'
        })
}
Export-OpsReport -Name 'inline-observations' -Record @($inlineObservations) -Directory $packDirectory |
    Out-Null
$inlineEvidence = 'inline-observations.csv;inline-observations.json'

$managementEvidenceRequested = [bool]($DefenderDeviceInventoryPath -or $CoverageManifestPath)
$excludedKeySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($excludedName in $excludedNames) {
    $excludedKeySet.Add((ConvertTo-OpsEndpointKey -Name $excludedName)) | Out-Null
}
$coveragePopulation = @()
$coverageRows = @()
$authorityRows = @()
$managementAttemptedNames = @()
$managementFailedNames = @()
$managementFailedReads = @()
if ($managementEvidenceRequested) {
    $inventoryReadable = $null -ne $defenderInput -and $defenderInput.Status -eq 'Read'
    $filteredDefenderRecords = @($defenderRecords | Where-Object {
            $key = ConvertTo-OpsEndpointKey -Name $_.ComputerDnsName
            $key -and -not $excludedKeySet.Contains($key)
        })
    $defenderNames = @($filteredDefenderRecords | ForEach-Object {
            ConvertTo-OpsEndpointKey -Name $_.ComputerDnsName
        } | Where-Object { $_ } | Sort-Object -Unique)
    $deviceCount = $defenderNames.Count
    $defenderBlankCount = @($defenderRecords | Where-Object {
            -not (ConvertTo-OpsEndpointKey -Name $_.ComputerDnsName)
        }).Count
    $attentionNames = @($filteredDefenderRecords | Where-Object {
            $_.Verdict -in @('Silent', 'Inactive', 'NotOnboarded')
        } | ForEach-Object {
            ConvertTo-OpsEndpointKey -Name $_.ComputerDnsName
        } | Sort-Object -Unique)
    $deviceUndeterminedNames = @($filteredDefenderRecords | Where-Object {
            $_.Verdict -notin @('Protected', 'Silent', 'Inactive', 'NotOnboarded') -or
            $_.CoverageStatus -notin @('Onboarded', 'NotOnboarded') -or
            $_.ContactStatus -notin @('Reporting', 'Silent', 'Inactive')
        } | ForEach-Object {
            ConvertTo-OpsEndpointKey -Name $_.ComputerDnsName
        } | Sort-Object -Unique)
    $attentionCount = $attentionNames.Count
    $deviceUndetermined = $deviceUndeterminedNames.Count

    $coverageReadable = $false
    if ($null -ne $coverage) {
        $coverageRowsFile = Get-ChildItem -LiteralPath $coverageRun.OutputPath `
            -Filter 'device-coverage.csv' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        $authorityRowsFile = Get-ChildItem -LiteralPath $coverageRun.OutputPath `
            -Filter 'authority-runs.csv' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        $coverageVerdict = [string](Get-OpsPropertyValue -InputObject $coverage -Name 'Verdict')
        if ($null -ne $coverageRowsFile -and $null -ne $authorityRowsFile -and
            $coverageVerdict -in @('Reconciled', 'GapsFound', 'Undetermined')) {
            $coverageRows = @(Import-Csv -LiteralPath $coverageRowsFile.FullName | Where-Object {
                    $key = ConvertTo-OpsEndpointKey -Name $_.MachineKey
                    $key -and -not $excludedKeySet.Contains($key)
                })
            $authorityRows = @(Import-Csv -LiteralPath $authorityRowsFile.FullName)
            $coverageReadable = $true
        }
    }

    $coveragePopulation = @($coverageRows | ForEach-Object {
            ConvertTo-OpsEndpointKey -Name $_.MachineKey
        } | Where-Object { $_ } | Sort-Object -Unique)
    $coverageGapNames = @($coverageRows | Where-Object { $_.Status -eq 'Gap' } |
            ForEach-Object { ConvertTo-OpsEndpointKey -Name $_.MachineKey } | Sort-Object -Unique)
    $coverageUndeterminedNames = @($coverageRows | Where-Object { $_.Status -eq 'Undetermined' } |
            ForEach-Object { ConvertTo-OpsEndpointKey -Name $_.MachineKey } | Sort-Object -Unique)
    $coverageGaps = if ($manifestIncludesDefenderInventory) { $coverageGapNames.Count } else { 0 }
    $coverageUndetermined = $coverageUndeterminedNames.Count
    $readRequiredRows = @($authorityRows | Where-Object {
            $_.Required -eq 'True' -and $_.Status -eq 'Read'
        })
    $readRequiredCount = $readRequiredRows.Count
    $unreadRequiredNames = @($authorityRows | Where-Object {
            $_.Required -eq 'True' -and $_.Status -ne 'Read'
        } | ForEach-Object { $_.Authority })
    $unreadRequired = $unreadRequiredNames.Count
    $defenderAuthorityRequiredRead = [bool]($manifestIncludesDefenderInventory -and
        @($readRequiredRows | Where-Object { $_.Authority -eq $defenderAuthorityName }).Count -gt 0)

    $edrStatus = Get-OpsEndpointCoverageStatus -InventoryReadable $inventoryReadable `
        -DeviceCount $deviceCount -CoverageReadable $coverageReadable `
        -ReconciledPopulationCount $coveragePopulation.Count `
        -RequiredAuthoritiesRead $readRequiredCount `
        -DefenderAuthorityIncluded $defenderAuthorityRequiredRead `
        -AttentionCount $attentionCount `
        -CoverageGapCount $coverageGaps -UnreadRequiredCount $unreadRequired `
        -UndeterminedCount ($deviceUndetermined + $coverageUndetermined)

    $managementAttemptedNames = if ($coveragePopulation.Count -gt 0) {
        $coveragePopulation
    } else {
        $defenderNames
    }
    $knownGapNames = @($attentionNames + $(if ($manifestIncludesDefenderInventory) { $coverageGapNames }) |
            Where-Object { $_ } | Sort-Object -Unique)
    $managementFailedNames = @($deviceUndeterminedNames + $coverageUndeterminedNames |
            Where-Object { $_ } | Sort-Object -Unique)
    if (-not $coverageReadable -or $readRequiredCount -lt 2 -or -not $defenderAuthorityRequiredRead) {
        $managementFailedNames = @($managementAttemptedNames | Where-Object {
                $_ -notin $knownGapNames
            })
    }

    if (-not $DefenderDeviceInventoryPath) {
        $managementFailedReads += 'Defender device inventory: not supplied'
    } elseif (-not $inventoryReadable) {
        $managementFailedReads += "Defender device inventory: $($defenderInput.Note)"
    }
    if (-not $CoverageManifestPath) {
        $managementFailedReads += 'Coverage manifest: not supplied'
    } elseif (-not $coverageReadable) {
        $managementFailedReads += 'Coverage manifest or reconciliation output: not readable'
    }
    if ($unreadRequiredNames.Count -gt 0) {
        $managementFailedReads += "Required authorities not read: $($unreadRequiredNames -join ', ')"
    }
    if ($readRequiredCount -lt 2) {
        $managementFailedReads += "Required authorities read: $readRequiredCount; at least 2 are required"
    }
    if (-not $defenderAuthorityRequiredRead) {
        $managementFailedReads += 'Defender inventory is not a readable required reconciliation authority'
    }
    if ($defenderBlankCount -gt 0) {
        $managementFailedReads += "Defender inventory rows without a machine name: $defenderBlankCount"
    }

    $edrEvidence = @($inputSources | Where-Object { $_.SnapshotPath } |
            ForEach-Object { $_.SnapshotPath })
    if ($coverageReadable) { $edrEvidence += $coverageRun.RelativeOutputPath }
    $coverageState = if (-not $CoverageManifestPath) {
        'not supplied'
    } elseif ($coverageReadable) {
        'read'
    } else {
        'not readable'
    }

    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status $edrStatus `
        -Finding "Management-plane devices in scope: $deviceCount. Silent, inactive, or not onboarded: $attentionCount. Unsupported, invalid, or unmeasured device readings: $deviceUndetermined. Coverage manifest: $coverageState. Required authorities read: $readRequiredCount. Reconciliation gaps: $($coverageGapNames.Count)$(if (-not $manifestIncludesDefenderInventory -and $coverageGapNames.Count -gt 0) { ' (not graded, the Defender inventory is not a reconciliation authority)' }). Reconciliation rows undetermined: $coverageUndetermined. Unread required authorities: $(if ($unreadRequiredNames.Count -gt 0) { $unreadRequiredNames -join ', ' } else { 'none' })." `
        -Evidence ($edrEvidence -join ';') `
        -Collector 'Export-DefenderEndpointDeviceInventory.ps1 + Export-CoverageReconciliation.ps1' `
        -Limitations 'Management-plane and reconciliation exports are point-in-time snapshots. Explicit scope exclusions are removed from the Defender and reconciled populations before this result is graded.'
} elseif ($isEstateScope) {
    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status 'NotAssessed' `
        -Finding 'Estate scope was requested, but no Defender management-plane inventory and coverage manifest were supplied. A local Defender read cannot establish protection across all endpoints.' `
        -Evidence $inlineEvidence -Collector 'inline:Get-MpComputerStatus' `
        -Limitations 'Local Defender state is not evidence of estate-wide deployment.'
} elseif ($null -eq $defenderStatus) {
    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status 'NotAssessed' -Finding 'Microsoft Defender status could not be read. A third-party product may be in use, which this script does not detect.' `
        -Evidence $inlineEvidence -Collector 'inline:Get-MpComputerStatus' `
        -Limitations 'No endpoint-protection state was readable on the local machine.'
} else {
    $realTime = [bool](Get-OpsPropertyValue -InputObject $defenderStatus -Name 'RealTimeProtectionEnabled')
    $signatureAge = Get-OpsPropertyValue -InputObject $defenderStatus -Name 'AntivirusSignatureAge'
    $tamper = [bool](Get-OpsPropertyValue -InputObject $defenderStatus -Name 'IsTamperProtected')

    $edrStatus = if ($realTime -and $null -ne $signatureAge -and [int]$signatureAge -le 7) { 'Met' } elseif ($realTime) { 'Partial' } else { 'NotMet' }
    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status $edrStatus `
        -Finding "Real-time protection: $realTime. Signature age: $signatureAge days. Tamper protection: $tamper. Scope: this machine only, Defender is read locally." `
        -Evidence $inlineEvidence -Collector 'inline:Get-MpComputerStatus' `
        -Limitations 'This observation covers only the machine that assembled the pack.'
}

if ($null -eq $defenderStatus) {
    Add-Control -Id 'EDR-02' -Question 'Is tamper protection enabled so malware cannot disable endpoint protection?' `
        -Status 'NotAssessed' -Finding 'Local Microsoft Defender tamper-protection state could not be read.' `
        -Evidence $inlineEvidence -Collector 'inline:Get-MpComputerStatus' `
        -Limitations 'No local tamper-protection state was readable.'
} else {
    $tamper = [bool](Get-OpsPropertyValue -InputObject $defenderStatus -Name 'IsTamperProtected')
    Add-Control -Id 'EDR-02' -Question 'Is tamper protection enabled so malware cannot disable endpoint protection?' `
        -Status $(if ($tamper) { 'Met' } else { 'NotMet' }) `
        -Finding "Tamper protection is $(if ($tamper) { 'enabled' } else { 'not enabled' }) on this machine." `
        -Evidence $inlineEvidence -Collector 'inline:Get-MpComputerStatus' `
        -Limitations 'This observation covers only the machine that assembled the pack.'
}

# ---------------------------------------------------------------------------
# Disk encryption and key recoverability.
# ---------------------------------------------------------------------------
$bitlockerRun = Invoke-Collector -Name 'bitlocker' -RelativePath 'it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1'
$bitlocker = Get-CollectorSummary -Run $bitlockerRun
if ($null -eq $bitlocker) {
    Add-Control -Id 'ENC-01' -Question 'Is disk encryption enabled on all endpoints and laptops?' `
        -Status 'NotAssessed' -Finding "The BitLocker collector did not produce a summary. Status: $($bitlockerRun.Status). $($bitlockerRun.Note)" -Collector 'Export-BitLockerEscrowStatus.ps1'
    Add-Control -Id 'ENC-02' -Question 'Are disk encryption recovery keys escrowed where they can be retrieved?' `
        -Status 'NotAssessed' -Finding 'Not assessed because the BitLocker collector did not run.' -Collector 'Export-BitLockerEscrowStatus.ps1'
} else {
    $atRisk = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'AtRiskCount')
    $undetermined = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'UndeterminedCount')
    $protected = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'ProtectedCount')
    $partial = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'PartiallyProtectedCount')
    $notEncrypted = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'NotEncryptedCount')

    $encStatus = if ($undetermined -gt 0) { 'NotAssessed' } elseif ($notEncrypted -gt 0) { 'NotMet' } elseif ($partial -gt 0) { 'Partial' } elseif ($protected -gt 0) { 'Met' } else { 'NotAssessed' }
    Add-Control -Id 'ENC-01' -Question 'Is disk encryption enabled on all endpoints and laptops?' `
        -Status $encStatus `
        -Finding "Protected: $protected. Partially protected: $partial. Not encrypted: $notEncrypted. Undetermined: $undetermined." `
        -Evidence $bitlockerRun.RelativeOutputPath -Collector 'Export-BitLockerEscrowStatus.ps1'

    $noKey = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'VolumesWithoutRecoveryKey')
    # Escrow is assessable wherever any volume is actually encrypted, including a
    # machine whose overall verdict is only PartiallyProtected.
    $escrowStatus = if ($undetermined -gt 0) { 'NotAssessed' } elseif ($atRisk -gt 0 -or $noKey -gt 0) { 'NotMet' } elseif (($protected + $partial) -gt 0) { 'Partial' } else { 'NotAssessed' }
    Add-Control -Id 'ENC-02' -Question 'Are disk encryption recovery keys escrowed where they can be retrieved?' `
        -Status $escrowStatus `
        -Finding "Volumes with no recovery key: $noKey. Machines at risk: $atRisk. Escrow was verified against a directory only where -VerifyAdEscrow was used; otherwise this reflects policy configuration." `
        -Evidence $bitlockerRun.RelativeOutputPath -Collector 'Export-BitLockerEscrowStatus.ps1'
}

# ---------------------------------------------------------------------------
# Privileged access on the endpoint.
# ---------------------------------------------------------------------------
$lapsRun = Invoke-Collector -Name 'local-admin' -RelativePath 'it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1'
$laps = Get-CollectorSummary -Run $lapsRun
if ($null -eq $laps) {
    Add-Control -Id 'PRIV-01' -Question 'Are local administrator passwords unique and managed?' `
        -Status 'NotAssessed' -Finding "The local admin collector did not produce a summary. Status: $($lapsRun.Status)." -Collector 'Export-LocalAdminAndLapsPosture.ps1'
} else {
    $unmanaged = [int](Get-OpsPropertyValue -InputObject $laps -Name 'UnmanagedCount')
    $needsAttention = [int](Get-OpsPropertyValue -InputObject $laps -Name 'NeedsAttentionCount')
    $managed = [int](Get-OpsPropertyValue -InputObject $laps -Name 'ManagedCount')
    $orphans = [int](Get-OpsPropertyValue -InputObject $laps -Name 'OrphanedSidTotal')

    $privStatus = if ($unmanaged -gt 0) { 'NotMet' } elseif ($needsAttention -gt 0) { 'Partial' } elseif ($managed -gt 0) { 'Met' } else { 'NotAssessed' }
    Add-Control -Id 'PRIV-01' -Question 'Are local administrator passwords unique and managed?' `
        -Status $privStatus `
        -Finding "LAPS managed: $managed. Needs attention: $needsAttention. Unmanaged: $unmanaged." `
        -Evidence $lapsRun.RelativeOutputPath -Collector 'Export-LocalAdminAndLapsPosture.ps1'

    Add-Control -Id 'PRIV-02' -Question 'Is local administrator group membership controlled and reviewed?' `
        -Status $(if ($orphans -gt 0) { 'NotMet' } else { 'Partial' }) `
        -Finding "Total local administrator members: $(Get-OpsPropertyValue -InputObject $laps -Name 'TotalAdminMembers'). Unresolvable SIDs holding admin: $orphans. Membership is reported, not approved; approval is a human review this cannot perform." `
        -Evidence $lapsRun.RelativeOutputPath -Collector 'Export-LocalAdminAndLapsPosture.ps1'
}

# ---------------------------------------------------------------------------
# Patching and supportability.
# ---------------------------------------------------------------------------
$updateRun = Invoke-Collector -Name 'update-health' -RelativePath 'it-operations\lifecycle\Export-WindowsUpdateHealth.ps1'
$update = Get-CollectorSummary -Run $updateRun
if ($null -eq $update) {
    Add-Control -Id 'PATCH-01' -Question 'Are security patches applied within a defined window?' `
        -Status 'NotAssessed' -Finding "The update health collector did not produce a summary. Status: $($updateRun.Status)." -Collector 'Export-WindowsUpdateHealth.ps1'
} else {
    $unhealthy = [int](Get-OpsPropertyValue -InputObject $update -Name 'UnhealthyCount')
    $degraded = [int](Get-OpsPropertyValue -InputObject $update -Name 'DegradedCount')
    $healthy = [int](Get-OpsPropertyValue -InputObject $update -Name 'HealthyCount')

    Add-Control -Id 'PATCH-01' -Question 'Are security patches applied within a defined window?' `
        -Status $(if ($unhealthy -gt 0) { 'NotMet' } elseif ($degraded -gt 0) { 'Partial' } elseif ($healthy -gt 0) { 'Met' } else { 'NotAssessed' }) `
        -Finding "Healthy: $healthy. Degraded: $degraded. Unhealthy: $unhealthy. Pending reboot on $(Get-OpsPropertyValue -InputObject $update -Name 'PendingRebootCount') machine(s)." `
        -Evidence $updateRun.RelativeOutputPath -Collector 'Export-WindowsUpdateHealth.ps1'
}

$lifecycleRun = Invoke-Collector -Name 'lifecycle' -RelativePath 'it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1'
$lifecycle = Get-CollectorSummary -Run $lifecycleRun
if ($null -eq $lifecycle) {
    Add-Control -Id 'PATCH-02' -Question 'Are all operating systems still receiving security updates from the vendor?' `
        -Status 'NotAssessed' -Finding "The lifecycle collector did not produce a summary. Status: $($lifecycleRun.Status)." -Collector 'Export-WindowsLifecycleInventory.ps1'
} else {
    $outOfSupport = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'OutOfSupportCount')
    $endingSoon = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'EndingSoonCount')
    $unknown = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'UnknownCount')

    Add-Control -Id 'PATCH-02' -Question 'Are all operating systems still receiving security updates from the vendor?' `
        -Status $(if ($outOfSupport -gt 0) { 'NotMet' } elseif ($unknown -gt 0) { 'Partial' } elseif ($endingSoon -gt 0) { 'Partial' } else { 'Met' }) `
        -Finding "Out of support: $outOfSupport. Support ending within the warning window: $endingSoon. Unrecognised build: $unknown." `
        -Evidence $lifecycleRun.RelativeOutputPath -Collector 'Export-WindowsLifecycleInventory.ps1'
}

# ---------------------------------------------------------------------------
# Transport security and hardening.
# ---------------------------------------------------------------------------
$hardeningRun = Invoke-Collector -Name 'hardening' -RelativePath 'windows-hardening\Test-WindowsHardeningState.ps1'
$hardening = Get-CollectorSummary -Run $hardeningRun
if ($null -eq $hardening) {
    Add-Control -Id 'CFG-01' -Question 'Are systems hardened to a documented configuration standard?' `
        -Status 'NotAssessed' -Finding "The hardening verifier did not produce a summary. Status: $($hardeningRun.Status)." -Collector 'Test-WindowsHardeningState.ps1'
} else {
    $drift = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'TotalDrift')
    $checked = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'ItemsChecked')
    $compliant = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'CompliantCount')

    Add-Control -Id 'CFG-01' -Question 'Are systems hardened to a documented configuration standard?' `
        -Status $(if ($checked -eq 0) { 'NotAssessed' } elseif ($drift -eq 0) { 'Met' } elseif ($compliant -gt 0) { 'Partial' } else { 'NotMet' }) `
        -Finding "$compliant of $checked hardening items are in the desired state. Items not in the desired state: $drift." `
        -Evidence $hardeningRun.RelativeOutputPath -Collector 'Test-WindowsHardeningState.ps1'
}

$certRun = Invoke-Collector -Name 'certificates' -RelativePath 'certificates\Export-CertificateExpiryInventory.ps1'
$certificates = Get-CollectorSummary -Run $certRun
if ($null -eq $certificates) {
    Add-Control -Id 'CFG-02' -Question 'Are certificates tracked and renewed before expiry?' `
        -Status 'NotAssessed' -Finding "The certificate collector did not produce a summary. Status: $($certRun.Status)." -Collector 'Export-CertificateExpiryInventory.ps1'
} else {
    $expired = [int](Get-OpsPropertyValue -InputObject $certificates -Name 'ExpiredCount')
    $soon = [int](Get-OpsPropertyValue -InputObject $certificates -Name 'ExpiringSoonCount')

    Add-Control -Id 'CFG-02' -Question 'Are certificates tracked and renewed before expiry?' `
        -Status $(if ($expired -gt 0) { 'NotMet' } elseif ($soon -gt 0) { 'Partial' } else { 'Met' }) `
        -Finding "Expired: $expired. Expiring within the warning window: $soon. Weak signature: $(Get-OpsPropertyValue -InputObject $certificates -Name 'WeakSignatureCount')." `
        -Evidence $certRun.RelativeOutputPath -Collector 'Export-CertificateExpiryInventory.ps1'
}

# ---------------------------------------------------------------------------
# Security logging. Assessors and insurers ask whether logs are kept and for how
# long, and both halves are asked separately because they fail separately: a
# machine can be generating everything and retaining six hours of it.
# ---------------------------------------------------------------------------
$telemetryRun = Invoke-Collector -Name 'telemetry-posture' -RelativePath 'logging\Export-EndpointTelemetryPosture.ps1'
$telemetry = Get-CollectorSummary -Run $telemetryRun
if ($null -eq $telemetry) {
    Add-Control -Id 'LOG-01' -Question 'Is security-relevant activity logged on endpoints?' `
        -Status 'NotAssessed' -Finding "The telemetry posture collector did not produce a summary. Status: $($telemetryRun.Status). $($telemetryRun.Note)" -Collector 'Export-EndpointTelemetryPosture.ps1'
    Add-Control -Id 'LOG-02' -Question 'Are logs retained long enough to investigate an incident found late?' `
        -Status 'NotAssessed' -Finding 'Not assessed because the telemetry posture collector did not run.' -Collector 'Export-EndpointTelemetryPosture.ps1'
} else {
    $settingsDisabled = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'RequiredSettingsDisabled')
    $settingsUnread = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'SettingsUndetermined')
    $checksGraded = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'ChecksGraded')

    # An unread setting is not a pass and not a failure. It is the reason the run
    # cannot answer the question, so it takes the control to NotAssessed outright.
    $logStatus = if ($checksGraded -eq 0 -or $settingsUnread -gt 0) { 'NotAssessed' } elseif ($settingsDisabled -gt 0) { 'NotMet' } else { 'Met' }
    Add-Control -Id 'LOG-01' -Question 'Is security-relevant activity logged on endpoints?' `
        -Status $logStatus `
        -Finding "Required logging settings switched off: $settingsDisabled of $checksGraded graded. Settings that could not be read: $settingsUnread. Machines fully covered: $(Get-OpsPropertyValue -InputObject $telemetry -Name 'CoveredCount'), partially: $(Get-OpsPropertyValue -InputObject $telemetry -Name 'PartialCount'), not covered: $(Get-OpsPropertyValue -InputObject $telemetry -Name 'NotCoveredCount')." `
        -Evidence $telemetryRun.RelativeOutputPath -Collector 'Export-EndpointTelemetryPosture.ps1'

    $shortRetention = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'ChannelsInsufficientRetention')
    $unmeasured = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'ChannelsUnmeasuredRetention')
    $channelsGraded = [int](Get-OpsPropertyValue -InputObject $telemetry -Name 'ChannelsGraded')
    $minimumDays = Get-OpsPropertyValue -InputObject $telemetry -Name 'MinimumRetentionDays'

    $retentionStatus = if ($channelsGraded -eq 0) { 'NotAssessed' } elseif ($shortRetention -gt 0) { 'NotMet' } elseif ($unmeasured -gt 0) { 'Partial' } else { 'Met' }
    Add-Control -Id 'LOG-02' -Question 'Are logs retained long enough to investigate an incident found late?' `
        -Status $retentionStatus `
        -Finding "Required channels retaining less than $minimumDays days: $shortRetention. Channels with no measurable history: $unmeasured of $channelsGraded. Retention is measured from the oldest record still present, not from configured log size, because a large log on a busy machine can hold hours." `
        -Evidence $telemetryRun.RelativeOutputPath -Collector 'Export-EndpointTelemetryPosture.ps1'
}

# ---------------------------------------------------------------------------
# Identity. Off by default: needs a tenant and consented scopes.
# ---------------------------------------------------------------------------
if ($IncludeEntra) {
    $mfaRun = Invoke-Collector -Name 'entra-auth-methods' -RelativePath 'entra\Export-EntraAuthMethodReadiness.ps1' -Argument @('-Connect')
    $mfa = Get-CollectorSummary -Run $mfaRun
    if ($null -eq $mfa) {
        Add-Control -Id 'MFA-01' -Question 'Is multi-factor authentication enforced for all users?' `
            -Status 'NotAssessed' -Finding "The Entra authentication method collector did not produce a summary. Status: $($mfaRun.Status). $($mfaRun.Note)" -Collector 'Export-EntraAuthMethodReadiness.ps1'
    } else {
        $noMfa = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'NoMfaRegisteredCount')
        $adminNoMfa = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'AdminsWithoutMfa')
        $reported = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'UsersReported')

        Add-Control -Id 'MFA-01' -Question 'Is multi-factor authentication enforced for all users?' `
            -Status $(if ($adminNoMfa -gt 0 -or $noMfa -gt 0) { 'NotMet' } elseif ($reported -gt 0) { 'Met' } else { 'NotAssessed' }) `
            -Finding "Users with no MFA method registered: $noMfa of $reported. Administrators with no MFA: $adminNoMfa. Registration is not the same as enforcement; see the Conditional Access control." `
            -Evidence $mfaRun.RelativeOutputPath -Collector 'Export-EntraAuthMethodReadiness.ps1'

        Add-Control -Id 'MFA-02' -Question 'Is MFA resistant to phishing and help desk social engineering?' `
            -Status $(if ([int](Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyCount') -gt 0) { 'NotMet' } elseif ([int](Get-OpsPropertyValue -InputObject $mfa -Name 'PhishingResistantCount') -gt 0) { 'Partial' } else { 'NotAssessed' }) `
            -Finding "Telephony-only users: $(Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyCount'), of which $(Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyAdminCount') are administrators. Phishing-resistant: $(Get-OpsPropertyValue -InputObject $mfa -Name 'PhishingResistantCount'). Microsoft-provided telephony delivery ends 1 February 2027." `
            -Evidence $mfaRun.RelativeOutputPath -Collector 'Export-EntraAuthMethodReadiness.ps1'
    }

    $caRun = Invoke-Collector -Name 'entra-conditional-access' -RelativePath 'entra\Export-EntraConditionalAccessBaseline.ps1' -Argument @('-Connect')
    $ca = Get-CollectorSummary -Run $caRun
    if ($null -eq $ca) {
        Add-Control -Id 'IAM-01' -Question 'Are access policies enforced, including a block on legacy authentication?' `
            -Status 'NotAssessed' -Finding "The Conditional Access collector did not produce a summary. Status: $($caRun.Status). $($caRun.Note)" -Collector 'Export-EntraConditionalAccessBaseline.ps1'
    } else {
        $criticalGaps = [int](Get-OpsPropertyValue -InputObject $ca -Name 'CriticalGapCount')
        $gaps = [int](Get-OpsPropertyValue -InputObject $ca -Name 'GapCount')

        Add-Control -Id 'IAM-01' -Question 'Are access policies enforced, including a block on legacy authentication?' `
            -Status $(if ($criticalGaps -gt 0) { 'NotMet' } elseif ($gaps -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Conditional Access policies: $(Get-OpsPropertyValue -InputObject $ca -Name 'PolicyCount') total, $(Get-OpsPropertyValue -InputObject $ca -Name 'EnabledCount') enforcing, $(Get-OpsPropertyValue -InputObject $ca -Name 'ReportOnlyCount') report-only. Missing baseline controls: $gaps, of which $criticalGaps are critical." `
            -Evidence $caRun.RelativeOutputPath -Collector 'Export-EntraConditionalAccessBaseline.ps1'
    }

    $credRun = Invoke-Collector -Name 'entra-app-credentials' -RelativePath 'entra\Export-EntraAppCredentialExpiry.ps1' -Argument @('-Connect', '-IncludeServicePrincipals')
    $credentials = Get-CollectorSummary -Run $credRun
    if ($null -eq $credentials) {
        Add-Control -Id 'IAM-02' -Question 'Are application credentials rotated before they expire?' `
            -Status 'NotAssessed' -Finding "The application credential collector did not produce a summary. Status: $($credRun.Status). $($credRun.Note)" -Collector 'Export-EntraAppCredentialExpiry.ps1'
    } else {
        $expiredCreds = [int](Get-OpsPropertyValue -InputObject $credentials -Name 'ExpiredCount')
        $expiringCreds = [int](Get-OpsPropertyValue -InputObject $credentials -Name 'ExpiringSoonCount')

        Add-Control -Id 'IAM-02' -Question 'Are application credentials rotated before they expire?' `
            -Status $(if ($expiredCreds -gt 0) { 'NotMet' } elseif ($expiringCreds -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Expired credentials still attached: $expiredCreds. Expiring within the warning window: $expiringCreds. Over-long secret lifetimes: $(Get-OpsPropertyValue -InputObject $credentials -Name 'ExceedsRecommendedLifetimeCount')." `
            -Evidence $credRun.RelativeOutputPath -Collector 'Export-EntraAppCredentialExpiry.ps1'
    }
} else {
    foreach ($pair in @(
            @('MFA-01', 'Is multi-factor authentication enforced for all users?'),
            @('MFA-02', 'Is MFA resistant to phishing and help desk social engineering?'),
            @('IAM-01', 'Are access policies enforced, including a block on legacy authentication?'),
            @('IAM-02', 'Are application credentials rotated before they expire?')
        )) {
        Add-Control -Id $pair[0] -Question $pair[1] -Status 'NotAssessed' `
            -Finding 'Not assessed. Re-run with -IncludeEntra and a Graph sign-in to cover the identity controls.' -Collector 'none'
    }
}

# ---------------------------------------------------------------------------
# Active Directory. Off by default: needs RSAT and a reachable domain.
# ---------------------------------------------------------------------------
if ($IncludeActiveDirectory) {
    $adArguments = @()
    if ($AdServer) { $adArguments = @('-Server', $AdServer) }

    $adRun = Invoke-Collector -Name 'ad-privileged-access' -RelativePath 'active-directory\Export-AdPrivilegedAccessAudit.ps1' -Argument $adArguments
    $ad = Get-CollectorSummary -Run $adRun
    if ($null -eq $ad) {
        Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
            -Status 'NotAssessed' -Finding "The Active Directory audit did not produce a summary. Status: $($adRun.Status). $($adRun.Note)" -Collector 'Export-AdPrivilegedAccessAudit.ps1'
    } else {
        $critical = [int](Get-OpsPropertyValue -InputObject $ad -Name 'CriticalCount')
        $high = [int](Get-OpsPropertyValue -InputObject $ad -Name 'HighCount')

        Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
            -Status $(if ($critical -gt 0) { 'NotMet' } elseif ($high -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Critical findings: $critical. High findings: $high. Tier-0 members: $(Get-OpsPropertyValue -InputObject $ad -Name 'Tier0MemberCount')." `
            -Evidence $adRun.RelativeOutputPath -Collector 'Export-AdPrivilegedAccessAudit.ps1'
    }
} else {
    Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
        -Status 'NotAssessed' -Finding 'Not assessed. Re-run with -IncludeActiveDirectory on a machine with RSAT and a reachable domain.' -Collector 'none'
}

# ---------------------------------------------------------------------------
# Controls this repo genuinely cannot evidence. Stated, not silently omitted.
# ---------------------------------------------------------------------------
Add-Control -Id 'BCK-01' -Question 'Are backups taken, stored offline or immutably, and restore-tested?' `
    -Status 'NotAssessed' `
    -Finding 'No collector in this toolkit reads backup state. A restore test is an operational exercise, not a configuration read, and claiming it from configuration would be false. Attach the backup product report and the dated restore test record.' -Collector 'none'

Add-Control -Id 'IR-01' -Question 'Is there a documented and exercised incident response plan?' `
    -Status 'NotAssessed' `
    -Finding 'Not technically assessable. Attach the plan and the date of the last tabletop or live exercise.' -Collector 'none'

Add-Control -Id 'TRN-01' -Question 'Do staff receive security awareness training, including help desk verification procedures?' `
    -Status 'NotAssessed' `
    -Finding 'Not technically assessable. Attach training completion records. Help desk verification procedure is worth calling out separately: vishing was the second most common initial infection vector in 2025 and MFA reset requests are the specific step to control.' -Collector 'none'

# ---------------------------------------------------------------------------
# Assemble.
# ---------------------------------------------------------------------------
$scriptSha256 = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $scriptsRoot '..')).Path
$toolkitRevision = 'Unavailable'
$toolkitDirty = $null
if (Get-Command git -ErrorAction SilentlyContinue) {
    try {
        $revision = & git -C $repositoryRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $revision) {
            $toolkitRevision = [string]$revision
        }
        $workingTreeState = @(& git -C $repositoryRoot status --porcelain 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $toolkitDirty = $workingTreeState.Count -gt 0
        }
    } catch {
        $toolkitRevision = 'Unavailable'
    }
}

$runContext = [ordered]@{
    GeneratedAt = $asOf
    Organization = $Organization
    EndpointScope = $scopeText
    RequestedTargets = $requestedTargets
    AttemptedTargets = $resolvedTargets
    Exclusions = @($exclusions)
    IncludeEntra = [bool]$IncludeEntra
    IncludeActiveDirectory = [bool]$IncludeActiveDirectory
    AdServer = $AdServer
    DefenderDeviceInventorySnapshot = if ($null -ne $defenderInput) { $defenderInput.SnapshotPath } else { '' }
    CoverageManifestSnapshot = if ($null -ne $coverageInput) { $coverageInput.SnapshotPath } else { '' }
    CollectorTimeoutSeconds = $CollectorTimeoutSeconds
    ScriptSha256 = $scriptSha256
    ToolkitRevision = $toolkitRevision
    ToolkitWorkingTreeDirty = $toolkitDirty
}
Set-Content -LiteralPath (Join-Path $packDirectory 'run-context.json') `
    -Value ($runContext | ConvertTo-Json -Depth 8) -Encoding utf8

$inputSourceExports = @(
    Export-OpsReport -Name 'input-sources' -Record @($inputSources) -Directory $packDirectory
)

$collectorReportRuns = foreach ($run in $collectorRuns) {
    $safeNote = [string]$run.Note
    foreach ($sensitivePath in @($repositoryRoot, $packDirectory, $DefenderDeviceInventoryPath, $CoverageManifestPath) |
            Where-Object { $_ }) {
        $safeNote = $safeNote -replace [regex]::Escape($sensitivePath), '[local path]'
    }
    [pscustomobject]@{
        Collector = $run.Collector
        Script = Split-Path -Path $run.ScriptPath -Leaf
        ScriptSha256 = if (Test-Path -LiteralPath $run.ScriptPath -PathType Leaf) {
            (Get-FileHash -LiteralPath $run.ScriptPath -Algorithm SHA256).Hash
        } else { '' }
        Status = $run.Status
        ExitCode = $run.ExitCode
        RelativeOutputPath = [string](Get-OpsPropertyValue -InputObject $run -Name 'RelativeOutputPath')
        DurationSeconds = $run.DurationSeconds
        Scope = $run.Scope
        Note = $safeNote
    }
}

$artifactControls = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$endpointIntended = @(if ($isEstateScope) { $resolvedTargets } else { $env:COMPUTERNAME })
$endpointAttempted = @(if ($isEstateScope) { $resolvedTargets } else { $env:COMPUTERNAME })
$exclusionText = @($exclusions | ForEach-Object { "$($_.Target): $($_.Reason)" }) -join ';'

foreach ($control in $controls) {
    $scopeKind = Get-OpsControlScopeKind -ControlId $control.ControlId
    $control.IntendedScope = switch ($scopeKind) {
        'EndpointPopulation' { "$($endpointIntended.Count) endpoint(s): $($endpointIntended -join ';')" }
        'LocalEndpoint' { "Local endpoint: $env:COMPUTERNAME" }
        'EntraTenant' { 'One Microsoft Entra tenant supplied to the collectors' }
        'ActiveDirectoryDomain' { 'One Active Directory domain supplied to the collector' }
        default { 'Organization-wide process or record set' }
    }
    $control.IntendedCount = switch ($scopeKind) {
        'EndpointPopulation' { $endpointIntended.Count }
        'LocalEndpoint' { 1 }
        'EntraTenant' { 1 }
        'ActiveDirectoryDomain' { 1 }
        default { 0 }
    }

    if ($scopeKind -eq 'EndpointPopulation') {
        $control.ExcludedPopulation = $excludedNames -join ';'
        $control.ExcludedCount = $exclusions.Count
        $control.ExclusionReasons = $exclusionText
    }

    $collectorRun = $collectorRuns | Where-Object {
        $leaf = Split-Path -Path $_.ScriptPath -Leaf
        $control.Collector -match [regex]::Escape($leaf)
    } | Select-Object -First 1

    if ($scopeKind -in @('EndpointPopulation', 'LocalEndpoint')) {
        $attemptedNames = @(if ($scopeKind -eq 'LocalEndpoint') { $env:COMPUTERNAME } else { $endpointAttempted })
        $attemptedCount = $attemptedNames.Count
        $failedCount = 0

        if ($null -ne $collectorRun) {
            if ($collectorRun.Scope -eq 'LocalMachineOnly' -or $collectorRun.Scope -eq 'LocalMachine') {
                $attemptedNames = @($env:COMPUTERNAME)
                $attemptedCount = 1
            }

            $collectorSummary = Get-CollectorSummary -Run $collectorRun
            foreach ($failureName in @('UnreachableCount', 'FailedCount', 'ErrorCount', 'UndeterminedCount')) {
                $candidate = Get-OpsPropertyValue -InputObject $collectorSummary -Name $failureName
                $parsedCandidate = 0
                if ($null -ne $candidate -and [int]::TryParse([string]$candidate, [ref]$parsedCandidate) -and
                    $parsedCandidate -gt $failedCount) {
                    $failedCount = $parsedCandidate
                }
            }
            if ($collectorRun.Status -ne 'Completed') {
                $failedCount = $attemptedCount
                $control.FailedReads = "$($collectorRun.Collector): $($collectorRun.Status)"
            }
        } elseif ($control.Collector -eq 'none') {
            $attemptedNames = @()
            $attemptedCount = 0
        }

        if ($control.ControlId -eq 'EDR-01' -and $managementEvidenceRequested) {
            $attemptedNames = @($managementAttemptedNames)
            $attemptedCount = $attemptedNames.Count
            $failedCount = @($managementFailedNames | Where-Object { $_ -in $attemptedNames } |
                    Sort-Object -Unique).Count
            $control.FailedReads = $managementFailedReads -join ';'
            $control.IntendedScope = if ($coveragePopulation.Count -gt 0) {
                "$($coveragePopulation.Count) reconciled endpoint(s): $($coveragePopulation -join ';')"
            } else {
                'Management-plane endpoint population pending reconciliation'
            }
            $control.IntendedCount = $coveragePopulation.Count
        } elseif ($control.ControlId -eq 'EDR-01' -and $isEstateScope) {
            $failedCount = $attemptedCount
        } elseif ($control.ControlId -in @('EDR-01', 'EDR-02') -and $null -eq $defenderStatus) {
            $failedCount = $attemptedCount
        }

        if ($control.Status -eq 'NotAssessed' -and $failedCount -eq 0 -and $attemptedCount -gt 0) {
            $failedCount = $attemptedCount
        }

        $control.AttemptedPopulation = $attemptedNames -join ';'
        $control.AttemptedCount = $attemptedCount
        $control.FailedCount = [math]::Min($attemptedCount, $failedCount)
        $control.ObservedCount = [math]::Max(0, $attemptedCount - $control.FailedCount)

        if ($scopeKind -eq 'EndpointPopulation' -and $control.Status -eq 'Met' -and
            $control.AttemptedCount -lt $control.IntendedCount) {
            $control.Status = 'Partial'
            $control.Conclusion = Get-OpsControlConclusion -Status $control.Status
            $control.Finding += " The collector observed $($control.AttemptedCount) of $($control.IntendedCount) intended endpoint(s), so an estate-wide Met conclusion is not supported."
        }
    } elseif ($scopeKind -eq 'EntraTenant') {
        $control.AttemptedPopulation = if ($IncludeEntra) { 'Configured Microsoft Entra tenant' } else { '' }
        $control.AttemptedCount = if ($IncludeEntra) { 1 } else { 0 }
        $control.ObservedCount = if ($IncludeEntra -and $control.Status -ne 'NotAssessed') { 1 } else { 0 }
        $control.FailedCount = $control.AttemptedCount - $control.ObservedCount
    } elseif ($scopeKind -eq 'ActiveDirectoryDomain') {
        $control.AttemptedPopulation = if ($IncludeActiveDirectory) { 'Configured Active Directory domain' } else { '' }
        $control.AttemptedCount = if ($IncludeActiveDirectory) { 1 } else { 0 }
        $control.ObservedCount = if ($IncludeActiveDirectory -and $control.Status -ne 'NotAssessed') { 1 } else { 0 }
        $control.FailedCount = $control.AttemptedCount - $control.ObservedCount
    }

    if (-not $control.Limitations) {
        $control.Limitations = if ($control.Status -eq 'NotAssessed') {
            'No sufficient automated evidence was produced. Review the finding for the operator-supplied evidence required.'
        } else {
            'Automated configuration evidence does not establish documented ownership, operating consistency, review cadence, maturity, or framework conformance.'
        }
    }

    $evidenceFiles = @(Get-OpsEvidenceFile -Evidence $control.Evidence -PackDirectory $packDirectory |
            Sort-Object FullName -Unique)
    if ($evidenceFiles.Count -gt 0) {
        $relativeArtifacts = [System.Collections.Generic.List[string]]::new()
        $hashes = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $evidenceFiles) {
            $relativePath = [System.IO.Path]::GetRelativePath($packDirectory, $file.FullName)
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            $relativeArtifacts.Add($relativePath)
            $hashes.Add("$relativePath|SHA256=$hash")
            if (-not $artifactControls.ContainsKey($relativePath)) {
                $artifactControls[$relativePath] = [System.Collections.Generic.List[string]]::new()
            }
            if (-not $artifactControls[$relativePath].Contains($control.ControlId)) {
                $artifactControls[$relativePath].Add($control.ControlId)
            }
        }
        $oldestObservation = $evidenceFiles | Sort-Object LastWriteTimeUtc | Select-Object -First 1
        $control.EvidenceArtifacts = $relativeArtifacts -join ';'
        $control.EvidenceHashes = $hashes -join ';'
        $control.EvidenceObservedAt = $oldestObservation.LastWriteTimeUtc
        $control.EvidenceAgeDays = [math]::Max(0, [math]::Floor(($asOf.ToUniversalTime() - $oldestObservation.LastWriteTimeUtc).TotalDays))
    }
}

$assessment = @($controls) | Sort-Object -Property @{ Expression = { switch ($_.Status) { 'NotMet' { 0 } 'Partial' { 1 } 'NotAssessed' { 2 } default { 3 } } } }, ControlId

$statusRollup = foreach ($group in (@($assessment) | Group-Object -Property Status)) {
    [pscustomobject]@{ Status = $group.Name; Count = $group.Count; Controls = (@($group.Group | ForEach-Object { $_.ControlId }) -join ';') }
}

$exports = @(
    $inputSourceExports
    Export-OpsReport -Name 'control-assessment' -Record $assessment -Directory $packDirectory
    Export-OpsReport -Name 'status-rollup' -Record @($statusRollup) -Directory $packDirectory
    Export-OpsReport -Name 'collector-runs' -Record @($collectorReportRuns) -Directory $packDirectory
)

$notMet = @($assessment | Where-Object { $_.Status -eq 'NotMet' })
$partial = @($assessment | Where-Object { $_.Status -eq 'Partial' })
$notAssessed = @($assessment | Where-Object { $_.Status -eq 'NotAssessed' })
$met = @($assessment | Where-Object { $_.Status -eq 'Met' })

$markdown = [System.Collections.Generic.List[string]]::new()
$markdown.Add("# Security control evidence pack")
$markdown.Add('')
$markdown.Add("Organization: $Organization")
$markdown.Add("Generated: $($asOf.ToString('yyyy-MM-dd HH:mm:ss'))")
$markdown.Add("Machine: $env:COMPUTERNAME")
$markdown.Add("Elevated: $isElevated")
$markdown.Add("Endpoint scope: $scopeText")
$markdown.Add('')
$markdown.Add('This is a point-in-time technical evidence snapshot. It is not a NIST maturity rating, ISO conformity decision, audit opinion, certification-readiness report, or substitute for assessor judgment.')
$markdown.Add('Every control is answered from collector output or is marked NotAssessed. Nothing is inferred.')
$markdown.Add('')
$markdown.Add("## Summary")
$markdown.Add('')
$markdown.Add("| Status | Count |")
$markdown.Add("| ------ | ----- |")
$markdown.Add("| Met | $($met.Count) |")
$markdown.Add("| Partial | $($partial.Count) |")
$markdown.Add("| Not met | $($notMet.Count) |")
$markdown.Add("| Not assessed | $($notAssessed.Count) |")
$markdown.Add('')
$markdown.Add('Not assessed is not a pass. It means no collector produced evidence for that control in this run.')
$markdown.Add('')
$markdown.Add("## Scope and provenance")
$markdown.Add('')
$markdown.Add("Requested endpoints: $($requestedTargets -join '; ')")
$markdown.Add("Attempted endpoints: $($endpointAttempted -join '; ')")
$markdown.Add("Excluded endpoints: $(if ($exclusions.Count -gt 0) { $exclusionText } else { 'none' })")
$markdown.Add("Toolkit revision: $toolkitRevision")
$markdown.Add("Assembly script SHA256: $scriptSha256")
$markdown.Add('Artifact paths, observation times, control associations, and SHA256 hashes are recorded in `evidence-manifest.csv` and `evidence-manifest.json`.')
$markdown.Add('`summary.json` is written last and is excluded from the manifest to avoid a self-referential hash.')
$markdown.Add('')
$markdown.Add("## Controls")
$markdown.Add('')
$markdown.Add("| Control | Status | Population intended / attempted / observed / failed | Evidence conclusion | Finding | Limitations |")
$markdown.Add("| ------- | ------ | -------------------------------------------------- | ------------------- | ------- | ----------- |")
foreach ($control in $assessment) {
    $finding = ($control.Finding -replace '\|', '/') -replace '\s+', ' '
    $conclusion = ($control.Conclusion -replace '\|', '/') -replace '\s+', ' '
    $limitations = ($control.Limitations -replace '\|', '/') -replace '\s+', ' '
    $markdown.Add("| $($control.ControlId) | $($control.Status) | $($control.IntendedCount) / $($control.AttemptedCount) / $($control.ObservedCount) / $($control.FailedCount) | $conclusion | $finding | $limitations |")
}
$markdown.Add('')
$markdown.Add("## Collector runs")
$markdown.Add('')
$markdown.Add("| Collector | Status | Scope | Seconds | Note |")
$markdown.Add("| --------- | ------ | ----- | ------- | ---- |")
foreach ($run in $collectorReportRuns) {
    $note = ($run.Note -replace '\|', '/') -replace '\s+', ' '
    $markdown.Add("| $($run.Collector) | $($run.Status) | $($run.Scope) | $($run.DurationSeconds) | $note |")
}
$markdown.Add('')
$markdown.Add('Raw collector output is under `collectors\`, one folder per collector.')

Set-Content -LiteralPath (Join-Path $packDirectory 'summary.md') -Value ($markdown -join [Environment]::NewLine) -Encoding utf8

$manifestFiles = @(
    Get-ChildItem -LiteralPath $packDirectory -File -Recurse |
        Where-Object { $_.Name -notin @('evidence-manifest.csv', 'evidence-manifest.json') } |
        Sort-Object FullName
)
$evidenceManifest = foreach ($file in $manifestFiles) {
    $relativePath = [System.IO.Path]::GetRelativePath($packDirectory, $file.FullName)
    [pscustomobject]@{
        Path = $relativePath
        SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        LengthBytes = $file.Length
        ObservedAt = $file.LastWriteTimeUtc
        ControlIds = if ($artifactControls.ContainsKey($relativePath)) {
            $artifactControls[$relativePath] -join ';'
        } else { '' }
    }
}
$manifestExports = @(
    Export-OpsReport -Name 'evidence-manifest' -Record @($evidenceManifest) -Directory $packDirectory
)
$exports += $manifestExports

$summaryExports = foreach ($export in @($exports)) {
    [pscustomobject]@{
        Name = $export.Name
        Count = $export.Count
        CsvPath = [System.IO.Path]::GetRelativePath($packDirectory, $export.CsvPath)
        JsonPath = [System.IO.Path]::GetRelativePath($packDirectory, $export.JsonPath)
    }
}

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    Organization = $Organization
    ComputerName = $env:COMPUTERNAME
    Elevated = $isElevated
    EndpointScope = $scopeText
    RequestedTargetCount = $requestedTargets.Count
    RequestedTargets = $requestedTargets
    ExcludedTargetCount = $exclusions.Count
    ScopeExclusions = @($exclusions)
    TargetCount = $resolvedTargets.Count
    Targets = $resolvedTargets
    PackDirectory = '.'
    IncludedEntra = [bool]$IncludeEntra
    IncludedActiveDirectory = [bool]$IncludeActiveDirectory
    ControlCount = $assessment.Count
    MetCount = $met.Count
    PartialCount = $partial.Count
    NotMetCount = $notMet.Count
    NotAssessedCount = $notAssessed.Count
    CollectorsRun = $collectorRuns.Count
    CollectorsCompleted = @($collectorRuns | Where-Object { $_.Status -eq 'Completed' }).Count
    CollectorsFailed = @($collectorRuns | Where-Object { $_.Status -in @('Failed', 'TimedOut', 'Missing') }).Count
    TechnicalEvidenceOnly = $true
    ScriptSha256 = $scriptSha256
    ToolkitRevision = $toolkitRevision
    ToolkitWorkingTreeDirty = $toolkitDirty
    EvidenceArtifactCount = @($evidenceManifest).Count
    EvidenceManifestPath = 'evidence-manifest.json'
    NotMetControls = @($notMet | ForEach-Object { $_.ControlId })
    NotAssessedControls = @($notAssessed | ForEach-Object { $_.ControlId })
    Exports = @($summaryExports)
}

$returnSummary = Export-OpsSummary -Summary $summary -Directory $packDirectory
$returnSummary.PackDirectory = $packDirectory
$returnSummary.EvidenceManifestPath = Join-Path $packDirectory 'evidence-manifest.json'
$returnSummary
