<#
.SYNOPSIS
Run a sequence of disk maintenance operations on a specified drive.

.INSTRUCTIONS
- Run as Administrator. chkdsk /f /r /x requires elevation and may schedule
  a reboot if the target volume is in use by Windows.
- Use -SkipChkdsk, -SkipCipherWipe, -SkipDefrag, or -SkipBenchmark to
  exclude individual steps without modifying the script.
- The cipher free-space wipe (-SkipCipherWipe is NOT set) can take several
  hours on large or nearly-full drives.

.PURPOSE
Consolidates four common disk-maintenance steps into one parameterised script:
chkdsk error and bad-sector scan, cipher free-space wipe, defrag/optimise,
and a 10 MB write/read speed benchmark. Each step is individually toggleable
via a skip switch.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1
pwsh -File .\scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1 -Drive C -SkipCipherWipe
pwsh -File .\scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1 -Drive D -SkipChkdsk -SkipDefrag

.OUTPUTS
Writes progress to the console. The benchmark writes and deletes a temporary
file at <Drive>:\speedtest.tmp; the file is removed in a finally block so it
is always cleaned up, even if the benchmark fails mid-run.

.STATUS
Active PowerShell replacement for InsightVault\scripts\original_project\DiskMaintenance.ps1.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$Drive = 'D',

    [Parameter()]
    [switch]$SkipChkdsk,

    [Parameter()]
    [switch]$SkipCipherWipe,

    [Parameter()]
    [switch]$SkipDefrag,

    [Parameter()]
    [switch]$SkipBenchmark
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$driveLetter = $Drive.ToUpper()

# ---------------------------------------------------------------------------
# Step 1: chkdsk
# ---------------------------------------------------------------------------
if ($SkipChkdsk) {
    Write-Host "[$driveLetter] Skipping chkdsk (SkipChkdsk set)."
} else {
    Write-Host "[$driveLetter] Running chkdsk /f /r /x — requires elevation. If the volume is in use, Windows will schedule the check on the next reboot."
    try {
        Start-Process -FilePath 'chkdsk' -ArgumentList "$driveLetter`: /f /r /x" -Wait -NoNewWindow
        Write-Host "[$driveLetter] chkdsk completed."
    } catch {
        Write-Error "[$driveLetter] chkdsk failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 2: cipher free-space wipe
# ---------------------------------------------------------------------------
if ($SkipCipherWipe) {
    Write-Host "[$driveLetter] Skipping cipher free-space wipe (SkipCipherWipe set)."
} else {
    Write-Host "[$driveLetter] Wiping free space with cipher.exe /w — this can take several hours on large drives."
    try {
        Start-Process -FilePath 'cipher.exe' -ArgumentList "/w:$driveLetter`:\" -Wait -NoNewWindow
        Write-Host "[$driveLetter] cipher free-space wipe completed."
    } catch {
        Write-Error "[$driveLetter] cipher wipe failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 3: defrag / optimise
# ---------------------------------------------------------------------------
if ($SkipDefrag) {
    Write-Host "[$driveLetter] Skipping defrag/optimise (SkipDefrag set)."
} else {
    Write-Host "[$driveLetter] Running defrag /U /V — Windows skips SSDs automatically."
    try {
        defrag "$driveLetter`:" /U /V
        Write-Host "[$driveLetter] defrag/optimise completed."
    } catch {
        Write-Error "[$driveLetter] defrag failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 4: 10 MB write / read benchmark
# ---------------------------------------------------------------------------
if ($SkipBenchmark) {
    Write-Host "[$driveLetter] Skipping benchmark (SkipBenchmark set)."
} else {
    $testFile = "$driveLetter`:\speedtest.tmp"
    $bufferSize = 10MB
    $buffer = [byte[]]::new($bufferSize)
    [System.Random]::new().NextBytes($buffer)

    try {
        Write-Host "[$driveLetter] Starting 10 MB write speed test..."
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [System.IO.File]::WriteAllBytes($testFile, $buffer)
        $sw.Stop()
        $writeSeconds = $sw.Elapsed.TotalSeconds
        Write-Host ("[$driveLetter] Write: 10 MB in {0:N2} s — {1:N2} MB/s" -f $writeSeconds, (10 / $writeSeconds))

        Write-Host "[$driveLetter] Starting 10 MB read speed test..."
        $sw.Restart()
        [System.IO.File]::ReadAllBytes($testFile) | Out-Null
        $sw.Stop()
        $readSeconds = $sw.Elapsed.TotalSeconds
        Write-Host ("[$driveLetter] Read:  10 MB in {0:N2} s — {1:N2} MB/s" -f $readSeconds, (10 / $readSeconds))
    } catch {
        Write-Error "[$driveLetter] Benchmark failed: $_"
    } finally {
        if (Test-Path -LiteralPath $testFile) {
            Remove-Item -LiteralPath $testFile -Force
            Write-Host "[$driveLetter] Benchmark temp file removed."
        }
    }
}

Write-Host "[$driveLetter] Disk maintenance sequence complete."
