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

# Verify the drive exists and is a local fixed disk before touching it.
$volume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
if (-not $volume) {
    Write-Error "Drive $driveLetter`: not found. Confirm the drive letter is correct and the volume is mounted."
    exit 1
}
if ($volume.DriveType -notin @('Fixed')) {
    Write-Error "Drive $driveLetter`: is type '$($volume.DriveType)'. This script only supports local fixed disks."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 1: chkdsk
# ---------------------------------------------------------------------------
if ($SkipChkdsk) {
    Write-Host "[$driveLetter] Skipping chkdsk (SkipChkdsk set)."
} else {
    Write-Host "[$driveLetter] Running chkdsk /f /r /x — requires elevation. If the volume is in use, Windows will schedule the check on the next reboot and exit 0 now."
    try {
        $proc = Start-Process -FilePath 'chkdsk' -ArgumentList "$driveLetter`: /f /r /x" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "[$driveLetter] chkdsk completed — no errors found."
        } elseif ($proc.ExitCode -eq 1) {
            Write-Host "[$driveLetter] chkdsk completed — errors were found and fixed."
        } elseif ($proc.ExitCode -eq 2) {
            Write-Host "[$driveLetter] chkdsk scheduled for next reboot (volume was locked)."
        } else {
            Write-Host "[$driveLetter] chkdsk exited with code $($proc.ExitCode) — review output above."
        }
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
        $proc = Start-Process -FilePath 'cipher.exe' -ArgumentList "/w:$driveLetter`:\" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "[$driveLetter] cipher free-space wipe completed."
        } else {
            Write-Host "[$driveLetter] cipher exited with code $($proc.ExitCode) — review output above."
        }
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
        $proc = Start-Process -FilePath 'defrag' -ArgumentList "$driveLetter`: /U /V" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "[$driveLetter] defrag/optimise completed."
        } else {
            Write-Host "[$driveLetter] defrag exited with code $($proc.ExitCode) — review output above."
        }
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
    $minSeconds = 0.001   # guard against divide-by-zero on cached/very fast writes

    try {
        Write-Host "[$driveLetter] Starting 10 MB write speed test..."
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [System.IO.File]::WriteAllBytes($testFile, $buffer)
        $sw.Stop()
        $writeSeconds = [math]::Max($sw.Elapsed.TotalSeconds, $minSeconds)
        Write-Host ("[$driveLetter] Write: 10 MB in {0:N3} s — {1:N2} MB/s" -f $sw.Elapsed.TotalSeconds, (10 / $writeSeconds))

        Write-Host "[$driveLetter] Starting 10 MB read speed test..."
        $sw.Restart()
        [System.IO.File]::ReadAllBytes($testFile) | Out-Null
        $sw.Stop()
        $readSeconds = [math]::Max($sw.Elapsed.TotalSeconds, $minSeconds)
        Write-Host ("[$driveLetter] Read:  10 MB in {0:N3} s — {1:N2} MB/s" -f $sw.Elapsed.TotalSeconds, (10 / $readSeconds))
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
