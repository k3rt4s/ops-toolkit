<#
.SYNOPSIS
Reclaim disk space from developer and Windows caches with plan/state reports and -WhatIf.

.INSTRUCTIONS
- Read the root README.md and the IT operations README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell to include ComponentStore (WinSxS) or WindowsUpdateCache targets.
- Use -Target to choose which caches to reclaim; omit it for the safe default set.
- HuggingFaceCache is opt-in only: clearing it forces large model re-downloads on the next AI run.
- Generated reports are written under C:\Code_data\ops-toolkit\windows-file-cleanup by default,
  per the workspace data-hygiene rule (generated data lives under C:\Code_data, never in the repo).

.PURPOSE
This script reclaims space from reclaimable caches that the file/temp cleanup helper does not
cover: the pip package cache, Docker build cache and dangling images, the Recycle Bin, the
Windows component store (WinSxS), and optionally the Windows Update download cache. It complements
Invoke-WindowsFileCleanup.ps1 (temp and stale files) and Invoke-DiskMaintenance.ps1 (chkdsk,
defrag, cipher wipe). It never touches source code, the live application database, audit_vault
evidence, or the active model cache unless explicitly opted in.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target PipCache,RecycleBin
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target ComponentStore  # elevated

.OUTPUTS
Writes plan and state CSV/JSON files under the report directory. Returns a summary object with
report paths, per-target reclaimed bytes, and a free-space before/after delta for the system drive.

.STATUS
Active script in the ops-toolkit repo. Companion to Invoke-WindowsFileCleanup.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('PipCache', 'DockerBuildCache', 'DockerDanglingImages', 'RecycleBin', 'ComponentStore', 'WindowsUpdateCache', 'HuggingFaceCache')]
    [string[]]$Target = @('PipCache', 'DockerBuildCache', 'DockerDanglingImages', 'RecycleBin', 'ComponentStore'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PipExecutable = 'pip',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = 'C:\Code_data\ops-toolkit\windows-file-cleanup'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Reclaim disk space from developer and Windows caches.

Usage:
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target PipCache,RecycleBin

Options:
  -Target           One or more of: PipCache, DockerBuildCache, DockerDanglingImages,
                    RecycleBin, ComponentStore, WindowsUpdateCache, HuggingFaceCache.
                    Default: PipCache, DockerBuildCache, DockerDanglingImages, RecycleBin, ComponentStore.
  -PipExecutable    pip/pip3 path or name used for "pip cache" operations. Default: pip.
  -ReportDirectory  Plan and state output directory.
  -WhatIf           Write reports and preview reclaim actions without deleting anything.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CommandPath {
    param([Parameter(Mandatory = $true)][string]$Name)
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $null
}

function Get-FolderSize {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    try {
        [long]((Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum)
    } catch {
        0
    }
}

function Get-FreeBytesSystemDrive {
    # Prefer the Storage module; fall back to CIM on SKUs where Get-Volume is unavailable.
    $sys = ($env:SystemDrive).TrimEnd(':')
    try {
        (Get-Volume -DriveLetter $sys -ErrorAction Stop).SizeRemaining
    } catch {
        (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
    }
}

# ---------------------------------------------------------------------------
# Per-target planners. Each returns a plan object describing what would run,
# the estimated reclaimable bytes (best effort, $null when not cheaply known),
# whether admin is required, and whether the tool is available on this box.
# ---------------------------------------------------------------------------

function Get-ReclaimPlanItem {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PipExecutable
    )

    switch ($Name) {
        'PipCache' {
            $pip = Get-CommandPath -Name $PipExecutable
            $bytes = $null
            if ($pip) {
                try {
                    $dir = (& $pip cache dir 2>$null | Select-Object -First 1)
                    if ($dir) { $bytes = Get-FolderSize -Path $dir.Trim() }
                } catch { $bytes = $null }
            }
            [pscustomobject]@{
                Target = 'PipCache'; Available = [bool]$pip; RequiresAdmin = $false
                EstimatedBytes = $bytes; Action = "$PipExecutable cache purge"
                Note = if ($pip) { 'Removes downloaded wheels and the HTTP index cache; pip re-fetches on demand.' } else { "pip not found ($PipExecutable)." }
            }
        }
        'DockerBuildCache' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerBuildCache'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker builder prune -f'
                Note = if ($docker) { 'Removes unused build cache only; tagged images and volumes are untouched.' } else { 'docker CLI not found.' }
            }
        }
        'DockerDanglingImages' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerDanglingImages'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker image prune -f'
                Note = if ($docker) { 'Removes dangling (untagged) images only; in-use images are untouched.' } else { 'docker CLI not found.' }
            }
        }
        'RecycleBin' {
            $bytes = 0
            foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' })) {
                $rb = "$($v.DriveLetter):\`$Recycle.Bin"
                $bytes += Get-FolderSize -Path $rb
            }
            [pscustomobject]@{
                Target = 'RecycleBin'; Available = $true; RequiresAdmin = $false
                EstimatedBytes = $bytes; Action = 'Clear-RecycleBin (all fixed drives)'
                Note = 'Permanently empties the Recycle Bin on all fixed drives.'
            }
        }
        'ComponentStore' {
            [pscustomobject]@{
                Target = 'ComponentStore'; Available = $true; RequiresAdmin = $true
                EstimatedBytes = $null; Action = 'Dism /Online /Cleanup-Image /StartComponentCleanup'
                Note = 'Removes superseded WinSxS components. Requires an elevated shell. Estimate via /AnalyzeComponentStore.'
            }
        }
        'WindowsUpdateCache' {
            $dl = Join-Path $env:windir 'SoftwareDistribution\Download'
            [pscustomobject]@{
                Target = 'WindowsUpdateCache'; Available = (Test-Path -LiteralPath $dl); RequiresAdmin = $true
                EstimatedBytes = (Get-FolderSize -Path $dl); Action = 'Stop wuauserv + bits, clear SoftwareDistribution\Download, restart services'
                Note = 'Clears cached update downloads. Windows re-downloads pending updates as needed. Requires elevation.'
            }
        }
        'HuggingFaceCache' {
            $hf = if ($env:HF_HOME) { $env:HF_HOME } else { Join-Path $env:USERPROFILE '.cache\huggingface' }
            [pscustomobject]@{
                Target = 'HuggingFaceCache'; Available = (Test-Path -LiteralPath $hf); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $hf); Action = "Remove-Item $hf"
                Note = 'OPT-IN. Active model cache; clearing forces large re-downloads on the next AI/transcription run.'
            }
        }
        default { throw "Unknown target: $Name" }
    }
}

# ---------------------------------------------------------------------------
# Apply one target. Returns a result string and the bytes reclaimed (best
# effort). Every destructive action is gated through ShouldProcess.
# ---------------------------------------------------------------------------

function Invoke-ReclaimTarget {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][string]$PipExecutable
    )

    if (-not $Plan.Available) { return [pscustomobject]@{ Result = 'Skipped: unavailable'; ReclaimedBytes = 0 } }
    if ($Plan.RequiresAdmin -and -not (Test-IsAdministrator)) {
        return [pscustomobject]@{ Result = 'Skipped: requires elevation'; ReclaimedBytes = 0 }
    }
    if (-not $PSCmdlet.ShouldProcess($Plan.Target, $Plan.Action)) {
        return [pscustomobject]@{ Result = 'Previewed'; ReclaimedBytes = 0 }
    }

    $before = Get-FreeBytesSystemDrive
    try {
        switch ($Plan.Target) {
            'PipCache' { & $PipExecutable cache purge *>$null }
            'DockerBuildCache' { docker builder prune -f *>$null }
            'DockerDanglingImages' { docker image prune -f *>$null }
            'RecycleBin' {
                foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' })) {
                    Clear-RecycleBin -DriveLetter $v.DriveLetter -Force -ErrorAction SilentlyContinue
                }
            }
            'ComponentStore' { Dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null }
            'WindowsUpdateCache' {
                # Stop both the update and BITS services, clear the cache, and
                # guarantee the services restart even if deletion throws midway.
                $updateServices = @('wuauserv', 'bits')
                try {
                    foreach ($svc in $updateServices) { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
                    Get-ChildItem -LiteralPath (Join-Path $env:windir 'SoftwareDistribution\Download') -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } finally {
                    foreach ($svc in $updateServices) { Start-Service -Name $svc -ErrorAction SilentlyContinue }
                }
            }
            'HuggingFaceCache' {
                $hf = if ($env:HF_HOME) { $env:HF_HOME } else { Join-Path $env:USERPROFILE '.cache\huggingface' }
                Remove-Item -LiteralPath $hf -Recurse -Force -ErrorAction Stop
            }
        }
    } catch {
        return [pscustomobject]@{ Result = "Failed: $($_.Exception.Message)"; ReclaimedBytes = 0 }
    }
    $after = Get-FreeBytesSystemDrive
    # Some tools (Docker VM disk, component store) free space inside a VHDX or
    # over time, so a same-drive delta can read low; report it honestly.
    [pscustomobject]@{ Result = 'Reclaimed'; ReclaimedBytes = [long][math]::Max(0, $after - $before) }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$freeBefore = Get-FreeBytesSystemDrive
$plan = @(foreach ($t in ($Target | Select-Object -Unique)) { Get-ReclaimPlanItem -Name $t -PipExecutable $PipExecutable })

$planPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "disk-space-reclaim-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $outcome = Invoke-ReclaimTarget -Plan $item -PipExecutable $PipExecutable -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $outcome.Result -Force
    $item | Add-Member -NotePropertyName ReclaimedBytes -NotePropertyValue $outcome.ReclaimedBytes -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

$freeAfter = Get-FreeBytesSystemDrive

[pscustomobject]@{
    Operation = 'DiskSpaceReclaim'
    Targets = @($Target)
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    ReclaimedTargets = @($state | Where-Object Result -eq 'Reclaimed').Count
    SkippedTargets = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedTargets = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    SystemDriveFreeBeforeGB = [math]::Round($freeBefore / 1GB, 2)
    SystemDriveFreeAfterGB = [math]::Round($freeAfter / 1GB, 2)
    SystemDriveReclaimedGB = [math]::Round(($freeAfter - $freeBefore) / 1GB, 2)
    Items = @($state)
}
