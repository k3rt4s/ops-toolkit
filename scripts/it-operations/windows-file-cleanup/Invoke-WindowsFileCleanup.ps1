<#
.SYNOPSIS
Plan and remove Windows temp items or stale files with guardrails and reports.

.INSTRUCTIONS
- Read the root README.md and IT operations README.md before running this script.
- Run with -WhatIf first and review the generated plan/state reports.
- Use -Mode Temp to remove immediate children of approved temp folders.
- Use -Mode OlderThan to remove files older than -OlderThanDays under explicit paths.
- Use -IncludeEmptyDirectories only after reviewing the plan because directory cleanup is recursive.
- Generated reports are written under reports\it-operations\windows-file-cleanup by default.

.PURPOSE
This script replaces the previous temp-folder cleanup and old-file recursive
cleanup helpers with one report-first command. It refuses broad or protected
paths such as drive roots, Windows, Program Files, user profile roots, and repo
roots unless future maintainers deliberately change the guardrail logic.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode Temp -WhatIf
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON files under reports\it-operations\windows-file-cleanup
by default. Returns a summary object with report paths and cleanup counts.

.STATUS
Active PowerShell replacement for Clear-UserAndDriveTempFolders.vbs,
Remove-OldFilesRecursively.vbs, and the previous split PowerShell helpers.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Temp', 'OlderThan')]
    [string]$Mode,

    [Parameter()]
    [string[]]$Path,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$OlderThanDays,

    [Parameter()]
    [switch]$IncludeEmptyDirectories,

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$MinimumAgeDaysForTemp = 0,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations\windows-file-cleanup')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows file cleanup.

Usage:
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode Temp -WhatIf
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf

Options:
  -Mode                    Temp or OlderThan.
  -Path                    Folder path(s). Optional for Temp; required for OlderThan.
  -OlderThanDays           Required with -Mode OlderThan.
  -IncludeEmptyDirectories Remove empty directories after file cleanup.
  -MinimumAgeDaysForTemp   Only remove temp items older than this many days. Default: 0.
  -ReportDirectory         Plan and state output directory.
  -WhatIf                  Write reports and preview deletions.
'@
}

function Get-DefaultTempPath {
    @(
        $env:TEMP
        $env:TMP
        'C:\Temp'
        'D:\Temp'
        'E:\Temp'
        'I:\Temp'
    ) | Where-Object { $_ } | Select-Object -Unique
}

function Get-ResolvedDirectoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    if (-not (Test-Path -LiteralPath $InputPath -PathType Container)) {
        throw "Directory not found: $InputPath"
    }

    (Resolve-Path -LiteralPath $InputPath).Path
}

function Test-ProtectedCleanupPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedPath
    )

    $full = [System.IO.Path]::GetFullPath($ResolvedPath).TrimEnd('\')
    $protected = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(
            $env:SystemDrive,
            $env:windir,
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)},
            $env:ProgramData,
            $env:USERPROFILE,
            (Join-Path $env:SystemDrive 'Users'),
            'C:\Code'
        )) {
        if ($item) {
            [void]$protected.Add([System.IO.Path]::GetFullPath($item).TrimEnd('\'))
        }
    }

    if ($full -match '^[A-Za-z]:$') {
        return $true
    }

    foreach ($protectedPath in $protected) {
        if ($full -ieq $protectedPath) {
            return $true
        }
    }

    $false
}

function Assert-CleanupArgument {
    if ($Mode -eq 'OlderThan') {
        if (-not $Path -or -not $OlderThanDays) {
            Show-Usage
            exit 2
        }
    }
}

function Get-CleanupRoot {
    param(
        [Parameter()]
        [string[]]$RequestedPath
    )

    $candidate = if ($RequestedPath) { $RequestedPath } else { Get-DefaultTempPath }
    foreach ($item in $candidate) {
        if (-not $item) {
            continue
        }

        $resolved = Get-ResolvedDirectoryPath -InputPath $item
        if (Test-ProtectedCleanupPath -ResolvedPath $resolved) {
            throw "Refusing to clean protected or overly broad path: $resolved"
        }

        $resolved
    }
}

function Get-CleanupPlan {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RootPath
    )

    $now = Get-Date
    $cutoff = if ($Mode -eq 'OlderThan') { $now.AddDays(-$OlderThanDays) } else { $now.AddDays(-$MinimumAgeDaysForTemp) }
    foreach ($root in $RootPath) {
        if ($Mode -eq 'Temp') {
            $items = Get-ChildItem -LiteralPath $root -Force -ErrorAction Continue | Where-Object {
                $_.LastWriteTime -lt $cutoff
            }
        } else {
            $items = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction Continue | Where-Object {
                $_.LastWriteTime -lt $cutoff
            }
            if ($IncludeEmptyDirectories) {
                $emptyDirs = Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction Continue |
                    Sort-Object FullName -Descending |
                    Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Select-Object -First 1) }
                $items = @($items) + @($emptyDirs)
            }
        }

        foreach ($item in $items) {
            [pscustomobject]@{
                Mode = $Mode
                RootPath = $root
                TargetPath = $item.FullName
                ItemType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                LengthBytes = if ($item.PSIsContainer) { 0 } else { $item.Length }
                LastWriteTime = $item.LastWriteTime
                AgeDays = [math]::Round(($now - $item.LastWriteTime).TotalDays, 2)
                Action = 'RemoveItem'
                Reason = if ($Mode -eq 'Temp') { 'Temp item selected for cleanup.' } else { "Item is older than $OlderThanDays days." }
            }
        }
    }
}

function Invoke-CleanupPlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($PSCmdlet.ShouldProcess($Item.TargetPath, 'Remove cleanup item')) {
        Remove-Item -LiteralPath $Item.TargetPath -Recurse -Force -ErrorAction Stop
        return 'Removed'
    }

    'Previewed'
}

Assert-CleanupArgument

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$roots = @(Get-CleanupRoot -RequestedPath $Path | Select-Object -Unique)
if (-not $roots) {
    throw 'No cleanup roots were found after reading the supplied arguments.'
}

$plan = @(Get-CleanupPlan -RootPath $roots)
$planPath = Join-Path $resolvedReportDirectory "windows-file-cleanup-$($Mode.ToLowerInvariant())-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "windows-file-cleanup-$($Mode.ToLowerInvariant())-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "windows-file-cleanup-$($Mode.ToLowerInvariant())-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "windows-file-cleanup-$($Mode.ToLowerInvariant())-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = try {
        Invoke-CleanupPlanItem -Item $item -WhatIf:$WhatIfPreference
    } catch {
        "Failed: $($_.Exception.Message)"
    }

    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    Operation = $Mode
    RootPaths = @($roots)
    OlderThanDays = if ($Mode -eq 'OlderThan') { $OlderThanDays } else { $null }
    MinimumAgeDaysForTemp = if ($Mode -eq 'Temp') { $MinimumAgeDaysForTemp } else { $null }
    IncludeEmptyDirectories = [bool]$IncludeEmptyDirectories
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    PlannedRemovalCount = @($plan).Count
    PlannedBytes = (@($plan) | Measure-Object -Property LengthBytes -Sum).Sum
    RemovedCount = @($state | Where-Object Result -eq 'Removed').Count
    PreviewedCount = @($state | Where-Object Result -eq 'Previewed').Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
