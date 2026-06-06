<#
.SYNOPSIS
Plan, apply, and roll back workstation performance settings: active power plan and Defender exclusions.

.INSTRUCTIONS
- Read the root README.md and the IT operations README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell to apply Defender exclusions (Add-MpPreference requires admin).
- Use -Rollback to restore the previous power plan and remove the exclusions this script added.
- Defender path/process exclusions reduce real-time scanning on the listed items; only exclude
  trusted build/data locations, and keep the list as narrow as the workload needs.
- Generated reports are written under C:\Code_data\ops-toolkit\windows-performance by default,
  per the workspace data-hygiene rule (generated data lives under C:\Code_data, never in the repo).

.PURPOSE
Use this to put a workstation into a sustained-performance posture for heavy local batch work
(media encode/transcode, transcription, large builds): activate the Ultimate or High Performance
power plan so the CPU does not park or downclock mid-job, and exclude a trusted data/scratch
location (and optionally specific processes) from Windows Defender real-time scanning so antivirus
does not tax every file read and written during a long job. It intentionally does not change BIOS,
OEM (MSI Center) modes, GPU clocks, or any security setting other than the explicit Defender
exclusions, which are fully reversible with -Rollback.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -WhatIf
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1            # elevated for Defender
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON files under the report directory, plus a rollback-state JSON on a
live forward run that records the previous active power scheme and the exclusions added, so a later
-Rollback can revert precisely. Returns a summary object with report paths and changed/skipped counts.

.STATUS
Active script in the ops-toolkit repo. Companion to Invoke-DiskSpaceReclaim.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('UltimatePerformance', 'HighPerformance', 'Balanced')]
    [string]$PowerPlan = 'UltimatePerformance',

    [Parameter()]
    [switch]$SkipPowerPlan,

    [Parameter()]
    [switch]$SkipDefenderExclusions,

    [Parameter()]
    [string[]]$DefenderPathExclusion = @('C:\Code_data'),

    [Parameter()]
    [string[]]$DefenderProcessExclusion = @(),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = 'C:\Code_data\ops-toolkit\windows-performance',

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Built-in power scheme template GUIDs.
$script:PowerSchemeGuids = @{
    UltimatePerformance = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
    HighPerformance = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    Balanced = '381b4222-f694-41f0-9685-ff5bb260df2e'
}

function Show-Usage {
    Write-Output @'
Set workstation performance posture (power plan + Defender exclusions).

Usage:
  pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -WhatIf
  pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1
  pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -Rollback -WhatIf

Options:
  -PowerPlan                 UltimatePerformance, HighPerformance, or Balanced. Default: UltimatePerformance.
  -SkipPowerPlan             Do not change the active power plan.
  -SkipDefenderExclusions    Do not add Defender exclusions.
  -DefenderPathExclusion     Path(s) to exclude from real-time scanning. Default: C:\Code_data.
  -DefenderProcessExclusion  Process name(s) to exclude (opt-in; empty by default).
  -ReportDirectory           Plan, state, and rollback output directory.
  -Rollback                  Restore the previous power plan and remove exclusions this script added.
  -WhatIf                    Write reports and preview changes without applying them.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ActiveSchemeGuid {
    $line = (powercfg /getactivescheme) 2>$null
    if ($line -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
        return $matches[1]
    }
    $null
}

function Get-SchemeNameForGuid {
    param([Parameter(Mandatory = $true)][string]$Guid)
    $line = (powercfg /query $Guid) 2>$null | Select-Object -First 1
    if ($line -match '\((.+)\)\s*$') { return $matches[1] }
    $Guid
}

function Resolve-TargetSchemeGuid {
    # Returns the GUID to activate for $PowerPlan, creating the Ultimate
    # Performance scheme from its template if the OS has not exposed it yet.
    param([Parameter(Mandatory = $true)][string]$PlanName)

    $template = $script:PowerSchemeGuids[$PlanName]
    $existing = (powercfg /list) 2>$null
    foreach ($l in $existing) {
        if ($l -match '([0-9a-fA-F-]{36})') {
            $g = $matches[1]
            if ($g -ieq $template) { return $g }    # canonical scheme already present
        }
    }
    if ($PlanName -eq 'UltimatePerformance') {
        # Ultimate Performance is often hidden until duplicated from its template.
        $out = (powercfg -duplicatescheme $template) 2>$null
        foreach ($l in $out) {
            if ($l -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
                return $matches[1]
            }
        }
    }
    $template
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    param(
        [Parameter(Mandatory = $true)][string]$PowerPlan,
        [switch]$SkipPowerPlan,
        [switch]$SkipDefenderExclusions,
        [string[]]$DefenderPathExclusion,
        [string[]]$DefenderProcessExclusion
    )

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $currentScheme = Get-ActiveSchemeGuid

    if (-not $SkipPowerPlan) {
        $items.Add([pscustomobject]@{
                Category = 'PowerPlan'; Setting = $PowerPlan
                CurrentValue = if ($currentScheme) { Get-SchemeNameForGuid -Guid $currentScheme } else { 'unknown' }
                DesiredValue = $PowerPlan; RequiresAdmin = $false
                Action = "Set active power scheme to $PowerPlan"
            })
    }

    if (-not $SkipDefenderExclusions) {
        $current = $null
        try { $current = Get-MpPreference -ErrorAction Stop } catch { $current = $null }
        $existingPaths = @(if ($current) { $current.ExclusionPath })
        $existingProcs = @(if ($current) { $current.ExclusionProcess })

        foreach ($p in $DefenderPathExclusion) {
            $already = $existingPaths -contains $p
            $items.Add([pscustomobject]@{
                    Category = 'DefenderPathExclusion'; Setting = $p
                    CurrentValue = if ($already) { 'present' } else { 'absent' }
                    DesiredValue = 'present'; RequiresAdmin = $true
                    Action = if ($already) { 'No change (already excluded)' } else { "Add Defender path exclusion: $p" }
                })
        }
        foreach ($proc in $DefenderProcessExclusion) {
            $already = $existingProcs -contains $proc
            $items.Add([pscustomobject]@{
                    Category = 'DefenderProcessExclusion'; Setting = $proc
                    CurrentValue = if ($already) { 'present' } else { 'absent' }
                    DesiredValue = 'present'; RequiresAdmin = $true
                    Action = if ($already) { 'No change (already excluded)' } else { "Add Defender process exclusion: $proc" }
                })
        }
    }
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'performance-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No performance-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($data.PreviousActiveSchemeGuid) {
        $items.Add([pscustomobject]@{
                Category = 'PowerPlan'; Setting = $data.PreviousActiveSchemeGuid
                CurrentValue = (Get-ActiveSchemeGuid); DesiredValue = $data.PreviousActiveSchemeGuid
                RequiresAdmin = $false; Action = "Restore previous power scheme $($data.PreviousActiveSchemeGuid)"
            })
    }
    foreach ($p in @($data.AddedDefenderPaths)) {
        if ($p) { $items.Add([pscustomobject]@{
                    Category = 'DefenderPathExclusion'; Setting = $p; CurrentValue = 'present'
                    DesiredValue = 'absent'; RequiresAdmin = $true; Action = "Remove Defender path exclusion: $p" }) }
    }
    foreach ($proc in @($data.AddedDefenderProcesses)) {
        if ($proc) { $items.Add([pscustomobject]@{
                    Category = 'DefenderProcessExclusion'; Setting = $proc; CurrentValue = 'present'
                    DesiredValue = 'absent'; RequiresAdmin = $true; Action = "Remove Defender process exclusion: $proc" }) }
    }
    , $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what actually changed (for the rollback file).
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        switch ($Item.Category) {
            'PowerPlan' {
                if ($Rollback) {
                    powercfg /setactive $Item.Setting | Out-Null
                } else {
                    $guid = Resolve-TargetSchemeGuid -PlanName $Item.Setting
                    powercfg /setactive $guid | Out-Null
                    $script:AppliedSchemeGuid = $guid
                }
            }
            'DefenderPathExclusion' {
                if ($Rollback) { Remove-MpPreference -ExclusionPath $Item.Setting -ErrorAction Stop }
                else { Add-MpPreference -ExclusionPath $Item.Setting -ErrorAction Stop; [void]$script:AddedPaths.Add($Item.Setting) }
            }
            'DefenderProcessExclusion' {
                if ($Rollback) { Remove-MpPreference -ExclusionProcess $Item.Setting -ErrorAction Stop }
                else { Add-MpPreference -ExclusionProcess $Item.Setting -ErrorAction Stop; [void]$script:AddedProcs.Add($Item.Setting) }
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }
    if ($Rollback) { 'Reverted' } else { 'Applied' }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$script:AddedPaths = [System.Collections.Generic.List[string]]::new()
$script:AddedProcs = [System.Collections.Generic.List[string]]::new()
$script:AppliedSchemeGuid = $null
$previousSchemeGuid = Get-ActiveSchemeGuid

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$plan = @(if ($Rollback) {
        Get-RollbackPlan
    } else {
        Get-ForwardPlan -PowerPlan $PowerPlan -SkipPowerPlan:$SkipPowerPlan -SkipDefenderExclusions:$SkipDefenderExclusions -DefenderPathExclusion $DefenderPathExclusion -DefenderProcessExclusion $DefenderProcessExclusion
    })

$planPath = Join-Path $resolvedReportDirectory "performance-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "performance-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "performance-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "performance-$mode-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = Invoke-PlanItem -Item $item -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

# On a live forward run that changed something, write the rollback record.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and ($script:AppliedSchemeGuid -or $script:AddedPaths.Count -or $script:AddedProcs.Count)) {
    $rollbackPath = Join-Path $resolvedReportDirectory "performance-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        PreviousActiveSchemeGuid = $previousSchemeGuid
        AppliedSchemeGuid = $script:AppliedSchemeGuid
        AddedDefenderPaths = @($script:AddedPaths)
        AddedDefenderProcesses = @($script:AddedProcs)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WorkstationPerformance ($mode)"
    PowerPlan = if ($SkipPowerPlan) { 'skipped' } else { $PowerPlan }
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
