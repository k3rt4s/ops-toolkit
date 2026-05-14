<#
.SYNOPSIS
Plan, add, or remove Windows printer connections.

.INSTRUCTIONS
- Read the root README.md and IT operations README.md before running this script.
- Use -Action Add with -PrinterPath or -PrinterListPath to add network printer connections.
- Use -Action Remove with -PrinterName, -PrinterListPath, or -AllConnectionPrinters to remove printer connections.
- Run with -WhatIf first and review the generated plan/state reports.
- Generated reports are written under reports\it-operations\printers by default.

.PURPOSE
This script replaces the separate add/remove printer connection helpers with a
single command-driven entry point. It keeps printer operations report-first and
avoids removing local printers unless -AllConnectionPrinters or explicit names
select them.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\data\it-operations\printers\printers.example.txt -WhatIf
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Remove -AllConnectionPrinters -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON files under reports\it-operations\printers by default.
Returns a summary object with report paths and action counts.

.STATUS
Active PowerShell replacement for the legacy printer VBScript helpers and the
previous split add/remove PowerShell scripts.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Add', 'Remove')]
    [string]$Action,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$PrinterPath,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PrinterListPath,

    [Parameter()]
    [string[]]$PrinterName,

    [Parameter()]
    [switch]$AllConnectionPrinters,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations\printers')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows printer connection management.

Usage:
  pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterPath "\\print01\Accounting" -WhatIf
  pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\data\it-operations\printers\printers.example.txt -WhatIf
  pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Remove -PrinterName "\\print01\Accounting" -WhatIf
  pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Remove -AllConnectionPrinters -WhatIf

Options:
  -Action                 Add or Remove.
  -PrinterPath            One or more printer UNC paths to add.
  -PrinterName            One or more printer names or UNC connection names to remove.
  -PrinterListPath        Text file containing one printer UNC path or printer name per line.
  -AllConnectionPrinters  Remove all printers whose Type is Connection.
  -ReportDirectory        Plan and state output directory.
  -WhatIf                 Write reports and preview changes.
'@
}

function Import-PrinterList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    @(Get-Content -LiteralPath $Path |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') } |
            Select-Object -Unique)
}

function Assert-PrinterArgument {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Add', 'Remove')]
        [string]$RequestedAction,

        [Parameter()]
        [string[]]$RequestedPrinterPath,

        [Parameter()]
        [string]$RequestedPrinterListPath,

        [Parameter()]
        [string[]]$RequestedPrinterName,

        [Parameter()]
        [switch]$RequestedAllConnectionPrinters
    )

    if ($RequestedAction -eq 'Add') {
        if (-not $RequestedPrinterPath -and -not $RequestedPrinterListPath) {
            Show-Usage
            exit 2
        }

        if ($RequestedPrinterName -or $RequestedAllConnectionPrinters) {
            throw 'Use -PrinterPath or -PrinterListPath with -Action Add. -PrinterName and -AllConnectionPrinters are remove-only options.'
        }
    }

    if ($RequestedAction -eq 'Remove') {
        if (-not $RequestedPrinterName -and -not $RequestedPrinterListPath -and -not $RequestedAllConnectionPrinters) {
            Show-Usage
            exit 2
        }

        if ($RequestedPrinterPath) {
            throw 'Use -PrinterName, -PrinterListPath, or -AllConnectionPrinters with -Action Remove. -PrinterPath is add-only.'
        }
    }
}

function Get-PrinterTarget {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Add', 'Remove')]
        [string]$RequestedAction,

        [Parameter()]
        [string[]]$RequestedPrinterPath,

        [Parameter()]
        [string]$RequestedPrinterListPath,

        [Parameter()]
        [string[]]$RequestedPrinterName,

        [Parameter()]
        [switch]$RequestedAllConnectionPrinters
    )

    if ($RequestedAction -eq 'Add') {
        $targets = @()
        if ($RequestedPrinterPath) {
            $targets += $RequestedPrinterPath
        }
        if ($RequestedPrinterListPath) {
            $targets += Import-PrinterList -Path $RequestedPrinterListPath
        }

        return @($targets | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    }

    if ($RequestedAllConnectionPrinters) {
        return @(Get-Printer | Where-Object Type -eq 'Connection' | Select-Object -ExpandProperty Name)
    }

    $removeTargets = @()
    if ($RequestedPrinterName) {
        $removeTargets += $RequestedPrinterName
    }
    if ($RequestedPrinterListPath) {
        $removeTargets += Import-PrinterList -Path $RequestedPrinterListPath
    }

    @($removeTargets | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ExistingPrinter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Get-Printer -Name $Name -ErrorAction SilentlyContinue
}

function Get-PrinterPlan {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Target
    )

    foreach ($targetName in $Target) {
        $existing = Get-ExistingPrinter -Name $targetName
        $isUnc = $targetName -like '\\*'
        $plannedAction = if ($Action -eq 'Add') {
            if ($existing) { 'NoChange' } else { 'AddPrinterConnection' }
        } elseif ($existing) {
            'RemovePrinter'
        } else {
            'Missing'
        }

        [pscustomobject]@{
            Action = $plannedAction
            RequestedAction = $Action
            Target = $targetName
            IsUncPath = $isUnc
            ExistingName = if ($existing) { $existing.Name } else { '' }
            ExistingType = if ($existing) { $existing.Type } else { '' }
            ExistingDriverName = if ($existing) { $existing.DriverName } else { '' }
            ExistingPortName = if ($existing) { $existing.PortName } else { '' }
            Reason = switch ($plannedAction) {
                'AddPrinterConnection' { 'Printer connection is not present and will be added.' }
                'RemovePrinter' { 'Printer exists and will be removed.' }
                'NoChange' { 'Printer connection already exists.' }
                'Missing' { 'Printer was requested for removal but was not found.' }
            }
        }
    }
}

function Invoke-PrinterPlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -eq 'AddPrinterConnection') {
        if (-not $Item.IsUncPath) {
            throw "Printer connection '$($Item.Target)' must be a UNC path like \\server\printer."
        }

        if ($PSCmdlet.ShouldProcess($Item.Target, 'Add printer connection')) {
            Add-Printer -ConnectionName $Item.Target
            return 'Changed'
        }

        return 'Previewed'
    }

    if ($Item.Action -eq 'RemovePrinter') {
        if ($PSCmdlet.ShouldProcess($Item.Target, 'Remove printer')) {
            Remove-Printer -Name $Item.Target
            return 'Changed'
        }

        return 'Previewed'
    }

    'Skipped'
}

Assert-PrinterArgument `
    -RequestedAction $Action `
    -RequestedPrinterPath $PrinterPath `
    -RequestedPrinterListPath $PrinterListPath `
    -RequestedPrinterName $PrinterName `
    -RequestedAllConnectionPrinters:$AllConnectionPrinters

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$targets = @(Get-PrinterTarget `
        -RequestedAction $Action `
        -RequestedPrinterPath $PrinterPath `
        -RequestedPrinterListPath $PrinterListPath `
        -RequestedPrinterName $PrinterName `
        -RequestedAllConnectionPrinters:$AllConnectionPrinters)
if (-not $targets) {
    throw 'No printer targets were found after reading the supplied arguments.'
}

$plan = @(Get-PrinterPlan -Target $targets)
$planPath = Join-Path $resolvedReportDirectory "windows-printer-connections-$($Action.ToLowerInvariant())-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "windows-printer-connections-$($Action.ToLowerInvariant())-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "windows-printer-connections-$($Action.ToLowerInvariant())-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "windows-printer-connections-$($Action.ToLowerInvariant())-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $planJsonPath -Value (@($plan) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = try {
        Invoke-PrinterPlanItem -Item $item -WhatIf:$WhatIfPreference
    } catch {
        "Failed: $($_.Exception.Message)"
    }

    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $stateJsonPath -Value (@($state) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    Operation = $Action
    TargetCount = @($targets).Count
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    PlannedChangeCount = @($plan | Where-Object Action -in @('AddPrinterConnection', 'RemovePrinter')).Count
    ChangedCount = @($state | Where-Object Result -eq 'Changed').Count
    PreviewedCount = @($state | Where-Object Result -eq 'Previewed').Count
    SkippedCount = @($state | Where-Object Result -eq 'Skipped').Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
