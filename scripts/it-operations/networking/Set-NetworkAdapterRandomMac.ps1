<#
.SYNOPSIS
Randomize or restore the MAC address of each physical network adapter, with plan, registry backup, and rollback.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell before applying live registry or adapter changes.
- Each targeted adapter's registry key is exported to a .reg file before changes unless -SkipRegistryBackup is used.
- Use -Rollback to remove the override and restore the burned-in (hardware) MAC.
- Do not run against the only adapter carrying your session, restarting it drops the link and can lock you out; use -SkipAdapterRestart to defer the bounce to the next enable or reboot.

.PURPOSE
Use this to replace the MAC address of physical adapters with a randomly generated,
locally-administered, unicast address, or to restore the hardware default. Each MAC is
written to the adapter's NetworkAddress driver registry value and applied by bouncing the
adapter, then read back and verified because some drivers silently ignore the override.

Typical use is defeating per-MAC tracking or per-device rate limiting on a local network or
captive portal. Note that many ISPs rate-limit on the router's WAN MAC rather than a host NIC,
in which case changing a host adapter here has no effect.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1 -WhatIf
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1 -Name "Wi-Fi"
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1 -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON files plus a rollback JSON under reports\itops\networking by
default. Live runs also export each targeted adapter's registry key to a .reg file before
changes unless -SkipRegistryBackup is used. Returns a summary object with the report and
backup paths, changed, ignored, skipped, and failed counts, and restart-required status.

.STATUS
Active script in the ops-toolkit repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$Name,

    [Parameter()]
    [switch]$Rollback,

    [Parameter()]
    [switch]$SkipRegistryBackup,

    [Parameter()]
    [switch]$SkipAdapterRestart,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\itops\networking')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$NetClassPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'

function Get-RandomMac {
    # Six random bytes, first byte forced to locally-administered (bit 1 set) and unicast (bit 0 clear).
    $bytes = 1..6 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }
    $bytes[0] = ($bytes[0] -band 0xFC) -bor 0x02
    ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
}

function Get-RegValue {
    # StrictMode-safe read of a single registry value; returns $null when the value is absent.
    param([string]$Path, [string]$ValueName)
    $item = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $ValueName)) {
        $item.$ValueName
    }
    else {
        $null
    }
}

function Get-AdapterRegKey {
    param([string]$InterfaceGuid)
    Get-ChildItem $NetClassPath -ErrorAction SilentlyContinue | Where-Object {
        (Get-RegValue -Path $_.PSPath -ValueName 'NetCfgInstanceId') -eq $InterfaceGuid
    } | Select-Object -First 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    Write-Warning 'Run this in an elevated shell to apply changes. Re-run with -WhatIf to plan without elevation.'
    return
}

$adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)
if ($Name) {
    $adapters = @($adapters | Where-Object { $_.Name -in $Name })
}
if (-not $adapters) {
    Write-Warning 'No matching physical adapters found.'
    return
}

if (-not (Test-Path $ReportDirectory)) {
    New-Item -ItemType Directory -Force -Path $ReportDirectory -WhatIf:$false | Out-Null
}
$resolvedReportDirectory = (Resolve-Path $ReportDirectory).Path
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$mode = if ($Rollback) { 'restore' } else { 'randomize' }

# --- Plan -------------------------------------------------------------------
$plan = foreach ($a in $adapters) {
    $reg = Get-AdapterRegKey -InterfaceGuid $a.InterfaceGuid
    [pscustomobject]@{
        Name = $a.Name
        InterfaceDescription = $a.InterfaceDescription
        InterfaceGuid = $a.InterfaceGuid
        Status = [string]$a.Status
        Action = if ($Rollback) { 'Restore' } else { 'Randomize' }
        CurrentMac = ($a.MacAddress -replace '[-:]', '')
        ProposedMac = if ($Rollback) { '(hardware default)' } else { Get-RandomMac }
        RegKeyFound = [bool]$reg
        RegistryKey = if ($reg) { $reg.Name } else { $null }
    }
}

$planCsv = Join-Path $resolvedReportDirectory "mac-$mode-plan-$timestamp.csv"
$planJson = Join-Path $resolvedReportDirectory "mac-$mode-plan-$timestamp.json"
$plan | Export-Csv -Path $planCsv -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJsonText = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJson -Value $planJsonText -Encoding utf8 -WhatIf:$false
Write-Verbose "Plan written: $planCsv"

# --- Apply ------------------------------------------------------------------
$results = foreach ($row in $plan) {
    if (-not $row.RegKeyFound) {
        Write-Warning "[$($row.Name)] no driver registry key found, skipping."
        [pscustomobject]@{
            Name = $row.Name
            Action = $row.Action
            CurrentMac = $row.CurrentMac
            ProposedMac = $row.ProposedMac
            ResultMac = $row.CurrentMac
            PreviousOverride = $null
            Status = 'Skipped-NoRegKey'
        }
        continue
    }

    $reg = Get-AdapterRegKey -InterfaceGuid $row.InterfaceGuid
    $prev = Get-RegValue -Path $reg.PSPath -ValueName 'NetworkAddress'
    $target = "$($row.Name) [$($row.CurrentMac)]"
    $desc = if ($Rollback) { 'Restore hardware MAC' } else { "Set MAC to $($row.ProposedMac)" }
    $status = 'WhatIf'
    $result = $row.CurrentMac

    if ($PSCmdlet.ShouldProcess($target, $desc)) {
        if (-not $SkipRegistryBackup) {
            $regExe = $reg.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
            $safeName = $row.Name -replace '[^\w.-]', '_'
            $backupFile = Join-Path $resolvedReportDirectory "regkey-$safeName-$timestamp.reg"
            & reg.exe export $regExe $backupFile /y | Out-Null
        }

        try {
            if ($Rollback) {
                Remove-ItemProperty -Path $reg.PSPath -Name NetworkAddress -ErrorAction SilentlyContinue
            }
            else {
                Set-ItemProperty -Path $reg.PSPath -Name NetworkAddress -Value $row.ProposedMac -Type String
            }

            if ($SkipAdapterRestart) {
                $status = 'Set-RestartPending'
            }
            else {
                Restart-NetAdapter -Name $row.Name -ErrorAction Stop
                Start-Sleep -Seconds 6
                $result = ((Get-NetAdapter -Name $row.Name -ErrorAction SilentlyContinue).MacAddress -replace '[-:]', '')
                if ($Rollback) {
                    $status = 'Restored'
                }
                elseif ($result -eq $row.ProposedMac) {
                    $status = 'Confirmed'
                }
                else {
                    $status = 'Ignored-ByDriver'
                }
            }

            if ($status -eq 'Ignored-ByDriver') {
                Write-Warning "[$($row.Name)] driver kept $result, MAC override ignored."
            }
            else {
                Write-Verbose "[$($row.Name)] $status -> $result"
            }
        }
        catch {
            $status = "Failed: $($_.Exception.Message)"
            Write-Warning "[$($row.Name)] $status"
        }
    }

    [pscustomobject]@{
        Name = $row.Name
        Action = $row.Action
        CurrentMac = $row.CurrentMac
        ProposedMac = $row.ProposedMac
        ResultMac = $result
        PreviousOverride = $prev
        Status = $status
    }
}

# --- State and rollback -----------------------------------------------------
$stateCsv = Join-Path $resolvedReportDirectory "mac-$mode-state-$timestamp.csv"
$stateJson = Join-Path $resolvedReportDirectory "mac-$mode-state-$timestamp.json"
$results | Export-Csv -Path $stateCsv -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJsonText = if (@($results).Count) { @($results) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJson -Value $stateJsonText -Encoding utf8 -WhatIf:$false

$rollbackJson = Join-Path $resolvedReportDirectory "mac-rollback-$timestamp.json"
$rollbackText = if (@($results).Count) { @($results | Select-Object Name, PreviousOverride) | ConvertTo-Json -Depth 3 } else { '[]' }
Set-Content -LiteralPath $rollbackJson -Value $rollbackText -Encoding utf8 -WhatIf:$false

$restartRequired = [bool](@($results | Where-Object { $_.Status -eq 'Set-RestartPending' }).Count)

[pscustomobject]@{
    Mode = $mode
    PlanReport = $planCsv
    StateReport = $stateCsv
    RollbackFile = $rollbackJson
    ReportDirectory = $resolvedReportDirectory
    Changed = @($results | Where-Object { $_.Status -in 'Confirmed', 'Restored', 'Set-RestartPending' }).Count
    IgnoredByDriver = @($results | Where-Object { $_.Status -eq 'Ignored-ByDriver' }).Count
    Skipped = @($results | Where-Object { $_.Status -like 'Skipped*' }).Count
    Failed = @($results | Where-Object { $_.Status -like 'Failed*' }).Count
    RestartRequired = $restartRequired
}
