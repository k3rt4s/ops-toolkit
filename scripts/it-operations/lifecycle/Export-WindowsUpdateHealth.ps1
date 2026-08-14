<#
.SYNOPSIS
Report why a Windows machine is or is not patching: service state, pending reboot, deferral policy, and recent update failures.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads services, the registry, and the Windows Update history and
  writes reports. It installs nothing and changes nothing.
- Runs unelevated. A few registry paths under HKLM policy keys read fine without
  elevation; anything unreadable is reported as such rather than assumed absent.
- -ComputerName needs WinRM and local administrator rights on each target.
- Safeguard holds are not enumerable through a supported API. This reports the
  policy and history evidence that a hold produces, and says so, rather than
  claiming to list hold IDs it cannot see.
- Generated reports are written under reports\it-operations by default.

Purpose:
"Why is this box not patching" is a recurring hour-long dig through services,
registry policy, reboot state, and update history. July 2026 made it worse by
shipping both a confirmed WSUS synchronization degradation and a hardware safeguard
hold, so the same symptom had two unrelated causes at once. This collects every
signal in one pass and states a verdict per machine, so the dig starts from
evidence rather than from the Settings app.

Required syntax:
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsUpdateHealth.ps1
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsUpdateHealth.ps1 -ComputerName pc01,pc02
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsUpdateHealth.ps1 -HistoryCount 100 -StaleUpdateDays 60

.OUTPUTS
Writes a per-machine health verdict, the signal detail, recent update history, and a
run summary as CSV and JSON under reports\it-operations by default. Returns a
summary object.

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
    [ValidateRange(1, 500)]
    [int]$HistoryCount = 50,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleUpdateDays = 45,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$LongUptimeDays = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'windows-update-health'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$healthProbe = {
    param($History, $StaleDays, $UptimeDays)

    function Get-RegValue {
        param($Path, $Name)
        try {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        } catch {
            return $null
        }
    }

    $signals = [System.Collections.Generic.List[object]]::new()
    function Add-Signal {
        param($List, $Name, $Status, $Value, $Note = '')
        $List.Add([pscustomobject]@{ Signal = $Name; Status = $Status; Value = "$Value"; Note = $Note })
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $uptimeDays = [int][math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalDays)

    foreach ($serviceName in @('wuauserv', 'bits', 'cryptsvc', 'trustedinstaller', 'usosvc')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Add-Signal $signals "Service:$serviceName" 'Warn' 'not present'
            continue
        }

        $startType = [string]$service.StartType
        $bad = $startType -eq 'Disabled'
        $serviceStatus = if ($bad) { 'Fail' } else { 'Pass' }
        $serviceNote = if ($bad) { 'Disabled. Windows Update cannot run with this service disabled.' } else { '' }
        Add-Signal $signals "Service:$serviceName" $serviceStatus "$($service.Status)/$startType" $serviceNote
    }

    # Pending reboot has several independent signals and any one of them blocks the
    # next install. Component Based Servicing is the one that matters most.
    $rebootSignals = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootSignals += 'CBS RebootPending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootSignals += 'WindowsUpdate RebootRequired' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending') { $rebootSignals += 'CBS PackagesPending' }
    if (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $rebootSignals += 'PendingFileRenameOperations' }
    $computerNameKey = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
    $pendingNameKey = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
    if ($computerNameKey -and $pendingNameKey -and $computerNameKey -ne $pendingNameKey) { $rebootSignals += 'Pending computer rename' }

    $rebootPending = $rebootSignals.Count -gt 0
    $rebootStatus = if ($rebootPending) { 'Fail' } else { 'Pass' }
    $rebootNote = if ($rebootPending) { 'Updates will not complete until this machine reboots.' } else { '' }
    Add-Signal $signals 'PendingReboot' $rebootStatus ($rebootSignals -join ';') $rebootNote

    $longUptime = $uptimeDays -gt $UptimeDays
    $uptimeStatus = if ($longUptime) { 'Warn' } else { 'Pass' }
    $uptimeNote = if ($longUptime) { "Up for $uptimeDays days. Combined with a pending reboot this is the usual cause of a stalled machine." } else { '' }
    Add-Signal $signals 'UptimeDays' $uptimeStatus $uptimeDays $uptimeNote

    # Update policy. A WSUS server that is unreachable or degraded, a deferral, a
    # pause, or a pinned target release all look identical from the Settings app.
    $wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wuAuPolicy = "$wuPolicy\AU"
    $wsusServer = Get-RegValue $wuPolicy 'WUServer'
    $useWsus = Get-RegValue $wuAuPolicy 'UseWUServer'
    $wsusStatus = if ($wsusServer) { 'Info' } else { 'Pass' }
    $wsusValue = if ($wsusServer) { "$wsusServer (UseWUServer=$useWsus)" } else { 'Windows Update (no WSUS policy)' }
    $wsusNote = if ($wsusServer) { 'Confirm the WSUS server is synchronizing. A degraded sync stalls every client pointed at it.' } else { '' }
    Add-Signal $signals 'WsusServer' $wsusStatus $wsusValue $wsusNote

    $targetRelease = Get-RegValue $wuPolicy 'TargetReleaseVersionInfo'
    $targetReleaseOn = Get-RegValue $wuPolicy 'TargetReleaseVersion'
    $targetStatus = if ($targetRelease) { 'Warn' } else { 'Pass' }
    $targetValue = if ($targetRelease) { "$targetRelease (enabled=$targetReleaseOn)" } else { 'not pinned' }
    $targetNote = if ($targetRelease) { 'Feature updates are pinned to this release. The machine will not move past it, which looks identical to a safeguard hold.' } else { '' }
    Add-Signal $signals 'TargetReleaseVersion' $targetStatus $targetValue $targetNote

    $deferFeature = Get-RegValue $wuPolicy 'DeferFeatureUpdatesPeriodInDays'
    $deferQuality = Get-RegValue $wuPolicy 'DeferQualityUpdatesPeriodInDays'
    Add-Signal $signals 'Deferrals' $(if ($deferFeature -or $deferQuality) { 'Info' } else { 'Pass' }) "feature=$deferFeature quality=$deferQuality"

    # Windows leaves the last pause expiry in the registry after the pause lapses, so
    # the value being present does not mean updates are paused now.
    $pauseExpiry = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
    $pauseActive = $false
    $pauseParsed = [datetime]::MinValue
    if ($pauseExpiry -and [datetime]::TryParse([string]$pauseExpiry, [ref]$pauseParsed)) {
        $pauseActive = $pauseParsed.ToUniversalTime() -gt (Get-Date).ToUniversalTime()
    }

    $pauseStatus = if ($pauseActive) { 'Warn' } else { 'Pass' }
    $pauseValue = if ($pauseActive) { "paused until $pauseExpiry" } elseif ($pauseExpiry) { "not paused (last pause expired $pauseExpiry)" } else { 'not paused' }
    $pauseNote = if ($pauseActive) { 'Updates are paused until this time.' } else { '' }
    Add-Signal $signals 'PauseUpdates' $pauseStatus $pauseValue $pauseNote

    # Last successful install. Get-HotFix misses feature updates and some servicing
    # stack updates, so the update history is read too and the later of the two wins.
    $lastHotfix = $null
    try {
        $lastHotfix = (Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    } catch {
        $lastHotfix = $null
    }

    $historyRecords = [System.Collections.Generic.List[object]]::new()
    $lastSuccess = $null
    $historyError = ''
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $take = [math]::Min($History, $total)
            foreach ($entry in $searcher.QueryHistory(0, $take)) {
                # The COM history Date is UTC but arrives with Kind Unspecified, so
                # comparing it against a local Get-Date reports an install that
                # happened hours ago as happening in the future.
                $entryDate = [datetime]::SpecifyKind($entry.Date, [System.DateTimeKind]::Utc).ToLocalTime()

                # ResultCode 2 is Succeeded, 3 SucceededWithErrors, 4 Failed, 5 Aborted.
                $outcome = switch ([int]$entry.ResultCode) {
                    1 { 'InProgress' }
                    2 { 'Succeeded' }
                    3 { 'SucceededWithErrors' }
                    4 { 'Failed' }
                    5 { 'Aborted' }
                    default { "Unknown($($entry.ResultCode))" }
                }

                $historyRecords.Add([pscustomobject]@{
                        Date = $entryDate
                        Outcome = $outcome
                        HResult = ('0x{0:X8}' -f [int]$entry.HResult)
                        Operation = switch ([int]$entry.Operation) { 1 { 'Install' } 2 { 'Uninstall' } default { 'Other' } }
                        Title = $entry.Title
                    })

                if ([int]$entry.ResultCode -in @(2, 3) -and (-not $lastSuccess -or $entryDate -gt $lastSuccess)) {
                    $lastSuccess = $entryDate
                }
            }
        }
    } catch {
        $historyError = $_.Exception.Message
    }

    $lastInstall = @($lastHotfix, $lastSuccess) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    # Clamp at zero. Clock skew between the history timestamp and now must never
    # render as a negative age, which reads as a future install.
    $daysSinceInstall = if ($lastInstall) { [math]::Max(0, [int][math]::Floor(((Get-Date) - $lastInstall).TotalDays)) } else { $null }
    $installStatus = if ($null -eq $daysSinceInstall) { 'Warn' } elseif ($daysSinceInstall -gt $StaleDays) { 'Fail' } else { 'Pass' }
    $installValue = if ($lastInstall) { "$lastInstall ($daysSinceInstall days ago)" } else { 'unknown' }
    $installNote = if ($historyError) { "Update history unreadable: $historyError" } else { '' }
    Add-Signal $signals 'LastSuccessfulInstall' $installStatus $installValue $installNote

    $recentFailures = @($historyRecords | Where-Object { $_.Outcome -in @('Failed', 'Aborted') })
    $failureStatus = if ($recentFailures.Count -gt 0) { 'Fail' } else { 'Pass' }
    $failureNote = if ($recentFailures.Count -gt 0) { "Most recent: $($recentFailures[0].Title) $($recentFailures[0].HResult)" } else { '' }
    Add-Signal $signals 'RecentFailures' $failureStatus $recentFailures.Count $failureNote

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Caption = $os.Caption
        Build = [int]$os.BuildNumber
        LastBootUpTime = $os.LastBootUpTime
        UptimeDays = $uptimeDays
        LastInstall = $lastInstall
        DaysSinceInstall = $daysSinceInstall
        Signals = @($signals)
        History = @($historyRecords)
    }
}

$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$verdicts = [System.Collections.Generic.List[object]]::new()
$signalDetail = [System.Collections.Generic.List[object]]::new()
$historyDetail = [System.Collections.Generic.List[object]]::new()

foreach ($target in $targets) {
    $probe = $null
    try {
        if ($target -eq $env:COMPUTERNAME) {
            $probe = & $healthProbe $HistoryCount $StaleUpdateDays $LongUptimeDays
        } else {
            $probe = Invoke-Command -ComputerName $target -ScriptBlock $healthProbe `
                -ArgumentList $HistoryCount, $StaleUpdateDays, $LongUptimeDays -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $verdicts.Add([pscustomobject]@{
                ComputerName = $target
                Verdict = 'Unreachable'
                FailedSignals = ''
                WarnSignals = ''
                UptimeDays = $null
                DaysSinceInstall = $null
                Note = $_.Exception.Message
            })
        continue
    }

    $signals = @(Get-OpsPropertyValue -InputObject $probe -Name 'Signals')
    foreach ($signal in $signals) {
        $signalDetail.Add([pscustomobject]@{
                ComputerName = $probe.ComputerName
                Signal = $signal.Signal
                Status = $signal.Status
                Value = $signal.Value
                Note = $signal.Note
            })
    }

    foreach ($entry in @(Get-OpsPropertyValue -InputObject $probe -Name 'History')) {
        $historyDetail.Add([pscustomobject]@{
                ComputerName = $probe.ComputerName
                Date = $entry.Date
                Outcome = $entry.Outcome
                HResult = $entry.HResult
                Operation = $entry.Operation
                Title = $entry.Title
            })
    }

    $failed = @($signals | Where-Object { $_.Status -eq 'Fail' })
    $warned = @($signals | Where-Object { $_.Status -eq 'Warn' })
    $verdict = if ($failed.Count -gt 0) { 'Unhealthy' } elseif ($warned.Count -gt 0) { 'Degraded' } else { 'Healthy' }

    $verdicts.Add([pscustomobject]@{
            ComputerName = $probe.ComputerName
            Verdict = $verdict
            Caption = $probe.Caption
            Build = $probe.Build
            UptimeDays = $probe.UptimeDays
            LastInstall = $probe.LastInstall
            DaysSinceInstall = $probe.DaysSinceInstall
            FailedSignals = (@($failed | ForEach-Object { $_.Signal }) -join ';')
            WarnSignals = (@($warned | ForEach-Object { $_.Signal }) -join ';')
            Note = ''
        })
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'update-health-verdict' -Record @($verdicts) -Directory $runDirectory
    Export-OpsReport -Name 'update-health-signals' -Record @($signalDetail) -Directory $runDirectory
    Export-OpsReport -Name 'update-history' -Record @($historyDetail) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    ComputersQueried = @($targets).Count
    HealthyCount = @($verdicts | Where-Object { $_.Verdict -eq 'Healthy' }).Count
    DegradedCount = @($verdicts | Where-Object { $_.Verdict -eq 'Degraded' }).Count
    UnhealthyCount = @($verdicts | Where-Object { $_.Verdict -eq 'Unhealthy' }).Count
    UnreachableCount = @($verdicts | Where-Object { $_.Verdict -eq 'Unreachable' }).Count
    PendingRebootCount = @($signalDetail | Where-Object { $_.Signal -eq 'PendingReboot' -and $_.Status -eq 'Fail' }).Count
    WsusManagedCount = @($signalDetail | Where-Object { $_.Signal -eq 'WsusServer' -and $_.Status -eq 'Info' }).Count
    HistoryRecordCount = $historyDetail.Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
