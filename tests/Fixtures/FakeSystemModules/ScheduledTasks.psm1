<#
.SYNOPSIS
Stand-in for the ScheduledTasks module so scripts that toggle tasks never reach the real ones.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_TASKS to a semicolon-separated list of "<TaskPath>|<TaskName>|<State>"
  entries describing the tasks that exist. Anything not listed does not exist, which is
  what the real cmdlet reports for a task Windows does not have.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Defining a function named Disable-ScheduledTask in the caller's scope does not reliably
shadow this module's command, and relying on it silently disabled four real scheduled
tasks on a development machine during a test run. Staging a module under the same name
earlier on PSModulePath means the real module is never loaded at all, which is the same
approach already used for ActiveDirectory and WebAdministration and the only one proven
to hold here.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeTaskMutation {
    param([string]$Command, [string]$Target)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = '' } | ConvertTo-Json -Compress)
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param([Parameter()]$TaskName, [Parameter()]$TaskPath)

    foreach ($entry in @(($env:OPSTOOLKIT_TEST_TASKS -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 3) { continue }
        if ($TaskName -and [string]$TaskName -ne $parts[1]) { continue }
        if ($TaskPath -and [string]$TaskPath -ne $parts[0]) { continue }
        [pscustomobject]@{ TaskPath = $parts[0]; TaskName = $parts[1]; State = $parts[2] }
    }
}

function Disable-ScheduledTask {
    [CmdletBinding()]
    param([Parameter()]$TaskName, [Parameter()]$TaskPath)
    Write-FakeTaskMutation -Command 'Disable-ScheduledTask' -Target "$TaskPath$TaskName"
}

function Enable-ScheduledTask {
    [CmdletBinding()]
    param([Parameter()]$TaskName, [Parameter()]$TaskPath)
    Write-FakeTaskMutation -Command 'Enable-ScheduledTask' -Target "$TaskPath$TaskName"
}

Export-ModuleMember -Function 'Get-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask'
