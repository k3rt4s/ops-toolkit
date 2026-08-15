<#
.SYNOPSIS
Verify that applied Windows hardening is still in place, and prove the TLS client policy with real handshakes.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It runs the Set- hardening scripts in -WhatIf mode, which changes
  nothing, and reads their plans to compare desired state against current state.
- Runs unelevated. The hardening scripts refuse to apply without elevation but
  will always produce a plan, which is all this needs.
- -ProbeEndpoint attempts a real TLS handshake per protocol version against a
  remote host. This is the only check here that leaves the machine, and it proves
  the client-side Schannel policy rather than trusting the registry.
- -ComputerName checks remote machines. The desired state still comes from running
  the hardening scripts locally in -WhatIf mode, because desired state is a property
  of the scripts rather than of any machine; only the current registry values are
  read remotely. That means the remote targets do not need a copy of this repo.
  Non-registry plan items, services and scheduled tasks, are reported as not checked
  remotely rather than assumed compliant.
- Generated reports are written under reports\windows-hardening by default.

Purpose:
Every hardening script in this repo applies state and none of them ever proved it
afterwards. Configuration drifts: a feature update rewrites a policy key, a
competing GPO wins, someone rolls back one setting by hand. A hardening run with no
verification is an assertion, and an assertion is what gets written into a
compliance questionnaire and later turns out to be false.

The compliance check derives its expectations from the hardening scripts themselves
rather than from a second copy of the settings, so the two can never disagree. The
handshake probe is deliberately independent: the registry says what Schannel was
told, and the handshake says what Schannel actually does, and those are different
claims. A protocol that negotiates while the registry says it is disabled is the
finding worth having.

Required syntax:
pwsh -File .\scripts\windows-hardening\Test-WindowsHardeningState.ps1
pwsh -File .\scripts\windows-hardening\Test-WindowsHardeningState.ps1 -Target SchannelTls -ProbeEndpoint 'www.microsoft.com:443'
pwsh -File .\scripts\windows-hardening\Test-WindowsHardeningState.ps1 -Target Privacy -FailOnDrift

.OUTPUTS
Writes per-item compliance, a per-category rollup, handshake results, and a run
summary as CSV and JSON under reports\windows-hardening by default. Returns a
summary object. Exits 1 with -FailOnDrift when any item has drifted.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('SchannelTls', 'Privacy')]
    [string[]]$Target = @('SchannelTls', 'Privacy'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ProbeEndpoint,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$ProbeTimeoutSeconds = 10,

    [Parameter()]
    [switch]$FailOnDrift,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\windows-hardening'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'windows-hardening-verification'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

$targetScript = @{
    SchannelTls = @{
        Path = Join-Path $PSScriptRoot 'Set-WindowsSchannelTlsHardening.ps1'
        PlanPattern = 'schannel-tls-hardening-plan-*.csv'
    }
    Privacy = @{
        Path = Join-Path $PSScriptRoot 'Set-Windows11PrivacyHardening.ps1'
        PlanPattern = '*plan*.csv'
    }
}

$machines = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$complianceRecords = [System.Collections.Generic.List[object]]::new()
$handshakeRecords = [System.Collections.Generic.List[object]]::new()
$scriptResults = [System.Collections.Generic.List[object]]::new()

foreach ($name in $Target) {
    $spec = $targetScript[$name]
    if (-not (Test-Path -LiteralPath $spec.Path)) {
        Write-Warning "Hardening script not found, skipped: $($spec.Path)"
        $scriptResults.Add([pscustomobject]@{ Target = $name; ComputerName = ''; Status = 'ScriptMissing'; ItemCount = 0; CompliantCount = 0; DriftCount = 0; Note = $spec.Path })
        continue
    }

    # Each plan goes to its own scratch directory so the newest-file pick cannot
    # collide with a plan an operator generated earlier in the same report folder.
    $planDirectory = Join-Path $runDirectory "plan-$name"
    New-Item -ItemType Directory -Path $planDirectory -Force | Out-Null

    try {
        # Run in a child process. ShouldProcess writes its "What if:" lines straight
        # to the host rather than to a redirectable stream, so an in-process call
        # floods the caller's console with a hundred lines of preview noise no matter
        # what is redirected. Both hardening scripts take -ReportDirectory, not
        # -OutputDirectory, and -SkipRegistryBackup keeps a verification pass from
        # leaving .reg exports of the machine's current state behind.
        $planLog = Join-Path $planDirectory 'plan-run.log'
        $arguments = @(
            '-NoProfile', '-NonInteractive', '-File', $spec.Path
            '-WhatIf', '-ReportDirectory', $planDirectory, '-SkipRegistryBackup'
        )
        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $planLog -RedirectStandardError "$planLog.err"
        if ($process.ExitCode -ne 0) {
            throw "Plan generation exited with code $($process.ExitCode). See $planLog.err"
        }
    } catch {
        Write-Warning "Could not generate a plan for $name : $($_.Exception.Message)"
        $scriptResults.Add([pscustomobject]@{ Target = $name; ComputerName = ''; Status = 'PlanFailed'; ItemCount = 0; CompliantCount = 0; DriftCount = 0; Note = $_.Exception.Message })
        continue
    }

    $planFile = Get-ChildItem -LiteralPath $planDirectory -Filter $spec.PlanPattern -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $planFile) {
        Write-Warning "No plan file matching $($spec.PlanPattern) was produced for $name."
        $scriptResults.Add([pscustomobject]@{ Target = $name; ComputerName = ''; Status = 'NoPlanFile'; ItemCount = 0; CompliantCount = 0; DriftCount = 0; Note = $planDirectory })
        continue
    }

    $planItems = @(Import-Csv -LiteralPath $planFile.FullName)
    foreach ($machine in $machines) {
        # The plan already carries the local machine's current values, so only a
        # remote target needs its registry read. Desired state is the same either way,
        # because it comes from the scripts rather than from any machine.
        $remoteValues = @{}
        if ($machine -ne $env:COMPUTERNAME) {
            $registryTargets = @($planItems |
                    Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'RegistryPath') } |
                    ForEach-Object {
                        [pscustomobject]@{
                            Path = [string](Get-OpsPropertyValue -InputObject $_ -Name 'RegistryPath')
                            Name = [string](Get-OpsPropertyValue -InputObject $_ -Name 'ValueName')
                        }
                    })

            try {
                # $using: rather than -ArgumentList: it avoids wrapping the array to
                # stop PowerShell unrolling it into separate arguments, and it is the
                # form the analyzer can actually verify.
                $readValues = Invoke-Command -ComputerName $machine -ErrorAction Stop -ScriptBlock {
                    $result = @{}
                    foreach ($item in @($using:registryTargets)) {
                        $key = "$($item.Path)\$($item.Name)"
                        try {
                            $result[$key] = [string](Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction Stop).($item.Name)
                        } catch {
                            $result[$key] = $null
                        }
                    }
                    $result
                }

                foreach ($key in $readValues.Keys) {
                    $remoteValues[$key] = $readValues[$key]
                }
            } catch {
                Write-Warning "Could not read the registry on $machine : $($_.Exception.Message)"
                $scriptResults.Add([pscustomobject]@{
                        Target = $name; ComputerName = $machine; Status = 'Unreachable'
                        ItemCount = 0; CompliantCount = 0; DriftCount = 0; Note = $_.Exception.Message
                    })
                continue
            }
        }

        foreach ($item in $planItems) {
            $action = [string](Get-OpsPropertyValue -InputObject $item -Name 'Action')
            $registryPath = [string](Get-OpsPropertyValue -InputObject $item -Name 'RegistryPath')
            $valueName = [string](Get-OpsPropertyValue -InputObject $item -Name 'ValueName')
            $desiredValue = [string](Get-OpsPropertyValue -InputObject $item -Name 'DesiredValue')
            $currentValue = [string](Get-OpsPropertyValue -InputObject $item -Name 'CurrentValue')

            if ($machine -eq $env:COMPUTERNAME) {
                # NoChange is the plan saying the machine already holds the desired
                # value. Anything else is the hardening not being in effect right now.
                $state = switch ($action) {
                    'NoChange' { 'Compliant' }
                    'CreateValue' { 'NotConfigured' }
                    'SetValue' { 'Drifted' }
                    'DeleteValue' { 'Drifted' }
                    'Skipped' { 'Skipped' }
                    default { if ($action) { "Other:$action" } else { 'Unknown' } }
                }
            } elseif (-not $registryPath) {
                # Services and scheduled tasks are in the plan but were not read
                # remotely. Saying so beats implying they were checked.
                $state = 'NotCheckedRemotely'
                $currentValue = ''
            } else {
                $key = "$registryPath\$valueName"
                $currentValue = if ($remoteValues.ContainsKey($key)) { [string]$remoteValues[$key] } else { '' }
                $state = if (-not $remoteValues.ContainsKey($key) -or $null -eq $remoteValues[$key] -or $currentValue -eq '') {
                    'NotConfigured'
                } elseif ($currentValue -eq $desiredValue) {
                    'Compliant'
                } else {
                    'Drifted'
                }
            }

            $complianceRecords.Add([pscustomobject]@{
                    Target = $name
                    ComputerName = $machine
                    State = $state
                    Category = [string](Get-OpsPropertyValue -InputObject $item -Name 'Category')
                    ItemType = [string](Get-OpsPropertyValue -InputObject $item -Name 'ItemType')
                    # The two hardening scripts describe the same thing differently: the
                    # privacy plan carries a combined Target, the Schannel plan carries
                    # RegistryPath and ValueName separately.
                    Item = if (Get-OpsPropertyValue -InputObject $item -Name 'Target') {
                        [string](Get-OpsPropertyValue -InputObject $item -Name 'Target')
                    } else {
                        (@($registryPath, $valueName) | Where-Object { $_ }) -join '\'
                    }
                    CurrentValue = $currentValue
                    DesiredValue = $desiredValue
                    DesiredState = [string](Get-OpsPropertyValue -InputObject $item -Name 'DesiredState')
                    PlannedAction = $action
                    Reason = [string](Get-OpsPropertyValue -InputObject $item -Name 'Reason')
                })
        }

        $forTarget = @($complianceRecords | Where-Object { $_.Target -eq $name -and $_.ComputerName -eq $machine })
        $scriptResults.Add([pscustomobject]@{
                Target = $name
                ComputerName = $machine
                Status = 'Checked'
                ItemCount = $forTarget.Count
                CompliantCount = @($forTarget | Where-Object { $_.State -eq 'Compliant' }).Count
                DriftCount = @($forTarget | Where-Object { $_.State -in @('Drifted', 'NotConfigured') }).Count
                Note = $planFile.Name
            })
    }
}

if ($ProbeEndpoint) {
    $parts = $ProbeEndpoint -split ':'
    $probeHost = $parts[0]
    $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }

    # Read the client-side Schannel policy so a handshake result can be judged
    # against what the machine was told, not just reported on its own.
    $protocolMap = [ordered]@{
        'TLS 1.0' = [System.Security.Authentication.SslProtocols]::Tls
        'TLS 1.1' = [System.Security.Authentication.SslProtocols]::Tls11
        'TLS 1.2' = [System.Security.Authentication.SslProtocols]::Tls12
        'TLS 1.3' = [System.Security.Authentication.SslProtocols]::Tls13
    }

    foreach ($protocolName in $protocolMap.Keys) {
        $clientKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocolName\Client"
        $enabledValue = $null
        $disabledByDefault = $null
        try {
            $enabledValue = (Get-ItemProperty -Path $clientKey -Name 'Enabled' -ErrorAction Stop).Enabled
        } catch {
            $enabledValue = $null
        }
        try {
            $disabledByDefault = (Get-ItemProperty -Path $clientKey -Name 'DisabledByDefault' -ErrorAction Stop).DisabledByDefault
        } catch {
            $disabledByDefault = $null
        }

        $policyState = if ($null -eq $enabledValue -and $null -eq $disabledByDefault) {
            'NotConfigured'
        } elseif ($enabledValue -eq 0) {
            'Disabled'
        } elseif ($disabledByDefault -eq 1) {
            'DisabledByDefault'
        } else {
            'Enabled'
        }

        $negotiated = $false
        $detail = ''
        $client = $null
        $stream = $null
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $connect = $client.ConnectAsync($probeHost, $port)
            if (-not $connect.Wait([timespan]::FromSeconds($ProbeTimeoutSeconds))) {
                throw "Connection timed out after $ProbeTimeoutSeconds seconds."
            }

            $stream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { $true })
            $stream.AuthenticateAsClient($probeHost, $null, $protocolMap[$protocolName], $false)
            $negotiated = $true
            $detail = "Negotiated $($stream.SslProtocol), cipher $($stream.NegotiatedCipherSuite)"
        } catch {
            $detail = $_.Exception.GetBaseException().Message
        } finally {
            if ($stream) { $stream.Dispose() }
            if ($client) { $client.Dispose() }
        }

        # A handshake that succeeds on a protocol the registry says is off is the
        # whole reason this probe exists. The reverse is not a finding: the remote
        # end is entitled to refuse a protocol this machine still allows.
        $verdict = if ($negotiated -and $policyState -in @('Disabled', 'DisabledByDefault')) {
            'PolicyNotEnforced'
        } elseif ($negotiated) {
            'Negotiated'
        } elseif ($policyState -in @('Disabled', 'DisabledByDefault')) {
            'BlockedAsConfigured'
        } else {
            'NotNegotiated'
        }

        $handshakeRecords.Add([pscustomobject]@{
                Endpoint = $ProbeEndpoint
                Protocol = $protocolName
                ClientPolicyState = $policyState
                RegistryEnabled = $enabledValue
                RegistryDisabledByDefault = $disabledByDefault
                Negotiated = $negotiated
                Verdict = $verdict
                Detail = $detail
            })
    }
}

$categoryRollup = foreach ($group in (@($complianceRecords) | Group-Object -Property Target, Category)) {
    $rows = @($group.Group)
    [pscustomobject]@{
        Target = $rows[0].Target
        Category = $rows[0].Category
        ItemCount = $rows.Count
        CompliantCount = @($rows | Where-Object { $_.State -eq 'Compliant' }).Count
        DriftedCount = @($rows | Where-Object { $_.State -eq 'Drifted' }).Count
        NotConfiguredCount = @($rows | Where-Object { $_.State -eq 'NotConfigured' }).Count
    }
}

$exports = @(
    Export-OpsReport -Name 'hardening-compliance' -Record @($complianceRecords) -Directory $runDirectory
    Export-OpsReport -Name 'category-rollup' -Record @($categoryRollup) -Directory $runDirectory
    Export-OpsReport -Name 'script-results' -Record @($scriptResults) -Directory $runDirectory
    Export-OpsReport -Name 'tls-handshakes' -Record @($handshakeRecords) -Directory $runDirectory
)

$driftCount = @($complianceRecords | Where-Object { $_.State -in @('Drifted', 'NotConfigured') }).Count
$notEnforced = @($handshakeRecords | Where-Object { $_.Verdict -eq 'PolicyNotEnforced' }).Count

# A target whose plan never ran has proved nothing. Reporting Passed because zero
# drift was found in zero items is the exact failure this script exists to prevent.
$uncheckedTargets = @($scriptResults | Where-Object { $_.Status -ne 'Checked' })

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    TargetsChecked = @($Target)
    MachinesChecked = @($machines)
    ItemsChecked = $complianceRecords.Count
    CompliantCount = @($complianceRecords | Where-Object { $_.State -eq 'Compliant' }).Count
    DriftedCount = @($complianceRecords | Where-Object { $_.State -eq 'Drifted' }).Count
    NotConfiguredCount = @($complianceRecords | Where-Object { $_.State -eq 'NotConfigured' }).Count
    TotalDrift = $driftCount
    ProbeEndpoint = $ProbeEndpoint
    HandshakesAttempted = $handshakeRecords.Count
    PolicyNotEnforcedCount = $notEnforced
    UncheckedTargets = @($uncheckedTargets | ForEach-Object { "$($_.Target):$($_.Status)" })
    Passed = ($driftCount -eq 0 -and $notEnforced -eq 0 -and $uncheckedTargets.Count -eq 0)
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($FailOnDrift -and -not $summary.Passed) {
    exit 1
}
