<#
.SYNOPSIS
Plan, apply, and roll back legacy network protocol hardening (SMBv1, PowerShell 2.0, SMB signing, LLMNR, NetBIOS over TCP/IP, optional mDNS) on a standalone Windows 11 machine.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to apply: every control here is machine-wide and needs administrator rights.
  A non-elevated live run writes the plan and marks each item 'Skipped: requires elevation'.
- A control that cannot be read is reported as 'unknown' and is never changed or counted as
  compliant. An optional feature that does not exist on this Windows build is 'absent' and is
  a no-change, not a failure.
- Use -Rollback to restore exactly what this script changed, from the latest rollback file in
  the report directory. A feature this script did not disable is not re-enabled.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  developer's workstation must never be applied to someone else's machine. Supply a directory
  outside the repo on every run.

Purpose:
Removes the legacy and relay-prone network protocols from a workgroup (non-domain) Windows 11
machine. Default controls:
- SMBv1 server protocol off (Set-SmbServerConfiguration) and the SMB1Protocol optional feature
  and its sub-features disabled (Disable-WindowsOptionalFeature -NoRestart).
- PowerShell 2.0 optional features (MicrosoftWindowsPowerShellV2 and ...V2Root) disabled.
  On recent Windows 11 builds these features are removed from the image and are no-change.
- SMB signing required on the client (LanmanWorkstation) and the server (LanmanServer) via the
  RequireSecuritySignature registry value. Some old NAS devices and appliances do not support
  signing and will fail to connect afterwards; pass -SkipSmbSigning if you use one.
- LLMNR off (DNSClient policy EnableMulticast = 0).
- NetBIOS over TCP/IP off on every adapter interface key (NetbiosOptions = 2), each interface a
  separate plan item with its prior value recorded. This can break name resolution of old hosts
  by NetBIOS name. -NetbiosInterface limits it to chosen interfaces.
Opt-in: -DisableMulticastDns turns off the Windows mDNS responder. This breaks casting,
AirPlay, Bonjour printer discovery and other .local discovery.

Not covered, on purpose: NTLM / LmCompatibilityLevel belongs to another script. WPAD is left
out because no supported local setting for a standalone machine could be verified; the
WinHttpAutoProxySvc service is never disabled by this script. SMB1 on the client side is
removed by the SMB1Protocol-Client optional feature; there is no client cmdlet switch for it.

SMB signing, LLMNR, NetBIOS and mDNS registry values apply when the related service or adapter
restarts, normally at the next reboot. RebootRequired in the summary is true only when an
optional feature was changed.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1 -ReportDirectory <dir>
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1 -ReportDirectory <dir> -SkipSmbSigning -DisableMulticastDns
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1 -ReportDirectory <dir> -NetbiosInterface 'Tcpip_{guid}'
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsNetworkProtocolHardening.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes network-protocol-hardening plan and state CSV/JSON under the report directory, plus a
network-protocol-hardening-rollback JSON holding the prior value of every control changed.
Returns a summary object with report paths, counts, RebootRequired and the Items.

.NOTES
Status:
Active script in the ops-toolkit repo. Part of the Windows 11 standalone hardening baseline.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    # Leave the client and server RequireSecuritySignature values alone. Use this when a
    # legacy NAS or appliance that cannot sign must stay reachable.
    [Parameter()]
    [switch]$SkipSmbSigning,

    # Only these NetBIOS interfaces, by registry key name (Tcpip_{GUID}) or bare GUID.
    # Wildcards are allowed. Default: every interface found.
    [Parameter()]
    [string[]]$NetbiosInterface,

    # Opt-in. Turns off the Windows mDNS responder; breaks casting, AirPlay and Bonjour printers.
    [Parameter()]
    [switch]$DisableMulticastDns,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ReportPrefix = 'network-protocol-hardening'
$script:NetbtRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Strict mode throws on a missing property; JSON entries and CIM-style objects both go through here.
function Get-OptionalProperty {
    param($InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

# Returns the value, 'absent' (key or value missing), or 'unknown' (could not be read).
function Get-RegistryState {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    try {
        $key = Get-Item -Path $Path -ErrorAction Stop
    } catch {
        if (-not (Test-Path -Path $Path)) { return 'absent' }
        return 'unknown'
    }
    try {
        $value = $key.GetValue($Name, $null)
    } catch {
        return 'unknown'
    }
    if ($null -eq $value) { 'absent' } else { $value }
}

# Returns Enabled, Disabled, ..., 'absent' (feature not on this build) or 'unknown'.
function Get-OptionalFeatureState {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
    } catch {
        $message = "$($_.Exception.Message)"
        if ($message -match 'is unknown|0x800f080c') { return 'absent' }
        return 'unknown'
    }
    $state = Get-OptionalProperty -InputObject $feature -Name 'State'
    if ($null -eq $state -or "$state" -eq '') { 'unknown' } else { "$state" }
}

function Get-PlanRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)][ValidateSet('Registry', 'SmbServerSmb1', 'OptionalFeature')][string]$Kind,
        [string]$RegistryPath = '',
        [string]$ValueName = '',
        [bool]$RequiresReboot = $false,
        [Parameter(Mandatory = $true)]$CurrentValue,
        [Parameter(Mandatory = $true)]$DesiredValue,
        [Parameter(Mandatory = $true)][string]$Describe
    )

    $current = "$CurrentValue"
    $desired = "$DesiredValue"
    $action = if ($current -eq 'unknown') {
        "Unreadable: $Describe (current state could not be read, left unchanged)"
    } elseif ($Kind -eq 'OptionalFeature' -and $current -eq 'absent') {
        "No change ($Setting is not present on this Windows build)"
    } elseif ($Kind -eq 'OptionalFeature' -and $current -in @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')) {
        "No change ($Setting already disabled)"
    } elseif ($current -eq $desired) {
        "No change ($Setting already $desired)"
    } else {
        $Describe
    }

    [pscustomobject]@{
        Category = $Category; Setting = $Setting; Kind = $Kind
        RegistryPath = $RegistryPath; ValueName = $ValueName; PropertyType = 'DWord'
        RequiresAdmin = $true; RequiresReboot = $RequiresReboot
        CurrentValue = $CurrentValue; DesiredValue = $DesiredValue
        Action = $action
    }
}

function Add-RegistryDwordItem {
    param(
        [Parameter(Mandatory = $true)]$Items,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value,
        [Parameter(Mandatory = $true)][string]$Describe
    )
    $state = Get-RegistryState -Path $Path -Name $Name
    $Items.Add((Get-PlanRecord -Category $Category -Setting $Setting -Kind Registry -RegistryPath $Path -ValueName $Name `
                -CurrentValue $state -DesiredValue $Value -Describe $Describe))
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    param(
        [switch]$SkipSmbSigning,
        [string[]]$NetbiosInterface,
        [switch]$DisableMulticastDns
    )

    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    # SMBv1 server protocol.
    $smb1 = 'unknown'
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        $v = Get-OptionalProperty -InputObject $cfg -Name 'EnableSMB1Protocol'
        if ($null -ne $v) { $smb1 = "$v" }
    } catch {
        $smb1 = 'unknown'
    }
    $items.Add((Get-PlanRecord -Category 'Smb1Server' -Setting 'EnableSMB1Protocol' -Kind SmbServerSmb1 `
                -CurrentValue $smb1 -DesiredValue 'False' -Describe 'Disable the SMBv1 server protocol (Set-SmbServerConfiguration -EnableSMB1Protocol $false)'))

    # Optional features: sub-features first so a rollback (reverse order) re-enables the parent first.
    foreach ($name in @('SMB1Protocol-Client', 'SMB1Protocol-Server', 'SMB1Protocol-Deprecation', 'SMB1Protocol')) {
        $items.Add((Get-PlanRecord -Category 'Smb1Feature' -Setting $name -Kind OptionalFeature -RequiresReboot $true `
                    -CurrentValue (Get-OptionalFeatureState -Name $name) -DesiredValue 'Disabled' `
                    -Describe "Disable optional feature $name (no restart)"))
    }
    foreach ($name in @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root')) {
        $items.Add((Get-PlanRecord -Category 'PowerShellV2Feature' -Setting $name -Kind OptionalFeature -RequiresReboot $true `
                    -CurrentValue (Get-OptionalFeatureState -Name $name) -DesiredValue 'Disabled' `
                    -Describe "Disable optional feature $name (no restart)"))
    }

    if (-not $SkipSmbSigning) {
        Add-RegistryDwordItem -Items $items -Category 'SmbSigningClient' -Setting 'LanmanWorkstation RequireSecuritySignature' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 `
            -Describe 'Require SMB signing on the client (some old NAS devices fail)'
        Add-RegistryDwordItem -Items $items -Category 'SmbSigningServer' -Setting 'LanmanServer RequireSecuritySignature' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 `
            -Describe 'Require SMB signing on the server'
    }

    Add-RegistryDwordItem -Items $items -Category 'Llmnr' -Setting 'DNSClient EnableMulticast' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 `
        -Describe 'Turn off LLMNR (multicast name resolution)'

    # NetBIOS over TCP/IP, one item per adapter interface key.
    $interfaceKeys = @()
    try {
        $interfaceKeys = @(Get-ChildItem -Path $script:NetbtRoot -ErrorAction Stop | Where-Object { $_.PSChildName -like 'Tcpip_*' })
    } catch {
        $interfaceKeys = @()
    }
    foreach ($key in $interfaceKeys) {
        $keyName = $key.PSChildName
        if ($NetbiosInterface -and $NetbiosInterface.Count -gt 0) {
            $guid = $keyName -replace '^Tcpip_', ''
            $hit = $false
            foreach ($pattern in $NetbiosInterface) {
                if ($keyName -like $pattern -or $guid -like $pattern) { $hit = $true }
            }
            if (-not $hit) { continue }
        }
        Add-RegistryDwordItem -Items $items -Category 'NetBIOS' -Setting $keyName `
            -Path (Join-Path $script:NetbtRoot $keyName) -Name 'NetbiosOptions' -Value 2 `
            -Describe "Disable NetBIOS over TCP/IP on interface $keyName (NetbiosOptions = 2)"
    }

    if ($DisableMulticastDns) {
        Add-RegistryDwordItem -Items $items -Category 'Mdns' -Setting 'Dnscache EnableMDNS' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0 `
            -Describe 'Turn off the mDNS responder (breaks casting, AirPlay, Bonjour printers)'
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # A rollback run writes '<prefix>-rollback-plan-*' and '<prefix>-rollback-state-*' files, so
    # a bare 'rollback-*' pattern would match those; the real record is followed by a digit.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter "$($script:ReportPrefix)-rollback-*.json" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '-rollback-\d' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:ReportPrefix)-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $entries = @(@(Get-OptionalProperty -InputObject $data -Name 'ChangedSettings') | Where-Object { $_ })
    [array]::Reverse($entries)

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $entries) {
        $prior = Get-OptionalProperty -InputObject $entry -Name 'PriorValue'
        $items.Add([pscustomobject]@{
                Category = Get-OptionalProperty -InputObject $entry -Name 'Category'
                Setting = Get-OptionalProperty -InputObject $entry -Name 'Setting'
                Kind = Get-OptionalProperty -InputObject $entry -Name 'Kind'
                RegistryPath = Get-OptionalProperty -InputObject $entry -Name 'RegistryPath'
                ValueName = Get-OptionalProperty -InputObject $entry -Name 'ValueName'
                PropertyType = 'DWord'
                RequiresAdmin = $true
                RequiresReboot = [bool](Get-OptionalProperty -InputObject $entry -Name 'RequiresReboot')
                CurrentValue = Get-OptionalProperty -InputObject $entry -Name 'AppliedValue'
                DesiredValue = $prior
                Action = "Restore $(Get-OptionalProperty -InputObject $entry -Name 'Category') '$(Get-OptionalProperty -InputObject $entry -Name 'Setting')' to '$prior'"
            })
    }
    $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($Item.Action -like 'Unreadable*') { return 'Skipped: current state unreadable' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    $desired = "$($Item.DesiredValue)"
    try {
        switch ($Item.Kind) {
            'SmbServerSmb1' {
                $enable = ($desired -eq 'True')
                Set-SmbServerConfiguration -EnableSMB1Protocol $enable -Force -Confirm:$false -ErrorAction Stop
            }
            'OptionalFeature' {
                if ($desired -in @('Enabled', 'EnablePending')) {
                    Enable-WindowsOptionalFeature -Online -FeatureName $Item.Setting -NoRestart -ErrorAction Stop | Out-Null
                } else {
                    Disable-WindowsOptionalFeature -Online -FeatureName $Item.Setting -NoRestart -ErrorAction Stop | Out-Null
                }
            }
            'Registry' {
                if ($desired -eq 'absent') {
                    Remove-ItemProperty -Path $Item.RegistryPath -Name $Item.ValueName -ErrorAction SilentlyContinue
                } else {
                    if (-not (Test-Path -Path $Item.RegistryPath)) {
                        New-Item -Path $Item.RegistryPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $Item.RegistryPath -Name $Item.ValueName -Value ([int]$Item.DesiredValue) -Type DWord -Force
                }
            }
            default { return "Failed: unknown item kind '$($Item.Kind)'" }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; Kind = $Item.Kind
            RegistryPath = $Item.RegistryPath; ValueName = $Item.ValueName; PropertyType = 'DWord'
            RequiresAdmin = $Item.RequiresAdmin; RequiresReboot = $Item.RequiresReboot
            PriorValue = $Item.CurrentValue; AppliedValue = $Item.DesiredValue
        })
    if ($Rollback) { 'Reverted' } else { 'Applied' }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$plan = @(if ($Rollback) {
        Get-RollbackPlan
    } else {
        Get-ForwardPlan -SkipSmbSigning:$SkipSmbSigning -NetbiosInterface $NetbiosInterface -DisableMulticastDns:$DisableMulticastDns
    })

$planPath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-$mode-state-$timestamp.json"

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

# Rollback record on a live forward run that changed at least one setting.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "NetworkProtocolHardening ($mode)"
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RebootRequired = [bool]@($script:ChangedSettings | Where-Object { $_.RequiresReboot }).Count
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
