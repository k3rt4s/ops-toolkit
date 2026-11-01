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
- Use -Rollback to restore exactly what this script changed, from the latest unconsumed rollback
  file in the report directory. A feature this script did not disable is not re-enabled. Each
  executing -Rollback that reverts everything marks its file consumed (see Rollback below), so
  running -Rollback again undoes the run before it, newest first.
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

Rollback: -Rollback reads the newest network-protocol-hardening-rollback-<timestamp>.json in the
report directory. Before any plan is written or any change made, it checks every recorded entry
against the controls this script's own forward plan can change (the same table the forward plan
reads, whatever switches the original run used): category, kind, setting, registry path, value name
and the types and direction of the prior and applied values (a prior value must be one the forward
plan would have changed, for example a feature state other than absent, unknown or disabled). A file
that does not parse, lacks a ChangedSettings array, or holds any entry outside that set is refused
whole with an error naming the file and the first bad entry, also under -WhatIf; move that file
aside to roll back an older run. NetBIOS interfaces are bounded by key name (Tcpip_ followed by a
GUID-like name) and the NetBT interfaces path, because the interfaces are found at run time. After
an executing -Rollback in which every item was reverted or needed no change, the file is renamed
network-protocol-hardening-rollback-<timestamp>.consumed-<timestamp>.json and is no longer picked.
Under -WhatIf, or when any item failed or was skipped (for example not elevated), the file is left in
place and the summary says so in RollbackNote.

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
$script:RollbackSourceFile = $null

# Every control the forward plan can change. Get-ForwardPlan reads its categories, names, paths and
# desired values from here, and the rollback validator accepts exactly these rows, so the two cannot
# drift. Kind is SmbServerSmb1, OptionalFeature or Registry. Settings lists the fixed setting names
# (null for NetBIOS, whose setting is an interface key name matched by Pattern under PathRoot).
$script:RollbackControls = @(
    [pscustomobject]@{ Category = 'Smb1Server'; Kind = 'SmbServerSmb1'; Settings = @('EnableSMB1Protocol'); Path = ''; Name = ''; PathRoot = $null; Pattern = $null; Desired = 'False'; RequiresReboot = $false }
    [pscustomobject]@{ Category = 'Smb1Feature'; Kind = 'OptionalFeature'; Settings = @('SMB1Protocol-Client', 'SMB1Protocol-Server', 'SMB1Protocol-Deprecation', 'SMB1Protocol'); Path = ''; Name = ''; PathRoot = $null; Pattern = $null; Desired = 'Disabled'; RequiresReboot = $true }
    [pscustomobject]@{ Category = 'PowerShellV2Feature'; Kind = 'OptionalFeature'; Settings = @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root'); Path = ''; Name = ''; PathRoot = $null; Pattern = $null; Desired = 'Disabled'; RequiresReboot = $true }
    [pscustomobject]@{ Category = 'SmbSigningClient'; Kind = 'Registry'; Settings = @('LanmanWorkstation RequireSecuritySignature'); Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; PathRoot = $null; Pattern = $null; Desired = 1; RequiresReboot = $false }
    [pscustomobject]@{ Category = 'SmbSigningServer'; Kind = 'Registry'; Settings = @('LanmanServer RequireSecuritySignature'); Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RequireSecuritySignature'; PathRoot = $null; Pattern = $null; Desired = 1; RequiresReboot = $false }
    [pscustomobject]@{ Category = 'Llmnr'; Kind = 'Registry'; Settings = @('DNSClient EnableMulticast'); Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; PathRoot = $null; Pattern = $null; Desired = 0; RequiresReboot = $false }
    [pscustomobject]@{ Category = 'NetBIOS'; Kind = 'Registry'; Settings = $null; Path = $null; Name = 'NetbiosOptions'; PathRoot = $script:NetbtRoot; Pattern = '^Tcpip_[0-9A-Za-z{}-]+$'; Desired = 2; RequiresReboot = $false }
    [pscustomobject]@{ Category = 'Mdns'; Kind = 'Registry'; Settings = @('Dnscache EnableMDNS'); Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'; Name = 'EnableMDNS'; PathRoot = $null; Pattern = $null; Desired = 0; RequiresReboot = $false }
)

function Get-NetworkControl {
    param([Parameter(Mandatory = $true)][string]$Category)
    $hit = @($script:RollbackControls | Where-Object { $_.Category -eq $Category })
    if ($hit.Count -ne 1) { throw "No network protocol control '$Category' is defined." }
    $hit[0]
}

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
        [Parameter(Mandatory = $true)]$Control,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)][string]$Describe,
        [string]$Path = $Control.Path
    )
    $Category = $Control.Category
    $Name = $Control.Name
    $Value = [int]$Control.Desired
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
    $smbControl = Get-NetworkControl 'Smb1Server'
    $items.Add((Get-PlanRecord -Category $smbControl.Category -Setting $smbControl.Settings[0] -Kind SmbServerSmb1 `
                -CurrentValue $smb1 -DesiredValue $smbControl.Desired -Describe 'Disable the SMBv1 server protocol (Set-SmbServerConfiguration -EnableSMB1Protocol $false)'))

    # Optional features: sub-features first so a rollback (reverse order) re-enables the parent first.
    $smbFeatures = Get-NetworkControl 'Smb1Feature'
    foreach ($name in $smbFeatures.Settings) {
        $items.Add((Get-PlanRecord -Category $smbFeatures.Category -Setting $name -Kind OptionalFeature -RequiresReboot $smbFeatures.RequiresReboot `
                    -CurrentValue (Get-OptionalFeatureState -Name $name) -DesiredValue $smbFeatures.Desired `
                    -Describe "Disable optional feature $name (no restart)"))
    }
    $psFeatures = Get-NetworkControl 'PowerShellV2Feature'
    foreach ($name in $psFeatures.Settings) {
        $items.Add((Get-PlanRecord -Category $psFeatures.Category -Setting $name -Kind OptionalFeature -RequiresReboot $psFeatures.RequiresReboot `
                    -CurrentValue (Get-OptionalFeatureState -Name $name) -DesiredValue $psFeatures.Desired `
                    -Describe "Disable optional feature $name (no restart)"))
    }

    if (-not $SkipSmbSigning) {
        $client = Get-NetworkControl 'SmbSigningClient'
        Add-RegistryDwordItem -Items $items -Control $client -Setting $client.Settings[0] `
            -Describe 'Require SMB signing on the client (some old NAS devices fail)'
        $server = Get-NetworkControl 'SmbSigningServer'
        Add-RegistryDwordItem -Items $items -Control $server -Setting $server.Settings[0] `
            -Describe 'Require SMB signing on the server'
    }

    $llmnr = Get-NetworkControl 'Llmnr'
    Add-RegistryDwordItem -Items $items -Control $llmnr -Setting $llmnr.Settings[0] `
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
        Add-RegistryDwordItem -Items $items -Control (Get-NetworkControl 'NetBIOS') -Setting $keyName `
            -Path (Join-Path $script:NetbtRoot $keyName) `
            -Describe "Disable NetBIOS over TCP/IP on interface $keyName (NetbiosOptions = 2)"
    }

    if ($DisableMulticastDns) {
        $mdns = Get-NetworkControl 'Mdns'
        Add-RegistryDwordItem -Items $items -Control $mdns -Setting $mdns.Settings[0] `
            -Describe 'Turn off the mDNS responder (breaks casting, AirPlay, Bonjour printers)'
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # A rollback run writes '<prefix>-rollback-plan-*' and '<prefix>-rollback-state-*' files, so
    # a bare 'rollback-*' pattern would match those; the real record is followed by a timestamp and
    # nothing else. A consumed file (...rollback-<ts>.consumed-<ts>.json) fails the exact pattern on
    # purpose, so repeated rollbacks walk back one run at a time. The name orders them.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter "$($script:ReportPrefix)-rollback-*.json" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^network-protocol-hardening-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# True for a whole number that fits a registry DWord read back as a signed 32-bit value.
function Test-RollbackDword {
    param($Value)
    ($Value -is [int] -or $Value -is [long]) -and $Value -ge [int]::MinValue -and $Value -le [int]::MaxValue
}

# Returns $null when the entry is acceptable, otherwise a short text saying what is wrong with it.
# An entry is acceptable only when its category, kind, setting, registry path, value name and values
# are ones the forward plan can produce for a row of $Controls. Pure: it reads nothing but its
# arguments.
function Get-RollbackEntryProblem {
    param($Entry, [Parameter(Mandatory = $true)]$Controls)
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($field in 'Category', 'Setting', 'Kind', 'RegistryPath', 'ValueName', 'RequiresAdmin', 'RequiresReboot', 'PriorValue', 'AppliedValue') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
    }
    foreach ($field in 'Category', 'Setting', 'Kind') {
        $text = $Entry.PSObject.Properties[$field].Value
        if ($text -isnot [string] -or [string]::IsNullOrWhiteSpace($text)) { return "$field is not a non-empty string" }
    }
    foreach ($field in 'RegistryPath', 'ValueName') {
        if ($Entry.PSObject.Properties[$field].Value -isnot [string]) { return "$field is not a string" }
    }
    $category = $Entry.Category
    $control = @($Controls | Where-Object { $_.Category -ceq $category })
    if ($control.Count -ne 1) { return "Category '$category' is not one this script records" }
    $control = $control[0]
    if ($Entry.Kind -cne $control.Kind) { return "Kind '$($Entry.Kind)' is not the kind $category uses" }
    if ($Entry.RequiresAdmin -isnot [bool] -or -not $Entry.RequiresAdmin) { return 'RequiresAdmin is not true' }
    if ($Entry.RequiresReboot -isnot [bool] -or $Entry.RequiresReboot -ne $control.RequiresReboot) {
        return "RequiresReboot is not $($control.RequiresReboot)"
    }
    if ($null -ne $control.Settings) {
        if ($Entry.Setting -cnotin @($control.Settings)) { return "Setting '$($Entry.Setting)' is not a $category control this script sets" }
    } elseif ($Entry.Setting -cnotmatch $control.Pattern) {
        return "Setting '$($Entry.Setting)' is not a $category interface key name"
    }
    $expectedPath = if ($null -ne $control.PathRoot) { "$($control.PathRoot)\$($Entry.Setting)" } else { $control.Path }
    if ($Entry.RegistryPath -cne $expectedPath) { return "RegistryPath '$($Entry.RegistryPath)' is not '$expectedPath'" }
    if ($Entry.ValueName -cne $control.Name) { return "ValueName '$($Entry.ValueName)' is not '$($control.Name)'" }

    $prior = $Entry.PriorValue
    $applied = $Entry.AppliedValue
    if ($control.Kind -eq 'Registry') {
        if (-not (Test-RollbackDword $applied) -or $applied -ne $control.Desired) { return "AppliedValue '$applied' is not $($control.Desired)" }
        if ($prior -is [string]) {
            if ($prior -cne 'absent') { return "PriorValue '$prior' is not 'absent' or a whole number" }
        } elseif (-not (Test-RollbackDword $prior)) {
            return "PriorValue '$prior' is not 'absent' or a whole number"
        } elseif ($prior -eq $applied) {
            return "PriorValue $prior equals the applied value, so the forward plan would not have changed it"
        }
    } elseif ($control.Kind -eq 'SmbServerSmb1') {
        if ($applied -isnot [string] -or $applied -cne $control.Desired) { return "AppliedValue '$applied' is not '$($control.Desired)'" }
        if ($prior -isnot [string] -or $prior -cne 'True') { return "PriorValue '$prior' is not 'True'" }
    } else {
        # OptionalFeature: the forward plan only disables a feature that is neither absent, unreadable
        # nor already disabled, so those states can never be a recorded prior.
        if ($applied -isnot [string] -or $applied -cne $control.Desired) { return "AppliedValue '$applied' is not '$($control.Desired)'" }
        if ($prior -isnot [string] -or $prior -cnotmatch '^[A-Za-z]{3,40}$') { return "PriorValue '$prior' is not a feature state" }
        if ($prior -cin @('absent', 'unknown', 'Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')) {
            return "PriorValue '$prior' is a state the forward plan leaves unchanged"
        }
    }
    $null
}

# True only for an executing rollback in which nothing failed, was skipped or was merely previewed.
# Only then is the rollback file spent; anything less leaves it for a retry.
function Test-RollbackFileConsumable {
    param($State, [bool]$Preview)
    if ($Preview) { return $false }
    if ($null -eq $State) { return $true }
    foreach ($item in @($State)) {
        if ($null -eq $item) { return $false }
        if ("$($item.Result)" -notin @('Reverted', 'NoChange')) { return $false }
    }
    $true
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:ReportPrefix)-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $advice = 'Nothing was changed. Move this file aside (out of the report directory) to roll back an older run.'
    try {
        $data = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Rollback file '$($file.FullName)' refused: the file could not be read as JSON ($($_.Exception.Message)). $advice"
    }
    if ($null -eq $data -or $data -isnot [pscustomobject] -or -not $data.PSObject.Properties['ChangedSettings']) {
        throw "Rollback file '$($file.FullName)' refused: the file has no ChangedSettings array. $advice"
    }
    $changed = $data.ChangedSettings
    if ($changed -isnot [array]) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is not an array. $advice"
    }
    $entries = @($changed)
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $problem = Get-RollbackEntryProblem -Entry $entries[$i] -Controls $script:RollbackControls
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    $script:RollbackSourceFile = $file
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

$rollbackSourcePath = $null
$rollbackConsumedPath = $null
$rollbackNote = $null
if ($Rollback -and $script:RollbackSourceFile) {
    $rollbackSourcePath = $script:RollbackSourceFile.FullName
    if (Test-RollbackFileConsumable -State $state -Preview ([bool]$WhatIfPreference)) {
        # Bookkeeping after a real change, not a previewed one: -WhatIf:$false on purpose.
        $consumedName = $script:RollbackSourceFile.Name -replace '\.json$', ".consumed-$timestamp.json"
        try {
            Rename-Item -LiteralPath $rollbackSourcePath -NewName $consumedName -WhatIf:$false -ErrorAction Stop
            $rollbackConsumedPath = Join-Path (Split-Path -Parent $rollbackSourcePath) $consumedName
            $rollbackNote = 'Rollback file consumed; the next -Rollback undoes the previous run.'
        } catch {
            $rollbackNote = "Rollback file could not be marked consumed ($($_.Exception.Message)); move it aside before the next -Rollback or it is replayed."
            Write-Warning $rollbackNote
        }
    } elseif ($WhatIfPreference) {
        $rollbackNote = 'Rollback file left unconsumed: -WhatIf changes nothing.'
    } else {
        $rollbackNote = 'Rollback file left unconsumed: at least one item failed or was skipped, so -Rollback can be run again.'
    }
}

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
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    RebootRequired = [bool]@($script:ChangedSettings | Where-Object { $_.RequiresReboot }).Count
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
