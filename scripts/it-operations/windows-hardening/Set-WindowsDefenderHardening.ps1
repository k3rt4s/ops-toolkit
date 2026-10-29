<#
.SYNOPSIS
Plan, apply, and roll back Microsoft Defender attack surface reduction, Controlled Folder Access, network protection, PUA and cloud protection settings on a standalone Windows 11 machine.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated to apply. Every Defender change needs administrator rights; an unelevated live
  run still writes the plan and marks each change "Skipped: requires elevation".
- The default run is audit-only for the three controls that can block legitimate software:
  attack surface reduction (ASR) rules, Controlled Folder Access and network protection all go
  to Audit mode, so nothing is blocked and Defender logs what it would have blocked
  (Microsoft-Windows-Windows Defender/Operational, event IDs 1122 for ASR and 1124 for
  Controlled Folder Access audits). Review those events for about a week, then re-run with
  -AsrMode Block, -ControlledFolderAccess Enabled and -NetworkProtection Enabled.
- -AsrMode Block switches the selected ASR rules to Block mode. Rule
  D1E49AAC-8F56-4280-B9BA-993A6D77406C (PSExec and WMI process creation) can break remote
  management and deployment tools, and rule 01443614-CD74-433A-B99E-2ECDC07BFC25 (prevalence,
  age, trusted list) is the most likely to block new or freshly built executables. Keep those
  two in Audit longest by running Block mode with -AsrRuleId set to the other rule IDs.
- -AsrRuleId restricts the run to the listed rule IDs. Only IDs from this script's built-in
  list of Microsoft-documented rules are accepted. Rules outside the list are never touched,
  and an existing rule is never removed or weakened on a forward run: a rule already in
  Block mode is left alone when the run asks for Audit.
- -ControlledFolderAccess Enabled turns Controlled Folder Access to Block mode. It then blocks
  every app not on Windows' trusted list, including dev tools, compilers, Python and other
  interpreters, from writing to Documents, Desktop, Pictures, Music and Videos, which breaks
  builds and scripts that write there until each executable is allowed. Use
  -ControlledFolderAllowedApplication to allow executables by full path (for example the
  python.exe of a project's virtual environment); those paths are an allow list for the
  feature and are not Defender scan exclusions.
- -NetworkProtection Enabled blocks connections to low-reputation hosts for all apps, which can
  block tools that reach unusual hosts. Audit mode only logs.
- Use -Rollback to restore the exact values this script changed. A rule or allowed
  application the script added is removed again, and a setting is returned to its prior value.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  developer's workstation must never be applied to someone else's machine. Supply the report
  directory explicitly on every run, under a data root outside the repo.

Purpose:
Raises Defender to a hardened baseline without breaking the machine on the first run: ASR
rules in Audit mode, Controlled Folder Access and network protection in Audit mode, PUA
protection Enabled, cloud protection (MAPS) Advanced, safe samples sent automatically, cloud
block level High and the cloud extended timeout at 50 seconds. The extended timeout holds a
never-seen file for up to 50 extra seconds while Defender asks the cloud, so a first run of a
new executable can pause briefly.

Report-only items are never changed: Tamper Protection state, Smart App Control state,
real-time protection and behavior monitoring state, signature age, and whether Defender is in
passive mode because a third-party antivirus is the active provider. When a third-party
antivirus is active, no Defender setting is planned at all. Defender exclusions are never
added or removed by this script.

Windows Tamper Protection, when on, can cause Defender to ignore or reject some changes made
through Set-MpPreference. Tamper Protection can only be turned on or off in Windows Security.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir>
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir> -AsrMode Block -AsrRuleId <guid>,<guid>
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir> -ControlledFolderAccess Enabled -ControlledFolderAllowedApplication <exe path>
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir> -NetworkProtection Enabled
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsDefenderHardening.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes defender-hardening plan and state CSV/JSON under the report directory, plus a
defender-hardening-rollback JSON holding the prior value of every setting changed so a later
-Rollback can revert precisely. Emits a summary object with paths, counts and Items.

.NOTES
Status:
Active script in the ops-toolkit repo. Reboot is not required. No Defender exclusion is added
or removed.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Audit logs what a rule would block; Block enforces it.
    [Parameter()]
    [ValidateSet('Audit', 'Block')]
    [string]$AsrMode = 'Audit',

    # Restrict the run to these ASR rule IDs (GUIDs from the built-in list).
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$AsrRuleId,

    # Enabled blocks unknown apps (dev tools, Python) from writing to protected folders.
    [Parameter()]
    [ValidateSet('AuditMode', 'Enabled')]
    [string]$ControlledFolderAccess = 'AuditMode',

    # Full paths of executables to allow through Controlled Folder Access.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ControlledFolderAllowedApplication,

    [Parameter()]
    [ValidateSet('AuditMode', 'Enabled')]
    [string]$NetworkProtection = 'AuditMode',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ReportPrefix = 'defender-hardening'
$script:SmartAppControlKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

# Microsoft-documented ASR rule GUIDs (lower case). Rules outside this list are never touched.
$script:AsrRuleCatalog = [ordered]@{
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet prevalence, age, or trusted list criteria'
}

# Strength of each setting value, higher is stronger. A forward run only raises a setting;
# it never lowers one that is already stronger than the target.
$script:AsrRank = @{ 0 = 0; 2 = 1; 6 = 2; 1 = 3 }           # Disabled, Audit, Warn, Block
$script:CfaRank = @{ 0 = 0; 2 = 1; 4 = 1; 3 = 2; 1 = 3 }    # Disabled, Audit, AuditDiskOnly, BlockDiskOnly, Block
$script:AuditRank = @{ 0 = 0; 2 = 1; 1 = 3 }                # Disabled, Audit, Enabled
$script:MapsRank = @{ 0 = 0; 1 = 1; 2 = 2 }                 # Disabled, Basic, Advanced
$script:SamplesRank = @{ 0 = 0; 2 = 0; 1 = 1; 3 = 2 }      # AlwaysPrompt/NeverSend, SendSafe, SendAll
$script:CloudRank = @{ 0 = 0; 1 = 1; 2 = 2; 4 = 3; 6 = 4 } # Default, Moderate, High, HighPlus, ZeroTolerance

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Strict mode throws on a missing property, and a real Defender object omits some.
function Get-OptionalProperty {
    param($InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $prop) { $prop.Value }
}

function Get-ValueRank {
    param($RankMap, [int]$Value)
    if ($null -eq $RankMap) { return $Value }
    if ($RankMap.ContainsKey($Value)) { return [int]$RankMap[$Value] }
    -1
}

function ConvertTo-PlanItem {
    param(
        [string]$Category, [string]$Setting, [bool]$RequiresAdmin,
        $CurrentValue, $DesiredValue, [string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; RequiresAdmin = $RequiresAdmin
        RequiresReboot = $false
        CurrentValue = $CurrentValue; DesiredValue = $DesiredValue; Action = $Action
    }
}

# One plan item for a Set-MpPreference style setting with an enum or numeric value.
function ConvertTo-PreferencePlanItem {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Setting,
        $Current,
        [Parameter(Mandatory = $true)][int]$Desired,
        [Parameter(Mandatory = $true)][string]$DesiredLabel,
        $RankMap
    )
    if ($null -eq $Current -or "$Current" -eq '') {
        return ConvertTo-PlanItem -Category $Category -Setting $Setting -RequiresAdmin $true `
            -CurrentValue 'unknown' -DesiredValue $Desired `
            -Action "Cannot assess $Setting (current value unreadable); not changed"
    }
    $cur = [int]$Current
    if ((Get-ValueRank -RankMap $RankMap -Value $cur) -ge (Get-ValueRank -RankMap $RankMap -Value $Desired)) {
        return ConvertTo-PlanItem -Category $Category -Setting $Setting -RequiresAdmin $true `
            -CurrentValue $cur -DesiredValue $Desired `
            -Action "No change ($Setting is $cur, already at or above $DesiredLabel)"
    }
    ConvertTo-PlanItem -Category $Category -Setting $Setting -RequiresAdmin $true `
        -CurrentValue $cur -DesiredValue $Desired -Action "Set $Setting to $DesiredLabel ($Desired)"
}

function Get-SmartAppControlState {
    $raw = $null
    $props = Get-ItemProperty -Path $script:SmartAppControlKey -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue
    if ($null -ne $props -and $props.PSObject.Properties['VerifiedAndReputablePolicyState']) {
        $raw = $props.VerifiedAndReputablePolicyState
    }
    if ($null -eq $raw) { return [pscustomobject]@{ Value = 'absent'; Label = 'not reported by this build' } }
    $label = switch ([int]$raw) {
        0 { 'Off' }
        1 { 'On (enforcing)' }
        2 { 'Evaluation mode' }
        default { 'unrecognised value' }
    }
    [pscustomobject]@{ Value = [int]$raw; Label = $label }
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ReportOnlyItem {
    param($Status)

    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    $tamper = Get-OptionalProperty -InputObject $Status -Name 'IsTamperProtected'
    $tamperText = if ($null -eq $tamper) { 'unknown' } else { "$tamper" }
    $tamperAction = if ($null -eq $tamper) { 'Report only: Tamper Protection state could not be read; it can only be changed in Windows Security' }
    elseif ($tamper) { 'Report only: Tamper Protection is on' }
    else { 'Report only: Tamper Protection is OFF; turn it on in Windows Security (this script cannot)' }
    $items.Add((ConvertTo-PlanItem -Category 'TamperProtection' -Setting 'IsTamperProtected' -RequiresAdmin $false `
                -CurrentValue $tamperText -DesiredValue 'True' -Action $tamperAction))

    $sac = Get-SmartAppControlState
    $items.Add((ConvertTo-PlanItem -Category 'SmartAppControl' -Setting 'VerifiedAndReputablePolicyState' -RequiresAdmin $false `
                -CurrentValue $sac.Value -DesiredValue 'n/a' `
                -Action "Report only: Smart App Control is $($sac.Label); it can only be turned back on by reinstalling Windows once turned off"))

    $age = Get-OptionalProperty -InputObject $Status -Name 'AntivirusSignatureAge'
    $ageText = if ($null -eq $age) { 'unknown' } else { "$age" }
    $ageAction = if ($null -eq $age) { 'Report only: signature age could not be read' }
    elseif ([int]$age -gt 7) { "Report only: signatures are $age days old; update them with Windows Update or Update-MpSignature" }
    else { "Report only: signatures are $age days old" }
    $items.Add((ConvertTo-PlanItem -Category 'SignatureAge' -Setting 'AntivirusSignatureAge' -RequiresAdmin $false `
                -CurrentValue $ageText -DesiredValue 'n/a' -Action $ageAction))

    $rtMon = Get-OptionalProperty -InputObject $Status -Name 'RealTimeProtectionEnabled'
    $rtText = if ($null -eq $rtMon) { 'unknown' } else { "$rtMon" }
    $rtAction = if ($null -eq $rtMon) { 'Report only: real-time protection state could not be read' }
    elseif ($rtMon) { 'Report only: real-time protection is on' }
    else { 'Report only: real-time protection is OFF; turn it on in Windows Security' }
    $items.Add((ConvertTo-PlanItem -Category 'RealTimeProtection' -Setting 'RealTimeProtectionEnabled' -RequiresAdmin $false `
                -CurrentValue $rtText -DesiredValue 'True' -Action $rtAction))

    $behavior = Get-OptionalProperty -InputObject $Status -Name 'BehaviorMonitorEnabled'
    $bhText = if ($null -eq $behavior) { 'unknown' } else { "$behavior" }
    $bhAction = if ($null -eq $behavior) { 'Report only: behavior monitoring state could not be read' }
    elseif ($behavior) { 'Report only: behavior monitoring is on' }
    else { 'Report only: behavior monitoring is OFF; turn it on in Windows Security' }
    $items.Add((ConvertTo-PlanItem -Category 'BehaviorMonitoring' -Setting 'BehaviorMonitorEnabled' -RequiresAdmin $false `
                -CurrentValue $bhText -DesiredValue 'True' -Action $bhAction))

    $items
}

function Get-AvProviderItem {
    param($Status)

    $mode = Get-OptionalProperty -InputObject $Status -Name 'AMRunningMode'
    $modeText = if ($null -eq $mode -or "$mode" -eq '') { 'unknown' } else { "$mode" }

    # Windows Security Center lists every registered antivirus product. It is informational
    # only; the decision to plan nothing rests on Defender's own running mode.
    $products = @()
    try {
        $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
                ForEach-Object { "$($_.displayName)" })
    } catch {
        $products = @()
    }
    $productText = if ($products.Count) { ($products -join '; ') } else { 'none listed' }

    if ($modeText -match 'Passive') {
        return ConvertTo-PlanItem -Category 'AvProvider' -Setting 'AMRunningMode' -RequiresAdmin $false `
            -CurrentValue $modeText -DesiredValue 'n/a' `
            -Action "Report only: Defender is in passive mode, so a third-party antivirus is the active provider; no Defender settings are planned (registered products: $productText)"
    }
    ConvertTo-PlanItem -Category 'AvProvider' -Setting 'AMRunningMode' -RequiresAdmin $false `
        -CurrentValue $modeText -DesiredValue 'n/a' `
        -Action "Report only: Defender running mode is $modeText (registered products: $productText)"
}

function Get-ForwardPlan {
    param(
        $Preference,
        $Status,
        [string]$AsrMode,
        [string[]]$AsrRuleId,
        [string]$ControlledFolderAccess,
        [string[]]$ControlledFolderAllowedApplication,
        [string]$NetworkProtection
    )

    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($i in @(Get-ReportOnlyItem -Status $Status)) { $items.Add($i) }

    $providerItem = Get-AvProviderItem -Status $Status
    $items.Add($providerItem)
    if ("$($providerItem.CurrentValue)" -match 'Passive') { return $items }

    if ($null -eq $Preference) {
        $items.Add((ConvertTo-PlanItem -Category 'DefenderPreference' -Setting 'Get-MpPreference' -RequiresAdmin $false `
                    -CurrentValue 'unknown' -DesiredValue 'n/a' `
                    -Action 'Report only: Defender settings could not be read (Defender is not running or its cmdlets are unavailable); nothing is planned'))
        return $items
    }

    # --- Attack surface reduction rules ---
    $asrDesired = if ($AsrMode -eq 'Block') { 1 } else { 2 }
    $asrLabel = if ($AsrMode -eq 'Block') { 'Block' } else { 'Audit' }
    $hasAsrProps = ($null -ne $Preference.PSObject.Properties['AttackSurfaceReductionRules_Ids']) -and
    ($null -ne $Preference.PSObject.Properties['AttackSurfaceReductionRules_Actions'])
    $curIds = @(@(Get-OptionalProperty -InputObject $Preference -Name 'AttackSurfaceReductionRules_Ids') | Where-Object { $null -ne $_ -and "$_" -ne '' })
    $curActions = @(@(Get-OptionalProperty -InputObject $Preference -Name 'AttackSurfaceReductionRules_Actions') | Where-Object { $null -ne $_ -and "$_" -ne '' })
    $asrMap = @{}
    for ($n = 0; $n -lt $curIds.Count; $n++) {
        $asrMap["$($curIds[$n])".ToLowerInvariant()] = if ($n -lt $curActions.Count) { [int]$curActions[$n] } else { $null }
    }

    $selected = @($script:AsrRuleCatalog.Keys)
    if ($AsrRuleId) { $selected = @($selected | Where-Object { $_ -in @($AsrRuleId | ForEach-Object { $_.ToLowerInvariant() }) }) }
    foreach ($id in $selected) {
        $name = $script:AsrRuleCatalog[$id]
        if (-not $hasAsrProps) {
            $items.Add((ConvertTo-PlanItem -Category 'AsrRule' -Setting $id -RequiresAdmin $true -CurrentValue 'unknown' -DesiredValue $asrDesired `
                        -Action "Cannot assess ASR rule '$name' (rule list unreadable); not changed"))
        } elseif (-not $asrMap.ContainsKey($id)) {
            $items.Add((ConvertTo-PlanItem -Category 'AsrRule' -Setting $id -RequiresAdmin $true -CurrentValue 'absent' -DesiredValue $asrDesired `
                        -Action "Set ASR rule '$name' to $asrLabel ($asrDesired)"))
        } elseif ($null -eq $asrMap[$id]) {
            $items.Add((ConvertTo-PlanItem -Category 'AsrRule' -Setting $id -RequiresAdmin $true -CurrentValue 'unknown' -DesiredValue $asrDesired `
                        -Action "Cannot assess ASR rule '$name' (action unreadable); not changed"))
        } else {
            $cur = [int]$asrMap[$id]
            if ((Get-ValueRank -RankMap $script:AsrRank -Value $cur) -ge (Get-ValueRank -RankMap $script:AsrRank -Value $asrDesired)) {
                $items.Add((ConvertTo-PlanItem -Category 'AsrRule' -Setting $id -RequiresAdmin $true -CurrentValue $cur -DesiredValue $asrDesired `
                            -Action "No change (ASR rule '$name' is $cur, already at or above $asrLabel)"))
            } else {
                $items.Add((ConvertTo-PlanItem -Category 'AsrRule' -Setting $id -RequiresAdmin $true -CurrentValue $cur -DesiredValue $asrDesired `
                            -Action "Set ASR rule '$name' to $asrLabel ($asrDesired)"))
            }
        }
    }

    # --- Controlled Folder Access ---
    # Allowed applications go first: the plan applies in order, so a failed or interrupted run never leaves
    # Block mode on with the developer tools not yet allowed.
    if ($ControlledFolderAllowedApplication) {
        $hasAppProp = $null -ne $Preference.PSObject.Properties['ControlledFolderAccessAllowedApplications']
        $curApps = @(@(Get-OptionalProperty -InputObject $Preference -Name 'ControlledFolderAccessAllowedApplications') |
                Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_".ToLowerInvariant() })
        foreach ($app in @($ControlledFolderAllowedApplication | Select-Object -Unique)) {
            if (-not $hasAppProp) {
                $items.Add((ConvertTo-PlanItem -Category 'CfaAllowedApplication' -Setting $app -RequiresAdmin $true -CurrentValue 'unknown' -DesiredValue 'present' `
                            -Action "Cannot assess Controlled Folder Access allowed application '$app' (list unreadable); not changed"))
            } elseif ($curApps -contains $app.ToLowerInvariant()) {
                $items.Add((ConvertTo-PlanItem -Category 'CfaAllowedApplication' -Setting $app -RequiresAdmin $true -CurrentValue 'present' -DesiredValue 'present' `
                            -Action "No change (Controlled Folder Access already allows '$app')"))
            } else {
                $items.Add((ConvertTo-PlanItem -Category 'CfaAllowedApplication' -Setting $app -RequiresAdmin $true -CurrentValue 'absent' -DesiredValue 'present' `
                            -Action "Allow '$app' through Controlled Folder Access"))
            }
        }
    }

    $cfaDesired = if ($ControlledFolderAccess -eq 'Enabled') { 1 } else { 2 }
    $items.Add((ConvertTo-PreferencePlanItem -Category 'ControlledFolderAccess' -Setting 'EnableControlledFolderAccess' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'EnableControlledFolderAccess') `
                -Desired $cfaDesired -DesiredLabel $ControlledFolderAccess -RankMap $script:CfaRank))

    # --- Network protection ---
    $npDesired = if ($NetworkProtection -eq 'Enabled') { 1 } else { 2 }
    $items.Add((ConvertTo-PreferencePlanItem -Category 'NetworkProtection' -Setting 'EnableNetworkProtection' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'EnableNetworkProtection') `
                -Desired $npDesired -DesiredLabel $NetworkProtection -RankMap $script:AuditRank))

    # --- PUA, cloud protection ---
    $items.Add((ConvertTo-PreferencePlanItem -Category 'PuaProtection' -Setting 'PUAProtection' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'PUAProtection') `
                -Desired 1 -DesiredLabel 'Enabled' -RankMap $script:AuditRank))
    $items.Add((ConvertTo-PreferencePlanItem -Category 'CloudProtection' -Setting 'MAPSReporting' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'MAPSReporting') `
                -Desired 2 -DesiredLabel 'Advanced' -RankMap $script:MapsRank))
    $items.Add((ConvertTo-PreferencePlanItem -Category 'SampleSubmission' -Setting 'SubmitSamplesConsent' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'SubmitSamplesConsent') `
                -Desired 1 -DesiredLabel 'SendSafeSamples' -RankMap $script:SamplesRank))
    $items.Add((ConvertTo-PreferencePlanItem -Category 'CloudBlockLevel' -Setting 'CloudBlockLevel' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'CloudBlockLevel') `
                -Desired 2 -DesiredLabel 'High' -RankMap $script:CloudRank))
    $items.Add((ConvertTo-PreferencePlanItem -Category 'CloudExtendedTimeout' -Setting 'CloudExtendedTimeout' `
                -Current (Get-OptionalProperty -InputObject $Preference -Name 'CloudExtendedTimeout') `
                -Desired 50 -DesiredLabel '50 seconds' -RankMap $null))

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # A rollback run writes defender-hardening-rollback-plan-*.json and -state-*.json, which
    # a bare "rollback-*" wildcard would also match, so the timestamp shape is matched exactly.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter "$($script:ReportPrefix)-rollback-*.json" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^defender-hardening-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:ReportPrefix)-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
        $items.Add((ConvertTo-PlanItem -Category $entry.Category -Setting $entry.Setting `
                    -RequiresAdmin ([bool]$entry.RequiresAdmin) -CurrentValue $entry.AppliedValue -DesiredValue $entry.PriorValue `
                    -Action "Restore $($entry.Category) '$($entry.Setting)' to '$($entry.PriorValue)'"))
    }
    $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'Report only*') { return 'ReportOnly' }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.Action -like 'Cannot assess*') { return 'Skipped: current value unreadable' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        $absent = ("$($Item.DesiredValue)" -eq 'absent')
        switch ($Item.Category) {
            'AsrRule' {
                if ($absent) {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $Item.Setting -ErrorAction Stop
                } else {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $Item.Setting `
                        -AttackSurfaceReductionRules_Actions ([int]$Item.DesiredValue) -ErrorAction Stop
                }
            }
            'CfaAllowedApplication' {
                if ($absent) {
                    Remove-MpPreference -ControlledFolderAccessAllowedApplications $Item.Setting -ErrorAction Stop
                } else {
                    Add-MpPreference -ControlledFolderAccessAllowedApplications $Item.Setting -ErrorAction Stop
                }
            }
            'ControlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess ([int]$Item.DesiredValue) -ErrorAction Stop }
            'NetworkProtection' { Set-MpPreference -EnableNetworkProtection ([int]$Item.DesiredValue) -ErrorAction Stop }
            'PuaProtection' { Set-MpPreference -PUAProtection ([int]$Item.DesiredValue) -ErrorAction Stop }
            'CloudProtection' { Set-MpPreference -MAPSReporting ([int]$Item.DesiredValue) -ErrorAction Stop }
            'SampleSubmission' { Set-MpPreference -SubmitSamplesConsent ([int]$Item.DesiredValue) -ErrorAction Stop }
            'CloudBlockLevel' { Set-MpPreference -CloudBlockLevel ([int]$Item.DesiredValue) -ErrorAction Stop }
            'CloudExtendedTimeout' { Set-MpPreference -CloudExtendedTimeout ([int]$Item.DesiredValue) -ErrorAction Stop }
            default { return "Failed: unknown category '$($Item.Category)'" }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting
            RequiresAdmin = $Item.RequiresAdmin
            PriorValue = $Item.CurrentValue; AppliedValue = $Item.DesiredValue
        })
    if ($Rollback) { 'Reverted' } else { 'Applied' }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($AsrRuleId) {
    $unknownRules = @($AsrRuleId | Where-Object { -not $script:AsrRuleCatalog.Contains($_.ToLowerInvariant()) })
    if ($unknownRules.Count) {
        throw "AsrRuleId not in this script's list of Microsoft-documented rules, refusing to touch it: $($unknownRules -join ', ')"
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$thirdPartyAv = $false
$plan = @()
if ($Rollback) {
    $plan = @(Get-RollbackPlan)
} else {
    $preference = $null
    try { $preference = Get-MpPreference -ErrorAction Stop } catch { $preference = $null }
    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $status = $null }
    $plan = @(Get-ForwardPlan -Preference $preference -Status $status -AsrMode $AsrMode -AsrRuleId $AsrRuleId `
            -ControlledFolderAccess $ControlledFolderAccess -ControlledFolderAllowedApplication $ControlledFolderAllowedApplication `
            -NetworkProtection $NetworkProtection)
    $thirdPartyAv = [bool](@($plan | Where-Object { $_.Category -eq 'AvProvider' -and "$($_.CurrentValue)" -match 'Passive' }).Count)
}

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

# Write rollback record on a live forward run that changed at least one setting.
$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:ReportPrefix)-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        AsrMode = $AsrMode
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WindowsDefenderHardening ($mode)"
    AsrMode = $AsrMode
    IsElevated = (Test-IsAdministrator)
    ThirdPartyAvActive = $thirdPartyAv
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RebootRequired = [bool](@($state | Where-Object { $_.RequiresReboot -and $_.Result -in @('Applied', 'Reverted') }).Count)
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    ReportOnlyCount = @($state | Where-Object Result -eq 'ReportOnly').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
