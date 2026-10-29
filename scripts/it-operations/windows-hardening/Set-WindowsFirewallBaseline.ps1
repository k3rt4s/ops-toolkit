<#
.SYNOPSIS
Plan, apply, and roll back a Windows Firewall baseline: pinned profile defaults, dropped-packet logging, and opt-in cleanup of risky inbound allow rules.

.DESCRIPTION
Instructions:
- Run elevated. Every control needs administrator rights, and so does the firewall backup this
  script takes first.
- Run with -WhatIf first and review the generated plan CSV/JSON. A -WhatIf run still writes the
  firewall backup (it is a plan artifact) and changes nothing else.
- Run without switches to pin the three profiles (Domain, Private, Public): firewall on, inbound
  blocked by default, outbound allowed by default, listener prompts off, dropped packets logged.
  What breaks with prompts off: a newly installed program that listens for inbound connections is
  blocked silently instead of asking; add an allow rule for it yourself (a prompt that is clicked
  through by habit is how unwanted listeners get allowed).
- Add the opt-in switches one at a time, smoke-testing connectivity after each:
  -BlockAllInboundOnPublic, -DisableStaleProgramRules, -DisablePublicFeatureGroup,
  -ScopeRuleDisplayName.
- Use -Rollback to reverse the individual changes the last forward run recorded.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  workstation must never be applied to someone else's machine. Supply the report directory
  explicitly on every run. Generated reports belong under a data root outside the repo.

Purpose:
Makes the implicit Windows Firewall defaults explicit so a later policy change cannot silently
weaken them, turns on dropped-packet logging for a forensic trail, and reduces the inbound
listening surface that installers accumulate. Targets a standalone (workgroup) machine and
changes the local persistent store only, never Group Policy.

Backup: before any change is made, on every run including -WhatIf and -Rollback, the script runs
`netsh advfirewall export` into <ReportDirectory>\firewall-backup-<timestamp>.wfw. If the export
fails on an elevated executing run the script stops before any change. On a -WhatIf or
non-elevated run, where nothing can change, a failed export is a warning and BackupPath is empty
(netsh needs elevation to export). The file is a full copy of every rule and profile setting.

Controls:
- Profile defaults (always): Enabled True, DefaultInboundAction Block, DefaultOutboundAction
  Allow, NotifyOnListen False, LogBlocked True, LogMaxSizeKilobytes (default 16384), applied to
  Domain, Private and Public. Each profile/property is its own plan item with its prior value
  recorded. A property already at the target is reported as NoChange. Note that Block inbound by
  default only denies traffic no allow rule matches; existing allow rules keep working.
- -BlockAllInboundOnPublic: sets AllowInboundRules False on the Public profile. This drops EVERY
  inbound allow rule on public networks, including ones you want (a game host, a file share, a
  dev server, remote tooling). Nothing warns you when a listener stops answering on a public
  network. Pilot it on a Public adapter and keep -Rollback ready.
- -DisableStaleProgramRules: disables enabled inbound Allow rules whose application filter Program
  is a concrete path (not Any or System; environment variables are expanded) that does not exist
  on disk. The rules are disabled, never deleted, and each rule is its own plan item. A program on
  a drive that is not mounted right now looks missing, so review the plan first.
- -DisablePublicFeatureGroup <group[],...>: disables enabled inbound rules that belong to the
  named rule groups and whose Profile includes Public (or Any, which covers Public). The whole
  rule is disabled, including its Private and Domain coverage. A group is matched exactly (case
  insensitive) against either the rule's Group property or its DisplayGroup. DisplayGroup is
  localized, and Group is often a resource string such as '@FirewallAPI.dll,-NNNNN', so pass the
  value shown on your own machine. To list them:
  Get-NetFirewallRule -Direction Inbound | Group-Object DisplayGroup | Sort-Object Name
  Groups commonly worth reviewing on a workstation that does not use the feature (English
  display names): 'Network Discovery', 'Cast to Device functionality', 'Wireless Display', and
  the Wi-Fi Direct groups (the Wi-Fi Direct spooler, scan and discovery rules, which expose the
  print spooler). An unmatched group name is reported in the plan rather than ignored.
- -ScopeRuleDisplayName <name[],...>: for each inbound Allow rule with exactly that DisplayName
  (case insensitive, no wildcards), sets Profile to Private and RemoteAddress to LocalSubnet.
  Profile is replaced, not merged, so a rule on Public and Private ends Private only. Prior
  Profile and RemoteAddress are recorded. A DisplayName that matches nothing is reported in the
  plan; it is never a silent no-op.

Rollback: -Rollback reads the newest firewall-baseline-rollback-<timestamp>.json in the report
directory and reverses each recorded change in reverse order: Enable-NetFirewallRule for disabled
rules, Set-NetFirewallProfile with the prior values, Set-NetFirewallRule with the prior Profile
and RemoteAddress. Last resort, never run by this script: the full restore from the backup file
replaces ALL rules and profile settings with the backup, discarding anything changed since.
Run it yourself from an elevated prompt:
  netsh advfirewall import "<ReportDirectory>\firewall-backup-<timestamp>.wfw"

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir>                                  # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -DisableStaleProgramRules       # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -DisablePublicFeatureGroup 'Network Discovery','Wireless Display'
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -ScopeRuleDisplayName '<rule display name>'
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -BlockAllInboundOnPublic
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsFirewallBaseline.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.PARAMETER ReportDirectory
Plan, state, rollback and firewall backup output directory. Required, no default.
The firewall backup is a full export of the rule set; keep this directory off shared storage.

.PARAMETER LogMaxSizeKilobytes
Maximum size of each profile's dropped-packet log in kilobytes. Default 16384.

.PARAMETER BlockAllInboundOnPublic
Sets AllowInboundRules False on the Public profile, which drops every inbound allow rule on public networks, including ones you want.

.PARAMETER DisableStaleProgramRules
Disables enabled inbound Allow rules whose program path does not exist on disk.

.PARAMETER DisablePublicFeatureGroup
Rule Group or DisplayGroup values whose enabled inbound rules that include the Public profile are disabled.

.PARAMETER ScopeRuleDisplayName
DisplayNames of inbound Allow rules to restrict to the Private profile and the LocalSubnet remote address.

.PARAMETER Rollback
Reverse the changes the newest forward run recorded.

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, the firewall backup, and a rollback JSON
capturing the prior value of every setting changed so a later -Rollback can revert precisely.
Emits a summary object (Operation, paths, counts, RebootRequired, Items).

.NOTES
Status:
Active script in the ops-toolkit repo. No reboot is needed. Unverified on real hardware by the test
suite: the suite fakes the NetSecurity module, so the real cmdlets' acceptance of AllowInboundRules
on the local persistent store has not been exercised.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [ValidateRange(1, 32767)]
    [int]$LogMaxSizeKilobytes = 16384,

    [Parameter()]
    [switch]$BlockAllInboundOnPublic,

    [Parameter()]
    [switch]$DisableStaleProgramRules,

    [Parameter()]
    [string[]]$DisablePublicFeatureGroup = @(),

    [Parameter()]
    [string[]]$ScopeRuleDisplayName = @(),

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:RuleCache = @{}
$script:RuleCacheFull = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-OptionalProperty {
    param($Object, [Parameter(Mandatory = $true)][string]$Name)
    # Strict mode throws on a missing property; a missing one reads as $null here.
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { $Object.PSObject.Properties[$Name].Value }
}

function Get-PlanItemObject {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Setting,
        [string]$Target = '',
        [string]$Property = '',
        [object]$CurrentValue = '',
        [object]$DesiredValue = '',
        [string]$CurrentProfile = '',
        [string]$CurrentRemoteAddress = '',
        [string]$DesiredProfile = '',
        [string]$DesiredRemoteAddress = '',
        [string]$DisplayName = '',
        [string]$Program = '',
        [Parameter(Mandatory = $true)][string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; Target = $Target; Property = $Property
        RequiresAdmin = $true
        CurrentValue = $CurrentValue; DesiredValue = $DesiredValue
        CurrentProfile = $CurrentProfile; CurrentRemoteAddress = $CurrentRemoteAddress
        DesiredProfile = $DesiredProfile; DesiredRemoteAddress = $DesiredRemoteAddress
        DisplayName = $DisplayName; Program = $Program
        Action = $Action
    }
}

function Export-FirewallBackup {
    param([Parameter(Mandatory = $true)][string]$Path, [bool]$ChangeCanFollow)
    # A plan artifact: written on every run, -WhatIf included. A failed export stops the run only
    # when a change could follow it; otherwise it is a warning and no backup path is returned.
    $global:LASTEXITCODE = 0
    $output = & netsh.exe advfirewall export $Path 2>&1
    $exit = $global:LASTEXITCODE
    if ($exit -eq 0 -and (Test-Path -LiteralPath $Path)) { return $Path }
    $message = "Firewall backup failed (netsh exit $exit). Output: $(@($output) -join ' ')"
    if ($ChangeCanFollow) { throw "$message Stopping before any change." }
    Write-Warning "$message No change can be made on this run (-WhatIf or not elevated), so it continues without a backup."
    $null
}

function Get-RuleObject {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:RuleCache.ContainsKey($Name)) { return $script:RuleCache[$Name] }
    if (-not $script:RuleCacheFull) {
        foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop)) {
            if (-not $script:RuleCache.ContainsKey([string]$r.Name)) { $script:RuleCache[[string]$r.Name] = $r }
        }
        $script:RuleCacheFull = $true
    }
    if ($script:RuleCache.ContainsKey($Name)) { return $script:RuleCache[$Name] }
    throw "Firewall rule '$Name' was not found."
}

function ConvertTo-ProfileText {
    param($ProfileValue)
    # Real values read 'Public, Private' or 'Any'; normalise to 'Public,Private'.
    (@("$ProfileValue" -split '[,\s]+') | Where-Object { $_ }) -join ','
}

function Get-AddressText {
    param($Rule)
    $filters = @($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    if ($filters.Count -eq 0) { return $null }
    $remote = Get-OptionalProperty $filters[0] 'RemoteAddress'
    if ($null -eq $remote) { return $null }
    $text = (@($remote) | ForEach-Object { "$_" }) -join ','
    # An empty address list is unreadable, not a value: a prior '' could not be restored by -Rollback.
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    param(
        [int]$LogMaxSizeKilobytes,
        [bool]$BlockAllInboundOnPublic,
        [bool]$DisableStaleProgramRules,
        [string[]]$DisablePublicFeatureGroup = @(),
        [string[]]$ScopeRuleDisplayName = @()
    )
    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    # ---- Profile defaults -------------------------------------------------
    $profileState = @{}
    $profileError = $null
    try {
        foreach ($p in @(Get-NetFirewallProfile -All -ErrorAction Stop)) { $profileState["$($p.Name)"] = $p }
    } catch {
        $profileError = $_.Exception.Message
    }

    $desired = [ordered]@{
        Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'
        NotifyOnListen = 'False'; LogBlocked = 'True'; LogMaxSizeKilobytes = "$LogMaxSizeKilobytes"
    }
    $profileSettings = [System.Collections.Generic.List[object]]::new()
    foreach ($name in 'Domain', 'Private', 'Public') {
        foreach ($prop in $desired.Keys) {
            $profileSettings.Add([pscustomobject]@{ Profile = $name; Property = $prop; Desired = $desired[$prop]; Switch = $false })
        }
    }
    if ($BlockAllInboundOnPublic) {
        $profileSettings.Add([pscustomobject]@{ Profile = 'Public'; Property = 'AllowInboundRules'; Desired = 'False'; Switch = $true })
    }

    foreach ($s in $profileSettings) {
        $cur = 'unknown'
        if ($profileState.ContainsKey($s.Profile)) {
            $v = Get-OptionalProperty $profileState[$s.Profile] $s.Property
            if ($null -ne $v -and "$v" -ne '') { $cur = "$v" }
        }
        $label = "$($s.Profile).$($s.Property)"
        $action = if ($cur -eq 'unknown') {
            "Cannot read $label$(if ($profileError) { " ($profileError)" }); not changed"
        } elseif ($cur -eq $s.Desired) {
            "No change ($label already $($s.Desired))"
        } else {
            "Set $label from '$cur' to '$($s.Desired)'"
        }
        $items.Add((Get-PlanItemObject -Category 'ProfileSetting' -Setting $label -Target $s.Profile -Property $s.Property `
                    -CurrentValue $cur -DesiredValue $s.Desired -Action $action))
    }

    # ---- Rule-based controls ----------------------------------------------
    $needRules = $DisableStaleProgramRules -or @($DisablePublicFeatureGroup).Count -gt 0 -or @($ScopeRuleDisplayName).Count -gt 0
    if (-not $needRules) { return $items }

    $inbound = $null
    try {
        $inbound = @(Get-NetFirewallRule -Direction Inbound -ErrorAction Stop |
                Where-Object { "$($_.Direction)" -eq 'Inbound' })
    } catch {
        $items.Add((Get-PlanItemObject -Category 'Unreadable' -Setting 'InboundRules' -CurrentValue "unknown: $($_.Exception.Message)" `
                    -Action "Cannot read inbound firewall rules ($($_.Exception.Message)); rule controls not planned"))
        return $items
    }
    foreach ($r in $inbound) { $script:RuleCache["$($r.Name)"] = $r }

    $planned = @{}

    if ($DisableStaleProgramRules) {
        foreach ($r in @($inbound | Where-Object { "$($_.Enabled)" -eq 'True' -and "$($_.Action)" -eq 'Allow' })) {
            $program = $null
            try {
                $filter = @($r | Get-NetFirewallApplicationFilter -ErrorAction Stop)
                if ($filter.Count) { $program = Get-OptionalProperty $filter[0] 'Program' }
            } catch {
                Write-Warning "Could not read the application filter of rule '$($r.Name)'; not treated as stale: $($_.Exception.Message)"
                continue
            }
            if ($null -eq $program -or "$program" -eq '' -or "$program" -in @('Any', 'System')) { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables("$program")
            if ($expanded -match '%[^%]+%') { continue }   # unexpanded variable: cannot judge, leave alone
            if (Test-Path -LiteralPath $expanded) { continue }
            $planned["$($r.Name)"] = $true
            $items.Add((Get-PlanItemObject -Category 'StaleProgramRule' -Setting "$($r.Name)" -Target "$($r.Name)" -Property 'Enabled' `
                        -CurrentValue 'True' -DesiredValue 'False' -DisplayName "$($r.DisplayName)" -Program "$program" `
                        -Action "Disable stale inbound rule '$($r.DisplayName)' (program missing: $program)"))
        }
    }

    foreach ($group in @($DisablePublicFeatureGroup | Where-Object { $_ })) {
        $matched = 0
        foreach ($r in $inbound) {
            $g = "$(Get-OptionalProperty $r 'Group')"
            $dg = "$(Get-OptionalProperty $r 'DisplayGroup')"
            if ($g -ne $group -and $dg -ne $group) { continue }
            $matched++
            if ("$($r.Enabled)" -ne 'True') { continue }
            $profiles = @((ConvertTo-ProfileText $r.Profile) -split ',')
            if ('Public' -notin $profiles -and 'Any' -notin $profiles) { continue }
            if ($planned.ContainsKey("$($r.Name)")) { continue }
            $planned["$($r.Name)"] = $true
            $items.Add((Get-PlanItemObject -Category 'PublicFeatureRule' -Setting "$($r.Name)" -Target "$($r.Name)" -Property 'Enabled' `
                        -CurrentValue 'True' -DesiredValue 'False' -DisplayName "$($r.DisplayName)" `
                        -CurrentProfile (ConvertTo-ProfileText $r.Profile) `
                        -Action "Disable inbound rule '$($r.DisplayName)' in group '$group' (profile includes Public)"))
        }
        if ($matched -eq 0) {
            Write-Warning "No inbound rule belongs to group '$group'."
            $items.Add((Get-PlanItemObject -Category 'PublicFeatureRule' -Setting "group:$group" -CurrentValue 'absent' `
                        -Action "No change (no inbound rule has Group or DisplayGroup '$group')"))
        }
    }

    foreach ($displayName in @($ScopeRuleDisplayName | Where-Object { $_ })) {
        $hits = @($inbound | Where-Object { "$($_.DisplayName)" -eq $displayName -and "$($_.Action)" -eq 'Allow' })
        if ($hits.Count -eq 0) {
            Write-Warning "No inbound Allow rule has DisplayName '$displayName'."
            $items.Add((Get-PlanItemObject -Category 'ScopeRule' -Setting "displayname:$displayName" -DisplayName $displayName -CurrentValue 'absent' `
                        -Action "No change (no inbound Allow rule has DisplayName '$displayName')"))
            continue
        }
        foreach ($r in $hits) {
            $curProfile = ConvertTo-ProfileText $r.Profile
            $curAddress = $null
            try { $curAddress = Get-AddressText $r } catch { $curAddress = $null }
            $unknown = (-not $curProfile) -or ($null -eq $curAddress)
            $addressText = if ($null -eq $curAddress) { 'unknown' } else { $curAddress }
            $profileText = if ($curProfile) { $curProfile } else { 'unknown' }
            $action = if ($unknown) {
                "Cannot read Profile/RemoteAddress of '$displayName'; not changed"
            } elseif ($curProfile -eq 'Private' -and $curAddress -eq 'LocalSubnet') {
                "No change ('$displayName' already Private and LocalSubnet)"
            } else {
                "Scope inbound rule '$displayName' to Profile Private, RemoteAddress LocalSubnet (was Profile $profileText, RemoteAddress $addressText)"
            }
            $items.Add((Get-PlanItemObject -Category 'ScopeRule' -Setting "$($r.Name)" -Target "$($r.Name)" -DisplayName $displayName `
                        -CurrentValue "Profile=$profileText;RemoteAddress=$addressText" -DesiredValue 'Profile=Private;RemoteAddress=LocalSubnet' `
                        -CurrentProfile $profileText -CurrentRemoteAddress $addressText `
                        -DesiredProfile 'Private' -DesiredRemoteAddress 'LocalSubnet' -Action $action))
        }
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # Exact name: the pattern must not also match firewall-baseline-rollback-plan-<ts>.json.
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'firewall-baseline-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^firewall-baseline-rollback-\d{8}_\d{6}\.json$' } |
        Sort-Object Name -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No firewall-baseline-rollback-<timestamp>.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $entries = @(@($data.ChangedSettings) | Where-Object { $_ })
    [array]::Reverse($entries)
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($e in $entries) {
        $category = "$(Get-OptionalProperty $e 'Category')"
        $setting = "$(Get-OptionalProperty $e 'Setting')"
        $prior = Get-OptionalProperty $e 'PriorValue'
        $applied = Get-OptionalProperty $e 'AppliedValue'
        $item = Get-PlanItemObject -Category $category -Setting $setting -Target "$(Get-OptionalProperty $e 'Target')" `
            -Property "$(Get-OptionalProperty $e 'Property')" -CurrentValue $applied -DesiredValue $prior `
            -DisplayName "$(Get-OptionalProperty $e 'DisplayName')" -Program "$(Get-OptionalProperty $e 'Program')" `
            -Action "Restore $category '$setting' to '$prior'"
        if ($category -eq 'ScopeRule') {
            $item.DesiredProfile = "$(Get-OptionalProperty $e 'PriorProfile')"
            $item.DesiredRemoteAddress = "$(Get-OptionalProperty $e 'PriorRemoteAddress')"
            $item.Action = "Restore scope of '$setting' to Profile $($item.DesiredProfile), RemoteAddress $($item.DesiredRemoteAddress)"
        }
        $items.Add($item)
    }
    $items
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [OutputType([string])]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.Category -eq 'Unreadable') { return "Failed: $($Item.CurrentValue)" }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $Rollback) {
        # A change whose prior value could not be read could not be rolled back, so it is not made.
        if ("$($Item.CurrentValue)" -eq 'unknown' -or "$($Item.CurrentProfile)" -eq 'unknown' -or "$($Item.CurrentRemoteAddress)" -eq 'unknown') {
            return 'Skipped: prior state unreadable'
        }
    }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        switch ($Item.Category) {
            'ProfileSetting' {
                $splat = @{ Name = $Item.Target }
                $splat[$Item.Property] = if ($Item.Property -eq 'LogMaxSizeKilobytes') { [int]$Item.DesiredValue } else { "$($Item.DesiredValue)" }
                Set-NetFirewallProfile @splat
            }
            { $_ -in @('StaleProgramRule', 'PublicFeatureRule') } {
                $rule = Get-RuleObject -Name $Item.Target
                if ("$($Item.DesiredValue)" -eq 'True') { $rule | Enable-NetFirewallRule } else { $rule | Disable-NetFirewallRule }
            }
            'ScopeRule' {
                $rule = Get-RuleObject -Name $Item.Target
                $rule | Set-NetFirewallRule -Profile @("$($Item.DesiredProfile)" -split ',') -RemoteAddress @("$($Item.DesiredRemoteAddress)" -split ',')
            }
            default { return "Failed: unknown category '$($Item.Category)'" }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting; Target = $Item.Target; Property = $Item.Property
            RequiresAdmin = $Item.RequiresAdmin; DisplayName = $Item.DisplayName; Program = $Item.Program
            PriorValue = $Item.CurrentValue; AppliedValue = $Item.DesiredValue
            PriorProfile = $Item.CurrentProfile; PriorRemoteAddress = $Item.CurrentRemoteAddress
            AppliedProfile = $Item.DesiredProfile; AppliedRemoteAddress = $Item.DesiredRemoteAddress
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
$plan = @(if ($Rollback) { Get-RollbackPlan } else {
        Get-ForwardPlan -LogMaxSizeKilobytes $LogMaxSizeKilobytes -BlockAllInboundOnPublic ([bool]$BlockAllInboundOnPublic) `
            -DisableStaleProgramRules ([bool]$DisableStaleProgramRules) -DisablePublicFeatureGroup $DisablePublicFeatureGroup `
            -ScopeRuleDisplayName $ScopeRuleDisplayName
    })

$planPath = Join-Path $resolvedReportDirectory "firewall-baseline-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "firewall-baseline-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "firewall-baseline-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "firewall-baseline-$mode-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

# Backup before any change, on every run. A failure here stops an elevated executing run with the
# plan already written.
$backupPath = Export-FirewallBackup -Path (Join-Path $resolvedReportDirectory "firewall-backup-$timestamp.wfw") `
    -ChangeCanFollow ((Test-IsAdministrator) -and -not $WhatIfPreference)

$state = foreach ($item in $plan) {
    $result = Invoke-PlanItem -Item $item -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

$rollbackPath = $null
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "firewall-baseline-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        BackupPath = $backupPath
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

[pscustomobject]@{
    Operation = "WindowsFirewallBaseline ($mode)"
    IsElevated = (Test-IsAdministrator)
    BackupPath = if ($backupPath) { (Resolve-Path -LiteralPath $backupPath).Path } else { $null }
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RebootRequired = $false
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}
