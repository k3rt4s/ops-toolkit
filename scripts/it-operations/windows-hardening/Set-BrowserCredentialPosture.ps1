<#
.SYNOPSIS
Plan, apply, and roll back browser policy that removes the infostealer credential-theft surface.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run elevated: every enforced setting is an HKLM machine policy and needs an elevated shell.
- Use -Rollback to restore the exact values this script changed.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to this
  developer's workstation must never be applied to someone else's machine. Supply the report
  directory explicitly on every run. Generated reports belong under a data root outside the
  repo, per the workspace data-hygiene rule (generated data lives outside the repo, in whatever
  data root the operator's own workspace uses).

Purpose:
An information stealer harvests a browser in one pass: saved passwords, live session cookies, and
anything a browser extension keeps in local storage, which for an authenticator extension is the
TOTP seed and for a password-manager extension can be the vault. The browser is then the single
point of compromise for both factors. This script enforces the two browser policies that shrink
that surface and can be pinned by local machine policy:
- Block the configured authenticator browser extensions in Chrome and Edge by default, and the
  well-known password-manager extensions as well when -IncludePasswordManagerExtensions is set, so an
  enterprise standardizes on a standalone (non-extension) password manager and a hardware or
  out-of-band authenticator instead. Password-manager extensions are opt-in, not a default, because
  blocking one can push a user back to browser-saved passwords, which is a net loss on its own.
- Pin Chrome Application-Bound Encryption on, so the cookie and password store is not readable by
  plain file IO from the user's own context.

The remaining talk defenses that are not a single local machine-policy value (Edge cookie
protection, Device-Bound Session Credentials, local administrator rights, SmartScreen state) are
reported as observations rather than enforced, so the record says plainly what was changed and what
was only measured. Local administrator and LAPS posture is reported in full by the companion
Export-LocalAdminAndLapsPosture.ps1 in this folder and is not duplicated here.

Every change is recorded in a rollback JSON so the posture can be precisely reversed with -Rollback.
The extension IDs blocked by default are a documented starting set, not an exhaustive one; verify
them against the Chrome Web Store and Edge Add-ons and extend -ExtensionBlockId for your environment.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir>            # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON under the report directory, plus a rollback JSON capturing the prior
value of every setting changed so a later -Rollback can revert precisely. Emits a summary object
whose Observations list carries the reported-not-enforced defenses.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Set-WorkstationLockPosture.ps1 and
Export-LocalAdminAndLapsPosture.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNull()]
    [string[]]$ExtensionBlockId = @(
        'bhghoamapcdpbohphigoooaddinpkbai' # Authenticator (authenticator.cc) - browser-extension TOTP
    ),

    [Parameter()]
    [switch]$IncludePasswordManagerExtensions,

    [Parameter()]
    [switch]$SkipExtensionBlock,

    [Parameter()]
    [switch]$SkipChromeAbe,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ChromePolicyPath = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$script:EdgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$script:SmartScreenPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()

# Well-known password-manager browser extensions. Not blocked by default: blocking a password-manager
# extension can push a user back to browser-saved passwords, a net loss on its own, so this set is
# opt-in via -IncludePasswordManagerExtensions rather than part of the default block list. Verify and
# extend against the Chrome Web Store and Edge Add-ons for your environment.
$script:PasswordManagerExtensionId = @(
    'nngceckbapebfimnlniiiahkandclblb', # Bitwarden
    'aeblfdkhhhdcdjpifhhbdiojplfjncoa', # 1Password
    'hdokiejnpimakedhajhdlcegeplioahd', # LastPass
    'fdjamakpfbbddfjaooikfcpapjohcfmg'  # Dashlane
)

function Show-Usage {
    Write-Output @'
Enforce browser policy that removes the infostealer credential-theft surface.

Usage:
  pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -WhatIf
  pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir>            # elevated
  pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -Rollback -WhatIf

Options:
  -ExtensionBlockId   Extension IDs to block in Chrome and Edge. Default: a documented starting set
                      of well-known authenticator extensions. Verify and extend.
  -IncludePasswordManagerExtensions
                      Also block the well-known password-manager browser extensions (Bitwarden,
                      1Password, LastPass, Dashlane). Opt-in, not a default: blocking these can push
                      a user back to browser-saved passwords.
  -SkipExtensionBlock Do not change the browser ExtensionSettings policy.
  -SkipChromeAbe      Do not pin Chrome Application-Bound Encryption on.
  -ReportDirectory    Plan, state, and rollback output directory. Required, no default.
  -Rollback           Restore all settings this script previously changed.
  -WhatIf             Write reports and preview changes without applying them.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    # Three cases, all of which must return $null cleanly under Set-StrictMode 3.0: the
    # key is absent (Get-ItemProperty yields $null), the key exists but this value does
    # not (the returned object has no such property, and a bare .$Name access on it
    # throws under strict mode), or the value is present. Browser policy keys commonly
    # exist with only some values set, so the middle case is normal, not exceptional.
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

# True when the current ExtensionSettings policy already blocks every requested extension. The
# check is on the parsed policy, not on a re-serialized string, so key ordering in the stored JSON
# never turns an already-satisfied policy into a spurious change.
function Test-ExtensionSettingsSatisfied {
    param([string]$Current, [string[]]$BlockId)
    if (-not $Current -or $Current -eq 'absent') { return $false }
    try { $obj = $Current | ConvertFrom-Json -ErrorAction Stop } catch { return $false }
    foreach ($id in $BlockId) {
        $entry = $obj.PSObject.Properties[$id]
        if (-not $entry) { return $false }
        if ($entry.Value.installation_mode -ne 'blocked') { return $false }
    }
    $true
}

# Merge the requested block IDs into any existing ExtensionSettings policy and return the JSON to
# write. Existing per-extension entries are carried forward so an admin's other managed extensions
# are not dropped; the requested IDs are set to installation_mode blocked. Top-level keys are sorted
# so a re-run produces the same string. The prior raw value is captured separately as CurrentValue,
# so an unparseable prior policy still round-trips through -Rollback.
function Get-DesiredExtensionPolicy {
    param([string]$Current, [string[]]$BlockId)
    $merged = [ordered]@{}
    if ($Current -and $Current -ne 'absent') {
        try {
            $obj = $Current | ConvertFrom-Json -ErrorAction Stop
            foreach ($prop in $obj.PSObject.Properties) { $merged[$prop.Name] = $prop.Value }
        } catch {
            # Unparseable prior policy: manage only the requested IDs. CurrentValue still holds the
            # prior raw string for rollback.
            Write-Verbose "Existing ExtensionSettings policy is not valid JSON; managing only the requested IDs."
        }
    }
    foreach ($id in $BlockId) { $merged[$id] = [pscustomobject]@{ installation_mode = 'blocked' } }
    $sorted = [ordered]@{}
    foreach ($name in ($merged.Keys | Sort-Object)) { $sorted[$name] = $merged[$name] }
    [pscustomobject]$sorted | ConvertTo-Json -Compress -Depth 6
}

# ---------------------------------------------------------------------------
# Plan builders
# ---------------------------------------------------------------------------

function Get-ForwardPlan {
    param(
        [Parameter(Mandatory = $true)][string[]]$ExtensionBlockId,
        [switch]$SkipExtensionBlock,
        [switch]$SkipChromeAbe
    )

    $items = [System.Collections.Generic.List[pscustomobject]]::new()

    if (-not $SkipExtensionBlock) {
        foreach ($browser in @(
                @{ Name = 'Chrome'; Path = $script:ChromePolicyPath },
                @{ Name = 'Edge'; Path = $script:EdgePolicyPath }
            )) {
            $cur = Get-RegValue -Path $browser.Path -Name 'ExtensionSettings'
            $curDisplay = if ($null -ne $cur) { [string]$cur } else { 'absent' }
            $satisfied = Test-ExtensionSettingsSatisfied -Current $curDisplay -BlockId $ExtensionBlockId
            $desired = if ($satisfied) { $curDisplay } else { Get-DesiredExtensionPolicy -Current $curDisplay -BlockId $ExtensionBlockId }
            $action = if ($satisfied) {
                "No change ($($browser.Name) already blocks every listed extension)"
            } else {
                "Block $($ExtensionBlockId.Count) listed credential-theft-surface extension(s) in $($browser.Name)"
            }
            $items.Add([pscustomobject]@{
                    Category = "$($browser.Name)ExtensionBlock"; Setting = 'ExtensionSettings'; RequiresAdmin = $true
                    RegPath = $browser.Path; RegName = 'ExtensionSettings'; RegKind = 'String'
                    CurrentValue = $curDisplay; DesiredValue = $desired; Action = $action
                })
        }
    }

    if (-not $SkipChromeAbe) {
        $curAbe = Get-RegValue -Path $script:ChromePolicyPath -Name 'ApplicationBoundEncryptionEnabled'
        $curAbeDisplay = if ($null -ne $curAbe) { [int]$curAbe } else { 'absent' }
        $action = if ($curAbeDisplay -eq 1) {
            'No change (Chrome Application-Bound Encryption already pinned on)'
        } elseif ($curAbeDisplay -eq 'absent') {
            'Pin Chrome Application-Bound Encryption on (currently default-on but not pinned by policy)'
        } else {
            'Re-enable Chrome Application-Bound Encryption (currently disabled by policy)'
        }
        $items.Add([pscustomobject]@{
                Category = 'ChromeAbe'; Setting = 'ApplicationBoundEncryptionEnabled'; RequiresAdmin = $true
                RegPath = $script:ChromePolicyPath; RegName = 'ApplicationBoundEncryptionEnabled'; RegKind = 'DWord'
                CurrentValue = $curAbeDisplay; DesiredValue = 1; Action = $action
            })
    }

    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    Get-ChildItem -LiteralPath $ReportDirectory -Filter 'browser-credential-posture-rollback-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No browser-credential-posture-rollback-*.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in @($data.ChangedSettings)) {
        if (-not $entry) { continue }
        $items.Add([pscustomobject]@{
                Category = $entry.Category; Setting = $entry.Setting; RequiresAdmin = [bool]$entry.RequiresAdmin
                RegPath = $entry.RegPath; RegName = $entry.RegName; RegKind = $entry.RegKind
                CurrentValue = $entry.AppliedValue; DesiredValue = $entry.PriorValue
                Action = "Restore $($entry.Category) '$($entry.Setting)' to its prior value"
            })
    }
    $items
}

# ---------------------------------------------------------------------------
# Reported-not-enforced observations
# ---------------------------------------------------------------------------

function Get-PostureObservation {
    $observations = [System.Collections.Generic.List[pscustomobject]]::new()

    $osSmartScreen = Get-RegValue -Path $script:SmartScreenPolicyPath -Name 'EnableSmartScreen'
    $observations.Add([pscustomobject]@{
            Check = 'SmartScreen (OS policy)'
            Value = if ($null -ne $osSmartScreen) { "EnableSmartScreen=$osSmartScreen" } else { 'not set by policy' }
            Guidance = 'Enable SmartScreen to reduce malicious-ad and drive-by delivery of stealers. Reported here, not enforced by this script.'
        })

    $observations.Add([pscustomobject]@{
            Check = 'Edge cookie protection'
            Value = 'not pinned by this script'
            Guidance = 'Edge protects its cookie store with app-bound encryption but exposes no single machine-policy value to pin equivalently to Chrome. Track Edge policy releases.'
        })

    $observations.Add([pscustomobject]@{
            Check = 'Device-Bound Session Credentials (DBSC)'
            Value = 'not a local machine-policy value'
            Guidance = 'DBSC binds session cookies to the TPM and shortens their life, but it is an origin/server-side capability (Google Workspace), not a local registry knob. Enable it where the identity provider supports it.'
        })

    $observations.Add([pscustomobject]@{
            Check = 'Local administrator rights'
            Value = 'reported by Export-LocalAdminAndLapsPosture.ps1'
            Guidance = 'Removing local admin raises the cost of the ABE and cookie-store bypasses. Run the companion Export-LocalAdminAndLapsPosture.ps1 for the full membership and LAPS posture; not duplicated here.'
        })

    $observations
}

# ---------------------------------------------------------------------------
# Apply one plan item. Records what changed into $script:ChangedSettings.
# ---------------------------------------------------------------------------

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    try {
        if ("$($Item.DesiredValue)" -eq 'absent') {
            Remove-ItemProperty -Path $Item.RegPath -Name $Item.RegName -ErrorAction SilentlyContinue
        } else {
            if (-not (Test-Path -LiteralPath $Item.RegPath)) {
                New-Item -Path $Item.RegPath -Force | Out-Null
            }
            if ($Item.RegKind -eq 'DWord') {
                Set-ItemProperty -Path $Item.RegPath -Name $Item.RegName -Value ([int]$Item.DesiredValue) -Type DWord -Force
            } else {
                Set-ItemProperty -Path $Item.RegPath -Name $Item.RegName -Value "$($Item.DesiredValue)" -Type String -Force
            }
        }
    } catch {
        return "Failed: $($_.Exception.Message)"
    }

    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Item.Category; Setting = $Item.Setting
            RequiresAdmin = $Item.RequiresAdmin
            RegPath = $Item.RegPath; RegName = $Item.RegName; RegKind = $Item.RegKind
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

# Authenticator extensions are blocked by default; the password-manager set is added only when the
# operator opts in with -IncludePasswordManagerExtensions, because blocking a password-manager
# extension can push a user back to browser-saved passwords. -ExtensionBlockId still supplies any
# custom set on top of the default.
$effectiveBlockId = @($ExtensionBlockId)
if ($IncludePasswordManagerExtensions) { $effectiveBlockId += $script:PasswordManagerExtensionId }
$effectiveBlockId = @($effectiveBlockId | Select-Object -Unique)

$plan = @(if ($Rollback) {
        Get-RollbackPlan
    } else {
        Get-ForwardPlan -ExtensionBlockId $effectiveBlockId `
            -SkipExtensionBlock:$SkipExtensionBlock -SkipChromeAbe:$SkipChromeAbe
    })

$planPath = Join-Path $resolvedReportDirectory "browser-credential-posture-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "browser-credential-posture-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "browser-credential-posture-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "browser-credential-posture-$mode-state-$timestamp.json"

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
    $rollbackPath = Join-Path $resolvedReportDirectory "browser-credential-posture-rollback-$timestamp.json"
    [pscustomobject]@{
        Timestamp = $timestamp
        ExtensionBlockId = @($effectiveBlockId)
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$observations = if ($Rollback) { @() } else { @(Get-PostureObservation) }

[pscustomobject]@{
    Operation = "BrowserCredentialPosture ($mode)"
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
    Observations = @($observations)
}
