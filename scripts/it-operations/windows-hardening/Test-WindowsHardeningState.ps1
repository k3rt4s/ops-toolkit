<#
.SYNOPSIS
Verify that applied Windows hardening is still in place, and prove the TLS client policy with real handshakes.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It runs the Set- hardening scripts in -WhatIf mode, which changes
  nothing, and reads their plans to compare desired state against current state.
- Runs unelevated. The hardening scripts refuse to apply without elevation but
  will always produce a plan, which is all this needs. Some current values cannot be
  read without elevation; those items are reported as Unread, never as compliant, and
  an elevated run reads them. Run unelevated under -WhatIf, a plan item whose value was read is
  'Previewed' (Drifted here) and one whose value was not read is 'Skipped: requires elevation
  (not read)' (Unread here).
- -Target selects what to verify. SchannelTls and Privacy are read from the older
  plan CSV (Action: NoChange, CreateValue, SetValue, DeleteValue, Skipped). A local row of
  that plan the checker cannot classify is Unread, not drift and not a pass: a Skipped
  row, a service row (the plan records no startup type to compare), a Missing row and
  any action it does not know. A scheduled-task row is compared (task state against
  desired state). Defender,
  CredentialProtection, NetworkProtocol, ExploitMitigation, AuditLogging, RemoteAccess,
  LocalAccount, Firewall and WdacAudit are read from the apply-state JSON the newer
  scripts write (Result: NoChange, Previewed, ReportOnly, Skipped, Failed). BitLocker
  is read directly from the OS volume with Get-BitLockerVolume, because
  Enable-BitLockerOsVolume.ps1 needs a key backup destination and is never run here;
  a second BitLocker row (Category KeyBackup, ReportOnly) names the destination the
  organisation settings file configures, or says it is not configured or invalid, and
  never claims a key reached it.
  The default is SchannelTls and Privacy, the two targets the evidence pack has always
  verified; name the newer targets with -Target to verify them. -Target also accepts one
  comma-joined value (A,B), which is how pwsh -File and the evidence pack pass a list.
- State per item: Compliant (already in the desired state), Drifted (the plan would
  change it), NotConfigured, Failed, ReportOnly (listed, not counted as compliant or
  drifted), Precondition (a prerequisite row, recorded and excluded from the counts),
  Unread (the value could not be read, for example because the item needs elevation
  to read, or the read failed) and NotCheckedRemotely. Unread and NotCheckedRemotely are
  undetermined: never counted compliant, and any one of them makes Passed false.
- 'Previewed' is Drifted. 'Skipped: requires elevation (not read)', which the scripts return
  for an unelevated -WhatIf item whose current value was not read, is Unread like any other
  'Skipped:*' result.
- A state file from an older run can still carry the exact result 'Skipped: requires elevation'
  (an unelevated item before the scripts previewed under -WhatIf). Such an item is
  reported as Drifted, because every one of those scripts decides 'No change' before it
  checks elevation, so reaching the elevation check means the value was read and is not
  the desired one. Where the item itself says its current value was unreadable, it is
  Unread instead.
- AuditLogging also carries the off-host rows of Set-WindowsAuditLogging (from the organisation
  settings file). The WEF subscription manager value and the NETWORK SERVICE group row are
  compared like any other setting (Compliant when already as configured, Drifted when the
  plan would change them). Its report-only rows (no destination configured or invalid, an
  Azure Monitor Agent or share destination, a WinRM service that is not confirmed running)
  are Unread, so none of them can lift a pass: delivery off the host is never assumed.
- WdacAudit is Compliant when the toolkit audit policy is already active, Drifted when
  it is not, and Unread when the active policy list cannot be read or the policy cannot
  be built (the ConfigCI module, CiTool.exe or the example policy is missing).
- -ProbeEndpoint attempts a real TLS handshake per protocol version against a
  remote host. This is the only check here that leaves the machine, and it proves
  the client-side Schannel policy rather than trusting the registry.
- -ComputerName checks remote machines. The desired state still comes from running
  the hardening scripts locally in -WhatIf mode, because desired state is a property
  of the scripts rather than of any machine; only the current registry values are
  read remotely. That means the remote targets do not need a copy of this repo.
  Non-registry plan items, services and scheduled tasks, every item of the newer
  targets, and BitLocker, are reported as not checked remotely rather than assumed
  compliant.
- The CredentialProtection target also reads Win32_DeviceGuard directly: Credential Guard
  listed in SecurityServicesConfigured but not in SecurityServicesRunning is Drifted (the
  setting is in place and the protection is not, for instance on an edition that is not
  licensed for it, or before the restart), never Compliant. -DeviceGuardSnapshotPath reads
  those two lists from a JSON file instead of CIM, for tests and offline review. Credential
  Guard running is Compliant. Neither configured nor running is ReportOnly (it is opt-in and
  not required by the baseline), so it is not counted as drift.
- Generated reports are written under reports\windows-hardening by default.
- What a run leaves in its run folder: one plan-<Target> folder per target holding the
  child process log (plan-run.log, plan-run.log.err) and the plan and state CSV/JSON of
  that -WhatIf run, which carry current setting values, local account names and firewall
  rule names. Registry backups are suppressed for SchannelTls and Privacy. The newer
  scripts have no switch to suppress their restore points, so a run can also
  leave: firewall-backup-<timestamp>.wfw (a full export of every firewall rule and
  profile, from Set-WindowsFirewallBaseline.ps1), exploit-mitigation-system-export-
  <timestamp>.xml (from Set-WindowsExploitMitigation.ps1, only when a system
  mitigation would change), auditpol-backup-<timestamp>.csv (from
  Set-WindowsAuditLogging.ps1), and the audit policy XML and .cip binary built by
  Set-WdacAuditPolicy.ps1. Without elevation the firewall export fails with a warning
  and is not written, while the exploit protection XML (it lists per-application
  mitigation settings) and an auditpol backup file (empty without elevation) are still
  created. No recovery password or key protector is ever written:
  the BitLocker check records only the volume and protection status. Keep the report
  directory off shared storage.

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
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1 -Target SchannelTls -ProbeEndpoint 'www.microsoft.com:443'
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1 -Target Privacy -FailOnDrift
pwsh -NoProfile -Command "& '.\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1' -Target Defender,Firewall,BitLocker -FailOnDrift"

.OUTPUTS
Writes per-item compliance, a per-category rollup, handshake results, and a run
summary as CSV and JSON under reports\windows-hardening by default. Returns a
summary object. Passed is false, and -FailOnDrift exits 1, when any item has drifted,
is not configured, failed, could not be read or was not checked remotely, or when a
target could not be checked. Unread items are also counted in UnreadCount, listed in
UnreadTargets and raised as a warning, so an elevated re-run can be told apart from a
real drift.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    # Not a ValidateSet: pwsh -File hands a comma-joined list (what the evidence pack sends) over as one
    # string, which a ValidateSet rejects. Each value, or each comma-separated part of one, must be a target name.
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete)
            $null = $commandName, $parameterName
            'SchannelTls', 'Privacy', 'Defender', 'CredentialProtection', 'NetworkProtocol',
            'ExploitMitigation', 'AuditLogging', 'RemoteAccess', 'LocalAccount', 'Firewall',
            'WdacAudit', 'BitLocker' | Where-Object { $_ -like "$wordToComplete*" }
        })]
    [ValidateScript({
            $valid = @('SchannelTls', 'Privacy', 'Defender', 'CredentialProtection', 'NetworkProtocol',
                'ExploitMitigation', 'AuditLogging', 'RemoteAccess', 'LocalAccount', 'Firewall',
                'WdacAudit', 'BitLocker')
            foreach ($part in ([string]$_ -split ',')) {
                if ($part.Trim() -notin $valid) {
                    throw "'$($part.Trim())' is not a target. Valid targets: $($valid -join ', ')."
                }
            }
            $true
        })]
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
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\windows-hardening'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'windows-hardening-verification',

    # JSON file holding a Win32_DeviceGuard object (SecurityServicesConfigured and
    # SecurityServicesRunning) to judge Credential Guard from, instead of reading CIM.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DeviceGuardSnapshotPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Hardening') -Force

# pwsh -File hands every argument as a literal string, so an estate-scoped caller
# that joins targets into one comma-separated value needs them split back into a
# real array here. An unbound -ComputerName is left alone.
if ($PSBoundParameters.ContainsKey('ComputerName')) {
    $ComputerName = ConvertTo-OpsSplitList -Value $ComputerName
}
# The same for -Target, which the evidence pack sends as one comma-joined value.
if ($PSBoundParameters.ContainsKey('Target')) {
    $Target = @(ConvertTo-OpsSplitList -Value $Target)
}

# Schema 'Legacy' reads the plan CSV of the two older scripts. Schema 'State' reads the
# <Prefix>-apply-state-<timestamp>.json the newer scripts write. Schema 'BitLocker' runs no script.
$targetScript = @{
    SchannelTls = @{
        Schema = 'Legacy'
        Path = Join-Path $PSScriptRoot 'Set-WindowsSchannelTlsHardening.ps1'
        PlanPattern = 'schannel-tls-hardening-plan-*.csv'
    }
    Privacy = @{
        Schema = 'Legacy'
        Path = Join-Path $PSScriptRoot 'Set-Windows11PrivacyHardening.ps1'
        PlanPattern = '*plan*.csv'
    }
    Defender = @{ Schema = 'State'; Prefix = 'defender-hardening'; Path = Join-Path $PSScriptRoot 'Set-WindowsDefenderHardening.ps1' }
    CredentialProtection = @{ Schema = 'State'; Prefix = 'credential-protection'; Path = Join-Path $PSScriptRoot 'Set-WindowsCredentialProtection.ps1' }
    NetworkProtocol = @{ Schema = 'State'; Prefix = 'network-protocol-hardening'; Path = Join-Path $PSScriptRoot 'Set-WindowsNetworkProtocolHardening.ps1' }
    ExploitMitigation = @{ Schema = 'State'; Prefix = 'exploit-mitigation'; Path = Join-Path $PSScriptRoot 'Set-WindowsExploitMitigation.ps1' }
    AuditLogging = @{ Schema = 'State'; Prefix = 'audit-logging'; Path = Join-Path $PSScriptRoot 'Set-WindowsAuditLogging.ps1' }
    RemoteAccess = @{ Schema = 'State'; Prefix = 'remote-access-posture'; Path = Join-Path $PSScriptRoot 'Set-WindowsRemoteAccessPosture.ps1' }
    LocalAccount = @{ Schema = 'State'; Prefix = 'local-account-policy'; Path = Join-Path $PSScriptRoot 'Set-WindowsLocalAccountPolicy.ps1' }
    Firewall = @{ Schema = 'State'; Prefix = 'firewall-baseline'; Path = Join-Path $PSScriptRoot 'Set-WindowsFirewallBaseline.ps1' }
    WdacAudit = @{ Schema = 'State'; Prefix = 'wdac-audit'; Path = Join-Path $PSScriptRoot 'Set-WdacAuditPolicy.ps1' }
    BitLocker = @{ Schema = 'BitLocker' }
}

# States that carry no verdict about the machine (NotCheckedRemotely is undetermined, like Unread).
# They are listed in the report but are not items checked, so they can never lift CompliantCount
# or hide drift.
$nonVerdictState = @('Unread', 'ReportOnly', 'Precondition', 'NotCheckedRemotely')

# Maps one local row of the older plan CSV to a state. A row the checker cannot classify is
# Unread, never drift and never a pass: Skipped rows, services (the plan records the status but not
# the startup type, so 'Stopped; Disabled' cannot be compared), Missing rows (an absent item cannot be
# told from a failed read) and any action this mapping does not know. A scheduled-task row carries the
# task state and the desired state, so it is compared.
function Get-LegacyRowState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Item)

    $action = [string](Get-OpsPropertyValue -InputObject $Item -Name 'Action')
    $current = ([string](Get-OpsPropertyValue -InputObject $Item -Name 'CurrentValue')).Trim()
    $desired = ([string](Get-OpsPropertyValue -InputObject $Item -Name 'DesiredValue')).Trim()

    switch ($action) {
        'NoChange' { return [pscustomobject]@{ State = 'Compliant'; Reason = '' } }
        'CreateValue' { return [pscustomobject]@{ State = 'NotConfigured'; Reason = '' } }
        'SetValue' { return [pscustomobject]@{ State = 'Drifted'; Reason = '' } }
        'DeleteValue' { return [pscustomobject]@{ State = 'Drifted'; Reason = '' } }
        { $_ -in @('DisableScheduledTask', 'EnableScheduledTask') } {
            $known = @('Ready', 'Running', 'Queued', 'Disabled')
            if ($current -notin $known -or $desired -notin @('Enabled', 'Disabled')) {
                return [pscustomobject]@{ State = 'Unread'; Reason = "The scheduled task state '$current' could not be compared with '$desired'; not assumed compliant." }
            }
            $isDisabled = ($current -eq 'Disabled')
            $meets = if ($desired -eq 'Disabled') { $isDisabled } else { -not $isDisabled }
            return [pscustomobject]@{ State = $(if ($meets) { 'Compliant' } else { 'Drifted' }); Reason = '' }
        }
        default {
            $why = if ($action -eq 'Skipped') { 'The plan skipped this row' } elseif ($action) { "The plan action '$action' cannot be compared with the machine" } else { 'The plan row carried no action' }
            return [pscustomobject]@{ State = 'Unread'; Reason = "$why; not assumed compliant." }
        }
    }
}

function Get-HardeningStateVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Item)

    $result = [string](Get-OpsPropertyValue -InputObject $Item -Name 'Result')
    $category = [string](Get-OpsPropertyValue -InputObject $Item -Name 'Category')
    $action = [string](Get-OpsPropertyValue -InputObject $Item -Name 'Action')
    $current = [string](Get-OpsPropertyValue -InputObject $Item -Name 'CurrentValue')

    if ($category -eq 'Precondition' -or $result -eq 'Met') {
        $state = 'Precondition'; $reason = 'Prerequisite row; not counted.'
    } elseif ($category -eq 'OffHostReport' -and $result -eq 'ReportOnly') {
        # The off-host rows of Set-WindowsAuditLogging. They state facts the script cannot turn into a delivery
        # check (no destination configured, an agent or share destination it only reports, a service that is
        # not running), so each is Unread, which keeps Passed false: logs that may never leave the host are
        # not a pass. The one exception is WinRM confirmed running, a supporting fact beside the WEF value row.
        $setting = [string](Get-OpsPropertyValue -InputObject $Item -Name 'Setting')
        if ($setting -eq 'WinRM service' -and $current -eq 'Running') {
            $state = 'ReportOnly'; $reason = 'WinRM is running; source-initiated forwarding can start. Delivery itself is not checked here.'
        } else {
            $state = 'Unread'; $reason = 'Whether logs leave this host is not established by this row; not assumed compliant.'
        }
    } elseif ($result -eq 'ReportOnly') {
        $state = 'ReportOnly'; $reason = 'Reported only; the script changes nothing here.'
    } elseif ($result -eq 'NoChange') {
        # A report-only row can come back as NoChange; it states a fact, not a setting held.
        if ($category -eq 'Report' -or $action -match 'report only') {
            $state = 'ReportOnly'; $reason = 'Reported only; the script changes nothing here.'
        } else {
            $state = 'Compliant'; $reason = 'No change: already in the desired state.'
        }
    } elseif ($result -eq 'Previewed') {
        $state = 'Drifted'; $reason = 'The plan would change this item.'
    } elseif ($result -like 'Failed:*') {
        $state = 'Failed'; $reason = 'The script reported a failure; counted as drift.'
    } elseif ($result -eq 'Skipped: requires elevation') {
        # The exact result now comes only from older state files and live unelevated runs (an unelevated
        # -WhatIf run returns Previewed or 'Skipped: requires elevation (not read)'). Every script
        # returns NoChange before it checks elevation, so an item that
        # reaches this result was read and is not already the desired value. The exceptions
        # are items whose own text says the read failed: Set-WindowsNetworkProtocolHardening
        # and Set-WindowsFirewallBaseline check elevation before their unreadable test.
        if ($action -match '^(Unreadable|Cannot assess|Skipped)' -or $current -match '^\s*(unknown|unreadable)\b') {
            $state = 'Unread'; $reason = 'Needs elevation and the current value was unreadable; not assumed compliant.'
        } else {
            $state = 'Drifted'; $reason = 'Not in the desired state; applying it needs elevation.'
        }
    } elseif ($result -like 'Skipped:*') {
        $state = 'Unread'; $reason = 'Not read or not assessed; not assumed compliant.'
    } elseif ($result) {
        $state = 'Unread'; $reason = "Unrecognised result: $result"
    } else {
        $state = 'Unread'; $reason = 'The state file carried no result for this item.'
    }

    [pscustomobject]@{ State = $state; Reason = $reason }
}

# Set-WdacAuditPolicy plans one DeployAuditPolicy row. Whether the toolkit audit policy is
# already active is told by the NoActiveAuditPolicy precondition, which fails when the policy
# IS active, so the generic Result of the deploy row alone says nothing useful.
function Get-WdacDeployVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Generic,
        [Parameter(Mandatory = $true)][hashtable]$PreconditionResult
    )

    $buildFailed = @('ConfigCI', 'CiTool', 'BasePolicyFile') | Where-Object { ([string]$PreconditionResult[$_]) -like 'Failed:*' }
    $activeCheck = [string]$PreconditionResult['NoActiveAuditPolicy']

    if ($buildFailed) {
        return [pscustomobject]@{ State = 'Unread'; Reason = "The audit policy could not be planned (failed precondition: $(@($buildFailed) -join ', ')); not assumed compliant." }
    }
    if ($activeCheck -like "Failed: a policy named*already active*") {
        return [pscustomobject]@{ State = 'Compliant'; Reason = 'The toolkit WDAC audit policy is already active.' }
    }
    if ($activeCheck -eq 'Met') {
        return $Generic
    }
    [pscustomobject]@{ State = 'Unread'; Reason = "Whether the audit policy is active could not be determined ($activeCheck)." }
}

# Reads the OS volume directly. Enable-BitLockerOsVolume.ps1 needs a recovery key destination and is
# never run here. Only status fields are read; no key protector or recovery password is touched.
function Get-BitLockerOsVolumeState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$MountPoint)

    try {
        $volume = @(Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop) | Select-Object -First 1
    } catch {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = ''; Reason = "Get-BitLockerVolume failed (it needs elevation): $($_.Exception.Message)" }
    }
    if (-not $volume) {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = ''; Reason = "Get-BitLockerVolume returned nothing for $MountPoint (it needs elevation)." }
    }

    $volumeStatus = [string](Get-OpsPropertyValue -InputObject $volume -Name 'VolumeStatus')
    $protectionText = [string](Get-OpsPropertyValue -InputObject $volume -Name 'ProtectionStatus')
    $protection = switch -Regex ($protectionText) {
        '^(On|1)$' { 'On' }
        '^(Off|0)$' { 'Off' }
        default { $protectionText }
    }
    $method = [string](Get-OpsPropertyValue -InputObject $volume -Name 'EncryptionMethod')
    $current = "VolumeStatus=$volumeStatus;ProtectionStatus=$protection;EncryptionMethod=$method"

    # Compliant needs both halves: the volume fully encrypted AND protection On. Encrypted data with
    # protection Off (suspended) is readable without the key protectors, and a volume part-way through
    # encrypting is not yet protected, so neither is a met control.
    if ([string]::IsNullOrWhiteSpace($volumeStatus) -or $protection -notin @('On', 'Off')) {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = $current; Reason = 'BitLocker status was not one this check can judge (volume or protection status missing or unrecognised).' }
    }
    if ($volumeStatus -eq 'FullyEncrypted' -and $protection -eq 'On') {
        return [pscustomobject]@{ State = 'Compliant'; CurrentValue = $current; Reason = 'OS volume is fully encrypted and protection is On.' }
    }
    if ($volumeStatus -eq 'FullyEncrypted') {
        return [pscustomobject]@{ State = 'Drifted'; CurrentValue = $current; Reason = 'OS volume is fully encrypted but protection is Off (BitLocker is suspended or its key protectors are not active); the data is readable without them.' }
    }
    if ($volumeStatus -in @('EncryptionInProgress', 'EncryptionPaused', 'DecryptionInProgress', 'DecryptionPaused')) {
        $missing = if ($protection -eq 'Off') { ' and protection is Off' } else { '' }
        return [pscustomobject]@{ State = 'Drifted'; CurrentValue = $current; Reason = "OS volume is not fully encrypted (VolumeStatus $volumeStatus)$missing; it is not yet protected." }
    }
    if ($volumeStatus -eq 'FullyDecrypted' -and $protection -eq 'Off') {
        return [pscustomobject]@{ State = 'NotConfigured'; CurrentValue = $current; Reason = 'OS volume is not encrypted.' }
    }
    [pscustomobject]@{ State = 'Unread'; CurrentValue = $current; Reason = 'BitLocker status was not one this check can judge.' }
}

# Reads Win32_DeviceGuard (or the snapshot file) and judges Credential Guard (service id 1) by whether
# it is running, not only configured. Read-only. A machine can list it as configured and still not run
# it, for instance on an edition not licensed for it or before the restart that starts it.
function Get-CredentialGuardState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string]$SnapshotPath)

    try {
        $deviceGuard = if ($SnapshotPath) {
            @(Get-Content -LiteralPath $SnapshotPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) | Select-Object -First 1
        } else {
            @(Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop) | Select-Object -First 1
        }
    } catch {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = ''; Reason = "Win32_DeviceGuard could not be read: $($_.Exception.Message)" }
    }
    if ($null -eq $deviceGuard) {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = ''; Reason = 'Win32_DeviceGuard returned nothing.' }
    }
    $configuredProperty = $deviceGuard.PSObject.Properties['SecurityServicesConfigured']
    $runningProperty = $deviceGuard.PSObject.Properties['SecurityServicesRunning']
    if ($null -eq $configuredProperty -or $null -eq $runningProperty -or ($null -eq $configuredProperty.Value -and $null -eq $runningProperty.Value)) {
        return [pscustomobject]@{ State = 'Unread'; CurrentValue = ''; Reason = 'Win32_DeviceGuard did not report SecurityServicesConfigured and SecurityServicesRunning.' }
    }
    $configured = @($configuredProperty.Value | Where-Object { $null -ne $_ })
    $running = @($runningProperty.Value | Where-Object { $null -ne $_ })
    $current = "SecurityServicesConfigured=$($configured -join ',');SecurityServicesRunning=$($running -join ',')"
    $isConfigured = $configured -contains 1
    $isRunning = $running -contains 1

    if ($isRunning) {
        return [pscustomobject]@{ State = 'Compliant'; CurrentValue = $current; Reason = 'Credential Guard is running.' }
    }
    if ($isConfigured) {
        return [pscustomobject]@{ State = 'Drifted'; CurrentValue = $current; Reason = 'Credential Guard is configured but not running (the edition may not be licensed for it, or a restart or a hardware prerequisite is missing).' }
    }
    # Opt-in and not required by the baseline (the credential script refuses it on editions that cannot
    # run it), so a machine without it is reported, not counted as drift.
    [pscustomobject]@{ State = 'ReportOnly'; CurrentValue = $current; Reason = 'Credential Guard is not configured; it is opt-in and not required by the baseline.' }
}

function ConvertTo-HardeningComplianceRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Target, [string]$ComputerName, [string]$State, [string]$Category, [string]$ItemType,
        [string]$Item, [string]$CurrentValue, [string]$DesiredValue, [string]$DesiredState,
        [string]$PlannedAction, [string]$Reason
    )

    [pscustomobject]@{
        Target = $Target
        ComputerName = $ComputerName
        State = $State
        Category = $Category
        ItemType = $ItemType
        Item = $Item
        CurrentValue = $CurrentValue
        DesiredValue = $DesiredValue
        DesiredState = $DesiredState
        PlannedAction = $PlannedAction
        Reason = $Reason
    }
}

# DriftCount keeps its old meaning (Drifted plus NotConfigured) for the two older targets and counts
# Drifted plus Failed for the newer ones. NotConfiguredCount is reported beside it for the newer ones.
function ConvertTo-HardeningScriptResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Target, [string]$ComputerName, [string]$Status, [string]$Note,
        [object[]]$Record = @(), [string]$Schema = 'Legacy'
    )

    $rows = @($Record)
    $driftStates = if ($Schema -eq 'Legacy') { @('Drifted', 'NotConfigured') } else { @('Drifted', 'Failed') }
    [pscustomobject]@{
        Target = $Target
        ComputerName = $ComputerName
        Status = $Status
        ItemCount = $rows.Count
        CompliantCount = @($rows | Where-Object { $_.State -eq 'Compliant' }).Count
        DriftCount = @($rows | Where-Object { $_.State -in $driftStates }).Count
        UnreadCount = @($rows | Where-Object { $_.State -eq 'Unread' }).Count
        NotConfiguredCount = @($rows | Where-Object { $_.State -eq 'NotConfigured' }).Count
        FailedCount = @($rows | Where-Object { $_.State -eq 'Failed' }).Count
        ReportOnlyCount = @($rows | Where-Object { $_.State -eq 'ReportOnly' }).Count
        Note = $Note
    }
}

$machines = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$complianceRecords = [System.Collections.Generic.List[object]]::new()
$handshakeRecords = [System.Collections.Generic.List[object]]::new()
$scriptResults = [System.Collections.Generic.List[object]]::new()

foreach ($name in $Target) {
    $spec = $targetScript[$name]

    if ($spec.Schema -eq 'BitLocker') {
        $mountPoint = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
        foreach ($machine in $machines) {
            if ($machine -eq $env:COMPUTERNAME) {
                $volumeState = Get-BitLockerOsVolumeState -MountPoint $mountPoint
                $state = $volumeState.State
                $currentValue = $volumeState.CurrentValue
                $reason = $volumeState.Reason
            } else {
                $state = 'NotCheckedRemotely'
                $currentValue = ''
                $reason = 'BitLocker is read from the local OS volume only.'
            }
            $complianceRecords.Add((ConvertTo-HardeningComplianceRecord -Target $name -ComputerName $machine -State $state `
                        -Category 'OsVolume' -ItemType 'BitLockerVolume' -Item $mountPoint -CurrentValue $currentValue `
                        -DesiredValue 'ProtectionStatus=On' -DesiredState 'OS volume encrypted with protection on' `
                        -PlannedAction '' -Reason $reason))
            if ($machine -eq $env:COMPUTERNAME) {
                # Where recovery keys are meant to go, from the organisation settings file. ReportOnly always: this
                # check does not read a protector or a key, so it cannot say a key reached the destination.
                $keyBackup = (Get-OpsOrgSettings).BitLockerKeyBackup
                $keyCurrent = "Status=$($keyBackup.Status);Type=$($keyBackup.Type)"
                $keyReason = if ($keyBackup.Status -eq 'Configured') {
                    $where = if ($keyBackup.Type -eq 'Folder') { " (folder $($keyBackup.FolderPath))" } else { '' }
                    "Organisation settings send recovery keys to $($keyBackup.Type)$where. Whether a key reached it is not checked here."
                } else {
                    "Key backup destination is $($keyBackup.Status): $($keyBackup.Reason)"
                }
                $complianceRecords.Add((ConvertTo-HardeningComplianceRecord -Target $name -ComputerName $machine -State 'ReportOnly' `
                            -Category 'KeyBackup' -ItemType 'OrgSetting' -Item 'BitLockerKeyBackup' -CurrentValue $keyCurrent `
                            -DesiredValue 'Configured' -DesiredState 'A recovery key destination is configured' `
                            -PlannedAction '' -Reason $keyReason))
            }
            $forTarget = @($complianceRecords | Where-Object { $_.Target -eq $name -and $_.ComputerName -eq $machine })
            $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -ComputerName $machine -Status 'Checked' `
                        -Note 'Get-BitLockerVolume' -Record $forTarget -Schema 'State'))
        }
        continue
    }

    if (-not (Test-Path -LiteralPath $spec.Path)) {
        Write-Warning "Hardening script not found, skipped: $($spec.Path)"
        $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -Status 'ScriptMissing' -Note $spec.Path))
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
        # what is redirected. All the hardening scripts take -ReportDirectory, not
        # -OutputDirectory. The two older ones take -SkipRegistryBackup, which keeps a
        # verification pass from leaving .reg exports of the machine's current state
        # behind; the newer ones have no such switch and reject it, so it is passed to the
        # older ones only.
        $planLog = Join-Path $planDirectory 'plan-run.log'
        # Start-Process joins these with bare spaces, so both paths are quoted.
        $arguments = @(
            '-NoProfile', '-NonInteractive', '-File', "`"$($spec.Path)`""
            '-WhatIf', '-ReportDirectory', "`"$planDirectory`""
        )
        if ($spec.Schema -eq 'Legacy') { $arguments += '-SkipRegistryBackup' }
        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $planLog -RedirectStandardError "$planLog.err"
        if ($process.ExitCode -ne 0) {
            throw "Plan generation exited with code $($process.ExitCode). See $planLog.err"
        }
    } catch {
        Write-Warning "Could not generate a plan for $name : $($_.Exception.Message)"
        $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -Status 'PlanFailed' -Note $_.Exception.Message))
        continue
    }

    if ($spec.Schema -eq 'Legacy') {
        $planPattern = $spec.PlanPattern
    } else {
        $planPattern = "$($spec.Prefix)-apply-state-*.json"
    }
    $planFile = Get-ChildItem -LiteralPath $planDirectory -Filter $planPattern -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $planFile) {
        Write-Warning "No plan file matching $planPattern was produced for $name."
        $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -Status 'NoPlanFile' -Note $planDirectory))
        continue
    }

    if ($spec.Schema -eq 'Legacy') {
        $planItems = @(Import-Csv -LiteralPath $planFile.FullName)
    } else {
        try {
            $planItems = @(Get-Content -LiteralPath $planFile.FullName -Raw | ConvertFrom-Json)
        } catch {
            Write-Warning "Could not read the state file for $name : $($_.Exception.Message)"
            $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -Status 'PlanFailed' -Note "State file unreadable: $($_.Exception.Message)"))
            continue
        }
        if ($planItems.Count -eq 0) {
            # A script that planned nothing has proved nothing.
            Write-Warning "The state file for $name held no items."
            $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -Status 'EmptyPlan' -Note $planFile.Name))
            continue
        }
    }

    # Needed to judge the WdacAudit deploy row.
    $preconditionResult = @{}
    if ($spec.Schema -eq 'State') {
        foreach ($item in $planItems) {
            if ([string](Get-OpsPropertyValue -InputObject $item -Name 'Category') -eq 'Precondition') {
                $preconditionResult[[string](Get-OpsPropertyValue -InputObject $item -Name 'Setting')] = [string](Get-OpsPropertyValue -InputObject $item -Name 'Result')
            }
        }
    }

    foreach ($machine in $machines) {
        # The plan already carries the local machine's current values, so only a
        # remote target needs its registry read. Desired state is the same either way,
        # because it comes from the scripts rather than from any machine. The newer
        # targets carry no registry path, so a remote machine's items are not read.
        $remoteValues = @{}
        if ($machine -ne $env:COMPUTERNAME -and $spec.Schema -eq 'Legacy') {
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
                $unreachable = ConvertTo-HardeningScriptResult -Target $name -ComputerName $machine -Status 'Unreachable' -Note $_.Exception.Message
                $scriptResults.Add($unreachable)
                continue
            }
        }

        foreach ($item in $planItems) {
            $action = [string](Get-OpsPropertyValue -InputObject $item -Name 'Action')
            $desiredValue = [string](Get-OpsPropertyValue -InputObject $item -Name 'DesiredValue')
            $currentValue = [string](Get-OpsPropertyValue -InputObject $item -Name 'CurrentValue')

            if ($spec.Schema -eq 'State') {
                if ($machine -eq $env:COMPUTERNAME) {
                    $verdict = Get-HardeningStateVerdict -Item $item
                    if ($name -eq 'WdacAudit' -and [string](Get-OpsPropertyValue -InputObject $item -Name 'Category') -eq 'DeployAuditPolicy') {
                        $verdict = Get-WdacDeployVerdict -Generic $verdict -PreconditionResult $preconditionResult
                    }
                    $state = $verdict.State
                    $reason = "Result: $([string](Get-OpsPropertyValue -InputObject $item -Name 'Result')). $($verdict.Reason)"
                } else {
                    $state = 'NotCheckedRemotely'
                    $currentValue = ''
                    $reason = 'The newer hardening targets are read from the local machine only.'
                }
                $setting = [string](Get-OpsPropertyValue -InputObject $item -Name 'Setting')
                $itemTarget = [string](Get-OpsPropertyValue -InputObject $item -Name 'Target')
                $itemLabel = if ($itemTarget -and $itemTarget -ne $setting) { "$setting [$itemTarget]" } else { $setting }

                $complianceRecords.Add((ConvertTo-HardeningComplianceRecord -Target $name -ComputerName $machine -State $state `
                            -Category ([string](Get-OpsPropertyValue -InputObject $item -Name 'Category')) `
                            -ItemType ([string](Get-OpsPropertyValue -InputObject $item -Name 'Kind')) `
                            -Item $itemLabel -CurrentValue $currentValue -DesiredValue $desiredValue -DesiredState '' `
                            -PlannedAction $action -Reason $reason))
                continue
            }

            $registryPath = [string](Get-OpsPropertyValue -InputObject $item -Name 'RegistryPath')
            $valueName = [string](Get-OpsPropertyValue -InputObject $item -Name 'ValueName')
            $legacyReason = ''

            if ($machine -eq $env:COMPUTERNAME) {
                # NoChange is the plan saying the machine already holds the desired
                # value. Anything else is the hardening not being in effect right now.
                $legacyRow = Get-LegacyRowState -Item $item
                $state = $legacyRow.State
                $legacyReason = $legacyRow.Reason
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

            # The two hardening scripts describe the same thing differently: the
            # privacy plan carries a combined Target, the Schannel plan carries
            # RegistryPath and ValueName separately.
            $rowReason = (@([string](Get-OpsPropertyValue -InputObject $item -Name 'Reason'), $legacyReason) | Where-Object { $_ }) -join ' '
            $itemLabel = if (Get-OpsPropertyValue -InputObject $item -Name 'Target') {
                [string](Get-OpsPropertyValue -InputObject $item -Name 'Target')
            } else {
                (@($registryPath, $valueName) | Where-Object { $_ }) -join '\'
            }

            $complianceRecords.Add((ConvertTo-HardeningComplianceRecord -Target $name -ComputerName $machine -State $state `
                        -Category ([string](Get-OpsPropertyValue -InputObject $item -Name 'Category')) `
                        -ItemType ([string](Get-OpsPropertyValue -InputObject $item -Name 'ItemType')) `
                        -Item $itemLabel -CurrentValue $currentValue -DesiredValue $desiredValue `
                        -DesiredState ([string](Get-OpsPropertyValue -InputObject $item -Name 'DesiredState')) `
                        -PlannedAction $action `
                        -Reason $rowReason))
        }

        if ($name -eq 'CredentialProtection') {
            if ($machine -eq $env:COMPUTERNAME) {
                $guardState = Get-CredentialGuardState -SnapshotPath $DeviceGuardSnapshotPath
            } else {
                $guardState = [pscustomobject]@{ State = 'NotCheckedRemotely'; CurrentValue = ''; Reason = 'Credential Guard is read from the local machine only.' }
            }
            $complianceRecords.Add((ConvertTo-HardeningComplianceRecord -Target $name -ComputerName $machine -State $guardState.State `
                        -Category 'CredentialGuard' -ItemType 'DeviceGuardService' -Item 'CredentialGuardRunning' `
                        -CurrentValue $guardState.CurrentValue -DesiredValue 'SecurityServicesRunning contains 1' `
                        -DesiredState 'Credential Guard running' -PlannedAction '' -Reason $guardState.Reason))
        }

        $forTarget = @($complianceRecords | Where-Object { $_.Target -eq $name -and $_.ComputerName -eq $machine })
        $scriptResults.Add((ConvertTo-HardeningScriptResult -Target $name -ComputerName $machine -Status 'Checked' `
                    -Note $planFile.Name -Record $forTarget -Schema $spec.Schema))
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
        FailedCount = @($rows | Where-Object { $_.State -eq 'Failed' }).Count
        UnreadCount = @($rows | Where-Object { $_.State -eq 'Unread' }).Count
        ReportOnlyCount = @($rows | Where-Object { $_.State -eq 'ReportOnly' }).Count
    }
}

$exports = @(
    Export-OpsReport -Name 'hardening-compliance' -Record @($complianceRecords) -Directory $runDirectory
    Export-OpsReport -Name 'category-rollup' -Record @($categoryRollup) -Directory $runDirectory
    Export-OpsReport -Name 'script-results' -Record @($scriptResults) -Directory $runDirectory
    Export-OpsReport -Name 'tls-handshakes' -Record @($handshakeRecords) -Directory $runDirectory
)

# Failed counts as drift: the script tried and could not establish the state. Unread is not
# drift, it is undetermined; it is counted on its own and still keeps Passed false.
$driftCount = @($complianceRecords | Where-Object { $_.State -in @('Drifted', 'NotConfigured', 'Failed') }).Count
$unreadRecords = @($complianceRecords | Where-Object { $_.State -eq 'Unread' })
$notCheckedRemotelyCount = @($complianceRecords | Where-Object { $_.State -eq 'NotCheckedRemotely' }).Count
$notEnforced = @($handshakeRecords | Where-Object { $_.Verdict -eq 'PolicyNotEnforced' }).Count

# A target whose plan never ran has proved nothing. Reporting Passed because zero
# drift was found in zero items is the exact failure this script exists to prevent.
$uncheckedTargets = @($scriptResults | Where-Object { $_.Status -ne 'Checked' })

$unreadTargets = @($unreadRecords | Group-Object -Property Target | ForEach-Object { "$($_.Name):$($_.Count)" })
if ($unreadRecords.Count -gt 0) {
    Write-Warning ("$($unreadRecords.Count) hardening item(s) could not be read and are NOT counted as compliant ($($unreadTargets -join ', ')). " +
        'Several need an elevated session to read; run elevated for a complete verification.')
}

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    TargetsChecked = @($Target)
    MachinesChecked = @($machines)
    # Items with a verdict. Unread, ReportOnly, Precondition and NotCheckedRemotely rows are in the report but are
    # not items checked, so a run of mostly unread items cannot read as a well-covered pass.
    ItemsChecked = @($complianceRecords | Where-Object { $_.State -notin $nonVerdictState }).Count
    CompliantCount = @($complianceRecords | Where-Object { $_.State -eq 'Compliant' }).Count
    DriftedCount = @($complianceRecords | Where-Object { $_.State -eq 'Drifted' }).Count
    NotConfiguredCount = @($complianceRecords | Where-Object { $_.State -eq 'NotConfigured' }).Count
    FailedCount = @($complianceRecords | Where-Object { $_.State -eq 'Failed' }).Count
    UnreadCount = $unreadRecords.Count
    ReportOnlyCount = @($complianceRecords | Where-Object { $_.State -eq 'ReportOnly' }).Count
    NotCheckedRemotelyCount = $notCheckedRemotelyCount
    TotalDrift = $driftCount
    ProbeEndpoint = $ProbeEndpoint
    HandshakesAttempted = $handshakeRecords.Count
    PolicyNotEnforcedCount = $notEnforced
    UncheckedTargets = @($uncheckedTargets | ForEach-Object { "$($_.Target):$($_.Status)" })
    UnreadTargets = @($unreadTargets)
    # Undetermined is never folded into a pass: an unread or remotely unchecked item fails it too.
    Passed = ($driftCount -eq 0 -and $notEnforced -eq 0 -and $uncheckedTargets.Count -eq 0 -and $unreadRecords.Count -eq 0 -and $notCheckedRemotelyCount -eq 0)
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($FailOnDrift -and -not $summary.Passed) {
    exit 1
}
