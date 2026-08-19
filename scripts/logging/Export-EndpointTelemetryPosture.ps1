<#
.SYNOPSIS
Report whether the security logging that a hunt or a detection would need is switched on, and how many days of it survive.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads registry policy values, audit policy, service state, and event
  log configuration, and writes reports. It enables no logging and changes no policy.
- Run elevated. Audit policy and the Security log cannot be read without it, and both
  are reported Undetermined rather than compliant when the read fails.
- -ComputerName needs WinRM and local administrator rights on each target.
- Sysmon and event forwarding are reported but not required by default, because an
  estate that does not run them is not thereby non-compliant. Use -RequireSysmon and
  -RequireEventForwarding to make their absence a finding.
- Retention is measured from the oldest record actually still in each channel, not
  from the configured size. A channel that has never been written to is reported
  Unmeasured.
- Generated reports are written under reports\logging by default.

Purpose:
Every detection and every threat hunt rests on telemetry that someone assumed was
being collected. The assumption is usually partly wrong, and it fails silently: a
query over a channel that was never enabled returns nothing, which reads exactly like
a clean result. The same is true of retention, where a 90-day investigation runs
against a Security log that rolled over in nine hours.

This answers the question that has to come first. Not "is there an attacker", but "if
there were, would anything have recorded it, and would the record still be here".

The design rule is the one already proven in Test-LdapSigningReadiness.ps1: report the
setting that governs whether the evidence exists before reporting the evidence. A
check that could not run is Undetermined, never compliant, because a silent absence of
findings is what this script exists to expose.

Required syntax:
pwsh -File .\scripts\logging\Export-EndpointTelemetryPosture.ps1
pwsh -File .\scripts\logging\Export-EndpointTelemetryPosture.ps1 -ComputerName pc01,pc02
pwsh -File .\scripts\logging\Export-EndpointTelemetryPosture.ps1 -MinimumRetentionDays 90 -RequireSysmon

.OUTPUTS
Writes per-setting telemetry checks, per-channel retention, a per-machine posture
verdict, and a run summary as CSV and JSON under reports\logging by default. Returns a
summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#requires -Version 7
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MinimumRetentionDays = 30,

    [Parameter()]
    [switch]$RequireSysmon,

    [Parameter()]
    [switch]$RequireEventForwarding,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\logging'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'endpoint-telemetry-posture'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# The audit subcategories worth requiring on an endpoint, by GUID rather than by name.
# The display name is localized, so on a non-English Windows a name match silently
# finds nothing and every subcategory reads as absent.
$script:AuditSubcategory = @{
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Process Creation'; Requirement = 'Required'; Why = 'Process creation events are the backbone of endpoint hunting. Without 4688 there is no record of what ran.' }
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = @{ Name = 'Logon'; Requirement = 'Required'; Why = 'Interactive and network logons. Without it there is no after-hours or abnormal-access analysis to do.' }
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = @{ Name = 'Special Logon'; Requirement = 'Required'; Why = 'Event 4672 marks a logon holding administrator-equivalent privilege.' }
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Credential Validation'; Requirement = 'Required'; Why = 'Local and NTLM credential checks, including the failures that make up a password spray.' }
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = @{ Name = 'User Account Management'; Requirement = 'Required'; Why = 'Account creation, enabling, and password resets, which is how persistence is established.' }
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = @{ Name = 'Security Group Management'; Requirement = 'Required'; Why = 'Additions to privileged groups.' }
    '{0CCE9228-69AE-11D9-BED3-505054503030}' = @{ Name = 'Sensitive Privilege Use'; Requirement = 'Recommended'; Why = 'Use of privileges such as SeDebugPrivilege. Noisy, which is why it is recommended rather than required.' }
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Policy Change'; Requirement = 'Required'; Why = 'An attacker turning auditing off is itself the event that must survive.' }
    '{0CCE9216-69AE-11D9-BED3-505054503030}' = @{ Name = 'Logoff'; Requirement = 'Recommended'; Why = 'Pairs with Logon to bound a session. Useful for dwell time, not load-bearing on its own.' }
}

# Channels whose configuration and real retention are read on every run. Requirement
# decides whether a disabled channel is a finding or an observation.
$script:TelemetryChannel = @(
    @{ LogName = 'Security'; Requirement = 'Required'; Why = 'Authentication and process creation land here.' }
    @{ LogName = 'System'; Requirement = 'Required'; Why = 'Service installation and driver loading, both common persistence points.' }
    @{ LogName = 'Application'; Requirement = 'Recommended'; Why = 'Application crash and error context around an incident.' }
    @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Requirement = 'Required'; Why = 'Script block logging writes event 4104 here. Enabling the policy without the channel records nothing.' }
    @{ LogName = 'Windows PowerShell'; Requirement = 'Recommended'; Why = 'The Windows PowerShell 5.1 engine log, still where module logging lands on older hosts.' }
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Requirement = 'Conditional'; Why = 'Present only where Sysmon is deployed.' }
    @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Requirement = 'Recommended'; Why = 'Client DNS queries, which is what a tunnelling or beaconing hunt reads. Disabled by default on Windows.' }
    @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Requirement = 'Recommended'; Why = 'Scheduled task creation, MITRE T1053.' }
    @{ LogName = 'Microsoft-Windows-WinRM/Operational'; Requirement = 'Recommended'; Why = 'Remote execution over WinRM, a lateral movement path.' }
    @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Requirement = 'Recommended'; Why = 'Detections, and the exclusions and tampering that precede them.' }
    @{ LogName = 'Microsoft-Windows-Forwarding/Operational'; Requirement = 'Conditional'; Why = 'Present only where event forwarding is configured.' }
)

function Get-TelemetryCheckStatus {
    <#
    .SYNOPSIS
    Grade one telemetry setting against what it should be.

    .DESCRIPTION
    Three outcomes and no fourth. Undetermined means the value could not be read and
    is deliberately not merged into either Enabled or Disabled: an unreadable setting
    is the case this script exists to surface, and folding it into a pass would make
    the report say the opposite of what it knows.

    .PARAMETER Actual
    The value read from the machine, or null when it could not be read.

    .PARAMETER Requirement
    Required, Recommended, or Conditional.

    .PARAMETER Enabled
    Whether the setting is on. Pass null when unknown.

    .OUTPUTS
    String. One of Enabled, Disabled, NotRequired, or Undetermined.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Required', 'Recommended', 'Conditional')]
        [string]$Requirement,

        [Parameter()]
        [AllowNull()]
        [object]$Enabled
    )

    if ($null -eq $Enabled) {
        # A Conditional item that is simply absent is a known absence, not a failed
        # read. Anything else that cannot be read is Undetermined.
        if ($Requirement -eq 'Conditional' -and $null -eq $Actual) {
            return 'NotRequired'
        }

        return 'Undetermined'
    }

    if ([bool]$Enabled) {
        return 'Enabled'
    }

    if ($Requirement -eq 'Conditional') {
        return 'NotRequired'
    }

    'Disabled'
}

function Get-RetentionStatus {
    <#
    .SYNOPSIS
    Grade the measured retention of one channel against the minimum required.

    .DESCRIPTION
    Retention is graded from the oldest record still present, because that is the only
    number that answers "how far back can I actually look". Configured maximum size
    does not answer it: a 4 GB Security log on a busy server can hold hours.

    A channel holding fewer days than the minimum is only Insufficient if it is full.
    A channel that has been collecting for two days on a machine built two days ago
    holds two days of history and is not misconfigured, so it is reported Building.

    .PARAMETER RetentionDays
    Measured days between the oldest record and now. Null when unmeasurable.

    .PARAMETER MinimumDays
    The required retention window.

    .PARAMETER IsFull
    Whether the channel has reached its configured size and begun overwriting.

    .OUTPUTS
    String. One of Sufficient, Insufficient, Building, or Unmeasured.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$RetentionDays,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 3650)]
        [int]$MinimumDays,

        [Parameter()]
        [AllowNull()]
        [object]$IsFull
    )

    if ($null -eq $RetentionDays) {
        return 'Unmeasured'
    }

    if ([double]$RetentionDays -ge $MinimumDays) {
        return 'Sufficient'
    }

    # Not yet full means the shortfall is age, not overwriting. Unknown fullness is
    # treated as full, because assuming the generous case is how a rolling log gets
    # reported as fine.
    if ($null -ne $IsFull -and -not [bool]$IsFull) {
        return 'Building'
    }

    'Insufficient'
}

function Get-MachineTelemetryVerdict {
    <#
    .SYNOPSIS
    Roll per-setting and per-channel outcomes into one verdict for a machine.

    .DESCRIPTION
    Undetermined outranks everything. A machine with two disabled settings and one
    unreadable one is Undetermined, not Partial, because the unread setting could be
    the one that matters and reporting the known subset as the whole picture is the
    failure this script is built to prevent.

    .PARAMETER DisabledCount
    Required settings found disabled.

    .PARAMETER UndeterminedCount
    Settings that could not be read.

    .PARAMETER InsufficientCount
    Required channels retaining less than the minimum.

    .PARAMETER CheckedCount
    Total settings and channels graded.

    .OUTPUTS
    String. One of Covered, Partial, NotCovered, or Undetermined.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][int]$DisabledCount,
        [Parameter(Mandatory = $true)][int]$UndeterminedCount,
        [Parameter(Mandatory = $true)][int]$InsufficientCount,
        [Parameter(Mandatory = $true)][int]$CheckedCount
    )

    if ($CheckedCount -eq 0) {
        # Zero problems across zero checks is not a pass, it is a run that read
        # nothing.
        return 'Undetermined'
    }

    if ($UndeterminedCount -gt 0) {
        return 'Undetermined'
    }

    if ($DisabledCount -eq 0 -and $InsufficientCount -eq 0) {
        return 'Covered'
    }

    if ($DisabledCount -ge $CheckedCount) {
        return 'NotCovered'
    }

    'Partial'
}

function Add-TelemetryCheck {
    <#
    .SYNOPSIS
    Grade one setting and append it to the check record list.

    .DESCRIPTION
    Kept as a function taking the list explicitly rather than closing over script
    scope, so the grading can be exercised by a unit test without running the script.

    .PARAMETER Record
    The list to append to.

    .PARAMETER ComputerName
    Machine the reading came from.

    .PARAMETER Category
    Grouping used in the report, for example PowerShell or AuditPolicy.

    .PARAMETER Setting
    Human-readable setting name.

    .PARAMETER Actual
    Raw value read from the machine, or null when unread.

    .PARAMETER Enabled
    Whether the setting is on. Null means it could not be determined.

    .PARAMETER Requirement
    Required, Recommended, or Conditional.

    .PARAMETER Why
    Why the setting matters, carried into the report so a finding is actionable.

    .PARAMETER Detail
    Remediation pointer or diagnostic text.

    .OUTPUTS
    None. Appends to the list.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter()][AllowNull()][object]$Actual,
        [Parameter()][AllowNull()][object]$Enabled,
        [Parameter(Mandatory = $true)][ValidateSet('Required', 'Recommended', 'Conditional')][string]$Requirement,
        [Parameter(Mandatory = $true)][string]$Why,
        [Parameter()][AllowEmptyString()][string]$Detail = ''
    )

    $Record.Add([pscustomobject]@{
            ComputerName = $ComputerName
            Category = $Category
            Setting = $Setting
            Requirement = $Requirement
            Status = (Get-TelemetryCheckStatus -Actual $Actual -Requirement $Requirement -Enabled $Enabled)
            Actual = (Join-OpsValue -Value $Actual)
            Why = $Why
            Detail = $Detail
        })
}

$telemetryProbe = {
    param($AuditSubcategoryTable, $ChannelTable)

    function Get-RegValue {
        param($Path, $Name)
        try {
            return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        } catch {
            return $null
        }
    }

    function Get-SafeProperty {
        # Get-WinEvent -ListLog does not expose the same properties on every Windows
        # build, and strict mode throws on a property that is not there rather than
        # returning null. The module helper is not available inside a remote session.
        param($InputObject, $Name)
        if ($null -eq $InputObject) { return $null }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    $isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    $psPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $auditPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $forwarding = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'

    # Module logging is only meaningful together with the module names it covers. A
    # policy enabled with no ModuleNames entry logs nothing, and reads as enabled.
    $moduleNames = @()
    try {
        $moduleKey = Get-Item -LiteralPath "$psPolicy\ModuleLogging\ModuleNames" -ErrorAction Stop
        $moduleNames = @($moduleKey.GetValueNames() | ForEach-Object { $moduleKey.GetValue($_) })
    } catch {
        $moduleNames = @()
    }

    $subscriptionManagers = @()
    try {
        $subKey = Get-Item -LiteralPath $forwarding -ErrorAction Stop
        $subscriptionManagers = @($subKey.GetValueNames() | ForEach-Object { [string]$subKey.GetValue($_) } | Where-Object { $_ })
    } catch {
        $subscriptionManagers = @()
    }

    # auditpol in CSV form. The GUID column is what is matched on, so a localized
    # Windows reports the same subcategories as an English one.
    $auditRows = @()
    $auditError = ''
    try {
        $raw = & auditpol.exe /get /category:* /r 2>&1
        if ($LASTEXITCODE -ne 0) {
            $auditError = "auditpol exited $LASTEXITCODE. $(($raw | Out-String).Trim())"
        } else {
            $auditRows = @($raw | Where-Object { $_ -is [string] -and $_.Trim() } | ConvertFrom-Csv)
        }
    } catch {
        $auditError = $_.Exception.Message
    }

    if (-not $isElevated -and $auditRows.Count -eq 0 -and -not $auditError) {
        $auditError = 'Audit policy could not be read and the session is not elevated.'
    }

    $auditReadings = @()
    foreach ($guid in @($AuditSubcategoryTable.Keys)) {
        $row = $auditRows |
            Where-Object { [string](Get-SafeProperty $_ 'Subcategory GUID') -eq $guid } |
            Select-Object -First 1
        $auditReadings += [pscustomobject]@{
            Guid = $guid
            Setting = [string](Get-SafeProperty $row 'Inclusion Setting')
            Found = [bool]$row
        }
    }

    # Sysmon registers its driver under a service name the operator can change at
    # install time, so the driver is found by image path rather than by name. The match
    # is on the executable, not anywhere in the path: a bare 'Sysmon' also matches a
    # service that merely lives in a directory with Sysmon in its name, such as a log
    # viewer, and reports Sysmon as running when it is not installed at all.
    $sysmonService = $null
    try {
        $sysmonService = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.PathName -match '(?i)Sysmon(64)?\.exe' } | Select-Object -First 1
    } catch {
        $sysmonService = $null
    }

    $sysmonConfigHash = $null
    if ($sysmonService) {
        foreach ($name in @($sysmonService.Name, 'SysmonDrv', 'Sysmon64', 'Sysmon')) {
            $hash = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Parameters" 'ConfigHash'
            if ($hash) {
                $sysmonConfigHash = [string]$hash
                break
            }
        }
    }

    $channelReadings = @()
    foreach ($channel in $ChannelTable) {
        $logName = [string]$channel.LogName
        $reading = [pscustomobject]@{
            LogName = $logName
            Present = $false
            IsEnabled = $null
            LogMode = ''
            MaximumSizeBytes = $null
            FileSizeBytes = $null
            RecordCount = $null
            OldestRecordTime = $null
            IsFull = $null
            Note = ''
        }

        $log = $null
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        } catch {
            $reading.Note = $_.Exception.Message
            $channelReadings += $reading
            continue
        }

        $maxBytes = Get-SafeProperty $log 'MaximumSizeInBytes'
        $fileBytes = Get-SafeProperty $log 'FileSize'
        $records = Get-SafeProperty $log 'RecordCount'

        $reading.Present = $true
        $reading.IsEnabled = [bool](Get-SafeProperty $log 'IsEnabled')
        $reading.LogMode = [string](Get-SafeProperty $log 'LogMode')
        $reading.MaximumSizeBytes = $maxBytes
        $reading.FileSizeBytes = $fileBytes
        $reading.RecordCount = $records

        # Fullness decides whether short retention is overwriting or just youth. The
        # 95% threshold is because a rolling log sits just under its maximum rather
        # than exactly on it.
        if ($null -ne $fileBytes -and $null -ne $maxBytes -and [double]$maxBytes -gt 0) {
            $reading.IsFull = ([double]$fileBytes / [double]$maxBytes) -ge 0.95
        }

        if ($reading.IsEnabled -and $null -ne $records -and [int]$records -gt 0) {
            try {
                $oldest = Get-WinEvent -LogName $logName -Oldest -MaxEvents 1 -ErrorAction Stop
                $reading.OldestRecordTime = $oldest.TimeCreated
            } catch {
                # Reading the Security channel without elevation fails here rather
                # than at ListLog, so retention stays unmeasured instead of wrong.
                $reading.Note = $_.Exception.Message
            }
        }

        $channelReadings += $reading
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Elevated = $isElevated
        ScriptBlockLogging = Get-RegValue "$psPolicy\ScriptBlockLogging" 'EnableScriptBlockLogging'
        ScriptBlockInvocationLogging = Get-RegValue "$psPolicy\ScriptBlockLogging" 'EnableScriptBlockInvocationLogging'
        ModuleLogging = Get-RegValue "$psPolicy\ModuleLogging" 'EnableModuleLogging'
        ModuleLoggingNames = @($moduleNames)
        Transcription = Get-RegValue "$psPolicy\Transcription" 'EnableTranscripting'
        TranscriptionDirectory = [string](Get-RegValue "$psPolicy\Transcription" 'OutputDirectory')
        CommandLineAuditing = Get-RegValue $auditPolicy 'ProcessCreationIncludeCmdLine_Enabled'
        AuditReadings = @($auditReadings)
        AuditError = $auditError
        SysmonServiceName = if ($sysmonService) { [string]$sysmonService.Name } else { '' }
        SysmonState = if ($sysmonService) { [string]$sysmonService.State } else { '' }
        SysmonConfigHash = $sysmonConfigHash
        SubscriptionManagers = @($subscriptionManagers)
        ChannelReadings = @($channelReadings)
    }
}

$targets = if ($ComputerName) { @($ComputerName | Where-Object { $_ }) } else { @($env:COMPUTERNAME) }
$checkRecords = [System.Collections.Generic.List[object]]::new()
$channelRecords = [System.Collections.Generic.List[object]]::new()
$postureRecords = [System.Collections.Generic.List[object]]::new()
$asOf = Get-Date

foreach ($target in $targets) {
    $probe = $null
    try {
        if ($target -eq $env:COMPUTERNAME) {
            $probe = & $telemetryProbe $script:AuditSubcategory $script:TelemetryChannel
        } else {
            $probe = Invoke-Command -ComputerName $target -ScriptBlock $telemetryProbe `
                -ArgumentList $script:AuditSubcategory, $script:TelemetryChannel -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $postureRecords.Add([pscustomobject]@{
                ComputerName = $target
                Verdict = 'Unreachable'
                Note = $_.Exception.Message
            })
        continue
    }

    $machine = [string](Get-OpsPropertyValue -InputObject $probe -Name 'ComputerName')
    $elevated = [bool](Get-OpsPropertyValue -InputObject $probe -Name 'Elevated')

    # ---- PowerShell logging -------------------------------------------------
    $scriptBlock = Get-OpsPropertyValue -InputObject $probe -Name 'ScriptBlockLogging'
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'PowerShell' -Setting 'Script block logging' -Actual $scriptBlock `
        -Enabled $(if ($null -eq $scriptBlock) { $false } else { [int]$scriptBlock -eq 1 }) `
        -Requirement 'Required' `
        -Why 'Event 4104 records the script text that actually ran, after de-obfuscation. Nothing else recovers what a fileless payload did.' `
        -Detail 'Set Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.'

    $moduleLogging = Get-OpsPropertyValue -InputObject $probe -Name 'ModuleLogging'
    $moduleNames = @(Get-OpsPropertyValue -InputObject $probe -Name 'ModuleLoggingNames' | Where-Object { $_ })
    $moduleEnabled = if ($null -eq $moduleLogging) { $false } else { [int]$moduleLogging -eq 1 -and $moduleNames.Count -gt 0 }
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'PowerShell' -Setting 'Module logging' -Actual $moduleLogging -Enabled $moduleEnabled `
        -Requirement 'Recommended' `
        -Why 'Pipeline execution detail per module. Enabled with no module names configured logs nothing at all, which is why the name list is checked too.' `
        -Detail "Module names configured: $($moduleNames.Count)."

    $transcription = Get-OpsPropertyValue -InputObject $probe -Name 'Transcription'
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'PowerShell' -Setting 'Transcription' -Actual $transcription `
        -Enabled $(if ($null -eq $transcription) { $false } else { [int]$transcription -eq 1 }) `
        -Requirement 'Recommended' `
        -Why 'A full session transcript, including output. Useful in an investigation and expensive to store, so it is recommended rather than required.' `
        -Detail "Output directory: $([string](Get-OpsPropertyValue -InputObject $probe -Name 'TranscriptionDirectory'))"

    # ---- Process creation ---------------------------------------------------
    $commandLine = Get-OpsPropertyValue -InputObject $probe -Name 'CommandLineAuditing'
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'ProcessCreation' -Setting 'Command line in process creation events' -Actual $commandLine `
        -Enabled $(if ($null -eq $commandLine) { $false } else { [int]$commandLine -eq 1 }) `
        -Requirement 'Required' `
        -Why 'Without it 4688 records the binary but not its arguments, so a LOLBin invocation is indistinguishable from a legitimate one.' `
        -Detail 'Set Administrative Templates > System > Audit Process Creation > Include command line in process creation events.'

    # ---- Audit policy -------------------------------------------------------
    $auditError = [string](Get-OpsPropertyValue -InputObject $probe -Name 'AuditError')
    $auditReadings = @(Get-OpsPropertyValue -InputObject $probe -Name 'AuditReadings' | Where-Object { $_ })

    foreach ($guid in @($script:AuditSubcategory.Keys)) {
        $definition = $script:AuditSubcategory[$guid]
        $reading = $auditReadings | Where-Object { [string]$_.Guid -eq $guid } | Select-Object -First 1
        $setting = if ($reading) { [string](Get-OpsPropertyValue -InputObject $reading -Name 'Setting') } else { '' }

        # An unreadable audit policy is null, not false. Passing $false here would
        # report every subcategory as switched off on any unelevated run.
        $enabled = if ($auditError -or -not $reading -or -not $setting) {
            $null
        } else {
            $setting -match 'Success' -or $setting -match 'Failure'
        }

        Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
            -Category 'AuditPolicy' -Setting ([string]$definition.Name) -Actual $setting -Enabled $enabled `
            -Requirement ([string]$definition.Requirement) -Why ([string]$definition.Why) `
            -Detail $(if ($auditError) { $auditError } else { "auditpol subcategory $guid" })
    }

    # ---- Sysmon -------------------------------------------------------------
    $sysmonName = [string](Get-OpsPropertyValue -InputObject $probe -Name 'SysmonServiceName')
    $sysmonState = [string](Get-OpsPropertyValue -InputObject $probe -Name 'SysmonState')
    $sysmonHash = [string](Get-OpsPropertyValue -InputObject $probe -Name 'SysmonConfigHash')
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'Sysmon' -Setting 'Sysmon running' -Actual $sysmonState `
        -Enabled $(if ($sysmonName) { $sysmonState -eq 'Running' } else { $false }) `
        -Requirement $(if ($RequireSysmon) { 'Required' } else { 'Conditional' }) `
        -Why 'Sysmon supplies process lineage, network connections, and image loads that Windows auditing does not. Optional unless the estate has standardised on it.' `
        -Detail $(if ($sysmonName) { "Service $sysmonName, config hash $(if ($sysmonHash) { $sysmonHash } else { 'not recorded' })." } else { 'No Sysmon service found.' })

    # ---- Event forwarding ---------------------------------------------------
    $managers = @(Get-OpsPropertyValue -InputObject $probe -Name 'SubscriptionManagers' | Where-Object { $_ })
    Add-TelemetryCheck -Record $checkRecords -ComputerName $machine `
        -Category 'Forwarding' -Setting 'Event forwarding subscription manager' -Actual (Join-OpsValue -Value $managers) `
        -Enabled ($managers.Count -gt 0) `
        -Requirement $(if ($RequireEventForwarding) { 'Required' } else { 'Conditional' }) `
        -Why 'Local logs are lost with the machine. A subscription manager is what gets them somewhere central before that happens.' `
        -Detail "Subscription managers configured: $($managers.Count)."

    # ---- Channels and real retention ---------------------------------------
    $channelReadings = @(Get-OpsPropertyValue -InputObject $probe -Name 'ChannelReadings' | Where-Object { $_ })
    foreach ($definition in $script:TelemetryChannel) {
        $logName = [string]$definition.LogName
        $reading = $channelReadings | Where-Object { [string]$_.LogName -eq $logName } | Select-Object -First 1

        $present = [bool](Get-OpsPropertyValue -InputObject $reading -Name 'Present')
        $isEnabled = Get-OpsPropertyValue -InputObject $reading -Name 'IsEnabled'
        $oldest = Get-OpsPropertyValue -InputObject $reading -Name 'OldestRecordTime'
        $isFull = Get-OpsPropertyValue -InputObject $reading -Name 'IsFull'
        $note = [string](Get-OpsPropertyValue -InputObject $reading -Name 'Note')

        $retentionDays = if ($null -eq $oldest) { $null } else { [math]::Round(($asOf - [datetime]$oldest).TotalDays, 1) }
        $retentionStatus = Get-RetentionStatus -RetentionDays $retentionDays -MinimumDays $MinimumRetentionDays -IsFull $isFull

        $requirement = [string]$definition.Requirement
        $channelStatus = if (-not $present) {
            if ($requirement -eq 'Conditional') { 'NotRequired' } else { 'Absent' }
        } else {
            Get-TelemetryCheckStatus -Actual $isEnabled -Requirement $requirement -Enabled $isEnabled
        }

        $maxBytes = Get-OpsPropertyValue -InputObject $reading -Name 'MaximumSizeBytes'
        $channelRecords.Add([pscustomobject]@{
                ComputerName = $machine
                LogName = $logName
                Requirement = $requirement
                Status = $channelStatus
                LogMode = [string](Get-OpsPropertyValue -InputObject $reading -Name 'LogMode')
                MaximumSizeMB = if ($null -eq $maxBytes) { $null } else { [math]::Round([double]$maxBytes / 1MB, 1) }
                RecordCount = Get-OpsPropertyValue -InputObject $reading -Name 'RecordCount'
                OldestRecord = $oldest
                RetentionDays = $retentionDays
                MinimumRetentionDays = $MinimumRetentionDays
                RetentionStatus = $retentionStatus
                IsFull = $isFull
                Why = [string]$definition.Why
                Note = $note
            })
    }

    # ---- Verdict ------------------------------------------------------------
    $machineChecks = @($checkRecords | Where-Object { $_.ComputerName -eq $machine })
    $machineChannels = @($channelRecords | Where-Object { $_.ComputerName -eq $machine })

    $disabled = @($machineChecks | Where-Object { $_.Status -eq 'Disabled' -and $_.Requirement -eq 'Required' }) +
    @($machineChannels | Where-Object { $_.Status -in @('Disabled', 'Absent') -and $_.Requirement -eq 'Required' })
    $undetermined = @($machineChecks | Where-Object { $_.Status -eq 'Undetermined' }) +
    @($machineChannels | Where-Object { $_.Status -eq 'Undetermined' })
    # Unmeasured retention on a required channel is an unread value, not a pass.
    $unmeasured = @($machineChannels | Where-Object { $_.Requirement -eq 'Required' -and $_.RetentionStatus -eq 'Unmeasured' })
    $insufficient = @($machineChannels | Where-Object { $_.Requirement -eq 'Required' -and $_.RetentionStatus -eq 'Insufficient' })

    $graded = @($machineChecks | Where-Object { $_.Requirement -ne 'Conditional' }).Count +
    @($machineChannels | Where-Object { $_.Requirement -ne 'Conditional' }).Count

    $verdict = Get-MachineTelemetryVerdict -DisabledCount $disabled.Count `
        -UndeterminedCount ($undetermined.Count + $unmeasured.Count) `
        -InsufficientCount $insufficient.Count -CheckedCount $graded

    # The disabled set mixes setting records and channel records, which do not share a
    # name property. Reading the missing one directly throws under strict mode.
    $gaps = @()
    foreach ($item in $disabled) {
        $name = Get-OpsPropertyValue -InputObject $item -Name 'Setting'
        if (-not $name) { $name = Get-OpsPropertyValue -InputObject $item -Name 'LogName' }
        $gaps += [string]$name
    }
    foreach ($item in $insufficient) {
        $gaps += "$($item.LogName) retains $($item.RetentionDays) of $MinimumRetentionDays days"
    }

    $postureRecords.Add([pscustomobject]@{
            ComputerName = $machine
            Verdict = $verdict
            Elevated = $elevated
            ChecksGraded = $graded
            RequiredGapCount = $disabled.Count
            UndeterminedCount = $undetermined.Count + $unmeasured.Count
            InsufficientRetentionCount = $insufficient.Count
            SysmonPresent = [bool]$sysmonName
            ForwardingConfigured = ($managers.Count -gt 0)
            MinimumRetentionDays = $MinimumRetentionDays
            Gaps = ($gaps -join '; ')
            Note = $(if ($auditError) { $auditError } elseif (-not $elevated) { 'Not elevated. Audit policy and Security log retention could not be read.' } else { '' })
        })
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'telemetry-checks' -Record @($checkRecords) -Directory $runDirectory
    Export-OpsReport -Name 'log-channels' -Record @($channelRecords) -Directory $runDirectory
    Export-OpsReport -Name 'telemetry-posture' -Record @($postureRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    ComputersQueried = @($targets).Count
    MinimumRetentionDays = $MinimumRetentionDays
    RequiredSysmon = [bool]$RequireSysmon
    RequiredEventForwarding = [bool]$RequireEventForwarding
    CoveredCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Covered' }).Count
    PartialCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Partial' }).Count
    NotCoveredCount = @($postureRecords | Where-Object { $_.Verdict -eq 'NotCovered' }).Count
    UndeterminedCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    UnreachableCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Unreachable' }).Count
    ChecksGraded = $checkRecords.Count
    ChannelsGraded = $channelRecords.Count
    RequiredSettingsDisabled = @($checkRecords | Where-Object { $_.Requirement -eq 'Required' -and $_.Status -eq 'Disabled' }).Count
    SettingsUndetermined = @($checkRecords | Where-Object { $_.Status -eq 'Undetermined' }).Count
    ChannelsInsufficientRetention = @($channelRecords | Where-Object { $_.Requirement -eq 'Required' -and $_.RetentionStatus -eq 'Insufficient' }).Count
    ChannelsUnmeasuredRetention = @($channelRecords | Where-Object { $_.RetentionStatus -eq 'Unmeasured' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
