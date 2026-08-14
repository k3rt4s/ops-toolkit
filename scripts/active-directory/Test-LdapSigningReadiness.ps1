<#
.SYNOPSIS
Report which clients still bind to a domain controller without LDAP signing or channel binding, before enforcement breaks them.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads the Directory Service event log and NTDS registry values and
  writes reports. It changes no policy and enforces nothing.
- Run against each domain controller with -ComputerName. Every DC logs only its own
  clients, so checking one DC gives you one DC's worth of the answer.
- Reading a remote event log needs the Remote Event Log Management firewall rule and
  rights on the target.
- Per-client detail (event 2889) is only logged when the NTDS diagnostic "16 LDAP
  Interface Events" is set to 2. This script reports that setting first, because
  without it an empty result means logging is off, not that nothing is failing.
- Generated reports are written under reports\active-directory by default.

Purpose:
Windows Server 2025 domain controllers default to requiring LDAP signing, and channel
binding enforcement is on the same path. When enforcement lands, every client still
doing a simple or unsigned bind stops authenticating at once, and the affected
clients are usually appliances, scanners, and line-of-business services nobody has
an inventory of. The evidence needed to find them is already in the Directory
Service log and is discarded on rotation. This collects it before it is needed.

The most important output is not the client list; it is whether the logging that
would produce that list is switched on at all.

Required syntax:
pwsh -File .\scripts\active-directory\Test-LdapSigningReadiness.ps1
pwsh -File .\scripts\active-directory\Test-LdapSigningReadiness.ps1 -ComputerName dc01,dc02 -LookbackDays 14
pwsh -File .\scripts\active-directory\Test-LdapSigningReadiness.ps1 -ComputerName dc01 -MaxEvent 5000

.OUTPUTS
Writes per-DC configuration, unsigned and unbound client detail, a client rollup, and
a run summary as CSV and JSON under reports\active-directory by default. Returns a
summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$LookbackDays = 7,

    [Parameter()]
    [ValidateRange(10, 100000)]
    [int]$MaxEvent = 2000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'ldap-signing-readiness'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# The events that matter, and what each one means for enforcement.
$script:LdapEvent = @{
    2886 = [pscustomobject]@{
        Meaning = 'This DC does not require LDAP signing. Unsigned binds are being accepted.'
        Severity = 'High'
        Kind = 'Configuration'
    }
    2887 = [pscustomobject]@{
        Meaning = 'Summary of unsigned or simple binds rejected or accepted in the last 24 hours.'
        Severity = 'Medium'
        Kind = 'Summary'
    }
    2888 = [pscustomobject]@{
        Meaning = 'Summary of binds rejected because signing is required.'
        Severity = 'Medium'
        Kind = 'Summary'
    }
    2889 = [pscustomobject]@{
        Meaning = 'A specific client performed an unsigned or simple LDAP bind. This client breaks on enforcement.'
        Severity = 'High'
        Kind = 'ClientDetail'
    }
    3039 = [pscustomobject]@{
        Meaning = 'A specific client bound without a channel binding token. This client breaks on channel binding enforcement.'
        Severity = 'High'
        Kind = 'ClientDetail'
    }
    3040 = [pscustomobject]@{
        Meaning = 'Summary of binds performed without channel binding tokens.'
        Severity = 'Medium'
        Kind = 'Summary'
    }
    3041 = [pscustomobject]@{
        Meaning = 'Summary of binds rejected for missing channel binding.'
        Severity = 'Medium'
        Kind = 'Summary'
    }
}

function Get-LdapClientDetail {
    <#
    .SYNOPSIS
    Pull the client address and identity out of a 2889 or 3039 event message.

    .DESCRIPTION
    These events carry the client address and bound identity in the message body
    rather than in named data fields, so the values are extracted by pattern. An
    address that cannot be parsed is returned empty rather than guessed, because a
    wrong address sends someone to remediate the wrong device.

    .PARAMETER Message
    The event message text.

    .OUTPUTS
    PSCustomObject with ClientAddress, ClientPort, and Identity.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message
    )

    $address = ''
    $port = ''
    $identity = ''

    # IPv4 with port, IPv6 with port, or a bare address.
    $addressMatch = [regex]::Match($Message, '(?m)^\s*(?:Client\s*(?:IP\s*address|Network\s*Address)?\s*:?\s*)?(?<addr>\[?[0-9a-fA-F:.]+\]?):(?<port>\d{1,5})\s*$')
    if (-not $addressMatch.Success) {
        $addressMatch = [regex]::Match($Message, '(?<addr>\b\d{1,3}(?:\.\d{1,3}){3}\b):(?<port>\d{1,5})')
    }

    if ($addressMatch.Success) {
        $address = $addressMatch.Groups['addr'].Value.Trim('[', ']')
        $port = $addressMatch.Groups['port'].Value
    }

    $identityMatch = [regex]::Match($Message, '(?im)^\s*Identity\s*(?:the client attempted to authenticate as)?\s*:?\s*(?<id>.+?)\s*$')
    if ($identityMatch.Success) {
        $identity = $identityMatch.Groups['id'].Value
    }

    [pscustomobject]@{
        ClientAddress = $address
        ClientPort = $port
        Identity = $identity
    }
}

$asOf = Get-Date
$startTime = $asOf.AddDays(-$LookbackDays)
$configRecords = [System.Collections.Generic.List[object]]::new()
$clientRecords = [System.Collections.Generic.List[object]]::new()
$eventRecords = [System.Collections.Generic.List[object]]::new()

foreach ($target in $ComputerName) {
    $isLocal = $target -eq $env:COMPUTERNAME
    $registryError = ''
    $ldapServerIntegrity = $null
    $channelBinding = $null
    $diagnosticLevel = $null

    try {
        $readRegistry = {
            $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $diag = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
            [pscustomobject]@{
                LDAPServerIntegrity = (Get-ItemProperty -Path $ntds -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
                LdapEnforceChannelBinding = (Get-ItemProperty -Path $ntds -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
                LdapInterfaceEvents = (Get-ItemProperty -Path $diag -Name '16 LDAP Interface Events' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
            }
        }

        $registry = if ($isLocal) { & $readRegistry } else { Invoke-Command -ComputerName $target -ScriptBlock $readRegistry -ErrorAction Stop }
        $ldapServerIntegrity = $registry.LDAPServerIntegrity
        $channelBinding = $registry.LdapEnforceChannelBinding
        $diagnosticLevel = $registry.LdapInterfaceEvents
    } catch {
        $registryError = $_.Exception.Message
    }

    # 1 is "none", 2 is "require signing". Unset behaves as 1 on pre-2025 DCs and as
    # 2 on Windows Server 2025, which is the entire compatibility problem.
    $signingState = switch ([int]($ldapServerIntegrity ?? -1)) {
        1 { 'NotRequired' }
        2 { 'Required' }
        default { 'NotConfigured' }
    }

    $channelBindingState = switch ([int]($channelBinding ?? -1)) {
        0 { 'Never' }
        1 { 'WhenSupported' }
        2 { 'Always' }
        default { 'NotConfigured' }
    }

    $loggingEnabled = [int]($diagnosticLevel ?? 0) -ge 2

    $events = @()
    $eventError = ''
    try {
        $filter = @{ LogName = 'Directory Service'; Id = @($script:LdapEvent.Keys); StartTime = $startTime }
        $eventParameter = @{ FilterHashtable = $filter; MaxEvents = $MaxEvent; ErrorAction = 'Stop' }
        if (-not $isLocal) {
            $eventParameter['ComputerName'] = $target
        }

        $events = @(Get-WinEvent @eventParameter)
    } catch {
        # "No events were found" is a normal outcome, not a failure, and must not be
        # reported as one or it reads as an inability to check.
        if ($_.Exception.Message -match 'No events were found') {
            $events = @()
        } else {
            $eventError = $_.Exception.Message
        }
    }

    foreach ($logEvent in $events) {
        $meta = $script:LdapEvent[[int]$logEvent.Id]
        $eventRecords.Add([pscustomobject]@{
                ComputerName = $target
                TimeCreated = $logEvent.TimeCreated
                EventId = $logEvent.Id
                Kind = $meta.Kind
                Severity = $meta.Severity
                Meaning = $meta.Meaning
                Message = ($logEvent.Message -replace '\s+', ' ').Trim()
            })

        if ($meta.Kind -ne 'ClientDetail') {
            continue
        }

        $detail = Get-LdapClientDetail -Message ([string]$logEvent.Message)
        $clientRecords.Add([pscustomobject]@{
                ComputerName = $target
                TimeCreated = $logEvent.TimeCreated
                EventId = $logEvent.Id
                Issue = if ([int]$logEvent.Id -eq 2889) { 'UnsignedBind' } else { 'NoChannelBinding' }
                ClientAddress = $detail.ClientAddress
                ClientPort = $detail.ClientPort
                Identity = $detail.Identity
            })
    }

    $detailEvents = @($eventRecords | Where-Object { $_.ComputerName -eq $target -and $_.Kind -eq 'ClientDetail' })
    $distinctClients = @($clientRecords | Where-Object { $_.ComputerName -eq $target -and $_.ClientAddress } |
            Select-Object -ExpandProperty ClientAddress -Unique)

    # Readiness is about what happens when enforcement lands, so a DC with no
    # evidence and no logging is not ready; it is unmeasured.
    $readiness = if ($registryError) {
        'Unreachable'
    } elseif (-not $loggingEnabled -and $detailEvents.Count -eq 0) {
        'Unmeasured'
    } elseif ($distinctClients.Count -gt 0) {
        'ClientsWillBreak'
    } elseif ($signingState -eq 'Required' -and $channelBindingState -eq 'Always') {
        'AlreadyEnforced'
    } else {
        'NoEvidenceOfBreakage'
    }

    $configRecords.Add([pscustomobject]@{
            ComputerName = $target
            Readiness = $readiness
            LdapSigning = $signingState
            LdapServerIntegrityValue = $ldapServerIntegrity
            ChannelBinding = $channelBindingState
            LdapEnforceChannelBindingValue = $channelBinding
            DiagnosticLoggingLevel = $diagnosticLevel
            PerClientLoggingEnabled = $loggingEnabled
            LookbackDays = $LookbackDays
            EventsRead = @($eventRecords | Where-Object { $_.ComputerName -eq $target }).Count
            ClientDetailEvents = $detailEvents.Count
            DistinctClientCount = $distinctClients.Count
            Note = @(
                $registryError
                $eventError
                if (-not $loggingEnabled) { 'Per-client logging is off. Set NTDS Diagnostics "16 LDAP Interface Events" to 2 to record which clients are affected, then re-run after a representative period.' }
            ) | Where-Object { $_ } | Join-String -Separator ' | '
        })
}

$clientRollup = foreach ($group in (@($clientRecords) | Where-Object { $_.ClientAddress } | Group-Object -Property ClientAddress)) {
    $rows = @($group.Group)
    [pscustomobject]@{
        ClientAddress = $group.Name
        BindCount = $rows.Count
        UnsignedBindCount = @($rows | Where-Object { $_.Issue -eq 'UnsignedBind' }).Count
        NoChannelBindingCount = @($rows | Where-Object { $_.Issue -eq 'NoChannelBinding' }).Count
        Identities = (@($rows | ForEach-Object { $_.Identity } | Where-Object { $_ } | Select-Object -Unique) -join ';')
        DomainControllers = (@($rows | ForEach-Object { $_.ComputerName } | Select-Object -Unique) -join ';')
        FirstSeen = ($rows | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        LastSeen = ($rows | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'dc-configuration' -Record @($configRecords) -Directory $runDirectory
    Export-OpsReport -Name 'client-rollup' -Record @($clientRollup) -Directory $runDirectory
    Export-OpsReport -Name 'client-binds' -Record @($clientRecords) -Directory $runDirectory
    Export-OpsReport -Name 'ldap-events' -Record @($eventRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    LookbackDays = $LookbackDays
    LookbackStart = $startTime
    DomainControllersChecked = @($ComputerName).Count
    ClientsWillBreakCount = @($configRecords | Where-Object { $_.Readiness -eq 'ClientsWillBreak' }).Count
    UnmeasuredCount = @($configRecords | Where-Object { $_.Readiness -eq 'Unmeasured' }).Count
    AlreadyEnforcedCount = @($configRecords | Where-Object { $_.Readiness -eq 'AlreadyEnforced' }).Count
    UnreachableCount = @($configRecords | Where-Object { $_.Readiness -eq 'Unreachable' }).Count
    DistinctAffectedClients = @($clientRollup).Count
    TotalClientDetailEvents = @($clientRecords).Count
    LoggingDisabledOnCount = @($configRecords | Where-Object { -not $_.PerClientLoggingEnabled }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
