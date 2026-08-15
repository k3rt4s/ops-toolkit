<#
.SYNOPSIS
Report mailbox forwarding, legacy protocol exposure, and EWS use across Exchange Online before the 2026 cutoffs.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads mailbox and organization configuration and writes reports. It
  disables no protocol and removes no forwarding rule.
- Requires the ExchangeOnlineManagement module and a role that can read mailbox
  configuration. View-Only Recipients plus View-Only Configuration is enough.
- Use -Connect when the shell is not already connected to Exchange Online. Do not
  use -Credential with Connect-ExchangeOnline: it relies on ROPC, cannot satisfy MFA
  or Conditional Access, and is removed from module versions released December 2026
  or later.
- -IncludeInboxRules reads every mailbox's rules, which is one call per mailbox and
  slow on a large tenant. It is off by default and worth the wait when investigating.
- No message content is read. Only configuration, addresses, and rule definitions.
- Generated reports are written under reports\microsoft-365 by default.

Purpose:
Two Exchange Online deadlines land in 2026: non-Microsoft applications are blocked
from using EWS on 1 October, and the -Credential parameter disappears from the
PowerShell module in December. Both are visible in configuration before they bite.

The same pass answers the question that matters more often, which is who is quietly
forwarding mail out of the organisation. External forwarding is the standard
persistence and exfiltration mechanism after a mailbox compromise, it survives a
password reset, and it is invisible unless someone looks. Forwarding set on the
mailbox and forwarding set by an inbox rule are different objects and are reported
separately, because remediating one does not touch the other.

Required syntax:
pwsh -File .\scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1 -Connect
pwsh -File .\scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1 -Connect -IncludeInboxRules
pwsh -File .\scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1 -Connect -Organization contoso.onmicrosoft.com -InternalDomain contoso.com,contoso.co.uk

.OUTPUTS
Writes mailbox posture, forwarding findings, protocol exposure, organization
settings, and a run summary as CSV and JSON under reports\microsoft-365 by default.
Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Organization,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$InternalDomain,

    [Parameter()]
    [switch]$IncludeInboxRules,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaxMailbox = 10000,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [switch]$DisconnectWhenFinished,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\microsoft-365'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'm365-mailbox-security-posture'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Assert-ExchangeCommand {
    <#
    .SYNOPSIS
    Fail with a clear message when an Exchange Online cmdlet is not available.

    .PARAMETER CommandName
    The cmdlet to check for.

    .OUTPUTS
    None.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName
    )

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName is not available. Connect with -Connect, or update the ExchangeOnlineManagement module."
    }
}

function Test-ExternalAddress {
    <#
    .SYNOPSIS
    Return true when an address is outside the supplied internal domains.

    .DESCRIPTION
    With no internal domain list, nothing can be classified, so this returns false
    and the caller reports the destination as unclassified rather than asserting it
    is internal. Calling an unknown destination internal is the failure that matters.

    .PARAMETER Address
    The address or forwarding target to test.

    .PARAMETER InternalDomain
    Domains considered internal.

    .OUTPUTS
    Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Address,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$InternalDomain = @()
    )

    if (-not $Address -or $InternalDomain.Count -eq 0) {
        return $false
    }

    # Forwarding targets arrive in several shapes: smtp:user@x, an X500 style path,
    # or a bare address. Only the last @-delimited segment is the domain.
    $candidate = $Address
    if ($candidate -match '([^\s:<>]+@[^\s:<>]+)') {
        $candidate = $Matches[1]
    }

    if ($candidate -notmatch '@') {
        return $false
    }

    $domain = ($candidate -split '@')[-1].Trim().TrimEnd('>', '"', "'")
    foreach ($internal in $InternalDomain) {
        if ($domain -ieq $internal) {
            return $false
        }
    }

    $true
}

function Get-ForwardingDestination {
    <#
    .SYNOPSIS
    Pull a readable destination out of a forwarding value.

    .PARAMETER Value
    The raw ForwardingAddress or ForwardingSmtpAddress value.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    $text = Join-OpsValue -Value $Value
    if (-not $text) {
        return ''
    }

    $text -replace '^smtp:', ''
}

if ($Connect) {
    Assert-ExchangeCommand -CommandName 'Connect-ExchangeOnline'
    $connectParameter = @{ ShowBanner = $false }
    if ($Organization) {
        $connectParameter['Organization'] = $Organization
    }

    Connect-ExchangeOnline @connectParameter | Out-Null
}

Assert-ExchangeCommand -CommandName 'Get-Mailbox'
Assert-ExchangeCommand -CommandName 'Get-CASMailbox'

$asOf = Get-Date

# Filter nulls. An unbound [string[]] parameter is $null, and @($null) is a
# one-element array containing null, so a bare @($InternalDomain) has Count 1. That
# made the accepted-domain lookup below never run, reported InternalDomainsKnown as
# true when nothing was known, and classified every destination as External because
# nothing matched the null entry.
$internalDomains = @($InternalDomain | Where-Object { $_ })

# Accepted domains are the authoritative internal list. Ask the tenant rather than
# making the operator supply it, and fall back to what was passed.
if ($internalDomains.Count -eq 0 -and (Get-Command -Name Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
    try {
        $internalDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { [string]$_.DomainName })
        Write-Verbose "Using $($internalDomains.Count) accepted domain(s) as the internal list."
    } catch {
        Write-Warning "Could not read accepted domains: $($_.Exception.Message). External classification will be reported as unclassified."
    }
}

if ($internalDomains.Count -eq 0) {
    Write-Warning 'No internal domains are known, so forwarding destinations cannot be classified as external. Pass -InternalDomain to enable that.'
}

Write-Verbose 'Reading mailboxes.'
$mailboxes = @(Get-Mailbox -ResultSize $MaxMailbox)
Write-Verbose "Read $($mailboxes.Count) mailbox(es). Reading client access settings."
$casMailboxes = @(Get-CASMailbox -ResultSize $MaxMailbox)
$casByGuid = @{}
foreach ($cas in $casMailboxes) {
    $key = [string]$cas.Guid
    if ($key) {
        $casByGuid[$key] = $cas
    }
}

$mailboxRecords = [System.Collections.Generic.List[object]]::new()
$forwardingFindings = [System.Collections.Generic.List[object]]::new()
$protocolFindings = [System.Collections.Generic.List[object]]::new()
$ruleFindings = [System.Collections.Generic.List[object]]::new()

foreach ($mailbox in $mailboxes) {
    $upn = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'UserPrincipalName')
    $primary = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'PrimarySmtpAddress')
    $cas = $casByGuid[[string]$mailbox.Guid]

    $forwardingAddress = Get-ForwardingDestination -Value (Get-OpsPropertyValue -InputObject $mailbox -Name 'ForwardingAddress')
    $forwardingSmtp = Get-ForwardingDestination -Value (Get-OpsPropertyValue -InputObject $mailbox -Name 'ForwardingSmtpAddress')
    $deliverAndForward = [bool](Get-OpsPropertyValue -InputObject $mailbox -Name 'DeliverToMailboxAndForward')

    $imapEnabled = if ($cas) { [bool](Get-OpsPropertyValue -InputObject $cas -Name 'ImapEnabled') } else { $null }
    $popEnabled = if ($cas) { [bool](Get-OpsPropertyValue -InputObject $cas -Name 'PopEnabled') } else { $null }
    $ewsEnabled = if ($cas) { Get-OpsPropertyValue -InputObject $cas -Name 'EwsEnabled' } else { $null }
    $activeSync = if ($cas) { [bool](Get-OpsPropertyValue -InputObject $cas -Name 'ActiveSyncEnabled') } else { $null }
    $smtpAuthDisabled = if ($cas) { Get-OpsPropertyValue -InputObject $cas -Name 'SmtpClientAuthenticationDisabled' } else { $null }

    $mailboxRecords.Add([pscustomobject]@{
            UserPrincipalName = $upn
            PrimarySmtpAddress = $primary
            DisplayName = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'DisplayName')
            RecipientTypeDetails = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'RecipientTypeDetails')
            ForwardingAddress = $forwardingAddress
            ForwardingSmtpAddress = $forwardingSmtp
            DeliverToMailboxAndForward = $deliverAndForward
            ImapEnabled = $imapEnabled
            PopEnabled = $popEnabled
            EwsEnabled = $ewsEnabled
            ActiveSyncEnabled = $activeSync
            SmtpClientAuthenticationDisabled = $smtpAuthDisabled
            LitigationHoldEnabled = Get-OpsPropertyValue -InputObject $mailbox -Name 'LitigationHoldEnabled'
            AuditEnabled = Get-OpsPropertyValue -InputObject $mailbox -Name 'AuditEnabled'
        })

    foreach ($pair in @(
            @{ Kind = 'MailboxForwardingAddress'; Value = $forwardingAddress },
            @{ Kind = 'MailboxForwardingSmtpAddress'; Value = $forwardingSmtp }
        )) {
        if (-not $pair.Value) {
            continue
        }

        $isExternal = Test-ExternalAddress -Address $pair.Value -InternalDomain $internalDomains
        $classification = if ($internalDomains.Count -eq 0) { 'Unclassified' } elseif ($isExternal) { 'External' } else { 'Internal' }

        $forwardingFindings.Add([pscustomobject]@{
                Severity = if ($classification -eq 'External') { 'High' } elseif ($classification -eq 'Unclassified') { 'Medium' } else { 'Low' }
                Kind = $pair.Kind
                Classification = $classification
                UserPrincipalName = $upn
                PrimarySmtpAddress = $primary
                Destination = $pair.Value
                DeliverToMailboxAndForward = $deliverAndForward
                Note = if ($classification -eq 'External') {
                    'Mail is leaving the organisation. Confirm this was requested; external forwarding is the standard persistence mechanism after a mailbox compromise and survives a password reset.'
                } elseif ($classification -eq 'Unclassified') {
                    'No internal domain list was available, so this destination could not be classified. Re-run with -InternalDomain.'
                } else {
                    'Internal forwarding. Confirm it is still wanted.'
                }
            })
    }

    # Legacy protocol exposure, framed against the dates that make it urgent.
    foreach ($protocol in @(
            @{ Name = 'IMAP'; Enabled = $imapEnabled; Severity = 'High'; Note = 'IMAP is a legacy protocol path. Disable it per mailbox unless a documented client needs it.' },
            @{ Name = 'POP'; Enabled = $popEnabled; Severity = 'High'; Note = 'POP is a legacy protocol path. Disable it per mailbox unless a documented client needs it.' },
            @{ Name = 'EWS'; Enabled = $ewsEnabled; Severity = 'Medium'; Note = 'Microsoft blocks non-Microsoft applications from using EWS against Exchange Online from 1 October 2026. Identify what still uses it and move it to Microsoft Graph.' },
            @{ Name = 'ActiveSync'; Enabled = $activeSync; Severity = 'Low'; Note = 'ActiveSync is enabled. Review whether mobile access should go through Outlook mobile and Conditional Access instead.' }
        )) {
        if ($protocol.Enabled -ne $true) {
            continue
        }

        $protocolFindings.Add([pscustomobject]@{
                Severity = $protocol.Severity
                Protocol = $protocol.Name
                UserPrincipalName = $upn
                PrimarySmtpAddress = $primary
                RecipientTypeDetails = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'RecipientTypeDetails')
                Note = $protocol.Note
            })
    }

    if ($smtpAuthDisabled -eq $false) {
        $protocolFindings.Add([pscustomobject]@{
                Severity = 'High'
                Protocol = 'SMTP AUTH'
                UserPrincipalName = $upn
                PrimarySmtpAddress = $primary
                RecipientTypeDetails = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'RecipientTypeDetails')
                Note = 'SMTP client authentication is explicitly enabled on this mailbox, which overrides the organization default and permits basic authentication for sending.'
            })
    }
}

if ($IncludeInboxRules) {
    Assert-ExchangeCommand -CommandName 'Get-InboxRule'
    Write-Verbose "Reading inbox rules for $($mailboxes.Count) mailbox(es). This is one call each."

    foreach ($mailbox in $mailboxes) {
        $upn = Join-OpsValue (Get-OpsPropertyValue -InputObject $mailbox -Name 'UserPrincipalName')
        $rules = @()
        try {
            $rules = @(Get-InboxRule -Mailbox $mailbox.Guid.ToString() -ErrorAction Stop)
        } catch {
            Write-Warning "Could not read inbox rules for $upn : $($_.Exception.Message)"
            continue
        }

        foreach ($rule in $rules) {
            $destinations = @()
            foreach ($property in @('ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo')) {
                foreach ($entry in @(Get-OpsPropertyValue -InputObject $rule -Name $property)) {
                    if ($entry) {
                        $destinations += [pscustomobject]@{ Property = $property; Value = (Get-ForwardingDestination -Value $entry) }
                    }
                }
            }

            if ($destinations.Count -eq 0) {
                continue
            }

            foreach ($destination in $destinations) {
                $isExternal = Test-ExternalAddress -Address $destination.Value -InternalDomain $internalDomains
                $classification = if ($internalDomains.Count -eq 0) { 'Unclassified' } elseif ($isExternal) { 'External' } else { 'Internal' }

                $ruleFindings.Add([pscustomobject]@{
                        Severity = if ($classification -eq 'External') { 'High' } elseif ($classification -eq 'Unclassified') { 'Medium' } else { 'Low' }
                        Classification = $classification
                        UserPrincipalName = $upn
                        RuleName = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'Name')
                        RuleEnabled = Get-OpsPropertyValue -InputObject $rule -Name 'Enabled'
                        Action = $destination.Property
                        Destination = $destination.Value
                        # A rule that hides mail after forwarding it is the classic
                        # compromise pattern, not an ordinary convenience rule.
                        AlsoDeletesOrMoves = [bool]((Get-OpsPropertyValue -InputObject $rule -Name 'DeleteMessage') -or (Get-OpsPropertyValue -InputObject $rule -Name 'MoveToFolder'))
                        Note = 'Inbox rule forwarding is set by the user and is not removed by clearing mailbox forwarding. Both have to be checked.'
                    })
            }
        }
    }
}

# Organization-level settings that decide the default for every mailbox.
$orgRecords = [System.Collections.Generic.List[object]]::new()
function Add-OrgSetting {
    param($Name, $Value, $Assessment, $Note)
    $orgRecords.Add([pscustomobject]@{ Setting = $Name; Value = Join-OpsValue $Value; Assessment = $Assessment; Note = $Note })
}

if (Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue) {
    try {
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        $smtpDisabled = Get-OpsPropertyValue -InputObject $orgConfig -Name 'SmtpClientAuthenticationDisabled'
        $smtpAssessment = if ($smtpDisabled -eq $true) { 'Good' } else { 'Review' }
        $smtpNote = 'When false, basic authentication for SMTP sending is permitted tenant-wide unless a mailbox overrides it.'
        Add-OrgSetting 'SmtpClientAuthenticationDisabled' $smtpDisabled $smtpAssessment $smtpNote

        $ewsPolicy = Get-OpsPropertyValue -InputObject $orgConfig -Name 'EwsApplicationAccessPolicy'
        $ewsAssessment = if ($ewsPolicy) { 'Configured' } else { 'Review' }
        $ewsNote = 'Controls which applications may use EWS. Microsoft blocks non-Microsoft applications from EWS against Exchange Online from 1 October 2026.'
        Add-OrgSetting 'EwsApplicationAccessPolicy' $ewsPolicy $ewsAssessment $ewsNote

        Add-OrgSetting 'EwsAllowList' (Get-OpsPropertyValue -InputObject $orgConfig -Name 'EwsAllowList') 'Informational' 'Applications explicitly allowed to use EWS.'
        Add-OrgSetting 'EwsEnabled' (Get-OpsPropertyValue -InputObject $orgConfig -Name 'EwsEnabled') 'Informational' 'Tenant-level EWS switch.'

        $auditDisabled = Get-OpsPropertyValue -InputObject $orgConfig -Name 'AuditDisabled'
        $auditAssessment = if ($auditDisabled -eq $true) { 'Bad' } else { 'Good' }
        $auditNote = 'When true, mailbox auditing is off tenant-wide and an investigation has nothing to work from.'
        Add-OrgSetting 'AuditDisabled' $auditDisabled $auditAssessment $auditNote
    } catch {
        Write-Warning "Could not read the organization configuration: $($_.Exception.Message)"
    }
}

if (Get-Command -Name Get-HostedOutboundSpamFilterPolicy -ErrorAction SilentlyContinue) {
    try {
        foreach ($policy in (Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)) {
            $mode = Join-OpsValue (Get-OpsPropertyValue -InputObject $policy -Name 'AutoForwardingMode')
            $modeAssessment = if ($mode -ieq 'Off') { 'Good' } elseif ($mode -ieq 'Automatic') { 'Review' } else { 'Bad' }
            $modeNote = 'Off blocks automatic external forwarding outright. On permits it. Automatic lets the service decide.'
            Add-OrgSetting "AutoForwardingMode ($($policy.Name))" $mode $modeAssessment $modeNote
        }
    } catch {
        Write-Warning "Could not read outbound spam filter policies: $($_.Exception.Message)"
    }
}

$allForwarding = @(@($forwardingFindings) + @($ruleFindings)) | Sort-Object -Property @{ Expression = { Get-OpsSeverityRank -Severity $_.Severity } }, UserPrincipalName
$sortedProtocols = @($protocolFindings) | Sort-Object -Property @{ Expression = { Get-OpsSeverityRank -Severity $_.Severity } }, Protocol, UserPrincipalName

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'mailbox-posture' -Record @($mailboxRecords) -Directory $runDirectory
    Export-OpsReport -Name 'forwarding-findings' -Record @($forwardingFindings) -Directory $runDirectory
    Export-OpsReport -Name 'inbox-rule-forwarding' -Record @($ruleFindings) -Directory $runDirectory
    Export-OpsReport -Name 'protocol-exposure' -Record $sortedProtocols -Directory $runDirectory
    Export-OpsReport -Name 'organization-settings' -Record @($orgRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    Organization = $Organization
    InternalDomains = @($internalDomains)
    InternalDomainsKnown = $internalDomains.Count -gt 0
    IncludedInboxRules = [bool]$IncludeInboxRules
    MailboxCount = $mailboxRecords.Count
    MailboxForwardingCount = $forwardingFindings.Count
    ExternalForwardingCount = @($allForwarding | Where-Object { $_.Classification -eq 'External' }).Count
    UnclassifiedForwardingCount = @($allForwarding | Where-Object { $_.Classification -eq 'Unclassified' }).Count
    InboxRuleForwardingCount = $ruleFindings.Count
    InboxRuleForwardAndHideCount = @($ruleFindings | Where-Object { $_.AlsoDeletesOrMoves }).Count
    ImapEnabledCount = @($sortedProtocols | Where-Object { $_.Protocol -eq 'IMAP' }).Count
    PopEnabledCount = @($sortedProtocols | Where-Object { $_.Protocol -eq 'POP' }).Count
    EwsEnabledCount = @($sortedProtocols | Where-Object { $_.Protocol -eq 'EWS' }).Count
    SmtpAuthEnabledCount = @($sortedProtocols | Where-Object { $_.Protocol -eq 'SMTP AUTH' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($DisconnectWhenFinished -and (Get-Command -Name Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
