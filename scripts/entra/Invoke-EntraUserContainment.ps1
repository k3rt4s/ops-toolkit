<#
.SYNOPSIS
Contain one or more suspected-compromised Entra user accounts by revoking sessions, disabling the account, optionally resetting the password, and exporting inbox rules and forwarding as evidence.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Run with -WhatIf first. The plan names exactly what will change for each user and why
  anything is skipped. The same run directory also receives the Exchange Online export,
  because the export is a read and runs under -WhatIf too.
- Requires Microsoft.Graph.Authentication only. Graph calls go through
  Invoke-MgGraphRequest against v1.0. Use -Connect when the shell has no Microsoft
  Graph session yet; -TenantId applies only to a new connection.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to
  one developer's workstation must never be applied to someone else's tenant. Reports go
  to a timestamped entra-containment-yyyyMMdd_HHmmss folder under it.
- -UserPrincipalName takes one or more UPNs. A comma-joined value is split, so a caller
  that can only pass strings still reaches every user.

What it does, in this order, for each user:
1. Looks the user up (id, accountEnabled, onPremisesSyncEnabled). A 404 is NotFound and
   nothing is attempted for that user. Any other failure is NotAssessed and nothing is
   attempted for that user.
2. Exports the user's inbox rules (Get-InboxRule) and mailbox forwarding (Get-Mailbox:
   ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward) through
   Exchange Online. This runs BEFORE any containment write so the evidence is the
   pre-containment state. It never deletes or changes a rule or a forward; removing them
   is a separate, deliberate decision. Each cmdlet is first confirmed to come from the
   ExchangeOnlineManagement module (or its generated tmpEXO_ proxy module); a missing
   cmdlet, or one supplied by Security and Compliance PowerShell or on-premises
   Exchange, makes the export NotAssessed for the run. Run Connect-ExchangeOnline and
   re-run with -ExportOnly to collect it. A user with no mailbox is NoMailbox, not a
   failure.
3. Revokes sign-in sessions (POST revokeSignInSessions). Works for synced and cloud-only
   users alike. Not reversible.
4. Disables the account (PATCH accountEnabled false) and records the prior value for
   rollback. An account that was already disabled is AlreadyDisabled and is not touched.
   A user with onPremisesSyncEnabled true is RequiresOnPremises: Graph refuses writes to
   on-premises-mastered attributes and directory sync would revert it anyway. Disable
   the account in Active Directory instead; scripts\active-directory\ holds the AD
   scripts.
5. With -ResetPassword only: sets a generated password and forces a change at next
   sign-in. Synced users are RequiresOnPremises, as for disable. Not reversible, and
   rollback never touches passwords.

Passwords: each -ResetPassword password is generated with
System.Security.Cryptography.RandomNumberGenerator (24 characters, all four character
classes) and shown ONCE on the console with Write-Host, labeled with the UPN. It is
never written to any report, summary, plan, state, rollback file, or error text. Under
-WhatIf no password is generated or shown. WARNING: an active Start-Transcript, or any
host that captures console output, will record the password. Stop transcription before
using -ResetPassword, and pass the password to the user over a separate channel.

Result values per user per action: Planned (plan only), Previewed (-WhatIf), Done,
AlreadyDisabled, RequiresOnPremises, NotFound, NotAssessed, NoMailbox (export only), and
Failed:<message>. Nothing that did not run is reported Done.

Graph permissions, least privileged per call, requested only when needed: User.Read.All
(lookup), User.RevokeSessions.All (revoke), User.EnableDisableAccount.All (disable and
rollback), User-PasswordProfile.ReadWrite.All (reset, only with -ResetPassword).

-Rollback re-enables only accounts whose recorded prior state was enabled and that this
script disabled; everything else is skipped with a reason. By default it reads the newest
containment run in -ReportDirectory that disabled at least one account; use
-RollbackStatePath to name a specific containment-rollback.json. Revoked sessions and
reset passwords cannot be restored.

Required syntax:
pwsh -File .\scripts\entra\Invoke-EntraUserContainment.ps1 -Connect -ReportDirectory <dir> -UserPrincipalName user@contoso.com -WhatIf
pwsh -File .\scripts\entra\Invoke-EntraUserContainment.ps1 -Connect -ReportDirectory <dir> -UserPrincipalName user1@contoso.com,user2@contoso.com
pwsh -File .\scripts\entra\Invoke-EntraUserContainment.ps1 -ReportDirectory <dir> -UserPrincipalName user@contoso.com -ResetPassword
pwsh -File .\scripts\entra\Invoke-EntraUserContainment.ps1 -ReportDirectory <dir> -UserPrincipalName user@contoso.com -ExportOnly
pwsh -File .\scripts\entra\Invoke-EntraUserContainment.ps1 -Connect -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes containment-plan, containment-state, inbox-rules, and mailbox-forwarding reports as
CSV and JSON, a containment-rollback.json, and summary.json under the run directory.
Returns a summary object. The summary never contains a generated password.

.NOTES
Status:
Active script in the ops-toolkit repo. Verified against stubbed Graph and Exchange Online
responses only; it has never run against a live tenant.
#>
#Requires -Version 7
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Contain')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Contain')]
    [ValidateNotNullOrEmpty()]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter(ParameterSetName = 'Contain')]
    [switch]$ResetPassword,

    [Parameter(ParameterSetName = 'Contain')]
    [switch]$ExportOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [switch]$Rollback,

    [Parameter(ParameterSetName = 'Rollback')]
    [ValidateNotNullOrEmpty()]
    [string]$RollbackStatePath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

# Split into a separate variable: assigning an empty list back to the validated parameter
# would fail with a validation error instead of the refusal below.
$targetUpn = @()
if ($PSBoundParameters.ContainsKey('UserPrincipalName')) {
    $targetUpn = @(ConvertTo-OpsSplitList -Value $UserPrincipalName)
}

$script:GraphBase = 'https://graph.microsoft.com/v1.0'
$script:Findings = [System.Collections.Generic.List[string]]::new()

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

function Get-ContainmentErrorInfo {
    <#
    .SYNOPSIS
    Reduce a failed call to a status code and a short message with any secret removed.

    .PARAMETER ErrorRecord
    The caught error record.

    .PARAMETER Secret
    A value that must never appear in the returned message.

    .OUTPUTS
    PSCustomObject with StatusCode (int or null), IsNotFound, and Message.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Secret
    )

    $exception = Get-OpsPropertyValue -InputObject $ErrorRecord -Name 'Exception'
    $text = [string](Get-OpsPropertyValue -InputObject $exception -Name 'Message')
    $details = Get-OpsPropertyValue -InputObject $ErrorRecord -Name 'ErrorDetails'
    $detailText = [string](Get-OpsPropertyValue -InputObject $details -Name 'Message')
    if ($detailText) { $text = "$text $detailText" }

    $statusCode = $null
    $response = Get-OpsPropertyValue -InputObject $exception -Name 'Response'
    $rawStatus = Get-OpsPropertyValue -InputObject $response -Name 'StatusCode'
    if ($null -ne $rawStatus) {
        try { $statusCode = [int]$rawStatus } catch { $statusCode = $null }
    }

    $isNotFound = ($statusCode -eq 404) -or ($null -eq $statusCode -and $text -match 'Request_ResourceNotFound|ResourceNotFound|\bNotFound\b|\b404\b')

    if ($Secret) { $text = $text.Replace($Secret, '[redacted]') }
    $text = ($text -replace '\s+', ' ').Trim()
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }

    [pscustomobject]@{ StatusCode = $statusCode; IsNotFound = $isNotFound; Message = $text }
}

function Invoke-ContainmentGraph {
    <#
    .SYNOPSIS
    Send one Graph request; the caller catches and reduces any failure.

    .PARAMETER Method
    HTTP method.

    .PARAMETER Path
    Path under the v1.0 endpoint.

    .PARAMETER Body
    Optional body object, sent as JSON.

    .OUTPUTS
    The Graph response, if any.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][AllowNull()][object]$Body
    )

    $request = @{ Method = $Method; Uri = "$($script:GraphBase)$Path"; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $request['Body'] = $Body | ConvertTo-Json -Depth 5 -Compress
        $request['ContentType'] = 'application/json'
    }

    Invoke-MgGraphRequest @request
}

function Get-ContainmentUser {
    <#
    .SYNOPSIS
    Look one user up and classify the outcome as Found, NotFound, or NotAssessed.

    .PARAMETER Identity
    The UPN or object id.

    .OUTPUTS
    PSCustomObject with Status, Message, and the user fields read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    $path = '/users/' + [uri]::EscapeDataString($Identity) + '?$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled'
    try {
        $user = Invoke-ContainmentGraph -Method GET -Path $path -Body $null
    } catch {
        $info = Get-ContainmentErrorInfo -ErrorRecord $_
        $status = if ($info.IsNotFound) { 'NotFound' } else { 'NotAssessed' }
        return [pscustomobject]@{
            Status = $status; Message = $info.Message; Id = ''; UserPrincipalName = $Identity
            AccountEnabled = $null; SyncEnabled = $false
        }
    }

    $id = [string](Get-OpsPropertyValue -InputObject $user -Name 'id')
    if (-not $id) {
        return [pscustomobject]@{
            Status = 'NotAssessed'; Message = 'Graph returned no user id.'; Id = ''; UserPrincipalName = $Identity
            AccountEnabled = $null; SyncEnabled = $false
        }
    }

    $upn = [string](Get-OpsPropertyValue -InputObject $user -Name 'userPrincipalName')
    $enabled = Get-OpsPropertyValue -InputObject $user -Name 'accountEnabled'
    $sync = Get-OpsPropertyValue -InputObject $user -Name 'onPremisesSyncEnabled'
    [pscustomobject]@{
        Status = 'Found'; Message = ''; Id = $id
        UserPrincipalName = $(if ($upn) { $upn } else { $Identity })
        AccountEnabled = $(if ($enabled -is [bool]) { $enabled } else { $null })
        SyncEnabled = ($sync -eq $true)
    }
}

function Get-ContainmentPassword {
    <#
    .SYNOPSIS
    Generate a random password with RandomNumberGenerator that meets Entra complexity.

    .PARAMETER Length
    Total length, at least 20.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [ValidateRange(20, 128)]
        [int]$Length = 24
    )

    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnpqrstuvwxyz'
    $digit = '23456789'
    $symbol = '!@#$%^&*-_+=?'
    $all = $upper + $lower + $digit + $symbol

    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($set in @($upper, $lower, $digit, $symbol)) {
        $chars.Add($set[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($set.Length)])
    }
    while ($chars.Count -lt $Length) {
        $chars.Add($all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)])
    }
    # Fisher-Yates so the guaranteed classes are not always the first four characters.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($i + 1)
        $swap = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $swap
    }

    -join $chars
}

function Show-ContainmentPassword {
    <#
    .SYNOPSIS
    Show a generated password once on the console, labeled with the UPN.

    .PARAMETER Account
    The account the value belongs to.

    .PARAMETER Secret
    The generated value.

    .OUTPUTS
    None. Console only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The password must reach the operator console only, never the pipeline or a file.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Account,
        [Parameter(Mandatory = $true)][string]$Secret
    )

    Write-Host "TEMPORARY PASSWORD for ${Account}: $Secret  (shown once, not saved anywhere; user must change it at next sign-in)"
}

function Test-ExchangeOnlineCommand {
    <#
    .SYNOPSIS
    Report whether a command exists and comes from Exchange Online PowerShell.

    .PARAMETER Name
    The cmdlet name.

    .OUTPUTS
    PSCustomObject with Available and Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        return [pscustomobject]@{ Available = $false; Reason = "$Name is not available in this session." }
    }

    $moduleName = [string](Get-OpsPropertyValue -InputObject $command -Name 'ModuleName')
    $source = [string](Get-OpsPropertyValue -InputObject $command -Name 'Source')
    $isExchangeOnline = ($moduleName -eq 'ExchangeOnlineManagement') -or ($source -eq 'ExchangeOnlineManagement') -or ($moduleName -like 'tmpEXO_*') -or ($source -like 'tmpEXO_*')
    if (-not $isExchangeOnline) {
        $origin = if ($moduleName) { $moduleName } elseif ($source) { $source } else { 'no module' }
        return [pscustomobject]@{ Available = $false; Reason = "$Name comes from '$origin', not Exchange Online PowerShell (it may be Security and Compliance or on-premises Exchange)." }
    }

    [pscustomobject]@{ Available = $true; Reason = '' }
}

function Export-UserMailboxEvidence {
    <#
    .SYNOPSIS
    Read one user's mailbox forwarding and inbox rules through Exchange Online, changing nothing.

    .PARAMETER UserPrincipalName
    The mailbox to read.

    .OUTPUTS
    PSCustomObject with ForwardingStatus, RulesStatus, Forwarding (record or null), Rule (records), and Detail.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    $result = [ordered]@{
        ForwardingStatus = 'Done'; RulesStatus = 'Done'; Forwarding = $null
        Rule = @(); ForwardingDetail = ''; RulesDetail = ''
    }

    try {
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
    } catch {
        $info = Get-ContainmentErrorInfo -ErrorRecord $_
        if ($info.Message -match "couldn't be found|could not be found|ManagementObjectNotFound|RecipientNotFound|isn't a mailbox|not found") {
            $result.ForwardingStatus = 'NoMailbox'; $result.RulesStatus = 'NoMailbox'
            $result.ForwardingDetail = 'The user has no Exchange Online mailbox.'
            $result.RulesDetail = $result.ForwardingDetail
        } else {
            $result.ForwardingStatus = "Failed:$($info.Message)"; $result.RulesStatus = "Failed:$($info.Message)"
        }
        return [pscustomobject]$result
    }

    if ($null -eq $mailbox) {
        $result.ForwardingStatus = 'NoMailbox'; $result.RulesStatus = 'NoMailbox'
        $result.ForwardingDetail = 'The user has no Exchange Online mailbox.'
        $result.RulesDetail = $result.ForwardingDetail
        return [pscustomobject]$result
    }

    $forwardingAddress = Get-ForwardingDestination -Value (Get-OpsPropertyValue -InputObject $mailbox -Name 'ForwardingAddress')
    $forwardingSmtp = Get-ForwardingDestination -Value (Get-OpsPropertyValue -InputObject $mailbox -Name 'ForwardingSmtpAddress')
    $deliver = Get-OpsPropertyValue -InputObject $mailbox -Name 'DeliverToMailboxAndForward'
    $result.Forwarding = [pscustomobject]@{
        UserPrincipalName = $UserPrincipalName
        ForwardingAddress = $forwardingAddress
        ForwardingSmtpAddress = $forwardingSmtp
        DeliverToMailboxAndForward = $(if ($null -eq $deliver) { '' } else { $deliver })
        HasForwarding = [bool]($forwardingAddress -or $forwardingSmtp)
    }
    $result.ForwardingDetail = if ($result.Forwarding.HasForwarding) { 'Mailbox forwarding is configured.' } else { 'No mailbox forwarding is configured.' }

    try {
        $rules = @(Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop | Where-Object { $null -ne $_ })
        $result.Rule = @(foreach ($rule in $rules) {
                $forwardTo = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'ForwardTo')
                $forwardAs = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'ForwardAsAttachmentTo')
                $redirectTo = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'RedirectTo')
                [pscustomobject]@{
                    UserPrincipalName = $UserPrincipalName
                    Name = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'Name')
                    Enabled = Get-OpsPropertyValue -InputObject $rule -Name 'Enabled'
                    Priority = Get-OpsPropertyValue -InputObject $rule -Name 'Priority'
                    ForwardTo = $forwardTo
                    ForwardAsAttachmentTo = $forwardAs
                    RedirectTo = $redirectTo
                    DeleteMessage = Get-OpsPropertyValue -InputObject $rule -Name 'DeleteMessage'
                    MoveToFolder = Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'MoveToFolder')
                    MarkAsRead = Get-OpsPropertyValue -InputObject $rule -Name 'MarkAsRead'
                    StopProcessingRules = Get-OpsPropertyValue -InputObject $rule -Name 'StopProcessingRules'
                    ForwardsOrRedirects = [bool]($forwardTo -or $forwardAs -or $redirectTo)
                    Description = (Join-OpsValue (Get-OpsPropertyValue -InputObject $rule -Name 'Description')) -replace '\s+', ' '
                }
            })
        $result.RulesDetail = "$($result.Rule.Count) inbox rule(s) exported."
    } catch {
        $info = Get-ContainmentErrorInfo -ErrorRecord $_
        $result.RulesStatus = "Failed:$($info.Message)"
    }

    [pscustomobject]$result
}

function Get-ContainmentRow {
    <#
    .SYNOPSIS
    Build one plan or state row.

    .PARAMETER UserPrincipalName
    The account.

    .PARAMETER UserId
    The object id, or empty.

    .PARAMETER Action
    The action name.

    .PARAMETER Result
    The result value.

    .PARAMETER Reversible
    Yes, No, or n/a.

    .PARAMETER PriorAccountEnabled
    The accountEnabled value read before any change, or empty.

    .PARAMETER Detail
    A sentence saying what will happen or why it is skipped.

    .OUTPUTS
    PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [Parameter()][string]$UserId = '',
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Result,
        [Parameter()][string]$Reversible = 'n/a',
        [Parameter()][AllowNull()][object]$PriorAccountEnabled = '',
        [Parameter()][string]$Detail = ''
    )

    [pscustomobject]@{
        UserPrincipalName = $UserPrincipalName
        UserId = $UserId
        Action = $Action
        Result = $Result
        Reversible = $Reversible
        PriorAccountEnabled = $(if ($null -eq $PriorAccountEnabled) { '' } else { $PriorAccountEnabled })
        Detail = $Detail
    }
}

function Get-LatestContainmentRollbackFile {
    <#
    .SYNOPSIS
    Find the newest containment-rollback.json that actually disabled an account.

    .PARAMETER Directory
    The report directory.

    .OUTPUTS
    String path, or null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory)) { return $null }
    $candidates = Get-ChildItem -LiteralPath $Directory -Directory -Filter 'entra-containment-*' -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'containment-rollback.json' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        ForEach-Object { Get-Item -LiteralPath $_ } |
        Sort-Object LastWriteTime -Descending
    foreach ($file in $candidates) {
        try {
            $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }
        $entries = @(Get-OpsPropertyValue -InputObject $data -Name 'Entries')
        if ((Get-OpsPropertyValue -InputObject $data -Name 'Mode') -eq 'Contain' -and
            @($entries | Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'DisabledByScript') -eq $true }).Count -gt 0) {
            return $file.FullName
        }
    }

    $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not $Rollback) {
    if ($targetUpn.Count -eq 0) {
        throw 'No user principal names remain after splitting -UserPrincipalName. Nothing was attempted.'
    }
    if ($ResetPassword -and $ExportOnly) {
        throw '-ResetPassword and -ExportOnly contradict each other: -ExportOnly performs no containment write.'
    }
}

$readScope = 'User.Read.All'
$writeScopes = if ($Rollback) {
    @('User.EnableDisableAccount.All')
} elseif ($ExportOnly) {
    @()
} else {
    $containScopes = @('User.RevokeSessions.All', 'User.EnableDisableAccount.All')
    if ($ResetPassword) { $containScopes += 'User-PasswordProfile.ReadWrite.All' }
    $containScopes
}

if ($Connect) {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Connect-MgGraph is not available. Install Microsoft.Graph.Authentication.'
    }

    $connectParameter = @{ Scopes = @($readScope) + @($writeScopes) }
    if ($TenantId) { $connectParameter['TenantId'] = $TenantId }
    if ($UseDeviceCode) { $connectParameter['UseDeviceCode'] = $true }
    Connect-MgGraph @connectParameter | Out-Null
} elseif ($TenantId -or $UseDeviceCode) {
    throw 'TenantId and UseDeviceCode apply only to a new connection. Add -Connect, or drop them and reuse the current Microsoft Graph session.'
}

if (-not (Get-MgContext)) {
    throw 'No Microsoft Graph session. Run again with -Connect, or connect first with Connect-MgGraph.'
}

$whatIf = [bool]$WhatIfPreference
$mode = if ($Rollback) { 'Rollback' } elseif ($ExportOnly) { 'ExportOnly' } else { 'Contain' }
$prefix = if ($Rollback) { 'entra-containment-rollback' } else { 'entra-containment' }

$rollbackFile = $null
$rollbackData = $null
if ($Rollback) {
    $rollbackFile = if ($RollbackStatePath) { $RollbackStatePath } else { Get-LatestContainmentRollbackFile -Directory $ReportDirectory }
    if (-not $rollbackFile -or -not (Test-Path -LiteralPath $rollbackFile -PathType Leaf)) {
        throw "No containment-rollback.json that disabled an account was found$(if (-not $RollbackStatePath) { " in $ReportDirectory" }). Nothing to roll back."
    }
    $rollbackData = Get-Content -LiteralPath $rollbackFile -Raw | ConvertFrom-Json
    if ((Get-OpsPropertyValue -InputObject $rollbackData -Name 'Mode') -ne 'Contain') {
        throw "$rollbackFile is not a containment rollback record."
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $ReportDirectory -Prefix $prefix
$plan = [System.Collections.Generic.List[pscustomobject]]::new()

if ($Rollback) {
    # Rollback plan: one row per recorded action, with the reason when it is skipped.
    foreach ($entry in @(Get-OpsPropertyValue -InputObject $rollbackData -Name 'Entries')) {
        if ($null -eq $entry) { continue }
        $entryUpn = [string](Get-OpsPropertyValue -InputObject $entry -Name 'UserPrincipalName')
        $entryId = [string](Get-OpsPropertyValue -InputObject $entry -Name 'UserId')
        $entryAction = [string](Get-OpsPropertyValue -InputObject $entry -Name 'Action')
        $prior = Get-OpsPropertyValue -InputObject $entry -Name 'PriorAccountEnabled'
        if ($entryAction -ne 'DisableAccount') {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $entryUpn -UserId $entryId -Action "Rollback$entryAction" -Result 'Skipped' -Reversible 'No' `
                        -Detail "$entryAction cannot be undone by this script."))
        } elseif ((Get-OpsPropertyValue -InputObject $entry -Name 'DisabledByScript') -ne $true) {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $entryUpn -UserId $entryId -Action 'EnableAccount' -Result 'Skipped' `
                        -PriorAccountEnabled $prior -Detail 'This script did not disable the account in that run, so it is not re-enabled.'))
        } elseif ($prior -ne $true) {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $entryUpn -UserId $entryId -Action 'EnableAccount' -Result 'Skipped' `
                        -PriorAccountEnabled $prior -Detail 'The recorded prior state was not enabled, so it is not re-enabled.'))
        } else {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $entryUpn -UserId $entryId -Action 'EnableAccount' -Result 'Planned' -Reversible 'Yes' `
                        -PriorAccountEnabled $prior -Detail 'Re-enable the account this script disabled; it was enabled before.'))
        }
    }
} else {
    # Phase 1: look every user up. Nothing is written yet.
    $users = foreach ($upn in $targetUpn) { Get-ContainmentUser -Identity $upn }

    foreach ($user in $users) {
        $upn = $user.UserPrincipalName
        if ($user.Status -eq 'NotFound') {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -Action 'Lookup' -Result 'NotFound' -Detail 'Graph returned 404; no such user. Nothing is attempted for this user.'))
            $script:Findings.Add("${upn}: user not found; nothing attempted.")
            continue
        }
        if ($user.Status -eq 'NotAssessed') {
            $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -Action 'Lookup' -Result 'NotAssessed' -Detail "The user could not be read: $($user.Message) Nothing is attempted for this user."))
            $script:Findings.Add("${upn}: lookup failed ($($user.Message)); nothing attempted.")
            continue
        }

        $id = $user.Id
        $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'ExportInboxRules' -Result 'Planned' -Detail 'Read inbox rules through Exchange Online before any change.'))
        $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'ExportForwarding' -Result 'Planned' -Detail 'Read mailbox forwarding through Exchange Online before any change.'))
        if ($ExportOnly) { continue }

        $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'RevokeSessions' -Result 'Planned' -Reversible 'No' `
                    -Detail 'Revoke all sign-in sessions and refresh tokens. Cannot be undone.'))

        if ($user.SyncEnabled) {
            $onPremDetail = 'Synced from on-premises: Graph refuses writes to on-premises-mastered attributes and sync would revert it. Do this in Active Directory (scripts\active-directory\ holds the AD scripts).'
            $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'DisableAccount' -Result 'RequiresOnPremises' -PriorAccountEnabled $user.AccountEnabled `
                        -Detail "Disable the account in AD. $onPremDetail"))
            $script:Findings.Add("${upn}: synced from on-premises; disable the account in Active Directory (scripts\active-directory\ holds the AD scripts).")
            if ($ResetPassword) {
                $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'ResetPassword' -Result 'RequiresOnPremises' -Reversible 'No' `
                            -Detail "Reset the password in AD. $onPremDetail"))
                $script:Findings.Add("${upn}: synced from on-premises; reset the password in Active Directory.")
            }
        } else {
            if ($null -eq $user.AccountEnabled) {
                $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'DisableAccount' -Result 'NotAssessed' `
                            -Detail 'Graph did not return accountEnabled, so the prior state cannot be recorded for rollback. Not disabled.'))
                $script:Findings.Add("${upn}: accountEnabled was not returned; not disabled.")
            } elseif ($user.AccountEnabled -eq $false) {
                $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'DisableAccount' -Result 'AlreadyDisabled' -Reversible 'Yes' -PriorAccountEnabled $false `
                            -Detail 'The account was already disabled; no change is made and rollback will not enable it.'))
            } else {
                $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'DisableAccount' -Result 'Planned' -Reversible 'Yes' -PriorAccountEnabled $true `
                            -Detail 'Set accountEnabled to false. Prior state enabled is recorded for rollback.'))
            }
            if ($ResetPassword) {
                $plan.Add((Get-ContainmentRow -UserPrincipalName $upn -UserId $id -Action 'ResetPassword' -Result 'Planned' -Reversible 'No' `
                            -Detail 'Set a generated password and require a change at next sign-in. Cannot be undone.'))
            }
        }
    }
}

# The plan is written before any export or write: writing it is the preview.
$planReport = Export-OpsReport -Name 'containment-plan' -Record @($plan) -Directory $runDirectory

$state = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($row in $plan) { $state.Add($row.PSObject.Copy()) }

$inboxRuleRecords = [System.Collections.Generic.List[pscustomobject]]::new()
$forwardingRecords = [System.Collections.Generic.List[pscustomobject]]::new()

if (-not $Rollback) {
    # Phase 2: export evidence BEFORE any containment write.
    $exportRows = @($state | Where-Object { $_.Action -in @('ExportInboxRules', 'ExportForwarding') })
    if ($exportRows.Count -gt 0) {
        $mailboxCheck = Test-ExchangeOnlineCommand -Name 'Get-Mailbox'
        $ruleCheck = Test-ExchangeOnlineCommand -Name 'Get-InboxRule'
        if (-not $mailboxCheck.Available -or -not $ruleCheck.Available) {
            $reasons = (@($mailboxCheck, $ruleCheck) | Where-Object { -not $_.Available } | ForEach-Object { $_.Reason }) -join ' '
            $finding = "Exchange Online export not assessed. $reasons Run Connect-ExchangeOnline and re-run with -ExportOnly."
            $script:Findings.Add($finding)
            foreach ($row in $exportRows) {
                $row.Result = 'NotAssessed'
                $row.Detail = $finding
            }
        } else {
            foreach ($upn in @($exportRows | ForEach-Object { $_.UserPrincipalName } | Select-Object -Unique)) {
                $evidence = Export-UserMailboxEvidence -UserPrincipalName $upn
                foreach ($row in @($exportRows | Where-Object { $_.UserPrincipalName -eq $upn })) {
                    if ($row.Action -eq 'ExportForwarding') {
                        $row.Result = $evidence.ForwardingStatus
                        $row.Detail = if ($evidence.ForwardingDetail) { $evidence.ForwardingDetail } else { $row.Detail }
                    } else {
                        $row.Result = $evidence.RulesStatus
                        $row.Detail = if ($evidence.RulesDetail) { $evidence.RulesDetail } else { $row.Detail }
                    }
                }
                if ($evidence.ForwardingStatus -eq 'Done' -and $null -ne $evidence.Forwarding) { $forwardingRecords.Add($evidence.Forwarding) }
                if ($evidence.RulesStatus -eq 'Done') { foreach ($rule in @($evidence.Rule)) { $inboxRuleRecords.Add($rule) } }
                if ($evidence.ForwardingStatus -like 'Failed:*' -or $evidence.RulesStatus -like 'Failed:*') {
                    $script:Findings.Add("${upn}: Exchange Online export failed ($($evidence.ForwardingStatus) / $($evidence.RulesStatus)).")
                }
                if ($evidence.ForwardingStatus -eq 'NoMailbox') {
                    $script:Findings.Add("${upn}: no Exchange Online mailbox; nothing to export.")
                }
            }
        }
    }

    # Phase 3: containment writes, one ShouldProcess per action.
    foreach ($row in @($state | Where-Object { $_.Action -in @('RevokeSessions', 'DisableAccount', 'ResetPassword') -and $_.Result -eq 'Planned' })) {
        $upn = $row.UserPrincipalName
        $encodedId = [uri]::EscapeDataString($row.UserId)

        if ($row.Action -eq 'RevokeSessions') {
            if (-not $PSCmdlet.ShouldProcess($upn, 'Revoke sign-in sessions')) { $row.Result = 'Previewed'; continue }
            try {
                $response = Invoke-ContainmentGraph -Method POST -Path "/users/$encodedId/revokeSignInSessions" -Body $null
                if ((Get-OpsPropertyValue -InputObject $response -Name 'value') -eq $false) {
                    $row.Result = 'Failed:Graph reported the sessions were not revoked.'
                } else {
                    $row.Result = 'Done'
                }
            } catch {
                $row.Result = 'Failed:' + (Get-ContainmentErrorInfo -ErrorRecord $_).Message
            }
        } elseif ($row.Action -eq 'DisableAccount') {
            if (-not $PSCmdlet.ShouldProcess($upn, 'Disable account (accountEnabled false)')) { $row.Result = 'Previewed'; continue }
            try {
                Invoke-ContainmentGraph -Method PATCH -Path "/users/$encodedId" -Body @{ accountEnabled = $false } | Out-Null
                $row.Result = 'Done'
            } catch {
                $row.Result = 'Failed:' + (Get-ContainmentErrorInfo -ErrorRecord $_).Message
            }
        } else {
            if (-not $PSCmdlet.ShouldProcess($upn, 'Reset password (generated, change required at next sign-in)')) { $row.Result = 'Previewed'; continue }
            $generated = Get-ContainmentPassword
            try {
                Invoke-ContainmentGraph -Method PATCH -Path "/users/$encodedId" -Body @{
                    passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $generated }
                } | Out-Null
                $row.Result = 'Done'
                Show-ContainmentPassword -Account $upn -Secret $generated
            } catch {
                $row.Result = 'Failed:' + (Get-ContainmentErrorInfo -ErrorRecord $_ -Secret $generated).Message
            } finally {
                $generated = $null
            }
        }
    }
} else {
    # Rollback: re-enable only what the recorded run disabled and found enabled.
    foreach ($row in @($state | Where-Object { $_.Action -eq 'EnableAccount' -and $_.Result -eq 'Planned' })) {
        $upn = $row.UserPrincipalName
        if (-not $row.UserId) {
            $row.Result = 'NotAssessed'; $row.Detail = 'The rollback record has no user id for this account.'
            $script:Findings.Add("${upn}: rollback record has no user id; not re-enabled.")
            continue
        }
        $current = Get-ContainmentUser -Identity $row.UserId
        if ($current.Status -eq 'NotFound') {
            $row.Result = 'NotFound'; $row.Detail = 'The account no longer exists.'
            continue
        }
        if ($current.Status -eq 'NotAssessed') {
            $row.Result = 'NotAssessed'; $row.Detail = "The account could not be read: $($current.Message)"
            $script:Findings.Add("${upn}: rollback could not read the account ($($current.Message)); not re-enabled.")
            continue
        }
        if ($current.AccountEnabled -eq $true) {
            $row.Result = 'Skipped'; $row.Detail = 'The account is already enabled.'
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($upn, 'Re-enable account (accountEnabled true)')) { $row.Result = 'Previewed'; continue }
        try {
            Invoke-ContainmentGraph -Method PATCH -Path ('/users/' + [uri]::EscapeDataString($row.UserId)) -Body @{ accountEnabled = $true } | Out-Null
            $row.Result = 'Done'
        } catch {
            $row.Result = 'Failed:' + (Get-ContainmentErrorInfo -ErrorRecord $_).Message
        }
    }
}

$stateReport = Export-OpsReport -Name 'containment-state' -Record @($state) -Directory $runDirectory
$rulesReport = $null
$forwardingReport = $null
if (-not $Rollback) {
    $rulesReport = Export-OpsReport -Name 'inbox-rules' -Record @($inboxRuleRecords) -Directory $runDirectory
    $forwardingReport = Export-OpsReport -Name 'mailbox-forwarding' -Record @($forwardingRecords) -Directory $runDirectory
}

# Rollback record: written for every containment run, but only a run that actually
# disabled an account is ever selected by -Rollback.
$rollbackPath = $null
if (-not $Rollback) {
    $entries = @($state | Where-Object { $_.Action -in @('RevokeSessions', 'DisableAccount', 'ResetPassword') } | ForEach-Object {
            [pscustomobject]@{
                UserPrincipalName = $_.UserPrincipalName
                UserId = $_.UserId
                Action = $_.Action
                Result = $_.Result
                Reversible = $_.Reversible
                PriorAccountEnabled = $_.PriorAccountEnabled
                DisabledByScript = ($_.Action -eq 'DisableAccount' -and $_.Result -eq 'Done')
            }
        })
    $rollbackPath = Join-Path $runDirectory 'containment-rollback.json'
    [pscustomobject]@{
        Mode = 'Contain'
        Executed = (-not $whatIf)
        Entries = $entries
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

function Measure-ContainmentResult {
    <#
    .SYNOPSIS
    Count state rows with a given result.

    .PARAMETER Result
    The result value, or a wildcard such as Failed:*.

    .OUTPUTS
    Int32.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Result)

    @($state | Where-Object { $_.Result -like $Result }).Count
}

$failedCount = Measure-ContainmentResult -Result 'Failed:*'
$notAssessedCount = Measure-ContainmentResult -Result 'NotAssessed'
$notFoundCount = Measure-ContainmentResult -Result 'NotFound'
$onPremCount = Measure-ContainmentResult -Result 'RequiresOnPremises'
$overall = if ($failedCount -or $notAssessedCount -or $notFoundCount -or $onPremCount) { 'Incomplete' } elseif ($whatIf) { 'Previewed' } else { 'Complete' }

$summary = [pscustomobject]@{
    Operation = "EntraUserContainment ($mode)"
    Mode = $mode
    WhatIf = $whatIf
    Status = $overall
    UserCount = @($state | ForEach-Object { $_.UserPrincipalName } | Select-Object -Unique).Count
    ResetPasswordRequested = [bool]$ResetPassword
    DoneCount = Measure-ContainmentResult -Result 'Done'
    PreviewedCount = Measure-ContainmentResult -Result 'Previewed'
    AlreadyDisabledCount = Measure-ContainmentResult -Result 'AlreadyDisabled'
    RequiresOnPremisesCount = $onPremCount
    NotFoundCount = $notFoundCount
    NotAssessedCount = $notAssessedCount
    NoMailboxCount = Measure-ContainmentResult -Result 'NoMailbox'
    SkippedCount = Measure-ContainmentResult -Result 'Skipped'
    FailedCount = $failedCount
    RolledBackCount = $(if ($Rollback) { Measure-ContainmentResult -Result 'Done' } else { 0 })
    RunDirectory = $runDirectory
    PlanCsvPath = $planReport.CsvPath
    PlanJsonPath = $planReport.JsonPath
    StateCsvPath = $stateReport.CsvPath
    StateJsonPath = $stateReport.JsonPath
    InboxRulesCsvPath = $(if ($rulesReport) { $rulesReport.CsvPath } else { $null })
    InboxRulesJsonPath = $(if ($rulesReport) { $rulesReport.JsonPath } else { $null })
    ForwardingCsvPath = $(if ($forwardingReport) { $forwardingReport.CsvPath } else { $null })
    ForwardingJsonPath = $(if ($forwardingReport) { $forwardingReport.JsonPath } else { $null })
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackFile
    Findings = @($script:Findings)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
