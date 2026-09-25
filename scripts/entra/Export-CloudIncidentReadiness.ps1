<#
.SYNOPSIS
Grade whether this tenant's logging, roles, and identity controls could support an incident investigation today.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only against the tenant and its subscriptions. It reads configuration and
  writes files locally. It creates, edits, and deletes nothing, and it never pulls,
  queries, or ingests log content itself.
- Requires Microsoft.Graph.Authentication and Az.Accounts only. Graph reads go
  through Invoke-MgGraphRequest; Azure Resource Manager reads go through
  Invoke-AzRestMethod with the api-version pinned on every call. No Az.Monitor, no
  Az.OperationalInsights, and no other Az module.
- Use -Connect when the shell has no Microsoft Graph session yet. Delegated scopes
  requested by default: Policy.Read.All, Directory.Read.All, User.Read.All,
  UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
  RoleEligibilitySchedule.Read.Directory. Override with -GraphScope. A Microsoft
  Graph session is mandatory; the script throws without one.
- Use -ConnectAzure when the shell has no Azure session yet. Azure Resource Manager
  reads (the tenant and subscription diagnostic settings, and the destination Log
  Analytics workspace retention) are optional: without an Azure session those checks
  report NotAssessed and every other check still runs.
- -SubscriptionId names the in-scope subscriptions for the Activity Log check. This
  script never discovers subscriptions on its own; without -SubscriptionId that
  check reports NotAssessed.
- -BreakGlassUpn names the break-glass accounts to check for FIDO2 registration.
  This script never guesses a break-glass account by naming convention; without
  -BreakGlassUpn that check reports NotAssessed.
- -TargetRetentionDaysUal and -TargetRetentionDaysActivityLog are separate
  parameters because the talk this script implements gives two different figures:
  about 90 days for Unified Audit Log data and about 180 days for Activity Log
  data. Both are the speaker's own opinion, not a Microsoft default, so both are
  parameters with defaults, never constants. A single -TargetRetentionDays could
  not hold two different numbers at once.
- -ResponderRoleName names the directory roles checked for PIM-eligible responder
  access. Defaults to Global Reader, Security Reader, and Security Operator. Each
  name is resolved to its role template ID by reading directoryRoleTemplates at
  run time rather than a hard-coded GUID, so a renamed or unavailable role reports
  NotAssessed instead of silently matching the wrong role.
- Generated reports are written under reports\entra by default.

Purpose:
Answers "could we investigate an incident in this tenant today", one check at a
time: Unified Audit Log ingestion; Entra sign-in and audit log export; each named
subscription's Activity Log export; whether the destination workspace retains logs
long enough; Microsoft Graph activity logs; responder role assignment and whether
it is PIM-eligible or standing; break-glass account FIDO2 coverage; the user-consent
setting and existing delegated OAuth grants; and Conditional Access coverage of the
device code authentication flow. Legacy authentication is already graded by
Export-EntraConditionalAccessBaseline.ps1 (control IAM-01 in the evidence pack) and
is referenced here, not graded a second time.

Every check that could not be read, that returned a permission error, or whose
input was never supplied is reported NotAssessed with the reason, never folded into
a pass and never a silent zero. The overall readiness status is never Met while any
check is NotAssessed.

Required syntax:
pwsh -File .\scripts\entra\Export-CloudIncidentReadiness.ps1 -Connect -ConnectAzure -SubscriptionId '00000000-0000-0000-0000-000000000000' -BreakGlassUpn 'breakglass1@contoso.com','breakglass2@contoso.com'
pwsh -File .\scripts\entra\Export-CloudIncidentReadiness.ps1 -Connect -ConnectAzure -SubscriptionId sub1,sub2 -TargetRetentionDaysUal 90 -TargetRetentionDaysActivityLog 180

.OUTPUTS
Writes readiness-checks, responder-roles, break-glass-accounts,
subscription-activity-log, and log-retention reports as CSV and JSON, plus a run
summary, under reports\entra by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo. Verified against stubbed
Graph and Azure Resource Manager responses only; it has never run against a live
tenant or subscription. See FUTURE_FEATURES.md for the residual-risk note.
#>
#Requires -Modules Microsoft.Graph.Authentication, Az.Accounts
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$BreakGlassUpn,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$TargetRetentionDaysUal = 90,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$TargetRetentionDaysActivityLog = 180,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ResponderRoleName = @('Global Reader', 'Security Reader', 'Security Operator'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$GraphScope,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [switch]$ConnectAzure,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$DisconnectWhenFinished,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\entra'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'cloud-incident-readiness'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Get-OpsOverallReadinessStatus {
    <#
    .SYNOPSIS
    Combine several check statuses into one, never Met while any input is NotAssessed.

    .PARAMETER Status
    Status strings to combine: Met, Partial, NotMet, or NotAssessed.

    .OUTPUTS
    String. NotAssessed beats NotMet beats Partial beats Met, and an empty input is NotAssessed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Status
    )

    $set = @($Status)
    if ($set.Count -eq 0 -or $set -contains 'NotAssessed') { return 'NotAssessed' }
    if ($set -contains 'NotMet') { return 'NotMet' }
    if ($set -contains 'Partial') { return 'Partial' }
    'Met'
}

function Get-UnifiedAuditLogIngestionRecord {
    <#
    .SYNOPSIS
    Grade whether Unified Audit Log ingestion is enabled.

    .DESCRIPTION
    Read through Get-AdminAuditLogConfig, which comes from Exchange Online
    PowerShell (Connect-ExchangeOnline). This script does not require or install
    that module; if the cmdlet is not present, or the read fails, or the field it
    needs is absent, the check is NotAssessed rather than guessed.

    .OUTPUTS
    PSCustomObject with CheckId, Name, Status, Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $name = 'Unified Audit Log ingestion enabled'
    $command = Get-Command -Name 'Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
    if (-not $command) {
        return [pscustomobject]@{
            CheckId = 'UAL-INGEST'
            Name = $name
            Status = 'NotAssessed'
            Finding = 'Get-AdminAuditLogConfig is not available. Unified Audit Log ingestion is read through Exchange Online PowerShell (Connect-ExchangeOnline), which this script does not require or install. Connect it yourself and re-run to cover this check.'
        }
    }

    try {
        $config = & $command
    } catch {
        return [pscustomobject]@{
            CheckId = 'UAL-INGEST'
            Name = $name
            Status = 'NotAssessed'
            Finding = "Get-AdminAuditLogConfig failed: $($_.Exception.Message)"
        }
    }

    $enabled = Get-OpsPropertyValue -InputObject $config -Name 'UnifiedAuditLogIngestionEnabled'
    if ($null -eq $enabled) {
        return [pscustomobject]@{
            CheckId = 'UAL-INGEST'
            Name = $name
            Status = 'NotAssessed'
            Finding = 'Get-AdminAuditLogConfig returned no UnifiedAuditLogIngestionEnabled value.'
        }
    }

    [pscustomobject]@{
        CheckId = 'UAL-INGEST'
        Name = $name
        Status = if ([bool]$enabled) { 'Met' } else { 'NotMet' }
        Finding = "UnifiedAuditLogIngestionEnabled=$([bool]$enabled)."
    }
}

function Get-OpsDiagnosticExportRecord {
    <#
    .SYNOPSIS
    Return whether a log category is exported by an enabled diagnostic setting, and to where.

    .PARAMETER Category
    The diagnostic setting log category to look for, for example AuditLogs, SignInLogs,
    MicrosoftGraphActivityLogs, or Administrative.

    .PARAMETER DiagnosticSetting
    The diagnostic settings list as returned by Azure Resource Manager. May be empty.

    .OUTPUTS
    PSCustomObject with Category, Exported, Destination (array of settings that export it), and Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$DiagnosticSetting
    )

    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($setting in @($DiagnosticSetting)) {
        $properties = Get-OpsPropertyValue -InputObject $setting -Name 'properties'
        foreach ($log in @(Get-OpsPropertyValue -InputObject $properties -Name 'logs')) {
            $logCategory = Join-OpsValue (Get-OpsPropertyValue -InputObject $log -Name 'category')
            $logEnabled = [bool](Get-OpsPropertyValue -InputObject $log -Name 'enabled')
            if ($logCategory -eq $Category -and $logEnabled) {
                $matched.Add([pscustomobject]@{
                        SettingName = Join-OpsValue (Get-OpsPropertyValue -InputObject $setting -Name 'name')
                        WorkspaceResourceId = Join-OpsValue (Get-OpsPropertyValue -InputObject $properties -Name 'workspaceId')
                        StorageAccountResourceId = Join-OpsValue (Get-OpsPropertyValue -InputObject $properties -Name 'storageAccountId')
                        EventHubAuthorizationRuleId = Join-OpsValue (Get-OpsPropertyValue -InputObject $properties -Name 'eventHubAuthorizationRuleId')
                    })
                break
            }
        }
    }

    $exported = $matched.Count -gt 0
    [pscustomobject]@{
        Category = $Category
        Exported = $exported
        Destination = @($matched)
        Finding = if ($exported) {
            "Exported by $($matched.Count) diagnostic setting(s): $((@($matched | ForEach-Object { $_.SettingName })) -join ', ')."
        } else {
            "No enabled diagnostic setting exports category '$Category'."
        }
    }
}

function Get-EntraLogExportRecord {
    <#
    .SYNOPSIS
    Grade whether Entra sign-in and audit logs are exported by a tenant diagnostic setting.

    .PARAMETER DiagnosticSetting
    The tenant-level diagnostic settings list (providers/microsoft.aadiam/diagnosticSettings). May be empty.

    .OUTPUTS
    PSCustomObject with CheckId, Name, Status, Finding, Destination.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$DiagnosticSetting
    )

    $audit = Get-OpsDiagnosticExportRecord -Category 'AuditLogs' -DiagnosticSetting $DiagnosticSetting
    $signIn = Get-OpsDiagnosticExportRecord -Category 'SignInLogs' -DiagnosticSetting $DiagnosticSetting

    $status = if ($audit.Exported -and $signIn.Exported) { 'Met' }
    elseif ($audit.Exported -or $signIn.Exported) { 'Partial' }
    else { 'NotMet' }

    [pscustomobject]@{
        CheckId = 'ENTRA-LOG-EXPORT'
        Name = 'Entra sign-in and audit logs exported by a tenant diagnostic setting'
        Status = $status
        Finding = "AuditLogs: $($audit.Finding) SignInLogs: $($signIn.Finding)"
        Destination = @(@($audit.Destination) + @($signIn.Destination))
    }
}

function Get-GraphActivityLogRecord {
    <#
    .SYNOPSIS
    Grade whether Microsoft Graph activity logs are exported by the tenant diagnostic setting.

    .PARAMETER DiagnosticSetting
    The tenant-level diagnostic settings list. May be empty.

    .OUTPUTS
    PSCustomObject with CheckId, Name, Status, Finding, Destination.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$DiagnosticSetting
    )

    $record = Get-OpsDiagnosticExportRecord -Category 'MicrosoftGraphActivityLogs' -DiagnosticSetting $DiagnosticSetting
    [pscustomobject]@{
        CheckId = 'GRAPH-ACTIVITY-LOG'
        Name = 'Microsoft Graph activity logs enabled'
        Status = if ($record.Exported) { 'Met' } else { 'NotMet' }
        Finding = $record.Finding
        Destination = @($record.Destination)
    }
}

function Get-SubscriptionActivityLogRecord {
    <#
    .SYNOPSIS
    Grade whether one subscription's Activity Log is exported by a diagnostic setting.

    .PARAMETER SubscriptionId
    The subscription being graded.

    .PARAMETER DiagnosticSetting
    The subscription's diagnostic settings list. May be empty.

    .OUTPUTS
    PSCustomObject with CheckId, SubscriptionId, Status, Finding, Destination.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$DiagnosticSetting
    )

    $record = Get-OpsDiagnosticExportRecord -Category 'Administrative' -DiagnosticSetting $DiagnosticSetting
    [pscustomobject]@{
        CheckId = 'SUB-ACTIVITY-LOG-EXPORT'
        SubscriptionId = $SubscriptionId
        Status = if ($record.Exported) { 'Met' } else { 'NotMet' }
        Finding = $record.Finding
        Destination = @($record.Destination)
    }
}

function Get-WorkspaceRetentionRecord {
    <#
    .SYNOPSIS
    Compare a destination Log Analytics workspace's retention against a target.

    .PARAMETER WorkspaceResourceId
    ARM resource ID of the workspace.

    .PARAMETER Workspace
    The workspace object as returned by Azure Resource Manager, or null when it could not be read.

    .PARAMETER TargetRetentionDays
    The retention target to compare against. -TargetRetentionDaysUal or -TargetRetentionDaysActivityLog.

    .PARAMETER Purpose
    Which check this workspace was found through: EntraLogs or SubscriptionActivityLog.

    .PARAMETER Reason
    Optional reason the workspace could not be read, for example no Azure session.

    .OUTPUTS
    PSCustomObject with CheckId, WorkspaceResourceId, Purpose, TargetRetentionDays, RetentionDays, Status, Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Workspace,

        [Parameter(Mandatory = $true)]
        [int]$TargetRetentionDays,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Purpose,

        [Parameter()]
        [string]$Reason = ''
    )

    if ($null -eq $Workspace) {
        return [pscustomobject]@{
            CheckId = 'LOG-RETENTION'
            WorkspaceResourceId = $WorkspaceResourceId
            Purpose = $Purpose
            TargetRetentionDays = $TargetRetentionDays
            RetentionDays = $null
            Status = 'NotAssessed'
            Finding = if ($Reason) { $Reason } else { 'The workspace could not be read.' }
        }
    }

    $properties = Get-OpsPropertyValue -InputObject $Workspace -Name 'properties'
    $retention = Get-OpsPropertyValue -InputObject $properties -Name 'retentionInDays'
    if ($null -eq $retention) {
        return [pscustomobject]@{
            CheckId = 'LOG-RETENTION'
            WorkspaceResourceId = $WorkspaceResourceId
            Purpose = $Purpose
            TargetRetentionDays = $TargetRetentionDays
            RetentionDays = $null
            Status = 'NotAssessed'
            Finding = 'The workspace has no retentionInDays property in the Azure Resource Manager response.'
        }
    }

    $days = [int]$retention
    [pscustomobject]@{
        CheckId = 'LOG-RETENTION'
        WorkspaceResourceId = $WorkspaceResourceId
        Purpose = $Purpose
        TargetRetentionDays = $TargetRetentionDays
        RetentionDays = $days
        Status = if ($days -ge $TargetRetentionDays) { 'Met' } else { 'NotMet' }
        Finding = "Workspace retains $days day(s) against a target of $TargetRetentionDays. The target is an opinion figure from the Johansen Azure incident-readiness talk, not a Microsoft default; see -TargetRetentionDaysUal and -TargetRetentionDaysActivityLog."
    }
}

function Merge-OpsWorkspaceRetentionTarget {
    <#
    .SYNOPSIS
    Record a workspace's retention target and purpose, keeping the stricter target when the workspace already has one recorded for a different purpose.

    .DESCRIPTION
    The same Log Analytics workspace can receive both the Entra diagnostic export and
    a subscription's Activity Log export. Recording a second purpose must never
    silently overwrite the first purpose's target; the stricter (higher) target
    always wins, and both purposes are kept so the reader knows two targets applied.

    .PARAMETER Table
    Ordered hashtable of workspace resource id to a target record. Mutated in place.

    .PARAMETER WorkspaceResourceId
    ARM resource ID of the workspace.

    .PARAMETER TargetRetentionDays
    The retention target this purpose expects.

    .PARAMETER Purpose
    Which check found this workspace: EntraLogs or SubscriptionActivityLog.

    .OUTPUTS
    None. Mutates Table in place.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Table,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory = $true)]
        [int]$TargetRetentionDays,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Purpose
    )

    if ($Table.Contains($WorkspaceResourceId)) {
        $entry = $Table[$WorkspaceResourceId]
        if ($entry.Purpose -notcontains $Purpose) {
            $entry.Purpose = @($entry.Purpose) + $Purpose
        }
        if ($TargetRetentionDays -gt $entry.TargetRetentionDays) {
            $entry.TargetRetentionDays = $TargetRetentionDays
        }
    } else {
        $Table[$WorkspaceResourceId] = [pscustomobject]@{ TargetRetentionDays = $TargetRetentionDays; Purpose = @($Purpose) }
    }
}

function Get-ResponderRoleRecord {
    <#
    .SYNOPSIS
    Grade one responder role's standing versus PIM-eligible assignment.

    .PARAMETER RoleName
    Display name of the directory role, for example Global Reader.

    .PARAMETER ActiveCount
    Count of standing (active) assignments, or null if it could not be read.

    .PARAMETER EligibleCount
    Count of PIM-eligible assignments, or null if it could not be read.

    .PARAMETER Reason
    Optional reason a count could not be read.

    .OUTPUTS
    PSCustomObject with CheckId, RoleName, ActiveCount, EligibleCount, Status, Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RoleName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [Nullable[int]]$ActiveCount,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [Nullable[int]]$EligibleCount,

        [Parameter()]
        [string]$Reason = ''
    )

    if ($null -eq $ActiveCount -or $null -eq $EligibleCount) {
        return [pscustomobject]@{
            CheckId = 'RESPONDER-ROLES'
            RoleName = $RoleName
            ActiveCount = $ActiveCount
            EligibleCount = $EligibleCount
            Status = 'NotAssessed'
            Finding = if ($Reason) { $Reason } else { 'Role assignment read failed.' }
        }
    }

    $status = if ($EligibleCount -gt 0 -and $ActiveCount -eq 0) { 'Met' }
    elseif ($EligibleCount -gt 0 -or $ActiveCount -gt 0) { 'Partial' }
    else { 'NotMet' }

    $standingNote = if ($ActiveCount -gt 0) { ' Standing assignment bypasses PIM activation and should be converted to eligible.' } else { '' }

    [pscustomobject]@{
        CheckId = 'RESPONDER-ROLES'
        RoleName = $RoleName
        ActiveCount = $ActiveCount
        EligibleCount = $EligibleCount
        Status = $status
        Finding = "Standing (active) assignments: $ActiveCount. PIM-eligible assignments: $EligibleCount.$standingNote"
    }
}

function Get-BreakGlassAccountRecord {
    <#
    .SYNOPSIS
    Grade one break-glass account's FIDO2 registration.

    .PARAMETER UserPrincipalName
    The break-glass UPN, supplied by the caller and never guessed.

    .PARAMETER LookupResult
    Found, NotFound, or NotAssessed.

    .PARAMETER Fido2Registered
    Whether a FIDO2 security key is registered, when LookupResult is Found.

    .PARAMETER Reason
    Optional reason when LookupResult is NotAssessed.

    .OUTPUTS
    PSCustomObject with CheckId, UserPrincipalName, Fido2Registered, Status, Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Found', 'NotFound', 'NotAssessed')]
        [string]$LookupResult,

        [Parameter()]
        [AllowNull()]
        [Nullable[bool]]$Fido2Registered,

        [Parameter()]
        [string]$Reason = ''
    )

    if ($LookupResult -eq 'NotFound') {
        return [pscustomobject]@{
            CheckId = 'BREAK-GLASS'
            UserPrincipalName = $UserPrincipalName
            Fido2Registered = $null
            Status = 'NotMet'
            Finding = 'Account was not found in the tenant.'
        }
    }

    if ($LookupResult -eq 'NotAssessed') {
        return [pscustomobject]@{
            CheckId = 'BREAK-GLASS'
            UserPrincipalName = $UserPrincipalName
            Fido2Registered = $null
            Status = 'NotAssessed'
            Finding = if ($Reason) { $Reason } else { 'Account or FIDO2 method read failed.' }
        }
    }

    [pscustomobject]@{
        CheckId = 'BREAK-GLASS'
        UserPrincipalName = $UserPrincipalName
        Fido2Registered = [bool]$Fido2Registered
        Status = if ($Fido2Registered) { 'Met' } else { 'NotMet' }
        Finding = if ($Fido2Registered) { 'A FIDO2 security key is registered.' } else { 'No FIDO2 security key is registered for this break-glass account.' }
    }
}

function Get-UserConsentRecord {
    <#
    .SYNOPSIS
    Grade the tenant user-consent policy and report the existing delegated OAuth grant count.

    .PARAMETER AuthorizationPolicy
    The tenant authorizationPolicy object, or null if it could not be read.

    .PARAMETER OAuthGrantCount
    Count of existing oauth2PermissionGrants.

    .OUTPUTS
    PSCustomObject with CheckId, Status, Finding, PermissionGrantPolicy, OAuthGrantCount.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$AuthorizationPolicy,

        [Parameter(Mandatory = $true)]
        [int]$OAuthGrantCount
    )

    if ($null -eq $AuthorizationPolicy) {
        return [pscustomobject]@{
            CheckId = 'USER-CONSENT'
            Status = 'NotAssessed'
            Finding = 'The tenant authorization policy could not be read.'
            PermissionGrantPolicy = ''
            OAuthGrantCount = $OAuthGrantCount
        }
    }

    $defaultPermissions = Get-OpsPropertyValue -InputObject $AuthorizationPolicy -Name 'defaultUserRolePermissions'

    # Get-OpsPropertyValue returning a genuinely present but empty array writes zero
    # objects to the pipeline, so @(...) around the call captures Count 0; a missing
    # or unreadable field instead returns the scalar $null, which @(...) captures as
    # a one-element array holding that $null. Reading the raw wrapped result first,
    # before running the array through the match logic below, is what tells "field
    # absent" apart from "field present and genuinely empty" (@($null) is a
    # one-element array, not an empty one, so this distinction is lost if the two
    # cases are not separated up front).
    $rawPolicies = @(Get-OpsPropertyValue -InputObject $defaultPermissions -Name 'permissionGrantPoliciesAssigned')
    if ($rawPolicies.Count -eq 1 -and $null -eq $rawPolicies[0]) {
        return [pscustomobject]@{
            CheckId = 'USER-CONSENT'
            Status = 'NotAssessed'
            Finding = 'permissionGrantPoliciesAssigned could not be read from the authorization policy.'
            PermissionGrantPolicy = ''
            OAuthGrantCount = $OAuthGrantCount
        }
    }

    $policies = $rawPolicies
    $policyText = Join-OpsValue $policies

    $status = if ($policies -match 'microsoft-user-default-legacy') { 'NotMet' }
    elseif ($policies -match 'microsoft-user-default-low') { 'Partial' }
    elseif ($policies.Count -eq 0) { 'Met' }
    else { 'Partial' }

    [pscustomobject]@{
        CheckId = 'USER-CONSENT'
        Status = $status
        Finding = "User consent policy assigned: '$policyText'. Existing delegated OAuth grants: $OAuthGrantCount."
        PermissionGrantPolicy = $policyText
        OAuthGrantCount = $OAuthGrantCount
    }
}

function Get-DeviceCodeFlowCoverageRecord {
    <#
    .SYNOPSIS
    Grade whether an enabled Conditional Access policy blocks the device code authentication flow.

    .DESCRIPTION
    Reads conditions.authenticationFlows.transferMethods, a v1.0 Conditional Access
    field (verified against the installed Microsoft.Graph.Identity.SignIns 2.39.0
    model, not a beta-only type). Legacy authentication is graded separately by
    Export-EntraConditionalAccessBaseline.ps1 (control IAM-01); this function does
    not repeat that grading.

    .PARAMETER Policy
    Conditional Access policies as returned by Graph. May be empty.

    .OUTPUTS
    PSCustomObject with CheckId, Name, Status, Finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Policy
    )

    $blocking = [System.Collections.Generic.List[string]]::new()
    $narrowBlocking = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Policy)) {
        $state = Join-OpsValue (Get-OpsPropertyValue -InputObject $item -Name 'state')
        if ($state -ne 'enabled') { continue }

        $conditions = Get-OpsPropertyValue -InputObject $item -Name 'conditions'
        $flows = Get-OpsPropertyValue -InputObject $conditions -Name 'authenticationFlows'
        $transferMethods = Join-OpsValue (Get-OpsPropertyValue -InputObject $flows -Name 'transferMethods')
        if ($transferMethods -notmatch 'deviceCodeFlow') { continue }

        $grant = Get-OpsPropertyValue -InputObject $item -Name 'grantControls'
        $controls = Join-OpsValue (Get-OpsPropertyValue -InputObject $grant -Name 'builtInControls')
        if ($controls -notmatch 'block') { continue }

        $displayName = Join-OpsValue (Get-OpsPropertyValue -InputObject $item -Name 'displayName')

        # Mirror Export-EntraConditionalAccessBaseline.ps1's own tenant-wide test
        # (conditions.users.includeUsers containing 'All') so the two scripts agree on
        # what "tenant-wide" means. A policy that blocks the flow but is scoped to a
        # pilot group, a narrower application scope, or carries any user/group/role
        # exclusion covers less than the tenant, and must not grade Met. Kept
        # conservative and simple: any exclusion at all, or an application scope
        # other than 'All', drops the policy out of tenant-wide coverage even if it
        # might still cover most of the tenant.
        $users = Get-OpsPropertyValue -InputObject $conditions -Name 'users'
        $includeUsers = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'includeUsers')
        $excludeUsers = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeUsers')
        $excludeGroups = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeGroups')
        $excludeRoles = Join-OpsValue (Get-OpsPropertyValue -InputObject $users -Name 'excludeRoles')
        $applications = Get-OpsPropertyValue -InputObject $conditions -Name 'applications'
        $includeApplications = Join-OpsValue (Get-OpsPropertyValue -InputObject $applications -Name 'includeApplications')
        $hasExclusion = [bool]($excludeUsers -or $excludeGroups -or $excludeRoles)
        $isAllApplications = ($includeApplications -eq 'All')

        if (($includeUsers -match 'All') -and $isAllApplications -and -not $hasExclusion) {
            $blocking.Add($displayName)
        } else {
            $narrowBlocking.Add($displayName)
        }
    }

    $covered = $blocking.Count -gt 0
    [pscustomobject]@{
        CheckId = 'CA-DEVICE-CODE'
        Name = 'Conditional Access coverage of the device code flow'
        Status = if ($covered) { 'Met' } else { 'NotMet' }
        Finding = if ($covered) {
            "Blocked by: $($blocking -join '; '). Legacy authentication is graded separately by Export-EntraConditionalAccessBaseline.ps1 (control IAM-01) and is not repeated here."
        } elseif ($narrowBlocking.Count -gt 0) {
            "Blocked only for a narrower scope, not all users: $($narrowBlocking -join '; '). This is a coverage gap, not tenant-wide protection. Legacy authentication is graded separately by Export-EntraConditionalAccessBaseline.ps1 (control IAM-01) and is not repeated here."
        } else {
            'No enabled policy blocks the device code authentication flow. Legacy authentication is graded separately by Export-EntraConditionalAccessBaseline.ps1 (control IAM-01) and is not repeated here.'
        }
    }
}

function Get-OpsGraphPagedValue {
    <#
    .SYNOPSIS
    Read every page of a Microsoft Graph collection and return the combined value.

    .PARAMETER Uri
    The starting Graph request URI.

    .OUTPUTS
    Object array.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
        foreach ($item in @(Get-OpsPropertyValue -InputObject $response -Name 'value')) {
            $results.Add($item)
        }

        $next = Join-OpsValue (Get-OpsPropertyValue -InputObject $response -Name '@odata.nextLink')
        if (-not $next) { $next = $null }
    }

    @($results)
}

function Get-OpsArmPagedValue {
    <#
    .SYNOPSIS
    Read every page of an Azure Resource Manager collection and return the combined value.

    .PARAMETER Path
    The starting Azure Resource Manager path, with the api-version pinned in the query string.

    .OUTPUTS
    Object array.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    while ($next) {
        $response = Invoke-AzRestMethod -Path $next -Method GET -ErrorAction Stop
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
            throw "Azure Resource Manager request to $next failed with status $($response.StatusCode): $($response.Content)"
        }

        $body = $response.Content | ConvertFrom-Json
        $rawValue = Get-OpsPropertyValue -InputObject $body -Name 'value'
        if ($null -ne $rawValue) {
            # @($null) is a one-element array, not an empty one, so a page with no
            # value field at all must not be iterated, or it adds one null item to
            # the results instead of zero.
            foreach ($item in @($rawValue)) {
                $results.Add($item)
            }
        }

        $next = Join-OpsValue (Get-OpsPropertyValue -InputObject $body -Name 'nextLink')
        if ($next -and $next -match '^https?://') {
            # Azure Resource Manager's nextLink is typically an absolute URL, but
            # Invoke-AzRestMethod's -Path expects a path relative to the ARM endpoint.
            # Strip the scheme and host so pagination works whether the response
            # returns a relative or absolute nextLink.
            $next = ([System.Uri]$next).PathAndQuery
        }
        if (-not $next) { $next = $null }
    }

    @($results)
}

function Get-OpsArmObject {
    <#
    .SYNOPSIS
    Read one Azure Resource Manager object.

    .PARAMETER Path
    The Azure Resource Manager path, with the api-version pinned in the query string.

    .OUTPUTS
    The parsed response object.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $response = Invoke-AzRestMethod -Path $Path -Method GET -ErrorAction Stop
    if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw "Azure Resource Manager request to $Path failed with status $($response.StatusCode): $($response.Content)"
    }

    $response.Content | ConvertFrom-Json
}

function Get-OpsHttpStatusCode {
    <#
    .SYNOPSIS
    Read the HTTP status code off a caught exception, without trusting its message text.

    .PARAMETER ErrorRecord
    The error record caught from a failed request.

    .OUTPUTS
    The status code as an int, or $null when no status code can be read.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $response = $null
    try { $response = $ErrorRecord.Exception.Response } catch { $response = $null }
    if ($null -eq $response) { return $null }

    $statusCode = $null
    try { $statusCode = $response.StatusCode } catch { $statusCode = $null }
    if ($null -eq $statusCode) { return $null }

    # Handles both an int (e.g. Invoke-AzRestMethod's response) and an enum
    # (e.g. System.Net.HttpStatusCode from a .NET HttpResponseException).
    try { return [int]$statusCode } catch { return $null }
}

function ConvertTo-OpsSplitList {
    <#
    .SYNOPSIS
    Splits comma-joined list values into a flat, trimmed list.

    .DESCRIPTION
    pwsh -File hands every argument to the script as a literal string, so a list
    typed as a,b, or passed by the evidence pack as one joined value, binds as
    the single string 'a,b', and a second bare value binds positionally to
    -TenantId. This splits each value on commas, trims it and drops empty
    entries, so every launch path reaches the checks as a real list.

    .PARAMETER Value
    The bound parameter values. May be null or empty.

    .OUTPUTS
    System.String[]
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Value
    )

    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        foreach ($part in ($item -split ',')) {
            $trimmed = $part.Trim()
            if ($trimmed) { $result.Add($trimmed) }
        }
    }
    $result.ToArray()
}

foreach ($listParameterName in @('SubscriptionId', 'BreakGlassUpn', 'ResponderRoleName', 'GraphScope')) {
    if (-not $PSBoundParameters.ContainsKey($listParameterName)) { continue }
    $splitValue = @(ConvertTo-OpsSplitList -Value $PSBoundParameters[$listParameterName])
    if ($splitValue.Count -eq 0) {
        throw "-$listParameterName contains no value once split on commas."
    }
    Set-Variable -Name $listParameterName -Value $splitValue
}

if ($GraphScope -and -not $Connect) {
    throw 'GraphScope applies only to a new connection. Add -Connect, or drop it and reuse the current Microsoft Graph session.'
}

if ($Connect) {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Connect-MgGraph is not available. Install Microsoft.Graph.Authentication.'
    }

    $scopes = if ($GraphScope) {
        @($GraphScope)
    } else {
        @('Policy.Read.All', 'Directory.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory', 'RoleEligibilitySchedule.Read.Directory')
    }
    $connectParameter = @{ Scopes = $scopes }
    if ($TenantId) { $connectParameter['TenantId'] = $TenantId }
    if ($UseDeviceCode) { $connectParameter['UseDeviceCode'] = $true }
    Connect-MgGraph @connectParameter | Out-Null
}

if (-not (Get-MgContext)) {
    throw 'No Microsoft Graph session. Run again with -Connect, or connect first with Connect-MgGraph.'
}

$mgTenantId = (Get-MgContext).TenantId

# -TenantId can be a GUID or a verified domain (Connect-MgGraph and
# Connect-AzAccount both accept either). Only a GUID is directly comparable to
# the GUID Get-MgContext reports; a domain is skipped rather than compared, to
# avoid ever flagging a false mismatch. When -TenantId is GUID-shaped and
# disagrees with the connected Graph session, fail closed before any read
# rather than silently grading whichever tenant happened to be connected.
$tenantIdGuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
if ($TenantId -and $TenantId -match $tenantIdGuidPattern -and $mgTenantId -and $TenantId -ne $mgTenantId) {
    throw "-TenantId '$TenantId' does not match the connected Microsoft Graph session's tenant ($mgTenantId). Connect to the right tenant before running this script."
}

if ($ConnectAzure) {
    if (-not (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue)) {
        throw 'Connect-AzAccount is not available. Install Az.Accounts.'
    }

    $azConnectParameter = @{}
    if ($TenantId) { $azConnectParameter['Tenant'] = $TenantId }
    if ($UseDeviceCode) { $azConnectParameter['UseDeviceAuthentication'] = $true }
    Connect-AzAccount @azConnectParameter | Out-Null
}

$azContext = $null
try {
    $azContext = Get-AzContext -ErrorAction Stop
} catch {
    $azContext = $null
}
$azConnected = [bool]$azContext
$noAzureSessionMessage = 'No Azure session. Run again with -ConnectAzure, or connect first with Connect-AzAccount.'

if ($azConnected) {
    # Get-AzContext only proves SOME Az session exists on disk (Az.Accounts autosaves
    # the last-used context), never that it matches the tenant this run is grading.
    # An Az session left over from a different tenant must be treated the same as no
    # Azure session at all, or checks 2-5 silently grade the wrong tenant's resources
    # under this run's TenantId. Always compared against the connected Graph
    # session's GUID tenant ID, never against -TenantId directly: -TenantId may be a
    # domain, and a GUID-vs-domain comparison is never equal even when they name the
    # same tenant, which would falsely flag every domain-named run as a mismatch.
    $azTenant = Get-OpsPropertyValue -InputObject $azContext -Name 'Tenant'
    $azTenantId = Get-OpsPropertyValue -InputObject $azTenant -Name 'Id'
    if ($mgTenantId -and $azTenantId -and $azTenantId -ne $mgTenantId) {
        $azConnected = $false
        $noAzureSessionMessage = "Azure session is connected to a different tenant ($azTenantId) than the Microsoft Graph session ($mgTenantId)."
    }
}

$asOf = Get-Date
Write-Verbose 'Grading incident readiness.'

# Check 1: Unified Audit Log ingestion.
$ualRecord = Get-UnifiedAuditLogIngestionRecord

# Checks 2 and 5 share one tenant diagnostic settings read.
$entraDiagnosticSetting = @()
$entraDiagnosticError = $null
if (-not $azConnected) {
    $entraDiagnosticError = $noAzureSessionMessage
} else {
    try {
        $entraDiagnosticSetting = @(Get-OpsArmPagedValue -Path '/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview')
    } catch {
        $entraDiagnosticError = $_.Exception.Message
    }
}

if ($entraDiagnosticError) {
    $entraLogExportRecord = [pscustomobject]@{ CheckId = 'ENTRA-LOG-EXPORT'; Name = 'Entra sign-in and audit logs exported by a tenant diagnostic setting'; Status = 'NotAssessed'; Finding = $entraDiagnosticError; Destination = @() }
    $graphActivityLogRecord = [pscustomobject]@{ CheckId = 'GRAPH-ACTIVITY-LOG'; Name = 'Microsoft Graph activity logs enabled'; Status = 'NotAssessed'; Finding = $entraDiagnosticError; Destination = @() }
} else {
    $entraLogExportRecord = Get-EntraLogExportRecord -DiagnosticSetting $entraDiagnosticSetting
    $graphActivityLogRecord = Get-GraphActivityLogRecord -DiagnosticSetting $entraDiagnosticSetting
}

# Check 3: each named subscription's Activity Log export.
$subscriptionRecords = [System.Collections.Generic.List[object]]::new()
if (-not $SubscriptionId -or $SubscriptionId.Count -eq 0) {
    $subscriptionRecords.Add([pscustomobject]@{ CheckId = 'SUB-ACTIVITY-LOG-EXPORT'; SubscriptionId = ''; Status = 'NotAssessed'; Finding = 'No -SubscriptionId supplied. In-scope subscriptions must be named explicitly; this script never discovers them.'; Destination = @() })
} elseif (-not $azConnected) {
    foreach ($sub in $SubscriptionId) {
        $subscriptionRecords.Add([pscustomobject]@{ CheckId = 'SUB-ACTIVITY-LOG-EXPORT'; SubscriptionId = $sub; Status = 'NotAssessed'; Finding = $noAzureSessionMessage; Destination = @() })
    }
} else {
    foreach ($sub in $SubscriptionId) {
        try {
            $subscriptionSetting = @(Get-OpsArmPagedValue -Path "/subscriptions/$sub/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview")
            $subscriptionRecords.Add((Get-SubscriptionActivityLogRecord -SubscriptionId $sub -DiagnosticSetting $subscriptionSetting))
        } catch {
            $subscriptionRecords.Add([pscustomobject]@{ CheckId = 'SUB-ACTIVITY-LOG-EXPORT'; SubscriptionId = $sub; Status = 'NotAssessed'; Finding = $_.Exception.Message; Destination = @() })
        }
    }
}
$subscriptionOverallStatus = Get-OpsOverallReadinessStatus -Status @($subscriptionRecords | ForEach-Object { $_.Status })

# Check 4: destination workspace retention, gathered from every workspace named by checks 2 and 3.
# A workspace can be the destination for both the Entra export and a subscription's
# Activity Log export; Merge-OpsWorkspaceRetentionTarget keeps the stricter target
# rather than letting the second loop silently overwrite the first loop's target.
$workspaceTargetDays = [ordered]@{}
foreach ($destination in @($entraLogExportRecord.Destination)) {
    if ($destination.WorkspaceResourceId) { Merge-OpsWorkspaceRetentionTarget -Table $workspaceTargetDays -WorkspaceResourceId $destination.WorkspaceResourceId -TargetRetentionDays $TargetRetentionDaysUal -Purpose 'EntraLogs' }
}
foreach ($subscriptionRecord in $subscriptionRecords) {
    foreach ($destination in @($subscriptionRecord.Destination)) {
        if ($destination.WorkspaceResourceId) { Merge-OpsWorkspaceRetentionTarget -Table $workspaceTargetDays -WorkspaceResourceId $destination.WorkspaceResourceId -TargetRetentionDays $TargetRetentionDaysActivityLog -Purpose 'SubscriptionActivityLog' }
    }
}

$retentionRecords = [System.Collections.Generic.List[object]]::new()
foreach ($workspaceResourceId in $workspaceTargetDays.Keys) {
    $entry = $workspaceTargetDays[$workspaceResourceId]
    $target = $entry.TargetRetentionDays
    $purpose = $entry.Purpose -join '+'

    if (-not $azConnected) {
        $retentionRecord = Get-WorkspaceRetentionRecord -WorkspaceResourceId $workspaceResourceId -Workspace $null -TargetRetentionDays $target -Purpose $purpose -Reason $noAzureSessionMessage
    } else {
        try {
            $workspace = Get-OpsArmObject -Path "${workspaceResourceId}?api-version=2022-10-01"
            $retentionRecord = Get-WorkspaceRetentionRecord -WorkspaceResourceId $workspaceResourceId -Workspace $workspace -TargetRetentionDays $target -Purpose $purpose
        } catch {
            $retentionRecord = Get-WorkspaceRetentionRecord -WorkspaceResourceId $workspaceResourceId -Workspace $null -TargetRetentionDays $target -Purpose $purpose -Reason $_.Exception.Message
        }
    }

    if (@($entry.Purpose).Count -gt 1) {
        $retentionRecord.Finding = "$($retentionRecord.Finding) This workspace serves both Entra log export and subscription Activity Log export, so the stricter of the two retention targets applies."
    }
    $retentionRecords.Add($retentionRecord)
}
if ($retentionRecords.Count -eq 0) {
    $retentionRecords.Add([pscustomobject]@{ CheckId = 'LOG-RETENTION'; WorkspaceResourceId = ''; Purpose = ''; TargetRetentionDays = $null; RetentionDays = $null; Status = 'NotAssessed'; Finding = 'No exporting diagnostic setting named a Log Analytics workspace destination to check retention against.' })
}
$retentionOverallStatus = Get-OpsOverallReadinessStatus -Status @($retentionRecords | ForEach-Object { $_.Status })

# Check 6: responder roles, PIM-eligible versus standing.
$responderRecords = [System.Collections.Generic.List[object]]::new()
foreach ($roleName in $ResponderRoleName) {
    $activeCount = $null
    $eligibleCount = $null
    $reason = ''
    $templateId = $null

    try {
        # The server $filter is never trusted for correctness: re-filter client-side
        # on the values actually returned. Zero or more than one match makes the
        # role unresolvable, not a guess at which one is right.
        $rawTemplateMatch = @(Get-OpsGraphPagedValue -Uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates?`$filter=displayName eq '$roleName'")
        $templateMatch = @($rawTemplateMatch | Where-Object { ([string](Get-OpsPropertyValue -InputObject $_ -Name 'displayName')) -eq $roleName })
        if ($templateMatch.Count -eq 0) {
            $reason = "No directory role template named '$roleName' was found."
        } elseif ($templateMatch.Count -gt 1) {
            $reason = "$($templateMatch.Count) directory role templates named '$roleName' were found; cannot unambiguously grade this role."
        } else {
            $templateId = Join-OpsValue (Get-OpsPropertyValue -InputObject $templateMatch[0] -Name 'id')
        }
    } catch {
        $reason = "Role template lookup failed: $($_.Exception.Message)"
    }

    if (-not $reason) {
        try {
            $rawActivatedRole = @(Get-OpsGraphPagedValue -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$templateId'")
            $activatedRole = @($rawActivatedRole | Where-Object { ([string](Get-OpsPropertyValue -InputObject $_ -Name 'roleTemplateId')) -eq $templateId })
            if ($activatedRole.Count -gt 1) {
                $reason = "$($activatedRole.Count) activated directory roles matched role template '$templateId'; cannot unambiguously grade this role."
            } elseif ($activatedRole.Count -eq 1) {
                $roleId = Join-OpsValue (Get-OpsPropertyValue -InputObject $activatedRole[0] -Name 'id')
                $members = @(Get-OpsGraphPagedValue -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members")
                $activeCount = @($members).Count
            } else {
                $activeCount = 0
            }
        } catch {
            $reason = "Active assignment read failed: $($_.Exception.Message)"
        }
    }

    if (-not $reason) {
        try {
            $rawEligible = @(Get-OpsGraphPagedValue -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=roleDefinitionId eq '$templateId'")
            $eligible = @($rawEligible | Where-Object { ([string](Get-OpsPropertyValue -InputObject $_ -Name 'roleDefinitionId')) -eq $templateId })
            $eligibleCount = @($eligible).Count
        } catch {
            $reason = "Eligible assignment read failed: $($_.Exception.Message)"
        }
    }

    $responderRecords.Add((Get-ResponderRoleRecord -RoleName $roleName -ActiveCount $activeCount -EligibleCount $eligibleCount -Reason $reason))
}
$responderOverallStatus = Get-OpsOverallReadinessStatus -Status @($responderRecords | ForEach-Object { $_.Status })

# Check 7: break-glass account FIDO2 registration.
$breakGlassRecords = [System.Collections.Generic.List[object]]::new()
if (-not $BreakGlassUpn -or $BreakGlassUpn.Count -eq 0) {
    $breakGlassRecords.Add([pscustomobject]@{ CheckId = 'BREAK-GLASS'; UserPrincipalName = ''; Fido2Registered = $null; Status = 'NotAssessed'; Finding = 'No -BreakGlassUpn supplied. Break-glass accounts must be named explicitly; this script never guesses one by naming convention.' })
} else {
    foreach ($upn in $BreakGlassUpn) {
        $encodedUpn = [uri]::EscapeDataString($upn)

        # Separate try blocks: the user read and the FIDO2 method read fail
        # independently, and each failure is graded on its own terms. "Not
        # found" is decided only from the HTTP status code on the exception,
        # never by matching text in the exception message (a message can
        # legitimately contain digits that look like a status code, e.g. a
        # GUID substring).
        $userId = $null
        $userLookupFailed = $false
        try {
            $user = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedUpn`?`$select=id,userPrincipalName,accountEnabled" -OutputType Hashtable -ErrorAction Stop
            $userId = Join-OpsValue (Get-OpsPropertyValue -InputObject $user -Name 'id')
        } catch {
            $userLookupFailed = $true
            $statusCode = Get-OpsHttpStatusCode -ErrorRecord $_
            if ($statusCode -eq 404) {
                $breakGlassRecords.Add((Get-BreakGlassAccountRecord -UserPrincipalName $upn -LookupResult 'NotFound'))
            } else {
                $breakGlassRecords.Add((Get-BreakGlassAccountRecord -UserPrincipalName $upn -LookupResult 'NotAssessed' -Reason $_.Exception.Message))
            }
        }

        if ($userLookupFailed) { continue }

        try {
            $fido2 = @(Get-OpsGraphPagedValue -Uri "https://graph.microsoft.com/v1.0/users/$userId/authentication/fido2Methods")
            $breakGlassRecords.Add((Get-BreakGlassAccountRecord -UserPrincipalName $upn -LookupResult 'Found' -Fido2Registered ([bool](@($fido2).Count -gt 0))))
        } catch {
            # Any failure reading FIDO2 methods, including a 403, is
            # NotAssessed for this account. The account was found; whether it
            # has a security key registered simply could not be read.
            $breakGlassRecords.Add((Get-BreakGlassAccountRecord -UserPrincipalName $upn -LookupResult 'NotAssessed' -Reason $_.Exception.Message))
        }
    }
}
$breakGlassOverallStatus = Get-OpsOverallReadinessStatus -Status @($breakGlassRecords | ForEach-Object { $_.Status })

# Check 8: user consent setting and existing delegated OAuth grants.
$authPolicy = $null
$oauthGrantCount = 0
$consentError = $null
try {
    $authResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType Hashtable -ErrorAction Stop
    $rawValue = Get-OpsPropertyValue -InputObject $authResponse -Name 'value'
    $authPolicy = if ($null -ne $rawValue) { @($rawValue) | Select-Object -First 1 } else { $authResponse }
} catch {
    $consentError = $_.Exception.Message
}

try {
    $grants = @(Get-OpsGraphPagedValue -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')
    $oauthGrantCount = @($grants).Count
} catch {
    if (-not $consentError) { $consentError = $_.Exception.Message }
}

$userConsentRecord = if ($consentError) {
    # A grants-read failure alone, even alongside a successful authorization-policy
    # read, must not fall through to Get-UserConsentRecord: that function would grade
    # a real read failure the same as a genuine zero-grant tenant.
    [pscustomobject]@{ CheckId = 'USER-CONSENT'; Status = 'NotAssessed'; Finding = $consentError; PermissionGrantPolicy = ''; OAuthGrantCount = $oauthGrantCount }
} else {
    Get-UserConsentRecord -AuthorizationPolicy $authPolicy -OAuthGrantCount $oauthGrantCount
}

# Check 9: Conditional Access coverage of the device code flow.
$caPolicy = @()
$caError = $null
try {
    $caPolicy = @(Get-OpsGraphPagedValue -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
} catch {
    $caError = $_.Exception.Message
}
$deviceCodeRecord = if ($caError) {
    [pscustomobject]@{ CheckId = 'CA-DEVICE-CODE'; Name = 'Conditional Access coverage of the device code flow'; Status = 'NotAssessed'; Finding = $caError }
} else {
    Get-DeviceCodeFlowCoverageRecord -Policy $caPolicy
}

$readinessChecks = @(
    $ualRecord
    ($entraLogExportRecord | Select-Object CheckId, Name, Status, Finding)
    [pscustomobject]@{ CheckId = 'SUB-ACTIVITY-LOG-EXPORT'; Name = 'Each in-scope subscription Activity Log exported by a diagnostic setting'; Status = $subscriptionOverallStatus; Finding = "$(@($subscriptionRecords | Where-Object { $_.Status -eq 'Met' }).Count) of $($subscriptionRecords.Count) subscription(s) exported." }
    [pscustomobject]@{ CheckId = 'LOG-RETENTION'; Name = 'Destination workspace retention meets the target'; Status = $retentionOverallStatus; Finding = "$(@($retentionRecords | Where-Object { $_.Status -eq 'Met' }).Count) of $($retentionRecords.Count) workspace(s) meet their target retention." }
    ($graphActivityLogRecord | Select-Object CheckId, Name, Status, Finding)
    [pscustomobject]@{ CheckId = 'RESPONDER-ROLES'; Name = 'Responder roles assigned and PIM-eligible rather than standing'; Status = $responderOverallStatus; Finding = "$(@($responderRecords | Where-Object { $_.Status -eq 'Met' }).Count) of $($responderRecords.Count) role(s) fully PIM-eligible with no standing assignment." }
    [pscustomobject]@{ CheckId = 'BREAK-GLASS'; Name = 'Break-glass accounts registered with FIDO2'; Status = $breakGlassOverallStatus; Finding = "$(@($breakGlassRecords | Where-Object { $_.Status -eq 'Met' }).Count) of $($breakGlassRecords.Count) break-glass account(s) have FIDO2 registered." }
    ($userConsentRecord | Select-Object CheckId, @{Name = 'Name'; Expression = { 'User consent setting and existing delegated OAuth grants' } }, Status, Finding)
    ($deviceCodeRecord | Select-Object CheckId, Name, Status, Finding)
)

$overallStatus = Get-OpsOverallReadinessStatus -Status @($readinessChecks | ForEach-Object { $_.Status })

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix

$exports = @(
    Export-OpsReport -Name 'readiness-checks' -Record @($readinessChecks) -Directory $runDirectory
    Export-OpsReport -Name 'responder-roles' -Record @($responderRecords) -Directory $runDirectory
    Export-OpsReport -Name 'break-glass-accounts' -Record @($breakGlassRecords) -Directory $runDirectory
    Export-OpsReport -Name 'subscription-activity-log' -Record @($subscriptionRecords | Select-Object CheckId, SubscriptionId, Status, Finding) -Directory $runDirectory
    Export-OpsReport -Name 'log-retention' -Record @($retentionRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    TenantId = (Get-MgContext).TenantId
    AzureConnected = $azConnected
    SubscriptionId = ($SubscriptionId -join ';')
    TargetRetentionDaysUal = $TargetRetentionDaysUal
    TargetRetentionDaysActivityLog = $TargetRetentionDaysActivityLog
    CheckCount = $readinessChecks.Count
    MetCount = @($readinessChecks | Where-Object { $_.Status -eq 'Met' }).Count
    PartialCount = @($readinessChecks | Where-Object { $_.Status -eq 'Partial' }).Count
    NotMetCount = @($readinessChecks | Where-Object { $_.Status -eq 'NotMet' }).Count
    NotAssessedCount = @($readinessChecks | Where-Object { $_.Status -eq 'NotAssessed' }).Count
    OverallStatus = $overallStatus
    UnifiedAuditLogStatus = $ualRecord.Status
    EntraLogExportStatus = $entraLogExportRecord.Status
    SubscriptionActivityLogStatus = $subscriptionOverallStatus
    SubscriptionActivityLogExportedCount = @($subscriptionRecords | Where-Object { $_.Status -eq 'Met' }).Count
    SubscriptionActivityLogTotalCount = $subscriptionRecords.Count
    LogRetentionStatus = $retentionOverallStatus
    GraphActivityLogStatus = $graphActivityLogRecord.Status
    ResponderRoleStatus = $responderOverallStatus
    ResponderRoleEligibleCount = @($responderRecords | Where-Object { $_.EligibleCount -gt 0 }).Count
    ResponderRoleStandingCount = @($responderRecords | Where-Object { $_.ActiveCount -gt 0 }).Count
    BreakGlassStatus = $breakGlassOverallStatus
    BreakGlassCount = @($breakGlassRecords | Where-Object { $_.UserPrincipalName }).Count
    BreakGlassFido2Count = @($breakGlassRecords | Where-Object { $_.Fido2Registered -eq $true }).Count
    UserConsentStatus = $userConsentRecord.Status
    OAuthGrantCount = $oauthGrantCount
    ConditionalAccessDeviceCodeStatus = $deviceCodeRecord.Status
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory

if ($DisconnectWhenFinished) {
    Disconnect-MgGraph | Out-Null
    if ($azConnected) {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
    }
}
