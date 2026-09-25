#Requires -Modules Pester

# End-to-end run of Export-CloudIncidentReadiness.ps1 against a stubbed Microsoft
# Graph and a stubbed Azure Resource Manager, with known facts planted: Unified
# Audit Log ingestion on, one of two subscriptions missing its Activity Log export,
# a destination workspace retaining fewer days than the target, a Security Reader
# read that fails with 403, and both a Graph and an Azure Resource Manager page
# reached only through its nextLink/@odata.nextLink. Every stub records the call it
# received to a log file the test reads back afterward, so a passing run proves the
# stub executed rather than the real cmdlet.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    # Import the real modules first, then define the stubs, exactly as
    # Integration.Entra.Tests.ps1 does: the script's own #Requires imports the real
    # module again, and a module imported after a function of the same name replaces
    # it, so a stub defined after the import is the one left standing.
    $script:graphStub = @'
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Connect-MgGraph { param($Scopes, $TenantId, $UseDeviceCode) }
function Get-MgContext { [pscustomobject]@{ TenantId = 'contoso-tenant-id'; Account = 'admin@contoso.com' } }
function Disconnect-MgGraph { }
'@

    $script:azStub = @'
Import-Module Az.Accounts -Force -ErrorAction SilentlyContinue

function Connect-AzAccount { param($Tenant, $UseDeviceAuthentication) }
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' }; Tenant = [pscustomobject]@{ Id = 'contoso-tenant-id' } } }
function Disconnect-AzAccount { }
'@
}

Describe 'Export-CloudIncidentReadiness end to end' {
    BeforeAll {
        $script:callLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "ops-callog-$([guid]::NewGuid().ToString('N')).log"
        Set-Content -LiteralPath $script:callLogPath -Encoding utf8 -Value ''

        $fixture = @"
`$env:OPSTOOLKIT_TEST_CALL_LOG = '$($script:callLogPath)'

function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = `$true } }

function Invoke-AzRestMethod {
    param(`$Path, `$Method, `$ErrorAction)
    Add-Content -LiteralPath `$env:OPSTOOLKIT_TEST_CALL_LOG -Encoding utf8 -Value ('AZ:' + `$Method + ':' + `$Path)

    if (`$Path -like '*microsoft.aadiam/diagnosticSettings*') {
        `$body = @{ value = @(
            @{ name = 'entra-export'; properties = @{
                workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/workspaceA'
                logs = @(
                    @{ category = 'AuditLogs'; enabled = `$true }
                    @{ category = 'SignInLogs'; enabled = `$true }
                    @{ category = 'MicrosoftGraphActivityLogs'; enabled = `$true }
                )
            } }
        ) } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*sub-1/providers/microsoft.insights/diagnosticSettings*' -and `$Path -notlike '*skiptoken*') {
        # First page carries no data and points at the second page, proving ARM
        # pagination is followed rather than assumed to be a single page.
        `$body = @{ value = @(); nextLink = 'https://management.azure.com/subscriptions/sub-1/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview&%24skiptoken=page2' } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*skiptoken=page2*') {
        `$body = @{ value = @(
            @{ name = 'sub1-activity-export'; properties = @{
                workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/workspaceB'
                logs = @( @{ category = 'Administrative'; enabled = `$true } )
            } }
        ) } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*sub-2/providers/microsoft.insights/diagnosticSettings*') {
        # Null shape: this subscription has no diagnostic settings at all.
        `$body = @{ value = @() } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*Microsoft.OperationalInsights/workspaces/workspaceA*') {
        `$body = @{ properties = @{ retentionInDays = 30 } } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*Microsoft.OperationalInsights/workspaces/workspaceB*') {
        `$body = @{ properties = @{ retentionInDays = 200 } } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    throw "Unstubbed Invoke-AzRestMethod path: `$Path"
}

function Invoke-MgGraphRequest {
    param(`$Method, `$Uri, `$OutputType, `$ErrorAction)
    Add-Content -LiteralPath `$env:OPSTOOLKIT_TEST_CALL_LOG -Encoding utf8 -Value ('MG:' + `$Method + ':' + `$Uri)

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies') {
        return @{
            value = @(
                @{ id = 'p1'; displayName = 'Report only device compliance'; state = 'enabledForReportingButNotEnforced'
                   conditions = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } }
                   grantControls = @{ builtInControls = @('block') } }
            )
            '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?%24skiptoken=page2'
        }
    }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?%24skiptoken=page2') {
        # Second page, reached only through @odata.nextLink, carries the policy that
        # actually blocks the flow. Proves Graph pagination is followed. Scoped to
        # includeUsers 'All' so it grades tenant-wide coverage, not a narrower scope.
        return @{
            value = @(
                @{ id = 'p2'; displayName = 'Block device code flow'; state = 'enabled'
                   conditions = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' }; users = @{ includeUsers = @('All') } }
                   grantControls = @{ builtInControls = @('block') } }
            )
        }
    }

    if (`$Uri -like '*directoryRoleTemplates*Global Reader*') { return @{ value = @(@{ id = 'tmpl-global-reader' }) } }
    if (`$Uri -like '*directoryRoleTemplates*Security Reader*') { return @{ value = @(@{ id = 'tmpl-security-reader' }) } }
    if (`$Uri -like '*directoryRoleTemplates*Security Operator*') { return @{ value = @(@{ id = 'tmpl-security-operator' }) } }

    if (`$Uri -like "*directoryRoles?*tmpl-global-reader*") { return @{ value = @(@{ id = 'role-global-reader' }) } }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/directoryRoles/role-global-reader/members') { return @{ value = @() } }
    if (`$Uri -like "*roleEligibilityScheduleInstances?*tmpl-global-reader*") { return @{ value = @(@{ id = 'elig-1' }) } }

    if (`$Uri -like "*directoryRoles?*tmpl-security-reader*") {
        throw 'Insufficient privileges to complete the operation. Status: 403 (Forbidden)'
    }

    if (`$Uri -like "*directoryRoles?*tmpl-security-operator*") {
        # Null shape: a role with no standing assignments at all.
        return @{ value = @() }
    }
    if (`$Uri -like "*roleEligibilityScheduleInstances?*tmpl-security-operator*") { return @{ value = @() } }

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy') {
        return @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } }
    }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants') {
        # Null shape: a tenant with no existing delegated OAuth grants at all.
        return @{ value = @() }
    }

    if (`$Uri -like '*/users/breakglass1@contoso.com*') {
        return @{ id = 'bg-1'; userPrincipalName = 'breakglass1@contoso.com'; accountEnabled = `$true }
    }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/users/bg-1/authentication/fido2Methods') {
        return @{ value = @(@{ id = 'fido-1' }) }
    }

    throw "Unstubbed Invoke-MgGraphRequest uri: `$Uri"
}
"@

        $setup = $script:graphStub + $script:azStub + $fixture

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-CloudIncidentReadiness.ps1' `
            -Setup $setup -Argument @{
            Connect = $true
            ConnectAzure = $true
            SubscriptionId = @('sub-1', 'sub-2')
            BreakGlassUpn = @('breakglass1@contoso.com')
            TargetRetentionDaysUal = 90
            TargetRetentionDaysActivityLog = 180
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "cloudir-$([guid]::NewGuid().ToString('N'))")
        }
        $script:summary = $script:run.Summary
        $script:checks = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'readiness-checks.csv')) } else { @() }
        $script:callLog = if (Test-Path -LiteralPath $script:callLogPath) { Get-Content -LiteralPath $script:callLogPath } else { @() }
    }

    It 'runs to completion against the stub' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'proves the stub executed rather than the real cmdlets' {
        # A real, unauthenticated Invoke-AzRestMethod/Invoke-MgGraphRequest call
        # would have thrown before writing any report and the run above would have
        # failed. This call log is written only by the stub functions, so its
        # presence with the expected paths and URIs is independent proof the stub
        # path executed for every read, not just that the exit code was 0.
        $script:callLog.Count | Should -BeGreaterThan 0
        ($script:callLog | Where-Object { $_ -match 'AZ:GET:.*microsoft\.aadiam/diagnosticSettings' }).Count | Should -BeGreaterThan 0
        ($script:callLog | Where-Object { $_ -match 'AZ:GET:.*sub-1/providers/microsoft\.insights/diagnosticSettings' }).Count | Should -BeGreaterThan 0
        ($script:callLog | Where-Object { $_ -match 'AZ:GET:.*sub-2/providers/microsoft\.insights/diagnosticSettings' }).Count | Should -BeGreaterThan 0
        ($script:callLog | Where-Object { $_ -match 'MG:GET:.*conditionalAccess/policies' }).Count | Should -BeGreaterThan 0
    }

    It 'grades Unified Audit Log ingestion Met' {
        ($script:checks | Where-Object { $_.CheckId -eq 'UAL-INGEST' }).Status | Should -Be 'Met'
    }

    It 'grades one of two subscriptions missing its Activity Log export as NotMet, not Partial or a silent pass' {
        $record = $script:checks | Where-Object { $_.CheckId -eq 'SUB-ACTIVITY-LOG-EXPORT' }
        $record.Status | Should -Be 'NotMet'
        $record.Finding | Should -Match '1 of 2'
    }

    It 'grades the under-retained destination workspace NotMet against its target' {
        $record = $script:checks | Where-Object { $_.CheckId -eq 'LOG-RETENTION' }
        $record.Status | Should -Be 'NotMet'
    }

    It 'grades the responder-role check NotAssessed and carries the 403 in its finding' {
        $record = $script:checks | Where-Object { $_.CheckId -eq 'RESPONDER-ROLES' }
        $record.Status | Should -Be 'NotAssessed'
        $roleRows = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'responder-roles.csv'))
        $securityReaderRow = $roleRows | Where-Object { $_.RoleName -eq 'Security Reader' }
        $securityReaderRow.Status | Should -Be 'NotAssessed'
        $securityReaderRow.Finding | Should -Match '403'
    }

    It 'never reports the overall readiness Met while any check is NotAssessed' {
        $script:summary.OverallStatus | Should -Not -Be 'Met'
        $script:summary.NotAssessedCount | Should -BeGreaterThan 0
    }

    It 'follows the Azure Resource Manager nextLink to the page carrying the actual export' {
        # The subscription Activity Log fixture returns nothing on the first ARM
        # page and only the real export on the page reached through nextLink; a
        # Met status here is only possible if that second page was fetched.
        $subscriptionRows = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'subscription-activity-log.csv'))
        ($subscriptionRows | Where-Object { $_.SubscriptionId -eq 'sub-1' }).Status | Should -Be 'Met'
    }

    It 'follows the Graph @odata.nextLink to the policy that blocks the device code flow' {
        ($script:checks | Where-Object { $_.CheckId -eq 'CA-DEVICE-CODE' }).Status | Should -Be 'Met'
    }

    It 'grades the break-glass account Met when FIDO2 is registered' {
        ($script:checks | Where-Object { $_.CheckId -eq 'BREAK-GLASS' }).Status | Should -Be 'Met'
    }

    It 'reports zero existing OAuth grants without failing the read' {
        $script:summary.OAuthGrantCount | Should -Be 0
    }

    It 'never writes a secret, token, or key into a report' {
        (Get-Content (Join-Path $script:summary.OutputDirectory 'summary.json') -Raw) | Should -Not -Match 'secret|password|clientsecret'
    }
}

Describe 'Export-CloudIncidentReadiness treats an Azure session in a different tenant as no Azure session' {
    BeforeAll {
        $script:callLogPath2 = Join-Path ([System.IO.Path]::GetTempPath()) "ops-callog-$([guid]::NewGuid().ToString('N')).log"
        Set-Content -LiteralPath $script:callLogPath2 -Encoding utf8 -Value ''

        $mismatchAzStub = @'
Import-Module Az.Accounts -Force -ErrorAction SilentlyContinue

function Connect-AzAccount { param($Tenant, $UseDeviceAuthentication) }
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-other' }; Tenant = [pscustomobject]@{ Id = 'fabrikam-tenant-id' } } }
function Disconnect-AzAccount { }
'@

        $fixture2 = @"
`$env:OPSTOOLKIT_TEST_CALL_LOG = '$($script:callLogPath2)'

function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = `$true } }

function Invoke-AzRestMethod {
    param(`$Path, `$Method, `$ErrorAction)
    Add-Content -LiteralPath `$env:OPSTOOLKIT_TEST_CALL_LOG -Encoding utf8 -Value ('AZ:' + `$Method + ':' + `$Path)
    throw 'Invoke-AzRestMethod must not be called once the tenant mismatch is detected.'
}

function Invoke-MgGraphRequest {
    param(`$Method, `$Uri, `$OutputType, `$ErrorAction)

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies') { return @{ value = @() } }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy') { return @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } } }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants') { return @{ value = @() } }

    throw "Unstubbed Invoke-MgGraphRequest uri: `$Uri"
}
"@

        $setup2 = $script:graphStub + $mismatchAzStub + $fixture2

        $script:run2 = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-CloudIncidentReadiness.ps1' `
            -Setup $setup2 -Argument @{
            Connect = $true
            ConnectAzure = $true
            TenantId = 'contoso-tenant-id'
            SubscriptionId = @('sub-1')
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "cloudir-$([guid]::NewGuid().ToString('N'))")
        }
        $script:summary2 = $script:run2.Summary
        $script:checks2 = if ($script:summary2) { @(Import-Csv (Join-Path $script:summary2.OutputDirectory 'readiness-checks.csv')) } else { @() }
        $script:callLog2 = if (Test-Path -LiteralPath $script:callLogPath2) { Get-Content -LiteralPath $script:callLogPath2 } else { @() }
    }

    It 'runs to completion' {
        $script:run2.ExitCode | Should -Be 0 -Because "the script failed: $($script:run2.Output)"
    }

    It 'never calls Invoke-AzRestMethod once the mismatch is detected, proving the check was skipped rather than raced' {
        # Set-Content -Value '' seeds the log file with one empty line, so Get-Content
        # always returns at least one element; filter blanks before counting real calls.
        @($script:callLog2 | Where-Object { $_ }).Count | Should -Be 0
    }

    It 'grades the Entra log export NotAssessed with the tenant mismatch reason, not a false read of the wrong tenant' {
        $record = $script:checks2 | Where-Object { $_.CheckId -eq 'ENTRA-LOG-EXPORT' }
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match 'different tenant'
    }

    It 'grades the subscription Activity Log check NotAssessed for the same reason' {
        ($script:checks2 | Where-Object { $_.CheckId -eq 'SUB-ACTIVITY-LOG-EXPORT' }).Status | Should -Be 'NotAssessed'
    }

    It 'reports AzureConnected false in the summary despite a live Az context existing' {
        $script:summary2.AzureConnected | Should -Be $false
    }
}

Describe 'Export-CloudIncidentReadiness grades user consent NotAssessed when only the grants read fails' {
    BeforeAll {
        $fixture3 = @"
function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = `$true } }

function Invoke-AzRestMethod {
    param(`$Path, `$Method, `$ErrorAction)
    throw "Unstubbed Invoke-AzRestMethod path: `$Path"
}

function Invoke-MgGraphRequest {
    param(`$Method, `$Uri, `$OutputType, `$ErrorAction)

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies') { return @{ value = @() } }

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy') {
        return @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }
    }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants') {
        throw 'Insufficient privileges to complete the operation. Status: 403 (Forbidden)'
    }

    throw "Unstubbed Invoke-MgGraphRequest uri: `$Uri"
}
"@

        $setup3 = $script:graphStub + $script:azStub + $fixture3

        $script:run3 = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-CloudIncidentReadiness.ps1' `
            -Setup $setup3 -Argument @{
            Connect = $true
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "cloudir-$([guid]::NewGuid().ToString('N'))")
        }
        $script:summary3 = $script:run3.Summary
        $script:checks3 = if ($script:summary3) { @(Import-Csv (Join-Path $script:summary3.OutputDirectory 'readiness-checks.csv')) } else { @() }
    }

    It 'runs to completion' {
        $script:run3.ExitCode | Should -Be 0 -Because "the script failed: $($script:run3.Output)"
    }

    It 'grades USER-CONSENT NotAssessed with the grants-read failure, not a silent zero-grant pass' {
        $record = $script:checks3 | Where-Object { $_.CheckId -eq 'USER-CONSENT' }
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match '403'
    }
}

Describe 'Export-CloudIncidentReadiness grades a workspace shared by Entra and subscription exports against the stricter target' {
    BeforeAll {
        $fixture4 = @"
function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = `$true } }

function Invoke-AzRestMethod {
    param(`$Path, `$Method, `$ErrorAction)

    if (`$Path -like '*microsoft.aadiam/diagnosticSettings*') {
        `$body = @{ value = @(
            @{ name = 'entra-export'; properties = @{
                workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/shared'
                logs = @( @{ category = 'AuditLogs'; enabled = `$true }, @{ category = 'SignInLogs'; enabled = `$true } )
            } }
        ) } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*sub-1/providers/microsoft.insights/diagnosticSettings*') {
        `$body = @{ value = @(
            @{ name = 'sub1-activity-export'; properties = @{
                workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/shared'
                logs = @( @{ category = 'Administrative'; enabled = `$true } )
            } }
        ) } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    if (`$Path -like '*Microsoft.OperationalInsights/workspaces/shared*') {
        `$body = @{ properties = @{ retentionInDays = 80 } } | ConvertTo-Json -Depth 10
        return [pscustomobject]@{ StatusCode = 200; Content = `$body }
    }

    throw "Unstubbed Invoke-AzRestMethod path: `$Path"
}

function Invoke-MgGraphRequest {
    param(`$Method, `$Uri, `$OutputType, `$ErrorAction)

    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies') { return @{ value = @() } }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy') { return @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } } }
    if (`$Uri -eq 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants') { return @{ value = @() } }

    throw "Unstubbed Invoke-MgGraphRequest uri: `$Uri"
}
"@

        $setup4 = $script:graphStub + $script:azStub + $fixture4

        $script:run4 = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-CloudIncidentReadiness.ps1' `
            -Setup $setup4 -Argument @{
            Connect = $true
            ConnectAzure = $true
            SubscriptionId = @('sub-1')
            TargetRetentionDaysUal = 100
            TargetRetentionDaysActivityLog = 50
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "cloudir-$([guid]::NewGuid().ToString('N'))")
        }
        $script:summary4 = $script:run4.Summary
        $script:retentionRows4 = if ($script:summary4) { @(Import-Csv (Join-Path $script:summary4.OutputDirectory 'log-retention.csv')) } else { @() }
    }

    It 'runs to completion' {
        $script:run4.ExitCode | Should -Be 0 -Because "the script failed: $($script:run4.Output)"
    }

    It 'grades the shared workspace against the stricter (higher) of the two targets, not whichever export was read last' {
        $script:retentionRows4.Count | Should -Be 1
        $record = $script:retentionRows4[0]
        $record.TargetRetentionDays | Should -Be 100
        $record.Status | Should -Be 'NotMet' -Because 'retention of 80 days meets the 50-day Activity Log target but not the stricter 100-day Entra target; a false Met here would mean the overwrite bug survived'
    }

    It 'notes on the shared workspace that both Entra logs and subscription Activity Log purposes apply' {
        $record = $script:retentionRows4[0]
        ($record.Purpose -match 'EntraLogs') | Should -BeTrue
        ($record.Purpose -match 'SubscriptionActivityLog') | Should -BeTrue
    }
}
