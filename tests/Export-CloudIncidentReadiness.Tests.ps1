#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\entra\Export-CloudIncidentReadiness.ps1'

    function New-DiagnosticSetting {
        param(
            $Name = 'export-1',
            $WorkspaceResourceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1',
            $Category = 'AuditLogs',
            $Enabled = $true
        )

        @{
            name = $Name
            properties = @{
                workspaceId = $WorkspaceResourceId
                logs = @(@{ category = $Category; enabled = $Enabled })
            }
        }
    }

    function New-CaPolicy {
        param($Id = 'p1', $Name = 'Policy', $State = 'enabled', $TransferMethods = 'deviceCodeFlow', $Controls = @('block'))

        @{
            id = $Id
            displayName = $Name
            state = $State
            conditions = @{ authenticationFlows = @{ transferMethods = $TransferMethods } }
            grantControls = @{ builtInControls = $Controls }
        }
    }
}

Describe 'Get-OpsOverallReadinessStatus' {
    It 'is NotAssessed when any input is NotAssessed, even alongside Met' {
        Get-OpsOverallReadinessStatus -Status @('Met', 'NotAssessed') | Should -Be 'NotAssessed'
    }

    It 'is NotAssessed for an empty input, never a silent pass' {
        Get-OpsOverallReadinessStatus -Status @() | Should -Be 'NotAssessed'
    }

    It 'is NotMet when NotMet and Partial are both present' {
        Get-OpsOverallReadinessStatus -Status @('NotMet', 'Partial', 'Met') | Should -Be 'NotMet'
    }

    It 'is Partial when Partial and Met are both present' {
        Get-OpsOverallReadinessStatus -Status @('Partial', 'Met') | Should -Be 'Partial'
    }

    It 'is Met only when every input is Met' {
        Get-OpsOverallReadinessStatus -Status @('Met', 'Met') | Should -Be 'Met'
    }
}

Describe 'Get-UnifiedAuditLogIngestionRecord' {
    It 'is NotAssessed when Get-AdminAuditLogConfig is not available' {
        if (Get-Command -Name Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
            Remove-Item -LiteralPath 'function:Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
        }
        $record = Get-UnifiedAuditLogIngestionRecord
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match 'Exchange Online'
    }

    It 'is Met when the cmdlet reports ingestion enabled' {
        try {
            function global:Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $true } }
            (Get-UnifiedAuditLogIngestionRecord).Status | Should -Be 'Met'
        } finally {
            Remove-Item -LiteralPath 'function:Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
        }
    }

    It 'is NotMet when the cmdlet reports ingestion disabled' {
        try {
            function global:Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $false } }
            (Get-UnifiedAuditLogIngestionRecord).Status | Should -Be 'NotMet'
        } finally {
            Remove-Item -LiteralPath 'function:Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
        }
    }

    It 'is NotAssessed, not a false pass, when the read throws' {
        try {
            function global:Get-AdminAuditLogConfig { throw 'access denied' }
            $record = Get-UnifiedAuditLogIngestionRecord
            $record.Status | Should -Be 'NotAssessed'
            $record.Finding | Should -Match 'access denied'
        } finally {
            Remove-Item -LiteralPath 'function:Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
        }
    }

    It 'is NotAssessed when the expected field is absent from the response' {
        try {
            function global:Get-AdminAuditLogConfig { [pscustomobject]@{ SomeOtherField = 'x' } }
            (Get-UnifiedAuditLogIngestionRecord).Status | Should -Be 'NotAssessed'
        } finally {
            Remove-Item -LiteralPath 'function:Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-OpsDiagnosticExportRecord' {
    It 'is not exported against an empty diagnostic settings array' {
        # Null shape: a subscription (or tenant) with no diagnostic settings at all.
        $record = Get-OpsDiagnosticExportRecord -Category 'AuditLogs' -DiagnosticSetting @()
        $record.Exported | Should -BeFalse
        $record.Destination.Count | Should -Be 0
    }

    It 'finds the category when an enabled log matches' {
        $record = Get-OpsDiagnosticExportRecord -Category 'AuditLogs' -DiagnosticSetting @((New-DiagnosticSetting -Category 'AuditLogs' -Enabled $true))
        $record.Exported | Should -BeTrue
        $record.Destination[0].WorkspaceResourceId | Should -Be '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1'
    }

    It 'does not count a disabled log as exported' {
        $record = Get-OpsDiagnosticExportRecord -Category 'AuditLogs' -DiagnosticSetting @((New-DiagnosticSetting -Category 'AuditLogs' -Enabled $false))
        $record.Exported | Should -BeFalse
    }

    It 'ignores a different category on the same setting' {
        $record = Get-OpsDiagnosticExportRecord -Category 'SignInLogs' -DiagnosticSetting @((New-DiagnosticSetting -Category 'AuditLogs'))
        $record.Exported | Should -BeFalse
    }
}

Describe 'Get-EntraLogExportRecord' {
    It 'is Met when both AuditLogs and SignInLogs are exported' {
        $settings = @((New-DiagnosticSetting -Category 'AuditLogs'), (New-DiagnosticSetting -Category 'SignInLogs'))
        (Get-EntraLogExportRecord -DiagnosticSetting $settings).Status | Should -Be 'Met'
    }

    It 'is Partial when only one of the two is exported' {
        $settings = @((New-DiagnosticSetting -Category 'AuditLogs'))
        (Get-EntraLogExportRecord -DiagnosticSetting $settings).Status | Should -Be 'Partial'
    }

    It 'is NotMet, not NotAssessed, when the read succeeded but found nothing' {
        (Get-EntraLogExportRecord -DiagnosticSetting @()).Status | Should -Be 'NotMet'
    }
}

Describe 'Get-SubscriptionActivityLogRecord' {
    It 'is NotMet against an empty diagnostic settings array' {
        # Null shape: the subscription has no diagnostic settings.
        $record = Get-SubscriptionActivityLogRecord -SubscriptionId 'sub-2' -DiagnosticSetting @()
        $record.Status | Should -Be 'NotMet'
        $record.SubscriptionId | Should -Be 'sub-2'
    }

    It 'is Met when the Administrative category is exported' {
        $record = Get-SubscriptionActivityLogRecord -SubscriptionId 'sub-1' -DiagnosticSetting @((New-DiagnosticSetting -Category 'Administrative'))
        $record.Status | Should -Be 'Met'
    }
}

Describe 'Get-WorkspaceRetentionRecord' {
    It 'is NotAssessed when the workspace could not be read at all' {
        $record = Get-WorkspaceRetentionRecord -WorkspaceResourceId '/ws1' -Workspace $null -TargetRetentionDays 90 -Purpose 'EntraLogs' -Reason 'read failed'
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match 'read failed'
    }

    It 'is NotAssessed, not a false pass, when the workspace has no retention property' {
        # Null shape: a workspace object with no retentionInDays property.
        $workspace = @{ properties = @{ sku = @{ name = 'PerGB2018' } } }
        $record = Get-WorkspaceRetentionRecord -WorkspaceResourceId '/ws1' -Workspace $workspace -TargetRetentionDays 90 -Purpose 'EntraLogs'
        $record.Status | Should -Be 'NotAssessed'
    }

    It 'is NotMet when retention is below the target' {
        $workspace = @{ properties = @{ retentionInDays = 30 } }
        $record = Get-WorkspaceRetentionRecord -WorkspaceResourceId '/ws1' -Workspace $workspace -TargetRetentionDays 90 -Purpose 'EntraLogs'
        $record.Status | Should -Be 'NotMet'
        $record.RetentionDays | Should -Be 30
    }

    It 'is Met when retention meets or exceeds the target' {
        $workspace = @{ properties = @{ retentionInDays = 180 } }
        $record = Get-WorkspaceRetentionRecord -WorkspaceResourceId '/ws1' -Workspace $workspace -TargetRetentionDays 180 -Purpose 'SubscriptionActivityLog'
        $record.Status | Should -Be 'Met'
    }
}

Describe 'Get-ResponderRoleRecord' {
    It 'is NotAssessed, not a false pass, when a count could not be read' {
        $record = Get-ResponderRoleRecord -RoleName 'Security Reader' -ActiveCount $null -EligibleCount $null -Reason 'Active assignment read failed: Insufficient privileges to complete the operation. 403 Forbidden'
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match '403'
    }

    It 'is NotMet when a role has no assignments at all' {
        # Null shape: a role with no active and no eligible assignments.
        $record = Get-ResponderRoleRecord -RoleName 'Security Operator' -ActiveCount 0 -EligibleCount 0
        $record.Status | Should -Be 'NotMet'
    }

    It 'is Met when the only assignment is PIM-eligible' {
        $record = Get-ResponderRoleRecord -RoleName 'Global Reader' -ActiveCount 0 -EligibleCount 2
        $record.Status | Should -Be 'Met'
    }

    It 'is Partial when a standing assignment exists alongside eligible coverage' {
        $record = Get-ResponderRoleRecord -RoleName 'Global Reader' -ActiveCount 1 -EligibleCount 2
        $record.Status | Should -Be 'Partial'
        $record.Finding | Should -Match 'Standing'
    }
}

Describe 'Get-BreakGlassAccountRecord' {
    It 'is Met when a FIDO2 key is registered' {
        (Get-BreakGlassAccountRecord -UserPrincipalName 'bg1@contoso.com' -LookupResult 'Found' -Fido2Registered $true).Status | Should -Be 'Met'
    }

    It 'is NotMet when no FIDO2 key is registered' {
        (Get-BreakGlassAccountRecord -UserPrincipalName 'bg1@contoso.com' -LookupResult 'Found' -Fido2Registered $false).Status | Should -Be 'NotMet'
    }

    It 'is NotMet when the named account does not exist' {
        (Get-BreakGlassAccountRecord -UserPrincipalName 'bg1@contoso.com' -LookupResult 'NotFound').Status | Should -Be 'NotMet'
    }

    It 'is NotAssessed, not a false pass, when the read failed' {
        $record = Get-BreakGlassAccountRecord -UserPrincipalName 'bg1@contoso.com' -LookupResult 'NotAssessed' -Reason '403 Forbidden'
        $record.Status | Should -Be 'NotAssessed'
        $record.Finding | Should -Match '403'
    }
}

Describe 'Get-UserConsentRecord' {
    It 'is NotAssessed, not a false pass, when the policy could not be read' {
        (Get-UserConsentRecord -AuthorizationPolicy $null -OAuthGrantCount 0).Status | Should -Be 'NotAssessed'
    }

    It 'reports zero existing grants without failing' {
        # Null shape: a tenant with no oauth2PermissionGrants at all.
        $policy = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }
        $record = Get-UserConsentRecord -AuthorizationPolicy $policy -OAuthGrantCount 0
        $record.OAuthGrantCount | Should -Be 0
        $record.Status | Should -Be 'Met'
    }

    It 'is NotMet when user consent for any app (legacy default) is assigned' {
        $policy = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') } }
        (Get-UserConsentRecord -AuthorizationPolicy $policy -OAuthGrantCount 3).Status | Should -Be 'NotMet'
    }

    It 'is Partial when consent is limited to low-risk apps' {
        $policy = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } }
        (Get-UserConsentRecord -AuthorizationPolicy $policy -OAuthGrantCount 1).Status | Should -Be 'Partial'
    }
}

Describe 'Get-DeviceCodeFlowCoverageRecord' {
    It 'is NotMet against an empty policy array' {
        # Null shape: a tenant with no Conditional Access policies at all.
        (Get-DeviceCodeFlowCoverageRecord -Policy @()).Status | Should -Be 'NotMet'
    }

    It 'is Met when an enabled policy blocks the device code flow' {
        $policy = @((New-CaPolicy -State 'enabled' -TransferMethods 'deviceCodeFlow' -Controls @('block')))
        (Get-DeviceCodeFlowCoverageRecord -Policy $policy).Status | Should -Be 'Met'
    }

    It 'ignores a report-only policy' {
        $policy = @((New-CaPolicy -State 'enabledForReportingButNotEnforced' -TransferMethods 'deviceCodeFlow' -Controls @('block')))
        (Get-DeviceCodeFlowCoverageRecord -Policy $policy).Status | Should -Be 'NotMet'
    }

    It 'ignores a policy that blocks a different flow' {
        $policy = @((New-CaPolicy -State 'enabled' -TransferMethods 'none' -Controls @('block')))
        (Get-DeviceCodeFlowCoverageRecord -Policy $policy).Status | Should -Be 'NotMet'
    }

    It 'never repeats the legacy-authentication grading owned by Export-EntraConditionalAccessBaseline.ps1' {
        $policy = @((New-CaPolicy -State 'enabled' -TransferMethods 'deviceCodeFlow' -Controls @('block')))
        (Get-DeviceCodeFlowCoverageRecord -Policy $policy).Finding | Should -Match 'IAM-01'
    }
}
