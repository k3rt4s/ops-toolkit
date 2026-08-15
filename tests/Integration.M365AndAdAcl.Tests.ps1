#Requires -Modules Pester

# End-to-end runs of the Microsoft 365 mailbox collector and the AD ACL risk report
# against stubbed back ends with known facts planted.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:modulePath = Use-FakeActiveDirectory
}

AfterAll {
    if ($script:modulePath -and (Test-Path $script:modulePath)) {
        Remove-Item $script:modulePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-M365MailboxSecurityPosture end to end' {
    BeforeAll {
        # Import first, then stub: the script's #Requires re-imports the module and a
        # later import replaces a function of the same name.
        $setup = @'
Import-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue

function Connect-ExchangeOnline { param($ShowBanner, $Organization) }
function Disconnect-ExchangeOnline { param($Confirm) }
function Get-AcceptedDomain { @([pscustomobject]@{ DomainName = 'contoso.com' }) }

function Get-Mailbox {
    param($ResultSize)
    @(
        [pscustomobject]@{ Guid = [guid]'11111111-1111-1111-1111-111111111111'
            UserPrincipalName = 'leaker@contoso.com'; PrimarySmtpAddress = 'leaker@contoso.com'
            DisplayName = 'Leaker'; RecipientTypeDetails = 'UserMailbox'
            ForwardingSmtpAddress = 'smtp:attacker@evil.example'; ForwardingAddress = $null
            DeliverToMailboxAndForward = $true; LitigationHoldEnabled = $false; AuditEnabled = $true }
        [pscustomobject]@{ Guid = [guid]'22222222-2222-2222-2222-222222222222'
            UserPrincipalName = 'internal@contoso.com'; PrimarySmtpAddress = 'internal@contoso.com'
            DisplayName = 'Internal Fwd'; RecipientTypeDetails = 'UserMailbox'
            ForwardingSmtpAddress = 'smtp:colleague@contoso.com'; ForwardingAddress = $null
            DeliverToMailboxAndForward = $false; LitigationHoldEnabled = $false; AuditEnabled = $true }
        [pscustomobject]@{ Guid = [guid]'33333333-3333-3333-3333-333333333333'
            UserPrincipalName = 'legacy@contoso.com'; PrimarySmtpAddress = 'legacy@contoso.com'
            DisplayName = 'Legacy Protocols'; RecipientTypeDetails = 'UserMailbox'
            ForwardingSmtpAddress = $null; ForwardingAddress = $null
            DeliverToMailboxAndForward = $false; LitigationHoldEnabled = $false; AuditEnabled = $true }
        [pscustomobject]@{ Guid = [guid]'44444444-4444-4444-4444-444444444444'
            UserPrincipalName = 'clean@contoso.com'; PrimarySmtpAddress = 'clean@contoso.com'
            DisplayName = 'Clean'; RecipientTypeDetails = 'UserMailbox'
            ForwardingSmtpAddress = $null; ForwardingAddress = $null
            DeliverToMailboxAndForward = $false; LitigationHoldEnabled = $true; AuditEnabled = $true }
    )
}

function Get-CASMailbox {
    param($ResultSize)
    @(
        [pscustomobject]@{ Guid = [guid]'11111111-1111-1111-1111-111111111111'; ImapEnabled = $false; PopEnabled = $false; EwsEnabled = $false; ActiveSyncEnabled = $false; SmtpClientAuthenticationDisabled = $true }
        [pscustomobject]@{ Guid = [guid]'22222222-2222-2222-2222-222222222222'; ImapEnabled = $false; PopEnabled = $false; EwsEnabled = $false; ActiveSyncEnabled = $false; SmtpClientAuthenticationDisabled = $true }
        [pscustomobject]@{ Guid = [guid]'33333333-3333-3333-3333-333333333333'; ImapEnabled = $true; PopEnabled = $true; EwsEnabled = $true; ActiveSyncEnabled = $true; SmtpClientAuthenticationDisabled = $false }
        [pscustomobject]@{ Guid = [guid]'44444444-4444-4444-4444-444444444444'; ImapEnabled = $false; PopEnabled = $false; EwsEnabled = $false; ActiveSyncEnabled = $false; SmtpClientAuthenticationDisabled = $true }
    )
}

# Forward externally then delete: the compromise pattern, not a convenience rule.
function Get-InboxRule {
    param($Mailbox)
    if ($Mailbox -eq '11111111-1111-1111-1111-111111111111') {
        return @([pscustomobject]@{ Name = 'hide it'; Enabled = $true; ForwardTo = @('attacker@evil.example'); ForwardAsAttachmentTo = @(); RedirectTo = @(); DeleteMessage = $true; MoveToFolder = $null })
    }
    @()
}

function Get-OrganizationConfig {
    [pscustomobject]@{ SmtpClientAuthenticationDisabled = $false; EwsApplicationAccessPolicy = $null
        EwsAllowList = @(); EwsEnabled = $true; AuditDisabled = $false }
}

function Get-HostedOutboundSpamFilterPolicy {
    @([pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Automatic' })
}
'@

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1' `
            -Setup $setup -Argument @{
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "m365-$([guid]::NewGuid().ToString('N'))")
            IncludeInboxRules = $true
        }
        $script:summary = $script:run.Summary
        if ($script:summary) {
            $script:forwarding = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'forwarding-findings.csv'))
            $script:rules = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'inbox-rule-forwarding.csv'))
            $script:protocols = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'protocol-exposure.csv'))
            $script:org = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'organization-settings.csv'))
        }
    }

    It 'runs to completion against a stubbed Exchange Online' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'reads accepted domains from the tenant rather than needing them supplied' {
        $script:summary.InternalDomainsKnown | Should -BeTrue
    }

    It 'classifies the external forward as External and rates it High' {
        $finding = @($script:forwarding | Where-Object { $_.PrimarySmtpAddress -eq 'leaker@contoso.com' })
        $finding.Count | Should -Be 1
        $finding[0].Classification | Should -Be 'External'
        $finding[0].Severity | Should -Be 'High'
    }

    It 'classifies the internal forward as Internal' {
        ($script:forwarding | Where-Object { $_.PrimarySmtpAddress -eq 'internal@contoso.com' }).Classification | Should -Be 'Internal'
    }

    It 'reports the inbox rule separately from the mailbox forward' {
        # Clearing mailbox forwarding does not remove an inbox rule. Both must be seen.
        $script:rules.Count | Should -Be 1
        $script:rules[0].Classification | Should -Be 'External'
    }

    It 'flags the rule that forwards and then hides the message' {
        $script:rules[0].AlsoDeletesOrMoves | Should -Be 'True'
        $script:summary.InboxRuleForwardAndHideCount | Should -Be 1
    }

    It 'finds every legacy protocol on the one mailbox that has them' {
        foreach ($protocol in 'IMAP', 'POP', 'EWS', 'SMTP AUTH') {
            @($script:protocols | Where-Object { $_.Protocol -eq $protocol }).PrimarySmtpAddress | Should -Be 'legacy@contoso.com'
        }
    }

    It 'does not report the clean mailbox' {
        @($script:forwarding | Where-Object { $_.PrimarySmtpAddress -eq 'clean@contoso.com' }).Count | Should -Be 0
        @($script:protocols | Where-Object { $_.PrimarySmtpAddress -eq 'clean@contoso.com' }).Count | Should -Be 0
    }

    It 'flags tenant-wide SMTP basic authentication as needing review' {
        ($script:org | Where-Object { $_.Setting -eq 'SmtpClientAuthenticationDisabled' }).Assessment | Should -Be 'Review'
    }

    It 'flags automatic external auto-forwarding as needing review' {
        ($script:org | Where-Object { $_.Setting -like 'AutoForwardingMode*' }).Assessment | Should -Be 'Review'
    }
}

Describe 'Export-AdAclRiskReport end to end' {
    BeforeAll {
        $setup = @'
$domainSid = 'S-1-5-21-1-2-3'
$domainDn = 'DC=test,DC=local'
$daDn = "CN=Domain Admins,$domainDn"

$global:FakeAdData = @{
    Domain = [pscustomobject]@{ DNSRoot = 'test.local'; DomainSID = $domainSid; DistinguishedName = $domainDn }
    Forest = [pscustomobject]@{ RootDomain = 'test.local' }
    Groups = @([pscustomobject]@{ Name = 'Domain Admins'; SID = "$domainSid-512"; DistinguishedName = $daDn; Members = @() })
    GroupMembers = @{ $daDn = @() }
}

# Get-Acl is a real cmdlet, so the stub must be defined after any module load. The
# domain root carries a DCSync grant; Domain Admins carries a GenericAll for an
# ordinary user; Local System is present and must be suppressed as expected.
function Get-Acl {
    param($Path, $Audit, $Filter)
    # Match the domain root exactly. "*$domainDn" also matches every child object,
    # including CN=Domain Admins, which handed the group the root's rules.
    $rules = if ($Path -eq "AD:\$domainDn") {
        @(
            [pscustomobject]@{ IdentityReference = 'CONTOSO\svc_backup'; ActiveDirectoryRights = 'ExtendedRight'; AccessControlType = 'Allow'; ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; IsInherited = $false }
            [pscustomobject]@{ IdentityReference = 'CONTOSO\svc_backup'; ActiveDirectoryRights = 'ExtendedRight'; AccessControlType = 'Allow'; ObjectType = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; IsInherited = $false }
            [pscustomobject]@{ IdentityReference = 'NT AUTHORITY\SYSTEM'; ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Allow'; ObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $false }
        )
    } else {
        @(
            [pscustomobject]@{ IdentityReference = 'CONTOSO\helpdesk'; ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Allow'; ObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $false }
            [pscustomobject]@{ IdentityReference = 'CONTOSO\auditor'; ActiveDirectoryRights = 'ReadProperty'; AccessControlType = 'Allow'; ObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $false }
            [pscustomobject]@{ IdentityReference = 'CONTOSO\denied'; ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Deny'; ObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $false }
        )
    }

    [pscustomobject]@{ Access = $rules }
}
'@

        $script:aclRun = Invoke-ScriptUnderTest -RelativePath 'scripts\active-directory\Export-AdAclRiskReport.ps1' `
            -Setup $setup -ModulePath $script:modulePath `
            -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "adacl-$([guid]::NewGuid().ToString('N'))") }
        $script:aclSummary = $script:aclRun.Summary
        $script:aclFindings = if ($script:aclSummary) { @(Import-Csv (Join-Path $script:aclSummary.OutputDirectory 'acl-findings.csv')) } else { @() }
        $script:principals = if ($script:aclSummary) { @(Import-Csv (Join-Path $script:aclSummary.OutputDirectory 'principal-rollup.csv')) } else { @() }
    }

    It 'runs to completion with no domain' {
        $script:aclRun.ExitCode | Should -Be 0 -Because "the script failed: $($script:aclRun.Output)"
        $script:aclSummary | Should -Not -BeNullOrEmpty
    }

    It 'finds both replication rights on the domain root' {
        $replication = @($script:aclFindings | Where-Object { $_.Right -like 'DS-Replication-Get-Changes*' })
        $replication.Count | Should -Be 2
    }

    It 'flags the principal holding both replication rights as granting DCSync' {
        # Holding both is a different and worse fact than holding either alone.
        ($script:principals | Where-Object { $_.Principal -eq 'CONTOSO\svc_backup' }).GrantsDcSync | Should -Be 'True'
        $script:aclSummary.PrincipalsWithDcSync | Should -Be 1
    }

    It 'finds GenericAll on the privileged group' {
        @($script:aclFindings | Where-Object { $_.Right -eq 'GenericAll' -and $_.Principal -eq 'CONTOSO\helpdesk' }).Count | Should -BeGreaterThan 0
    }

    It 'suppresses Local System, which holds broad rights by design' {
        @($script:aclFindings | Where-Object { $_.Principal -eq 'NT AUTHORITY\SYSTEM' }).Count | Should -Be 0
    }

    It 'does not treat a Deny ACE as a grant' {
        @($script:aclFindings | Where-Object { $_.Principal -eq 'CONTOSO\denied' }).Count | Should -Be 0
    }

    It 'ignores a harmless right' {
        @($script:aclFindings | Where-Object { $_.Principal -eq 'CONTOSO\auditor' }).Count | Should -Be 0
    }

    It 'sorts the most severe finding first' {
        $script:aclFindings[0].Severity | Should -Be 'Critical'
    }
}
