#Requires -Modules Pester

# End-to-end runs of the three Entra scripts against a stubbed Graph, with known
# facts planted. The Microsoft.Graph modules are installed, so the stubs are global
# functions that shadow the real cmdlets; a function beats a cmdlet in PowerShell's
# command lookup. Proves the whole pipeline short of the HTTP call itself.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    # Import the real modules first, then define the stubs. A module imported after a
    # function of the same name replaces it, and the script's own #Requires triggers
    # that import, so stubs defined first are silently clobbered and the real cmdlet
    # runs. This cost a debugging round: the failure looked like the stub was ignored.
    $script:graphStub = @'
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Force -ErrorAction SilentlyContinue

function Connect-MgGraph { param($Scopes, $TenantId, $UseDeviceCode) }
function Get-MgContext { [pscustomobject]@{ TenantId = 'contoso-tenant-id'; Account = 'admin@contoso.com' } }
function Disconnect-MgGraph { }
'@
}

Describe 'Export-EntraAppCredentialExpiry end to end' {
    BeforeAll {
        $setup = $script:graphStub + @'

$now = Get-Date
function Get-MgApplication {
    param([switch]$All, $Property)
    @(
        [pscustomobject]@{
            Id = 'app-1'; AppId = 'aaaa-1111'; DisplayName = 'Billing Sync'; SignInAudience = 'AzureADMyOrg'
            PasswordCredentials = @(
                [pscustomobject]@{ KeyId = 'k-expired'; DisplayName = 'prod'; StartDateTime = $now.AddDays(-800); EndDateTime = $now.AddDays(-30); CustomKeyIdentifier = $null }
                [pscustomobject]@{ KeyId = 'k-soon'; DisplayName = 'staging'; StartDateTime = $now.AddDays(-100); EndDateTime = $now.AddDays(20); CustomKeyIdentifier = $null }
            )
            KeyCredentials = @(
                [pscustomobject]@{ KeyId = 'k-cert'; DisplayName = 'signing'; StartDateTime = $now.AddDays(-100); EndDateTime = $now.AddDays(400); CustomKeyIdentifier = [byte[]](0xAB,0xCD,0x01) }
            )
        }
        [pscustomobject]@{
            Id = 'app-2'; AppId = 'bbbb-2222'; DisplayName = 'No Creds App'; SignInAudience = 'AzureADMyOrg'
            PasswordCredentials = @(); KeyCredentials = @()
        }
    )
}
function Get-MgServicePrincipal { param([switch]$All, $Property) @() }
function Get-MgApplicationOwner { param($ApplicationId, [switch]$All) @() }
function Get-MgServicePrincipalOwner { param($ServicePrincipalId, [switch]$All) @() }

# Only the expired credential has been used recently. That is the distinction the
# report exists to draw: renew this one, remove the others.
function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $ErrorAction)
    @{ value = @(
        @{ appId = 'aaaa-1111'; createdDateTime = (Get-Date).AddDays(-2).ToString('o'); servicePrincipalCredentialKeyId = 'k-expired' }
    ) }
}
'@

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-EntraAppCredentialExpiry.ps1' `
            -Setup $setup -Argument @{
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "entracred-$([guid]::NewGuid().ToString('N'))")
            IncludeSignInUsage = $true
        }
        $script:summary = $script:run.Summary
        $script:credentials = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'credentials.csv')) } else { @() }
    }

    It 'runs to completion against a stubbed Graph' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'reports every credential on the application' {
        $script:credentials.Count | Should -Be 3
    }

    It 'classifies expired, expiring and valid correctly' {
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-expired' }).Status | Should -Be 'Expired'
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-soon' }).Status | Should -Be 'ExpiringSoon'
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-cert' }).Status | Should -Be 'Valid'
    }

    It 'matches the sign-in against the specific credential that was used' {
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-expired' }).SignInStatus | Should -Be 'InUse'
    }

    It 'distinguishes an app active on another credential from an unused one' {
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-soon' }).SignInStatus | Should -Be 'AppActiveOnOtherCredential'
    }

    It 'renders the certificate thumbprint as hex' {
        ($script:credentials | Where-Object { $_.KeyId -eq 'k-cert' }).Thumbprint | Should -Be 'ABCD01'
    }

    It 'records the application that has no credentials at all' {
        $script:summary.ObjectsWithoutCredentialsCount | Should -Be 1
    }

    It 'never writes a secret value into a report' {
        (Get-Content (Join-Path $script:summary.OutputDirectory 'credentials.json') -Raw) | Should -Not -Match 'secretText|SecretText'
    }
}

Describe 'Export-EntraAuthMethodReadiness end to end' {
    BeforeAll {
        $setup = $script:graphStub + @'

function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $ErrorAction)
    @{ value = @(
        # Telephony only: the migration list.
        @{ id = 'u1'; userPrincipalName = 'sms.only@contoso.com'; userDisplayName = 'SMS Only'; userType = 'Member'
           isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $false
           methodsRegistered = @('sms'); userPreferredMethodForSecondaryAuthentication = 'sms'
           isSystemPreferredAuthenticationMethodEnabled = $false; systemPreferredAuthenticationMethods = @() }
        # Has a phone number but also Authenticator, so not telephony-only.
        @{ id = 'u2'; userPrincipalName = 'mixed@contoso.com'; userDisplayName = 'Mixed'; userType = 'Member'
           isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $false
           methodsRegistered = @('sms','microsoftAuthenticatorPush'); userPreferredMethodForSecondaryAuthentication = 'microsoftAuthenticatorPush'
           isSystemPreferredAuthenticationMethodEnabled = $true; systemPreferredAuthenticationMethods = @('microsoftAuthenticatorPush') }
        # An admin with nothing registered at all.
        @{ id = 'u3'; userPrincipalName = 'admin.nomfa@contoso.com'; userDisplayName = 'Admin No MFA'; userType = 'Member'
           isAdmin = $true; isMfaRegistered = $false; isMfaCapable = $false; isPasswordlessCapable = $false
           methodsRegistered = @(); userPreferredMethodForSecondaryAuthentication = $null
           isSystemPreferredAuthenticationMethodEnabled = $false; systemPreferredAuthenticationMethods = @() }
        @{ id = 'u4'; userPrincipalName = 'fido@contoso.com'; userDisplayName = 'Fido'; userType = 'Member'
           isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $true
           methodsRegistered = @('fido2SecurityKey'); userPreferredMethodForSecondaryAuthentication = 'fido2SecurityKey'
           isSystemPreferredAuthenticationMethodEnabled = $true; systemPreferredAuthenticationMethods = @('fido2SecurityKey') }
        @{ id = 'g1'; userPrincipalName = 'guest@partner.com'; userDisplayName = 'Guest'; userType = 'Guest'
           isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $false
           methodsRegistered = @('sms'); userPreferredMethodForSecondaryAuthentication = 'sms'
           isSystemPreferredAuthenticationMethodEnabled = $false; systemPreferredAuthenticationMethods = @() }
    ) }
}
'@

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-EntraAuthMethodReadiness.ps1' `
            -Setup $setup -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "entraauth-$([guid]::NewGuid().ToString('N'))") }
        $script:summary = $script:run.Summary
        $script:rows = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'auth-method-readiness.csv')) } else { @() }
    }

    It 'runs to completion' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
    }

    It 'excludes guests by default' {
        $script:summary.UsersRead | Should -Be 5
        $script:summary.UsersReported | Should -Be 4
    }

    It 'finds the telephony-only user' {
        @($script:rows | Where-Object { $_.Readiness -eq 'TelephonyOnly' }).UserPrincipalName | Should -Be 'sms.only@contoso.com'
    }

    It 'does not call a user with a phone number and Authenticator telephony-only' {
        # This is the distinction that makes the migration list small enough to act on.
        ($script:rows | Where-Object { $_.UserPrincipalName -eq 'mixed@contoso.com' }).Readiness | Should -Be 'StrongNotPhishingResistant'
    }

    It 'counts the administrator with no MFA' {
        $script:summary.AdminsWithoutMfa | Should -Be 1
    }

    It 'sorts administrators above everyone else' {
        $script:rows[0].UserPrincipalName | Should -Be 'admin.nomfa@contoso.com'
    }

    It 'reads the v1.0 preferred-method field rather than the beta one' {
        # An earlier version read defaultMfaMethod, which is beta only, so this column
        # was empty on every row with no error to say why.
        ($script:rows | Where-Object { $_.UserPrincipalName -eq 'fido@contoso.com' }).PreferredMethod | Should -Be 'fido2SecurityKey'
    }

    It 'counts users with system-preferred authentication enabled' {
        $script:summary.SystemPreferredEnabledCount | Should -Be 2
    }
}

Describe 'Export-EntraConditionalAccessBaseline end to end' {
    BeforeAll {
        $setup = $script:graphStub + @'

function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $ErrorAction)
    @{ value = @(
        @{ id = 'p1'; displayName = 'Block legacy auth'; state = 'enabled'
           conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                           applications = @{ includeApplications = @('All'); excludeApplications = @() }
                           clientAppTypes = @('exchangeActiveSync','other'); signInRiskLevels = @(); userRiskLevels = @() }
           grantControls = @{ operator = 'OR'; builtInControls = @('block'); authenticationStrength = $null }
           sessionControls = $null }
        @{ id = 'p2'; displayName = 'MFA for all users'; state = 'enabled'
           conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                           applications = @{ includeApplications = @('All'); excludeApplications = @() }
                           clientAppTypes = @('all'); signInRiskLevels = @(); userRiskLevels = @() }
           grantControls = @{ operator = 'OR'; builtInControls = @('mfa'); authenticationStrength = $null }
           sessionControls = $null }
        @{ id = 'p3'; displayName = 'Device compliance (report only)'; state = 'enabledForReportingButNotEnforced'
           conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                           applications = @{ includeApplications = @('All'); excludeApplications = @() }
                           clientAppTypes = @('all'); signInRiskLevels = @(); userRiskLevels = @() }
           grantControls = @{ operator = 'OR'; builtInControls = @('compliantDevice'); authenticationStrength = $null }
           sessionControls = $null }
    ) }
}
'@

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\entra\Export-EntraConditionalAccessBaseline.ps1' `
            -Setup $setup -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "entraca-$([guid]::NewGuid().ToString('N'))") }
        $script:summary = $script:run.Summary
        $script:gaps = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'gap-analysis.csv')) } else { @() }
    }

    It 'runs to completion' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
    }

    It 'counts enforcing and report-only policies separately' {
        $script:summary.PolicyCount | Should -Be 3
        $script:summary.EnabledCount | Should -Be 2
        $script:summary.ReportOnlyCount | Should -Be 1
    }

    It 'sees the legacy authentication block as present' {
        ($script:gaps | Where-Object { $_.Control -eq 'BlockLegacyAuthentication' }).Status | Should -Be 'Present'
    }

    It 'reports the missing admin MFA policy as a critical gap' {
        $adminGap = $script:gaps | Where-Object { $_.Control -eq 'RequireMfaForAdmins' }
        $adminGap.Status | Should -Be 'Missing'
        $adminGap.Severity | Should -Be 'Critical'
    }

    It 'surfaces the report-only policy as not enforcing' {
        # It looks present in the portal and changes no sign-in outcome.
        @($script:gaps | Where-Object { $_.Status -eq 'NotEnforcing' }).MatchingPolicies | Should -Be 'Device compliance (report only)'
    }

    It 'does not credit the report-only policy with the device compliance control' {
        ($script:gaps | Where-Object { $_.Control -eq 'RequireCompliantDevice' }).Status | Should -Be 'Missing'
    }

    It 'writes the raw policy JSON for diffing' {
        Test-Path $script:summary.RawPolicyPath | Should -BeTrue
    }
}
