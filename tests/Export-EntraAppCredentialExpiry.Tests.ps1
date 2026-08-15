#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\entra\Export-EntraAppCredentialExpiry.ps1'

    $script:asOf = [datetime]::new(2026, 8, 14, 12, 0, 0, [DateTimeKind]::Utc)
    $script:app = [pscustomobject]@{ DisplayName = 'Billing Sync'; AppId = 'aaaa-1111'; Id = 'obj-1'; SignInAudience = 'AzureADMyOrg' }

    function New-Credential {
        param($KeyId, $Start, $End, $Display = 'x', $CustomKeyIdentifier = $null)
        [pscustomobject]@{
            KeyId = $KeyId; StartDateTime = $Start; EndDateTime = $End
            DisplayName = $Display; CustomKeyIdentifier = $CustomKeyIdentifier
        }
    }

    $script:usage = [pscustomobject]@{
        Available = $true
        ByCredential = @{ 'aaaa-1111|k-expired' = [datetime]'2026-08-10T03:00:00Z' }
        ByApplication = @{ 'aaaa-1111' = [datetime]'2026-08-10T03:00:00Z' }
    }

    $script:common = @{
        ObjectType = 'Application'; DirectoryObject = $script:app; AsOfUtc = $script:asOf
        ExpiringWithinDays = 60; RecommendedSecretLifetimeDays = 180
    }
}

Describe 'Get-CredentialRecord classification' {
    It 'reports an expired secret as Expired with a negative day count' {
        # The 2024-cut two-year secret, which is the case expiring across tenants now.
        $entry = New-Credential -KeyId 'k-expired' -Start ([datetime]'2024-07-01Z') -End ([datetime]'2026-07-01Z')
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $script:usage
        $record.Status | Should -Be 'Expired'
        $record.DaysToExpiry | Should -BeLessThan 0
        $record.LifetimeDays | Should -Be 730
    }

    It 'reports a secret inside the warning window as ExpiringSoon' {
        $entry = New-Credential -KeyId 'k-soon' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $script:usage
        $record.Status | Should -Be 'ExpiringSoon'
        $record.DaysToExpiry | Should -Be 20
    }

    It 'reports a credential with no end date as Unknown rather than guessing' {
        $entry = New-Credential -KeyId 'k-none' -Start ([datetime]'2026-01-01Z') -End $null
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $null
        $record.Status | Should -Be 'Unknown'
        $record.DaysToExpiry | Should -BeNullOrEmpty
    }

    It 'flags an over-long client secret lifetime' {
        $entry = New-Credential -KeyId 'k-long' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $script:usage
        $record.ExceedsRecommendedLifetime | Should -BeTrue
    }

    It 'never flags a certificate on lifetime' {
        # Certificates legitimately run one to two years. Applying the secret guidance
        # to them flags every valid certificate and buries the real findings.
        $entry = New-Credential -KeyId 'k-cert' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(300)
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'Certificate' -Usage $script:usage
        $record.ExceedsRecommendedLifetime | Should -BeFalse
        $record.Status | Should -Be 'Valid'
    }

    It 'renders a byte-array thumbprint as hex' {
        $entry = New-Credential -KeyId 'k-cert' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(300) -CustomKeyIdentifier ([byte[]](0xAB, 0xCD, 0x01))
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'Certificate' -Usage $script:usage
        $record.Thumbprint | Should -Be 'ABCD01'
    }

    It 'never writes a secret value into the record' {
        $entry = New-Credential -KeyId 'k1' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(10)
        $entry | Add-Member -NotePropertyName SecretText -NotePropertyValue 'super-secret-value'
        $record = Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $null
        ($record | ConvertTo-Json -Depth 5) | Should -Not -BeLike '*super-secret-value*'
    }
}

Describe 'Get-CredentialRecord sign-in usage states' {
    It 'reports InUse when the credential key id was seen signing in' {
        $entry = New-Credential -KeyId 'k-expired' -Start ([datetime]'2024-07-01Z') -End ([datetime]'2026-07-01Z')
        (Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $script:usage).SignInStatus | Should -Be 'InUse'
    }

    It 'distinguishes an app active on a different credential from an unused one' {
        # This is the distinction that decides whether to renew or remove.
        $entry = New-Credential -KeyId 'k-other' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        (Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $script:usage).SignInStatus | Should -Be 'AppActiveOnOtherCredential'
    }

    It 'reports NotChecked when usage was not requested, never unused' {
        $entry = New-Credential -KeyId 'k1' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        (Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $null).SignInStatus | Should -Be 'NotChecked'
    }

    It 'reports Unavailable when the usage lookup failed' {
        $failed = [pscustomobject]@{ Available = $false; ByCredential = @{}; ByApplication = @{} }
        $entry = New-Credential -KeyId 'k1' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        (Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $failed).SignInStatus | Should -Be 'Unavailable'
    }

    It 'reports NoRecentSignIn when the application never appears' {
        $other = [pscustomobject]@{ Available = $true; ByCredential = @{}; ByApplication = @{ 'zzzz-9999' = [datetime]'2026-08-01Z' } }
        $entry = New-Credential -KeyId 'k1' -Start ([datetime]'2026-01-01Z') -End $script:asOf.AddDays(20)
        (Get-CredentialRecord @script:common -KeyEntry $entry -KeyEntryType 'ClientSecret' -Usage $other).SignInStatus | Should -Be 'NoRecentSignIn'
    }
}

Describe 'Get-ServicePrincipalSignInUsage' {
    BeforeAll {
        function Set-GraphStub {
            param([int]$FailAfter = -1)
            $script:pageCalls = 0
            $script:failAfter = $FailAfter
            function global:Invoke-MgGraphRequest {
                param($Method, $Uri, $OutputType, $ErrorAction)
                $script:pageCalls++
                if ($script:failAfter -ge 0 -and $script:pageCalls -gt $script:failAfter) {
                    throw 'Insufficient privileges (simulated)'
                }

                if ($script:pageCalls -eq 1) {
                    return @{
                        'value' = @(
                            @{ appId = 'aaaa-1111'; createdDateTime = '2026-08-10T03:00:00Z'; servicePrincipalCredentialKeyId = 'k-expired' }
                            @{ appId = 'aaaa-1111'; createdDateTime = '2026-08-12T09:30:00Z'; servicePrincipalCredentialKeyId = $null }
                            @{ appId = 'bbbb-2222'; createdDateTime = '2026-08-01T00:00:00Z'; servicePrincipalCredentialKeyId = 'k-other' }
                        )
                        '@odata.nextLink' = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=abc'
                    }
                }

                return @{ 'value' = @(@{ appId = 'aaaa-1111'; createdDateTime = '2026-08-13T23:00:00Z'; servicePrincipalCredentialKeyId = 'k-expired' }) }
            }
        }
    }

    It 'follows nextLink until the collection is exhausted' {
        Set-GraphStub
        $result = Get-ServicePrincipalSignInUsage -LookbackDays 30 -MaxSignInRecord 50000
        $script:pageCalls | Should -Be 2
        $result.SignInCount | Should -Be 4
        $result.Available | Should -BeTrue
    }

    It 'keeps the latest sign-in per credential, not the first seen' {
        Set-GraphStub
        $result = Get-ServicePrincipalSignInUsage -LookbackDays 30 -MaxSignInRecord 50000
        $result.ByCredential['aaaa-1111|k-expired'].ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2026-08-13'
    }

    It 'skips a sign-in with no credential key id' {
        Set-GraphStub
        $result = Get-ServicePrincipalSignInUsage -LookbackDays 30 -MaxSignInRecord 50000
        $result.ByCredential.ContainsKey('aaaa-1111|') | Should -BeFalse
    }

    It 'still records application activity for a sign-in with no key id' {
        Set-GraphStub
        $result = Get-ServicePrincipalSignInUsage -LookbackDays 30 -MaxSignInRecord 50000
        $result.ByApplication.ContainsKey('aaaa-1111') | Should -BeTrue
    }

    It 'degrades to Unavailable instead of throwing when the lookup fails' {
        # The expiry report is the point; usage is enrichment. A permission or licence
        # failure must not take the whole report down with it.
        Set-GraphStub -FailAfter 0
        $result = Get-ServicePrincipalSignInUsage -LookbackDays 30 -MaxSignInRecord 50000 -WarningAction SilentlyContinue
        $result.Available | Should -BeFalse
        $result.Error | Should -Not -BeNullOrEmpty
    }

    AfterAll {
        Remove-Item -LiteralPath 'function:global:Invoke-MgGraphRequest' -ErrorAction SilentlyContinue
    }
}

Describe 'Get-ApplicationRollup' {
    It 'counts secrets, certificates, and expiry states per application' {
        $records = @(
            [pscustomobject]@{ ObjectType = 'Application'; ObjectId = 'o1'; DisplayName = 'A'; AppId = 'a'; CredentialType = 'ClientSecret'; Status = 'Expired'; DaysToExpiry = -5; EndDateTime = (Get-Date); SignInStatus = 'InUse'; Owners = '' }
            [pscustomobject]@{ ObjectType = 'Application'; ObjectId = 'o1'; DisplayName = 'A'; AppId = 'a'; CredentialType = 'Certificate'; Status = 'Valid'; DaysToExpiry = 300; EndDateTime = (Get-Date); SignInStatus = 'NoRecentSignIn'; Owners = '' }
        )
        $rollup = @(Get-ApplicationRollup -Record $records)
        $rollup.Count | Should -Be 1
        $rollup[0].SecretCount | Should -Be 1
        $rollup[0].CertificateCount | Should -Be 1
        $rollup[0].ExpiredCount | Should -Be 1
        $rollup[0].InUseCount | Should -Be 1
        $rollup[0].EarliestExpiryDays | Should -Be -5
    }
}
