#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1'
    Import-ScriptFunction -RelativePath 'scripts\azure\Export-AzOrphanedResource.ps1'

    $script:asOf = [datetime]::new(2026, 8, 14, 0, 0, 0, [DateTimeKind]::Utc)
    $script:internal = @('contoso.com', 'contoso.co.uk')
}

Describe 'Test-ExternalAddress' {
    It 'classifies an address outside the internal domains as external' {
        Test-ExternalAddress -Address 'attacker@evil.example' -InternalDomain $script:internal | Should -BeTrue
    }

    It 'does not classify an internal address as external' {
        Test-ExternalAddress -Address 'user@contoso.com' -InternalDomain $script:internal | Should -BeFalse
    }

    It 'matches an internal domain case-insensitively' {
        Test-ExternalAddress -Address 'user@CONTOSO.COM' -InternalDomain $script:internal | Should -BeFalse
    }

    It 'handles a second internal domain' {
        Test-ExternalAddress -Address 'user@contoso.co.uk' -InternalDomain $script:internal | Should -BeFalse
    }

    It 'strips an smtp: prefix before reading the domain' {
        Test-ExternalAddress -Address 'smtp:attacker@evil.example' -InternalDomain $script:internal | Should -BeTrue
    }

    It 'extracts the address from a display-name form' {
        Test-ExternalAddress -Address 'Some User <attacker@evil.example>' -InternalDomain $script:internal | Should -BeTrue
    }

    It 'returns false when no internal domains are known, so the caller reports unclassified' {
        # Calling an unknown destination internal is the failure that matters. The
        # caller turns this into Unclassified rather than into a clean bill of health.
        Test-ExternalAddress -Address 'attacker@evil.example' -InternalDomain @() | Should -BeFalse
    }

    It 'returns false for an empty address' {
        Test-ExternalAddress -Address '' -InternalDomain $script:internal | Should -BeFalse
    }

    It 'returns false for a value with no domain at all' {
        Test-ExternalAddress -Address 'not-an-address' -InternalDomain $script:internal | Should -BeFalse
    }

    It 'does not treat a lookalike subdomain as internal' {
        # contoso.com.evil.example is not contoso.com.
        Test-ExternalAddress -Address 'user@contoso.com.evil.example' -InternalDomain $script:internal | Should -BeTrue
    }
}

Describe 'Get-ForwardingDestination' {
    It 'strips the smtp prefix' {
        Get-ForwardingDestination -Value 'smtp:user@example.com' | Should -Be 'user@example.com'
    }

    It 'returns empty for null' {
        Get-ForwardingDestination -Value $null | Should -Be ''
    }

    It 'passes a bare address through' {
        Get-ForwardingDestination -Value 'user@example.com' | Should -Be 'user@example.com'
    }
}

Describe 'Get-ResourceAgeDay' {
    It 'reads the age from TimeCreated' {
        $resource = [pscustomobject]@{ TimeCreated = $script:asOf.AddDays(-45) }
        Get-ResourceAgeDay -Resource $resource -AsOf $script:asOf | Should -Be 45
    }

    It 'returns null when no timestamp property is present rather than inventing one' {
        # An empty age column is honest. A fabricated one drives a deletion decision.
        $resource = [pscustomobject]@{ Name = 'disk1' }
        Get-ResourceAgeDay -Resource $resource -AsOf $script:asOf | Should -BeNullOrEmpty
    }

    It 'ignores a property that holds something other than a date' {
        # DiskState is a string like "Unattached", not a timestamp.
        $resource = [pscustomobject]@{ DiskState = 'Unattached' }
        Get-ResourceAgeDay -Resource $resource -AsOf $script:asOf | Should -BeNullOrEmpty
    }
}

Describe 'Get-PriceEstimate' {
    BeforeAll {
        $script:prices = @(
            [pscustomobject]@{ ResourceType = 'ManagedDisk'; Sku = 'Premium_LRS'; MonthlyRate = '0.20' }
            [pscustomobject]@{ ResourceType = 'ManagedDisk'; Sku = ''; MonthlyRate = '0.05' }
            [pscustomobject]@{ ResourceType = 'PublicIpAddress'; Sku = 'Standard'; MonthlyRate = '3.65' }
        )
    }

    It 'returns null when no price table was supplied' {
        # An invented rate in a savings report is worse than no rate.
        Get-PriceEstimate -PriceTable $null -ResourceType 'ManagedDisk' -Sku 'Premium_LRS' -Quantity 100 | Should -BeNullOrEmpty
    }

    It 'multiplies the rate by the quantity' {
        Get-PriceEstimate -PriceTable $script:prices -ResourceType 'ManagedDisk' -Sku 'Premium_LRS' -Quantity 100 | Should -Be 20
    }

    It 'prefers an exact SKU match over the wildcard row' {
        Get-PriceEstimate -PriceTable $script:prices -ResourceType 'ManagedDisk' -Sku 'Premium_LRS' -Quantity 1 | Should -Be 0.2
    }

    It 'falls back to the row with an empty SKU' {
        Get-PriceEstimate -PriceTable $script:prices -ResourceType 'ManagedDisk' -Sku 'Standard_LRS' -Quantity 10 | Should -Be 0.5
    }

    It 'returns null for a resource type that is not priced' {
        Get-PriceEstimate -PriceTable $script:prices -ResourceType 'Snapshot' -Sku 'Standard_LRS' -Quantity 10 | Should -BeNullOrEmpty
    }

    It 'returns null when the rate is not a number' {
        $bad = @([pscustomobject]@{ ResourceType = 'Snapshot'; Sku = ''; MonthlyRate = 'ask finance' })
        Get-PriceEstimate -PriceTable $bad -ResourceType 'Snapshot' -Sku '' -Quantity 1 | Should -BeNullOrEmpty
    }
}
