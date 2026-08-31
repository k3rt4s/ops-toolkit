#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ScriptFunction -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
        -FunctionName @('Get-OpsEndpointCoverageStatus', 'Get-OpsControlConclusion')
}

Describe 'Security evidence-pack endpoint coverage decisions' {
    It 'reports a known management-plane or reconciliation gap as NotMet' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 1 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotMet'
    }

    It 'keeps the result NotAssessed when a required authority was unread' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 1 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }

    It 'keeps the result NotAssessed when inventory could not be read or was empty' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $false -DeviceCount 0 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 0 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }

    It 'reports Met only when both evidence sources are readable and complete' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'Met'
    }

    It 'requires two readable required authorities including the Defender inventory' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 1 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $false `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }
}

Describe 'Security evidence-pack conclusion language' {
    It 'describes evidence without declaring framework conformance' {
        foreach ($status in @('Met', 'NotMet', 'Partial', 'NotAssessed')) {
            $conclusion = Get-OpsControlConclusion -Status $status
            $conclusion | Should -Not -Match '(?i)compliant|conformant|certified|maturity'
        }
    }
}

Describe 'Security evidence-pack host requirement' {
    It 'fails fast before collectors on Windows PowerShell 5.1' {
        $firstLine = Get-Content `
            (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
            -First 1
        $firstLine | Should -Be '#Requires -Version 7.0'
    }
}
