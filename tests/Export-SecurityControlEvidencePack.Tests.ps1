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

Describe 'Security evidence-pack LOG-03 cloud incident readiness wiring' {
    BeforeAll {
        # Add-Control, Invoke-Collector, and Get-CollectorSummary close over
        # top-level $controls / $collectorRuns state that is not $script:-prefixed,
        # so Import-ScriptFunction (which only lifts $script:-prefixed assignments
        # alongside function bodies) cannot bring this wiring into a callable,
        # mockable scope, and running it for real means a live Graph/Azure session
        # for every Entra-gated control, not just this one. That is true today of
        # IAM-01, IAM-02, MFA-01, and MFA-02 as well: none of them have a
        # behavioral test in this suite either. Until that seam exists, these specs
        # verify the wiring in the source itself, the same way the host-requirement
        # spec above verifies the #Requires line, rather than asserting on values a
        # live run would have to produce.
        $script:packSource = Get-Content -Raw `
            (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1')
    }

    It 'calls the cloud incident readiness collector the same way IAM-01 calls its collector' {
        $script:packSource | Should -Match (
            [regex]::Escape("Invoke-Collector -Name 'entra-cloud-incident-readiness' -RelativePath 'entra\Export-CloudIncidentReadiness.ps1' -Argument @('-Connect')")
        )
        $script:packSource | Should -Match ([regex]::Escape("`$cloudIr = Get-CollectorSummary -Run `$cloudIrRun"))
    }

    It 'reports LOG-03 NotAssessed when the collector produced no summary, without folding it into a pass' {
        $script:packSource | Should -Match (
            "if \(\`$null -eq \`$cloudIr\) \{\s*" +
            [regex]::Escape("Add-Control -Id 'LOG-03'") + "[\s\S]{0,150}" +
            [regex]::Escape("-Status 'NotAssessed'")
        )
    }

    It "flows the collector's own OverallStatus straight into the LOG-03 grade" {
        $script:packSource | Should -Match (
            [regex]::Escape("`$cloudIrOverallStatus = [string](Get-OpsPropertyValue -InputObject `$cloudIr -Name 'OverallStatus')")
        )
        $script:packSource | Should -Match (
            [regex]::Escape("Add-Control -Id 'LOG-03'") +
            "[\s\S]{0,200}-Status `\`$cloudIrOverallStatus"
        )
        $script:packSource | Should -Match ([regex]::Escape("-Collector 'Export-CloudIncidentReadiness.ps1'"))
    }

    It 'falls back to NotAssessed when the collector summary carries an unrecognized OverallStatus' {
        $script:packSource | Should -Match (
            [regex]::Escape("if (`$cloudIrOverallStatus -notin @('Met', 'NotMet', 'Partial', 'NotAssessed')) {") +
            "[\s\S]{0,200}" + [regex]::Escape("-Status 'NotAssessed'")
        )
    }

    It 'uses the same control question text everywhere LOG-03 is referenced' {
        $question = 'Could this tenant support an incident investigation today?'
        @($script:packSource | Select-String -Pattern ([regex]::Escape($question)) -AllMatches).Matches.Count |
            Should -BeGreaterOrEqual 2
    }

    It 'lists LOG-03 as NotAssessed alongside the other identity controls when -IncludeEntra is off' {
        $script:packSource | Should -Match (
            "@\('IAM-02', 'Are application credentials rotated before they expire\?'\),\s*" +
            [regex]::Escape("@('LOG-03', 'Could this tenant support an incident investigation today?')")
        )
    }
}
