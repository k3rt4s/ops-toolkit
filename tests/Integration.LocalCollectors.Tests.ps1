#Requires -Modules Pester

# The two scripts that read only the local machine and so can be run for real here,
# rather than against a stub. Running them is the point: this is the one place in the
# suite where the back end is the actual system.
#
# Assertions are on invariants, not on values. What Defender reports or how many
# volumes are encrypted is a property of whatever machine this runs on and will differ
# elsewhere. What must hold everywhere is that the arithmetic is honest, and both of
# these scripts have previously got that wrong in the same direction: reporting a pass
# for something nobody checked.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-local-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:liveSetupTimeoutSeconds = 120
    # The evidence pack runs seven already-bounded collectors in sequence, so its
    # outer bound has to exceed the sum of the individual 60-second limits.
    $script:evidencePackTimeoutSeconds = 600
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) {
        Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-SecurityControlEvidencePack against this machine' {
    BeforeAll {
        # Seven collectors, so this is the slowest spec in the suite. It runs once and
        # every test below reads the same pack.
        $expectedPath = Join-Path $script:workRoot 'expected-endpoints.csv'
        @(
            [pscustomobject]@{ Name = $env:COMPUTERNAME }
            [pscustomobject]@{ Name = 'MISSING-EDR' }
            [pscustomobject]@{ Name = 'EXCLUDED01' }
        ) | Export-Csv -LiteralPath $expectedPath -NoTypeInformation -Encoding utf8

        $defenderPath = Join-Path $script:workRoot 'defender-devices.csv'
        @(
            [pscustomobject]@{
                ComputerDnsName = $env:COMPUTERNAME
                Verdict = 'Protected'
                CoverageStatus = 'Onboarded'
                ContactStatus = 'Reporting'
            }
        ) | Export-Csv -LiteralPath $defenderPath -NoTypeInformation -Encoding utf8
        (Get-Item -LiteralPath $defenderPath).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddDays(-60)

        $manifestPath = Join-Path $script:workRoot 'coverage-manifest.json'
        @(
            @{ Name = 'ExpectedInventory'; Path = $expectedPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $defenderPath; KeyColumn = 'ComputerDnsName'; Required = $true }
        ) | ConvertTo-Json -Depth 5 -AsArray |
            Set-Content -LiteralPath $manifestPath -Encoding utf8

        $script:packRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
            -Argument @{
            ComputerName = @($env:COMPUTERNAME, 'EXCLUDED01')
            DefenderDeviceInventoryPath = $defenderPath
            CoverageManifestPath = $manifestPath
            CollectorTimeoutSeconds = 60
            OutputDirectory = (Join-Path $script:workRoot 'pack')
        } -RawArgument @{
            ScopeExclusion = "@(@{ Target = 'EXCLUDED01'; Reason = 'Retired synthetic test asset' })"
        } -TimeoutSeconds $script:evidencePackTimeoutSeconds
        $script:packSummary = $script:packRun.Summary
        if ($script:packRun.Status -eq 'Completed') {
            $script:controls = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'control-assessment.csv'))
            $script:collectorRuns = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'collector-runs.csv'))
            $script:manifest = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'evidence-manifest.csv'))
        } else {
            $script:controls = @()
            $script:collectorRuns = @()
            $script:manifest = @()
        }
    }

    BeforeEach {
        Confirm-LiveScriptRun -Run $script:packRun
    }

    It 'produces a pack with every report the layout promises' {
        (Split-Path $script:packSummary.PackDirectory -Leaf) | Should -Match '^security-control-evidence-\d{8}_\d{6}$'
        foreach ($name in @('control-assessment', 'collector-runs', 'status-rollup', 'input-sources', 'evidence-manifest')) {
            Test-Path (Join-Path $script:packSummary.PackDirectory "$name.csv") | Should -BeTrue -Because "$name.csv should exist"
            Test-Path (Join-Path $script:packSummary.PackDirectory "$name.json") | Should -BeTrue -Because "$name.json should exist"
        }
        Test-Path (Join-Path $script:packSummary.PackDirectory 'summary.json') | Should -BeTrue
        Test-Path (Join-Path $script:packSummary.PackDirectory 'run-context.json') | Should -BeTrue
    }

    It 'assesses every control to one of the four defined outcomes' {
        $script:controls.Count | Should -BeGreaterThan 0
        foreach ($control in $script:controls) {
            $control.Status | Should -BeIn @('Met', 'NotMet', 'Partial', 'NotAssessed')
            $control.ControlId | Should -Not -BeNullOrEmpty
            # A finding is what makes the status auditable. A bare status is an
            # assertion; a status with a finding is evidence.
            $control.Finding | Should -Not -BeNullOrEmpty
        }
    }

    It 'never folds an unassessed control into a pass' {
        # This is the pack's load-bearing rule. Converting "we did not check" into "we
        # are fine" is worse than shipping no pack at all, and it fails silently: the
        # only visible symptom is a better-looking number.
        $counted = $script:packSummary.MetCount + $script:packSummary.PartialCount +
        $script:packSummary.NotMetCount + $script:packSummary.NotAssessedCount
        $counted | Should -Be $script:packSummary.ControlCount
        $script:packSummary.ControlCount | Should -Be $script:controls.Count

        $script:packSummary.MetCount | Should -Be @($script:controls | Where-Object { $_.Status -eq 'Met' }).Count
        $script:packSummary.NotAssessedCount | Should -Be @($script:controls | Where-Object { $_.Status -eq 'NotAssessed' }).Count
    }

    It 'names the controls behind the summary counts' {
        # A count with no names cannot be acted on, and cannot be checked either.
        @($script:packSummary.NotAssessedControls).Count | Should -Be $script:packSummary.NotAssessedCount
        @($script:packSummary.NotMetControls).Count | Should -Be $script:packSummary.NotMetCount
        foreach ($id in @($script:packSummary.NotAssessedControls)) {
            $control = $script:controls | Where-Object { $_.ControlId -eq $id }
            $control.Status | Should -Be 'NotAssessed'
        }
    }

    It 'reports a failed collector as failed rather than dropping it' {
        # A collector that dies must not simply be absent from the pack, or the
        # controls it fed would silently lose their evidence.
        @($script:collectorRuns).Count | Should -Be $script:packSummary.CollectorsRun
        $script:packSummary.CollectorsCompleted + $script:packSummary.CollectorsFailed |
            Should -Be $script:packSummary.CollectorsRun
    }

    It 'states the endpoint scope it actually covered' {
        # Every reader assumes an evidence pack covers the estate. This one covers the
        # machine it ran on unless told otherwise, and has to say so.
        $script:packSummary.EndpointScope | Should -Not -BeNullOrEmpty
        $script:packSummary.Elevated | Should -BeOfType [bool]
        $script:packSummary.RequestedTargetCount | Should -Be 2
        $script:packSummary.TargetCount | Should -Be 1
        $script:packSummary.ExcludedTargetCount | Should -Be 1
    }

    It 'records traceability and limitations for every control' {
        foreach ($control in $script:controls) {
            $control.Conclusion | Should -Not -BeNullOrEmpty
            $control.IntendedScope | Should -Not -BeNullOrEmpty
            $control.AttemptedCount | Should -Match '^\d+$'
            $control.ObservedCount | Should -Match '^\d+$'
            $control.FailedCount | Should -Match '^\d+$'
            $control.Limitations | Should -Not -BeNullOrEmpty
            if ($control.EvidenceArtifacts) {
                $control.EvidenceHashes | Should -Match 'SHA256=[A-Fa-f0-9]{64}'
            }
            $attemptedNames = @($control.AttemptedPopulation -split ';' | Where-Object { $_ })
            [int]$control.AttemptedCount | Should -Be $attemptedNames.Count
            ([int]$control.ObservedCount + [int]$control.FailedCount) | Should -Be ([int]$control.AttemptedCount)
            foreach ($excluded in @($control.ExcludedPopulation -split ';' | Where-Object { $_ })) {
                $attemptedNames | Should -Not -Contain $excluded
            }
        }
    }

    It 'uses management-plane inventory and reconciliation for estate endpoint coverage' {
        $edr = $script:controls | Where-Object { $_.ControlId -eq 'EDR-01' }
        $edr.Status | Should -Be 'NotMet' -Because 'the synthetic expected inventory contains one device absent from Defender'
        $edr.Collector | Should -Match 'Export-DefenderEndpointDeviceInventory'
        $edr.Collector | Should -Match 'Export-CoverageReconciliation'
        $edr.EvidenceArtifacts | Should -Match 'defender-device-inventory.csv'
        $edr.EvidenceArtifacts | Should -Match 'inputs\\authorities'
        $edr.EvidenceArtifacts | Should -Match 'coverage-reconciliation'
        $edr.AttemptedPopulation | Should -Match 'MISSING-EDR'
        $edr.AttemptedPopulation | Should -Not -Match 'EXCLUDED01'
        [int]$edr.EvidenceAgeDays | Should -BeGreaterOrEqual 59
        $coverageRun = $script:collectorRuns | Where-Object { $_.Collector -eq 'coverage-reconciliation' }
        $coverageRun.Scope | Should -Be 'InputDefined'
        $coverageRun.Note | Should -Not -Match 'only the machine'
    }

    It 'records valid hashes for every artifact in the evidence manifest' {
        $script:manifest.Count | Should -BeGreaterThan 0
        foreach ($artifact in $script:manifest) {
            $path = Join-Path $script:packSummary.PackDirectory $artifact.Path
            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash | Should -Be $artifact.SHA256
        }
        $manifestPaths = @($script:manifest.Path)
        $allPackFiles = @(Get-ChildItem -LiteralPath $script:packSummary.PackDirectory -File -Recurse |
            ForEach-Object { [System.IO.Path]::GetRelativePath($script:packSummary.PackDirectory, $_.FullName) } |
            Where-Object { $_ -notin @('summary.json', 'evidence-manifest.csv', 'evidence-manifest.json') })
        foreach ($path in $allPackFiles) {
            $manifestPaths | Should -Contain $path
        }
        $manifestPaths | Should -Contain 'summary.md'
        $manifestPaths | Should -Not -Contain 'summary.json'
    }

    It 'snapshots authority inputs without recording absolute source paths' {
        $inputs = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'input-sources.csv'))
        $inputs.Count | Should -BeGreaterOrEqual 4
        foreach ($input in $inputs) {
            [System.IO.Path]::IsPathRooted($input.SourcePath) | Should -BeFalse
            if ($input.Status -eq 'Read') {
                $input.SHA256 | Should -Match '^[A-Fa-f0-9]{64}$'
                Test-Path -LiteralPath (Join-Path $script:packSummary.PackDirectory $input.SnapshotPath) |
                    Should -BeTrue
            }
        }
        $authorityRunsPath = Get-ChildItem -LiteralPath $script:packSummary.PackDirectory `
            -Filter 'authority-runs.csv' -File -Recurse | Select-Object -First 1
        $authorityRunsPath | Should -Not -BeNullOrEmpty
        foreach ($run in @(Import-Csv -LiteralPath $authorityRunsPath.FullName)) {
            [System.IO.Path]::IsPathRooted($run.Path) | Should -BeFalse
        }
        foreach ($run in $script:collectorRuns) {
            $run.Script | Should -Not -Match '[/\\]'
            $run.ScriptSha256 | Should -Match '^[A-Fa-f0-9]{64}$'
        }
        $savedSummary = Get-Content -LiteralPath (Join-Path $script:packSummary.PackDirectory 'summary.json') -Raw |
            ConvertFrom-Json
        $savedSummary.PackDirectory | Should -Be '.'
        [System.IO.Path]::IsPathRooted($savedSummary.EvidenceManifestPath) | Should -BeFalse
    }

    It 'states that the pack is technical evidence and not an audit or conformity decision' {
        $summaryText = Get-Content -LiteralPath (Join-Path $script:packSummary.PackDirectory 'summary.md') -Raw
        $script:packSummary.TechnicalEvidenceOnly | Should -BeTrue
        $summaryText | Should -Match 'not a NIST maturity rating'
        $summaryText | Should -Match 'ISO conformity decision'
    }
}

Describe 'Export-SecurityControlEvidencePack NotAssessed population accounting' {
    BeforeAll {
        $script:noInputRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
            -Argument @{
            ComputerName = @($env:COMPUTERNAME)
            CollectorTimeoutSeconds = 60
            OutputDirectory = (Join-Path $script:workRoot 'pack-no-inputs')
        } -TimeoutSeconds $script:evidencePackTimeoutSeconds
        $script:noInputSummary = $script:noInputRun.Summary
        $script:noInputControls = if ($script:noInputRun.Status -eq 'Completed') {
            @(Import-Csv (Join-Path $script:noInputSummary.PackDirectory 'control-assessment.csv'))
        } else {
            @()
        }

        $defenderOnlyPath = Join-Path $script:workRoot 'defender-only.csv'
        @([pscustomobject]@{
                ComputerDnsName = $env:COMPUTERNAME
                Verdict = 'Protected'
                CoverageStatus = 'Onboarded'
                ContactStatus = 'Reporting'
            }) | Export-Csv -LiteralPath $defenderOnlyPath -NoTypeInformation -Encoding utf8
        $script:defenderOnlyRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
            -Argument @{
            ComputerName = @($env:COMPUTERNAME)
            DefenderDeviceInventoryPath = $defenderOnlyPath
            CollectorTimeoutSeconds = 60
            OutputDirectory = (Join-Path $script:workRoot 'pack-defender-only')
        } -TimeoutSeconds $script:evidencePackTimeoutSeconds
        $script:defenderOnlySummary = $script:defenderOnlyRun.Summary
        $script:defenderOnlyControls = if ($script:defenderOnlyRun.Status -eq 'Completed') {
            @(Import-Csv (Join-Path $script:defenderOnlySummary.PackDirectory 'control-assessment.csv'))
        } else {
            @()
        }
    }

    BeforeEach {
        Confirm-LiveScriptRun -Run $script:noInputRun
        Confirm-LiveScriptRun -Run $script:defenderOnlyRun
    }

    It 'does not claim estate endpoints were observed when no management evidence was supplied' {
        $edr = $script:noInputControls | Where-Object { $_.ControlId -eq 'EDR-01' }
        $edr.Status | Should -Be 'NotAssessed'
        [int]$edr.AttemptedCount | Should -Be 1
        [int]$edr.ObservedCount | Should -Be 0
        [int]$edr.FailedCount | Should -Be 1
    }

    It 'names a missing coverage manifest instead of inventing an unread authority' {
        $edr = $script:defenderOnlyControls | Where-Object { $_.ControlId -eq 'EDR-01' }
        $edr.Status | Should -Be 'NotAssessed'
        $edr.Finding | Should -Match 'Coverage manifest: not supplied'
        $edr.FailedReads | Should -Match 'Coverage manifest: not supplied'
        [int]$edr.ObservedCount | Should -Be 0
        [int]$edr.FailedCount | Should -Be ([int]$edr.AttemptedCount)
    }
}

Describe 'Export-SecurityControlEvidencePack ungraded reconciliation gaps' {
    BeforeAll {
        $expectedPath = Join-Path $script:workRoot 'nograde-expected-endpoints.csv'
        @(
            [pscustomobject]@{ Name = $env:COMPUTERNAME }
            [pscustomobject]@{ Name = 'MISSING-DEFENDER-AUTHORITY' }
        ) | Export-Csv -LiteralPath $expectedPath -NoTypeInformation -Encoding utf8

        $assetPath = Join-Path $script:workRoot 'nograde-asset-endpoints.csv'
        @(
            [pscustomobject]@{ Name = $env:COMPUTERNAME }
        ) | Export-Csv -LiteralPath $assetPath -NoTypeInformation -Encoding utf8

        $defenderPath = Join-Path $script:workRoot 'nograde-defender-devices.csv'
        @(
            [pscustomobject]@{
                ComputerDnsName = $env:COMPUTERNAME
                Verdict = 'Protected'
                CoverageStatus = 'Onboarded'
                ContactStatus = 'Reporting'
            }
        ) | Export-Csv -LiteralPath $defenderPath -NoTypeInformation -Encoding utf8

        $manifestPath = Join-Path $script:workRoot 'nograde-coverage-manifest.json'
        @(
            @{ Name = 'ExpectedInventory'; Path = $expectedPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'AssetInventory'; Path = $assetPath; KeyColumn = 'Name'; Required = $true }
        ) | ConvertTo-Json -Depth 5 -AsArray |
            Set-Content -LiteralPath $manifestPath -Encoding utf8

        $script:ungradedGapRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
            -Argument @{
            DefenderDeviceInventoryPath = $defenderPath
            CoverageManifestPath = $manifestPath
            CollectorTimeoutSeconds = 60
            OutputDirectory = (Join-Path $script:workRoot 'pack-ungraded-gap')
        } -TimeoutSeconds $script:evidencePackTimeoutSeconds
        $script:ungradedGapSummary = $script:ungradedGapRun.Summary
        $script:ungradedGapControls = if ($script:ungradedGapRun.Status -eq 'Completed') {
            @(Import-Csv (Join-Path $script:ungradedGapSummary.PackDirectory 'control-assessment.csv'))
        } else {
            @()
        }
    }

    BeforeEach {
        Confirm-LiveScriptRun -Run $script:ungradedGapRun
    }

    It 'keeps reconciliation gaps visible when Defender is not a reconciliation authority' {
        $edr = $script:ungradedGapControls | Where-Object { $_.ControlId -eq 'EDR-01' }
        $edr.Status | Should -Be 'NotAssessed'
        $edr.Finding | Should -Match '\(not graded, the Defender inventory is not a reconciliation authority\)'
        $gapMatch = [regex]::Match($edr.Finding, 'Reconciliation gaps: (?<GapCount>\d+)')
        $gapMatch.Success | Should -BeTrue
        [int]$gapMatch.Groups['GapCount'].Value | Should -BeGreaterThan 0
        "$($edr.Limitations);$($edr.FailedReads)" |
            Should -Match 'Defender inventory is not a readable required reconciliation authority'
    }
}

Describe 'Export-SecurityControlEvidencePack scope exclusion validation' {
    It 'rejects an unknown target' {
        {
            & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
                -ComputerName 'PC01' -ScopeExclusion @(@{ Target = 'PC02'; Reason = 'Not requested' }) `
                -OutputDirectory (Join-Path $script:workRoot 'invalid-unknown')
        } | Should -Throw '*not in -ComputerName*'
    }

    It 'rejects a duplicate target regardless of case' {
        {
            & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
                -ComputerName 'PC01' -ScopeExclusion @(
                @{ Target = 'PC01'; Reason = 'First reason' }
                @{ Target = 'pc01'; Reason = 'Second reason' }
            ) -OutputDirectory (Join-Path $script:workRoot 'invalid-duplicate')
        } | Should -Throw '*more than once*'
    }

    It 'rejects a whitespace-only reason' {
        {
            & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
                -ComputerName 'PC01' -ScopeExclusion @(@{ Target = 'PC01'; Reason = '   ' }) `
                -OutputDirectory (Join-Path $script:workRoot 'invalid-reason')
        } | Should -Throw '*non-empty Target and Reason*'
    }

    It 'rejects exclusions against an explicitly supplied empty target list' {
        $emptyTargets = Join-Path $script:workRoot 'empty-targets.txt'
        Set-Content -LiteralPath $emptyTargets -Value @('# no targets') -Encoding utf8
        $defenderPath = Join-Path $script:workRoot 'empty-targets-defender.csv'
        @(
            [pscustomobject]@{
                ComputerDnsName = 'PC01'
                Verdict = 'Protected'
                CoverageStatus = 'Onboarded'
                ContactStatus = 'Reporting'
            }
        ) | Export-Csv -LiteralPath $defenderPath -NoTypeInformation -Encoding utf8

        {
            & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
                -TargetListPath $emptyTargets -DefenderDeviceInventoryPath $defenderPath `
                -ScopeExclusion @(@{ Target = 'PC01'; Reason = 'Retired asset' }) `
                -OutputDirectory (Join-Path $script:workRoot 'invalid-empty-target-list')
        } | Should -Throw '*not in -ComputerName*'
    }
}

Describe 'Test-WindowsHardeningState against this machine' {
    BeforeAll {
        # Note the path: Test-WindowsHardeningState lives in scripts\windows-hardening,
        # while Export-BitLockerEscrowStatus and Export-LocalAdminAndLapsPosture live in
        # scripts\it-operations\windows-hardening. The category exists at both levels.
        $script:hardeningRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\windows-hardening\Test-WindowsHardeningState.ps1' `
            -Argument @{ OutputDirectory = (Join-Path $script:workRoot 'hardening') } `
            -TimeoutSeconds $script:liveSetupTimeoutSeconds
        $script:hardening = $script:hardeningRun.Summary
        $script:items = if ($script:hardeningRun.Status -eq 'Completed') {
            @(Import-Csv (Join-Path $script:hardening.OutputDirectory 'hardening-compliance.csv'))
        } else {
            @()
        }
    }

    BeforeEach {
        Confirm-LiveScriptRun -Run $script:hardeningRun
    }

    It 'writes the run-directory layout the comparison tool needs' {
        (Split-Path $script:hardening.OutputDirectory -Leaf) | Should -Match '^windows-hardening-verification-\d{8}_\d{6}$'
        foreach ($name in @('hardening-compliance', 'category-rollup', 'script-results', 'tls-handshakes')) {
            Test-Path (Join-Path $script:hardening.OutputDirectory "$name.csv") | Should -BeTrue -Because "$name.csv should exist"
        }
    }

    It 'counts every checked item into exactly one outcome' {
        $script:hardening.ItemsChecked | Should -Be $script:items.Count
        $counted = $script:hardening.CompliantCount + $script:hardening.DriftedCount + $script:hardening.NotConfiguredCount
        $counted | Should -Be $script:hardening.ItemsChecked
    }

    It 'does not pass on an absence of evidence' {
        # Zero drift across zero items is not a pass, it is a run that checked
        # nothing. The verifier previously reported Passed while both hardening plans
        # had failed to produce any desired state at all.
        if ($script:hardening.ItemsChecked -eq 0) {
            $script:hardening.Passed | Should -BeFalse -Because 'a run that checked nothing cannot pass'
        }
        if ($script:hardening.TotalDrift -gt 0) {
            $script:hardening.Passed | Should -BeFalse -Because 'drift was found'
        }
        # Passing requires items checked and no drift, in that order.
        if ($script:hardening.Passed) {
            $script:hardening.ItemsChecked | Should -BeGreaterThan 0
            $script:hardening.TotalDrift | Should -Be 0
        }
    }

    It 'reports any target it could not check rather than omitting it' {
        # An unchecked target that vanishes from the report reads as a clean one.
        foreach ($target in @($script:hardening.UncheckedTargets)) {
            $target | Should -Not -BeNullOrEmpty
        }
        $checkedAndUnchecked = @($script:hardening.TargetsChecked).Count + @($script:hardening.UncheckedTargets).Count
        $checkedAndUnchecked | Should -BeGreaterThan 0
    }
}

Describe 'Export-EndpointTelemetryPosture against this machine' {
    BeforeAll {
        $script:telemetryRun = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\logging\Export-EndpointTelemetryPosture.ps1' `
            -Argument @{ OutputDirectory = (Join-Path $script:workRoot 'telemetry') } `
            -TimeoutSeconds $script:liveSetupTimeoutSeconds
        $script:telemetry = $script:telemetryRun.Summary
        if ($script:telemetryRun.Status -eq 'Completed') {
            $script:checks = @(Import-Csv (Join-Path $script:telemetry.OutputDirectory 'telemetry-checks.csv'))
            $script:channels = @(Import-Csv (Join-Path $script:telemetry.OutputDirectory 'log-channels.csv'))
            $script:posture = @(Import-Csv (Join-Path $script:telemetry.OutputDirectory 'telemetry-posture.csv'))
        } else {
            $script:checks = @()
            $script:channels = @()
            $script:posture = @()
        }
    }

    BeforeEach {
        Confirm-LiveScriptRun -Run $script:telemetryRun
    }

    It 'writes the run-directory layout the comparison tool needs' {
        (Split-Path $script:telemetry.OutputDirectory -Leaf) | Should -Match '^endpoint-telemetry-posture-\d{8}_\d{6}$'
        foreach ($name in @('telemetry-checks', 'log-channels', 'telemetry-posture')) {
            Test-Path (Join-Path $script:telemetry.OutputDirectory "$name.csv") | Should -BeTrue -Because "$name.csv should exist"
            Test-Path (Join-Path $script:telemetry.OutputDirectory "$name.json") | Should -BeTrue -Because "$name.json should exist"
        }
        Test-Path (Join-Path $script:telemetry.OutputDirectory 'summary.json') | Should -BeTrue
    }

    It 'grades every setting and channel to a defined outcome' {
        $script:checks.Count | Should -BeGreaterThan 0
        $script:channels.Count | Should -BeGreaterThan 0
        foreach ($check in $script:checks) {
            $check.Status | Should -BeIn @('Enabled', 'Disabled', 'NotRequired', 'Undetermined')
            $check.Requirement | Should -BeIn @('Required', 'Recommended', 'Conditional')
            # A finding with no stated reason cannot be acted on by the operator who
            # reads the CSV six weeks from now.
            $check.Why | Should -Not -BeNullOrEmpty
        }
        foreach ($channel in $script:channels) {
            $channel.Status | Should -BeIn @('Enabled', 'Disabled', 'NotRequired', 'Undetermined', 'Absent')
            $channel.RetentionStatus | Should -BeIn @('Sufficient', 'Insufficient', 'Building', 'Unmeasured')
        }
    }

    It 'never reports a setting it could not read as compliant' {
        # The load-bearing rule, and the reason this collector exists. Its own summary
        # counts must reconcile against the rows, or an Undetermined setting could be
        # quietly absent from the totals a reader actually looks at.
        $script:telemetry.ChecksGraded | Should -Be $script:checks.Count
        $script:telemetry.ChannelsGraded | Should -Be $script:channels.Count
        $script:telemetry.SettingsUndetermined |
            Should -Be @($script:checks | Where-Object { $_.Status -eq 'Undetermined' }).Count
        $script:telemetry.RequiredSettingsDisabled |
            Should -Be @($script:checks | Where-Object { $_.Requirement -eq 'Required' -and $_.Status -eq 'Disabled' }).Count
    }

    It 'measures retention from records rather than from configured size' {
        # A 4 GB Security log on a busy machine can hold hours. Any channel claiming
        # sufficient retention has to have produced a real oldest-record timestamp to
        # claim it from.
        foreach ($channel in @($script:channels | Where-Object { $_.RetentionStatus -eq 'Sufficient' })) {
            $channel.OldestRecord | Should -Not -BeNullOrEmpty -Because "$($channel.LogName) claims sufficient retention"
            [double]$channel.RetentionDays | Should -BeGreaterOrEqual ([double]$channel.MinimumRetentionDays)
        }
        # And a channel with no measurable history must not have been graded at all.
        foreach ($channel in @($script:channels | Where-Object { $_.RetentionStatus -eq 'Unmeasured' })) {
            $channel.RetentionDays | Should -BeNullOrEmpty -Because "$($channel.LogName) reported no measurable history"
        }
    }

    It 'does not report a machine as covered while anything is unread' {
        $verdict = $script:posture[0].Verdict
        $verdict | Should -BeIn @('Covered', 'Partial', 'NotCovered', 'Undetermined', 'Unreachable')
        if ($verdict -eq 'Covered') {
            [int]$script:posture[0].RequiredGapCount | Should -Be 0
            [int]$script:posture[0].UndeterminedCount | Should -Be 0
            [int]$script:posture[0].InsufficientRetentionCount | Should -Be 0
            [int]$script:posture[0].ChecksGraded | Should -BeGreaterThan 0
        }
        if ([int]$script:posture[0].UndeterminedCount -gt 0) {
            $verdict | Should -Be 'Undetermined' -Because 'an unread setting outranks the ones that were read'
        }
    }

    It 'names the gaps behind the counts' {
        # A count with no names cannot be acted on, and cannot be checked either.
        $gapCount = [int]$script:posture[0].RequiredGapCount + [int]$script:posture[0].InsufficientRetentionCount
        if ($gapCount -gt 0) {
            $script:posture[0].Gaps | Should -Not -BeNullOrEmpty
            @($script:posture[0].Gaps -split ';').Count | Should -Be $gapCount
        }
    }

    It 'does not treat an absent optional component as a gap' {
        # Sysmon and event forwarding are Conditional by default. An estate that runs
        # neither must not be told it has holes where they would be.
        foreach ($check in @($script:checks | Where-Object { $_.Requirement -eq 'Conditional' })) {
            $check.Status | Should -Not -Be 'Disabled'
        }
    }
}
