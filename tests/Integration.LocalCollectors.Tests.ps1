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
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) {
        Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-SecurityControlEvidencePack against this machine' {
    BeforeAll {
        # Six collectors, so this is the slowest spec in the suite. It runs once and
        # every test below reads the same pack.
        $script:packSummary = & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
            -OutputDirectory (Join-Path $script:workRoot 'pack')
        $script:controls = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'control-assessment.csv'))
        $script:collectorRuns = @(Import-Csv (Join-Path $script:packSummary.PackDirectory 'collector-runs.csv'))
    }

    It 'produces a pack with every report the layout promises' {
        (Split-Path $script:packSummary.PackDirectory -Leaf) | Should -Match '^security-control-evidence-\d{8}_\d{6}$'
        foreach ($name in @('control-assessment', 'collector-runs', 'status-rollup')) {
            Test-Path (Join-Path $script:packSummary.PackDirectory "$name.csv") | Should -BeTrue -Because "$name.csv should exist"
            Test-Path (Join-Path $script:packSummary.PackDirectory "$name.json") | Should -BeTrue -Because "$name.json should exist"
        }
        Test-Path (Join-Path $script:packSummary.PackDirectory 'summary.json') | Should -BeTrue
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
    }
}

Describe 'Test-WindowsHardeningState against this machine' {
    BeforeAll {
        # Note the path: Test-WindowsHardeningState lives in scripts\windows-hardening,
        # while Export-BitLockerEscrowStatus and Export-LocalAdminAndLapsPosture live in
        # scripts\it-operations\windows-hardening. The category exists at both levels.
        $script:hardening = & (Get-RepositoryScriptPath -RelativePath 'scripts\windows-hardening\Test-WindowsHardeningState.ps1') `
            -OutputDirectory (Join-Path $script:workRoot 'hardening')
        $script:items = @(Import-Csv (Join-Path $script:hardening.OutputDirectory 'hardening-compliance.csv'))
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
