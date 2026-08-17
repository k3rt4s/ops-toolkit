#Requires -Modules Pester

# End-to-end runs of the coverage reconciliation report against real CSV files on disk.
# There is no service to stub here: the authorities are exports, so this exercises the
# whole script including its file reading.
#
# The cases that matter are the ones where an authority is not what it appears to be.
# An unreadable file, a missing key column, and a name that is spelled differently in
# each source all produce a report that looks fine and says the opposite of the truth.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-recon-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    function New-AuthorityCsv {
        param($Name, $Column, $Value)
        $path = Join-Path $script:workRoot "$Name.csv"
        @($Value | ForEach-Object { [pscustomobject]@{ $Column = $_ } }) |
            Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8
        $path
    }

    function New-Manifest {
        param($Entry)
        $path = Join-Path $script:workRoot "manifest-$([guid]::NewGuid().ToString('N')).json"
        Set-Content -LiteralPath $path -Encoding utf8 -Value ($Entry | ConvertTo-Json -Depth 5 -AsArray)
        $path
    }

    function Invoke-Reconciliation {
        param($ManifestPath, $MatchOn = 'ShortName')
        Invoke-ScriptUnderTest -RelativePath 'scripts\reporting\Export-CoverageReconciliation.ps1' `
            -Setup '# no stubs needed, the authorities are files' `
            -Argument @{
            ManifestPath = $ManifestPath
            MatchOn = $MatchOn
            OutputDirectory = (Join-Path $script:workRoot "out-$([guid]::NewGuid().ToString('N'))")
        }
    }

    # AD holds five machines. Defender holds three of them plus one AD does not have.
    # PC03 is the coverage gap: in the directory, no EDR agent.
    $script:adPath = New-AuthorityCsv -Name 'ad' -Column 'Name' -Value @('PC01', 'PC02', 'PC03', 'PC04', 'PC05')
    $script:mdePath = New-AuthorityCsv -Name 'mde' -Column 'ComputerDnsName' `
        -Value @('pc01.contoso.com', 'PC02.contoso.com', 'PC04.contoso.com', 'PC05.contoso.com', 'ROGUE01.contoso.com')
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) {
        Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-CoverageReconciliation across two authorities' {
    BeforeAll {
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $script:mdePath; KeyColumn = 'ComputerDnsName'; Required = $true }
        )
        $script:run = Invoke-Reconciliation -ManifestPath $manifest
        $script:summary = $script:run.Summary
        $script:coverage = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'device-coverage.csv')) } else { @() }
        $script:gaps = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'coverage-gaps.csv')) } else { @() }
    }

    It 'runs to completion' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'matches the same machine across authorities that name it differently' {
        # AD says PC01, the EDR console says pc01.contoso.com. Matching raw strings
        # would report two machines, each missing from the other, turning one covered
        # machine into two false gaps.
        $script:summary.MachineCount | Should -Be 6
        ($script:coverage | Where-Object { $_.MachineKey -eq 'PC01' }).Status | Should -Be 'Covered'
    }

    It 'finds the machine the directory knows and the EDR does not' {
        $gap = $script:coverage | Where-Object { $_.MachineKey -eq 'PC03' }
        $gap.Status | Should -Be 'Gap'
        $gap.ActiveDirectory | Should -Be 'Present'
        $gap.Defender | Should -Be 'Absent'
        $gap.MissingFromRequired | Should -Be 'Defender'
    }

    It 'finds the machine the EDR knows and the directory does not' {
        # The gap runs both ways. An agent on a machine no directory lists is an
        # unmanaged device, and it is just as invisible from inside either console.
        $rogue = $script:coverage | Where-Object { $_.MachineKey -eq 'ROGUE01' }
        $rogue.Status | Should -Be 'Gap'
        $rogue.ActiveDirectory | Should -Be 'Absent'
    }

    It 'names every gap it counts' {
        $script:gaps.Count | Should -Be $script:summary.GapCount
        $script:summary.GapCount | Should -Be 2
        foreach ($gap in $script:gaps) {
            $gap.MissingFromRequired | Should -Not -BeNullOrEmpty
        }
    }

    It 'counts every machine into exactly one status' {
        $counted = $script:summary.CoveredCount + $script:summary.GapCount + $script:summary.UndeterminedCount
        $counted | Should -Be $script:summary.MachineCount
        $script:summary.Verdict | Should -Be 'GapsFound'
    }
}

Describe 'Export-CoverageReconciliation when an authority cannot be read' {
    It 'reports NotAssessed rather than Absent, and does not call anything covered' {
        # The load-bearing case. If an unread authority were graded as Absent, every
        # machine would be a gap. If it were skipped, every machine would be covered.
        # Both are confident and wrong, and the input looks identical.
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $script:mdePath; KeyColumn = 'ComputerDnsName'; Required = $true }
            @{ Name = 'AssetSystem'; Path = (Join-Path $script:workRoot 'does-not-exist.csv'); KeyColumn = 'Hostname'; Required = $true }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $run.ExitCode | Should -Be 0 -Because "the script failed: $($run.Output)"

        $coverage = @(Import-Csv (Join-Path $run.Summary.OutputDirectory 'device-coverage.csv'))
        ($coverage | Where-Object { $_.MachineKey -eq 'PC01' }).AssetSystem | Should -Be 'NotAssessed'
        ($coverage | Where-Object { $_.MachineKey -eq 'PC01' }).Status | Should -Be 'Undetermined'

        $run.Summary.Verdict | Should -Be 'Undetermined'
        $run.Summary.AuthoritiesNotRead | Should -Be 1
        @($run.Summary.UnreadRequiredAuthorities) | Should -Contain 'AssetSystem'
    }

    It 'still reports a known gap while another authority is unread' {
        # A gap found against the sources that were read is true regardless of what
        # the unread one would have said, so it must not be suppressed.
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $script:mdePath; KeyColumn = 'ComputerDnsName'; Required = $true }
            @{ Name = 'AssetSystem'; Path = (Join-Path $script:workRoot 'does-not-exist.csv'); KeyColumn = 'Hostname'; Required = $true }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $coverage = @(Import-Csv (Join-Path $run.Summary.OutputDirectory 'device-coverage.csv'))
        ($coverage | Where-Object { $_.MachineKey -eq 'PC03' }).Status | Should -Be 'Gap'
    }

    It 'treats a wrong key column as unread rather than as an empty authority' {
        # A CSV that parsed but has no such column is a misconfiguration. Grading
        # against it would report every machine in the estate as missing from it.
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $script:mdePath; KeyColumn = 'ComputerDnsName'; Required = $true }
            @{ Name = 'Typo'; Path = $script:adPath; KeyColumn = 'HostName'; Required = $true }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $runs = @(Import-Csv (Join-Path $run.Summary.OutputDirectory 'authority-runs.csv'))
        $typo = $runs | Where-Object { $_.Authority -eq 'Typo' }
        $typo.Status | Should -Be 'NotRead'
        $typo.Note | Should -Match "Column 'HostName' not found"
        $run.Summary.Verdict | Should -Be 'Undetermined'
    }

    It 'does not produce gaps from an authority that is not required' {
        # A partial source such as a subnet scan is worth reporting and must not
        # invent a finding for every machine it happens not to contain.
        $partial = New-AuthorityCsv -Name 'scan' -Column 'Address' -Value @('PC01')
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Defender'; Path = $script:mdePath; KeyColumn = 'ComputerDnsName'; Required = $true }
            @{ Name = 'SubnetScan'; Path = $partial; KeyColumn = 'Address'; Required = $false }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $coverage = @(Import-Csv (Join-Path $run.Summary.OutputDirectory 'device-coverage.csv'))

        ($coverage | Where-Object { $_.MachineKey -eq 'PC02' }).SubnetScan | Should -Be 'Absent'
        ($coverage | Where-Object { $_.MachineKey -eq 'PC02' }).Status | Should -Be 'Covered'
        $run.Summary.GapCount | Should -Be 2
    }
}

Describe 'Export-CoverageReconciliation refusals' {
    It 'refuses a single authority, because one source can only agree with itself' {
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'at least two independent sources'
    }

    It 'refuses when fewer than two authorities could actually be read' {
        # Two authorities configured and one readable is the same problem as one
        # authority configured, and it must fail the same way rather than reporting
        # a clean estate.
        $manifest = New-Manifest -Entry @(
            @{ Name = 'ActiveDirectory'; Path = $script:adPath; KeyColumn = 'Name'; Required = $true }
            @{ Name = 'Missing'; Path = (Join-Path $script:workRoot 'nope.csv'); KeyColumn = 'Name'; Required = $true }
        )
        $run = Invoke-Reconciliation -ManifestPath $manifest
        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'nothing to reconcile'
    }
}
