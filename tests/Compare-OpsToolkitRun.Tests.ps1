#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
}

Describe 'Compare-OpsRecordSet' {
    It 'reports a record present only in the current run as added' {
        $result = Compare-OpsRecordSet -Previous @() -Current @([pscustomobject]@{ Id = 'a'; Value = '1' }) -KeyColumn 'Id'
        $result.Added.Count | Should -Be 1
        $result.Removed.Count | Should -Be 0
    }

    It 'reports a record present only in the previous run as removed' {
        $result = Compare-OpsRecordSet -Previous @([pscustomobject]@{ Id = 'a'; Value = '1' }) -Current @() -KeyColumn 'Id'
        $result.Removed.Count | Should -Be 1
        $result.Added.Count | Should -Be 0
    }

    It 'reports an identical record as unchanged' {
        $record = [pscustomobject]@{ Id = 'a'; Value = '1' }
        $result = Compare-OpsRecordSet -Previous @($record) -Current @($record) -KeyColumn 'Id'
        $result.UnchangedCount | Should -Be 1
        $result.Changed.Count | Should -Be 0
    }

    It 'names the column that changed and both of its values' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; Status = 'Valid' }) `
            -Current @([pscustomobject]@{ Id = 'a'; Status = 'Expired' }) -KeyColumn 'Id'
        $result.Changed.Count | Should -Be 1
        $result.Changed[0].Differences[0].Column | Should -Be 'Status'
        $result.Changed[0].Differences[0].Before | Should -Be 'Valid'
        $result.Changed[0].Differences[0].After | Should -Be 'Expired'
    }

    It 'ignores a volatile column so an unchanged record does not look changed' {
        # DaysToExpiry moves every day by arithmetic. Comparing it would mark every
        # credential in the report as changed and bury the real differences.
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '30'; EndDateTime = '2026-09-13' }) `
            -Current @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '29'; EndDateTime = '2026-09-13' }) -KeyColumn 'Id'
        $result.Changed.Count | Should -Be 0
        $result.UnchangedCount | Should -Be 1
    }

    It 'still detects a change to the fact the volatile column is derived from' {
        # The date moving is a real change: someone renewed or re-cut the credential.
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '30'; EndDateTime = '2026-09-13' }) `
            -Current @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '395'; EndDateTime = '2027-09-13' }) -KeyColumn 'Id'
        $result.Changed.Count | Should -Be 1
        $result.Changed[0].Differences[0].Column | Should -Be 'EndDateTime'
    }

    It 'compares volatile columns when explicitly asked to' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '30' }) `
            -Current @([pscustomobject]@{ Id = 'a'; DaysToExpiry = '29' }) -KeyColumn 'Id' -IncludeVolatileColumn
        $result.Changed.Count | Should -Be 1
    }

    It 'honours an explicit ignore list' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; Note = 'before' }) `
            -Current @([pscustomobject]@{ Id = 'a'; Note = 'after' }) -KeyColumn 'Id' -IgnoreColumn 'Note'
        $result.Changed.Count | Should -Be 0
    }

    It 'matches on a composite key' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Host = 'pc1'; Check = 'Tpm2'; Status = 'Pass' }) `
            -Current @([pscustomobject]@{ Host = 'pc1'; Check = 'Tpm2'; Status = 'Fail' }) -KeyColumn @('Host', 'Check')
        $result.Changed.Count | Should -Be 1
        $result.UnchangedCount | Should -Be 0
    }

    It 'does not confuse two records that differ only in the second key column' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Host = 'pc1'; Check = 'Tpm2'; Status = 'Pass' }) `
            -Current @([pscustomobject]@{ Host = 'pc1'; Check = 'SecureBoot'; Status = 'Pass' }) -KeyColumn @('Host', 'Check')
        $result.Added.Count | Should -Be 1
        $result.Removed.Count | Should -Be 1
        $result.Changed.Count | Should -Be 0
    }

    It 'reports a non-unique key instead of pairing records arbitrarily' {
        # With duplicate keys any pairing is a guess, and a guessed pairing produces a
        # confident and wrong list of changes.
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; V = '1' }, [pscustomobject]@{ Id = 'a'; V = '2' }) `
            -Current @([pscustomobject]@{ Id = 'a'; V = '3' }) -KeyColumn 'Id'
        $result.KeyIsUnique | Should -BeFalse
        $result.DuplicateKey | Should -Contain 'a'
        $result.Changed.Count | Should -Be 0
    }

    It 'handles a column that exists in only one of the two runs' {
        $result = Compare-OpsRecordSet `
            -Previous @([pscustomobject]@{ Id = 'a'; Old = 'x' }) `
            -Current @([pscustomobject]@{ Id = 'a'; Old = 'x'; New = 'y' }) -KeyColumn 'Id'
        $result.Changed.Count | Should -Be 1
        $result.Changed[0].Differences[0].Column | Should -Be 'New'
    }

    It 'treats two empty record sets as no change rather than throwing' {
        $result = Compare-OpsRecordSet -Previous @() -Current @() -KeyColumn 'Id'
        $result.Added.Count | Should -Be 0
        $result.Removed.Count | Should -Be 0
        $result.UnchangedCount | Should -Be 0
    }
}

Describe 'Get-OpsRunDirectory' {
    BeforeAll {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) "ops-runs-$([guid]::NewGuid().ToString('N'))"
        foreach ($name in @('thing-20260101_010000', 'thing-20260814_093000', 'thing-20260501_120000', 'other-20260601_000000', 'not-a-run')) {
            New-Item -ItemType Directory -Path (Join-Path $script:root $name) -Force | Out-Null
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force }
    }

    It 'returns runs newest first' {
        $runs = @(Get-OpsRunDirectory -Path $script:root -Prefix 'thing')
        $runs.Count | Should -Be 3
        $runs[0].Timestamp.ToString('yyyyMMdd') | Should -Be '20260814'
        $runs[2].Timestamp.ToString('yyyyMMdd') | Should -Be '20260101'
    }

    It 'filters by prefix' {
        @(Get-OpsRunDirectory -Path $script:root -Prefix 'other').Count | Should -Be 1
    }

    It 'ignores a directory that is not a run folder' {
        @(Get-OpsRunDirectory -Path $script:root | Where-Object { $_.Path -like '*not-a-run*' }).Count | Should -Be 0
    }

    It 'returns nothing for a path that does not exist rather than throwing' {
        @(Get-OpsRunDirectory -Path (Join-Path $script:root 'missing')).Count | Should -Be 0
    }
}

Describe 'Compare-OpsToolkitRun end to end' {
    BeforeAll {
        $script:scriptPath = Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Compare-OpsToolkitRun.ps1'
        $script:reportRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-compare-$([guid]::NewGuid().ToString('N'))"

        $first = Join-Path $script:reportRoot 'sample-20260801_090000'
        $second = Join-Path $script:reportRoot 'sample-20260814_090000'
        New-Item -ItemType Directory -Path $first -Force | Out-Null
        New-Item -ItemType Directory -Path $second -Force | Out-Null

        @(
            [pscustomobject]@{ FindingId = 'AD-ASREP-001'; DistinguishedName = 'CN=a'; SamAccountName = 'a'; Severity = 'High' }
            [pscustomobject]@{ FindingId = 'AD-KRBRST-001'; DistinguishedName = 'CN=b'; SamAccountName = 'b'; Severity = 'Medium' }
        ) | Export-Csv -Path (Join-Path $first 'findings.csv') -NoTypeInformation -Encoding utf8

        @(
            # a is unchanged, b escalated, c is brand new, and the old one is gone.
            [pscustomobject]@{ FindingId = 'AD-ASREP-001'; DistinguishedName = 'CN=a'; SamAccountName = 'a'; Severity = 'High' }
            [pscustomobject]@{ FindingId = 'AD-KRBRST-001'; DistinguishedName = 'CN=b'; SamAccountName = 'b'; Severity = 'Critical' }
            [pscustomobject]@{ FindingId = 'AD-DELEG-001'; DistinguishedName = 'CN=c'; SamAccountName = 'c'; Severity = 'Critical' }
        ) | Export-Csv -Path (Join-Path $second 'findings.csv') -NoTypeInformation -Encoding utf8

        $script:outputRoot = Join-Path $script:reportRoot 'out'
        $script:summary = & $script:scriptPath -Path $script:reportRoot -OutputDirectory $script:outputRoot
        $script:changes = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'changes.csv'))
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:reportRoot) { Remove-Item -LiteralPath $script:reportRoot -Recurse -Force }
    }

    It 'picks the two most recent runs' {
        $script:summary.PreviousRunAt.ToString('yyyyMMdd') | Should -Be '20260801'
        $script:summary.CurrentRunAt.ToString('yyyyMMdd') | Should -Be '20260814'
        $script:summary.ElapsedDays | Should -Be 13
    }

    It 'classifies a new row in a findings report as a new finding, not just a new record' {
        $script:summary.NewFindingCount | Should -Be 1
        @($script:changes | Where-Object { $_.Significance -eq 'NewFinding' }).Key | Should -BeLike '*AD-DELEG-001*'
    }

    It 'reports a severity escalation as a field change with both values' {
        $escalation = @($script:changes | Where-Object { $_.Change -eq 'Changed' -and $_.Column -eq 'Severity' })
        $escalation.Count | Should -Be 1
        $escalation[0].Before | Should -Be 'Medium'
        $escalation[0].After | Should -Be 'Critical'
    }

    It 'sorts new findings above everything else' {
        $script:changes[0].Significance | Should -Be 'NewFinding'
    }

    It 'uses the configured key for a known report rather than the first-column fallback' {
        $rollup = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'report-rollup.csv'))
        ($rollup | Where-Object { $_.Report -eq 'findings' }).KeySource | Should -Be 'KnownReport'
    }

    It 'exits 2 and prints usage when -Path is missing' {
        $null = & pwsh -NoProfile -NonInteractive -File $script:scriptPath 2>&1
        $LASTEXITCODE | Should -Be 2
    }
}

Describe 'Two identical runs' {
    BeforeAll {
        # The ordinary case for a healthy estate, and the one that broke: with no
        # changes at all Sort-Object emits nothing, so an unwrapped result is null
        # and every count on it throws.
        $script:sameRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-same-$([guid]::NewGuid().ToString('N'))"
        foreach ($stamp in @('20260801_090000', '20260814_090000')) {
            $directory = Join-Path $script:sameRoot "sample-$stamp"
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            @([pscustomobject]@{ FindingId = 'x'; DistinguishedName = 'CN=a'; SamAccountName = 'a'; Severity = 'High' }) |
                Export-Csv -Path (Join-Path $directory 'findings.csv') -NoTypeInformation -Encoding utf8
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:sameRoot) { Remove-Item -LiteralPath $script:sameRoot -Recurse -Force }
    }

    It 'reports zero changes without throwing' {
        $summary = & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Compare-OpsToolkitRun.ps1') `
            -Path $script:sameRoot -OutputDirectory (Join-Path $script:sameRoot 'out')
        $summary.ChangeCount | Should -Be 0
        $summary.NewFindingCount | Should -Be 0
    }

    It 'still writes the changes report when it is empty' {
        $summary = & (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Compare-OpsToolkitRun.ps1') `
            -Path $script:sameRoot -OutputDirectory (Join-Path $script:sameRoot 'out2')
        Test-Path -LiteralPath (Join-Path $summary.OutputDirectory 'changes.csv') | Should -BeTrue
    }
}
