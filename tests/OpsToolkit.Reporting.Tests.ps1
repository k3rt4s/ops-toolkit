#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    $script:asOf = [datetime]::new(2026, 8, 14, 0, 0, 0, [DateTimeKind]::Utc)
}

Describe 'Get-OpsAge' {
    It 'returns null for a null timestamp' {
        Get-OpsAge -Timestamp $null -AsOf $script:asOf | Should -BeNullOrEmpty
    }

    It 'treats a zero file time as never set rather than as the year 1601' {
        # AD and Windows write "never" as 0, not as null. Reporting 155000 days is worse
        # than reporting nothing.
        Get-OpsAge -Timestamp ([long]0) -AsOf $script:asOf | Should -BeNullOrEmpty
    }

    It 'treats a negative file time as never set' {
        Get-OpsAge -Timestamp ([long]-1) -AsOf $script:asOf | Should -BeNullOrEmpty
    }

    It 'treats an early-1601 date as never set' {
        Get-OpsAge -Timestamp ([datetime]'1601-01-01Z') -AsOf $script:asOf | Should -BeNullOrEmpty
    }

    It 'computes whole days from a DateTime' {
        Get-OpsAge -Timestamp $script:asOf.AddDays(-100) -AsOf $script:asOf | Should -Be 100
    }

    It 'computes whole days from a Windows file time' {
        Get-OpsAge -Timestamp ($script:asOf.AddDays(-30).ToFileTimeUtc()) -AsOf $script:asOf | Should -Be 30
    }

    It 'parses a date supplied as a string' {
        Get-OpsAge -Timestamp $script:asOf.AddDays(-7).ToString('o') -AsOf $script:asOf | Should -Be 7
    }

    It 'returns null for an unparseable string rather than throwing' {
        Get-OpsAge -Timestamp 'not a date' -AsOf $script:asOf | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-OpsHexString' {
    It 'renders a byte array as uppercase hex' {
        ConvertTo-OpsHexString -Value ([byte[]](0xAB, 0xCD, 0x01)) | Should -Be 'ABCD01'
    }

    It 'renders an object array of bytes as hex' {
        # PowerShell unrolls an array returned from a function, so a [byte[]] read off
        # an object arrives as [object[]] and a [byte[]] type test would miss it.
        ConvertTo-OpsHexString -Value @(171, 205, 1) | Should -Be 'ABCD01'
    }

    It 'passes a string through unchanged' {
        ConvertTo-OpsHexString -Value 'ABC123' | Should -Be 'ABC123'
    }

    It 'returns empty for null' {
        ConvertTo-OpsHexString -Value $null | Should -Be ''
    }

    It 'returns empty for an empty sequence' {
        ConvertTo-OpsHexString -Value @() | Should -Be ''
    }

    It 'does not coerce a dictionary into nonsense hex' {
        ConvertTo-OpsHexString -Value @{ b = 2; a = 1 } | Should -Be 'a=1;b=2'
    }

    It 'falls back to a joined value when a sequence is not byte-convertible' {
        ConvertTo-OpsHexString -Value @('x', 'y') | Should -Be 'x;y'
    }
}

Describe 'Join-OpsValue' {
    It 'returns empty for null' {
        Join-OpsValue -Value $null | Should -Be ''
    }

    It 'joins an array with semicolons' {
        Join-OpsValue -Value @('a', 'b', 'c') | Should -Be 'a;b;c'
    }

    It 'drops nulls inside an array' {
        Join-OpsValue -Value @('a', $null, 'b') | Should -Be 'a;b'
    }

    It 'renders a dictionary as sorted key=value pairs rather than type names' {
        Join-OpsValue -Value ([ordered]@{ zeta = 1; alpha = 2 }) | Should -Be 'alpha=2;zeta=1'
    }

    It 'passes a string through unchanged' {
        Join-OpsValue -Value 'plain' | Should -Be 'plain'
    }
}

Describe 'Get-OpsSeverityRank' {
    It 'ranks worst first' {
        $ranks = 'Critical', 'High', 'Medium', 'Low', 'Informational' | ForEach-Object { Get-OpsSeverityRank -Severity $_ }
        $ranks -join ',' | Should -Be '0,1,2,3,4'
    }

    It 'ranks an unknown severity last' {
        Get-OpsSeverityRank -Severity 'Whatever' | Should -Be 4
    }
}

Describe 'Get-OpsPropertyValue' {
    It 'returns null for a null object' {
        Get-OpsPropertyValue -InputObject $null -Name 'Anything' | Should -BeNullOrEmpty
    }

    It 'returns null for a property that does not exist, rather than throwing under strict mode' {
        Get-OpsPropertyValue -InputObject ([pscustomobject]@{ A = 1 }) -Name 'B' | Should -BeNullOrEmpty
    }

    It 'reads a property from an object' {
        Get-OpsPropertyValue -InputObject ([pscustomobject]@{ A = 42 }) -Name 'A' | Should -Be 42
    }

    It 'reads a key from a hashtable' {
        Get-OpsPropertyValue -InputObject @{ 'a' = 'x' } -Name 'a' | Should -Be 'x'
    }

    It 'returns null for a hashtable key that is absent' {
        Get-OpsPropertyValue -InputObject @{ 'a' = 'x' } -Name 'b' | Should -BeNullOrEmpty
    }
}

Describe 'Export-OpsReport' {
    BeforeAll {
        $script:reportDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "ops-report-test-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:reportDirectory -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:reportDirectory) {
            Remove-Item -LiteralPath $script:reportDirectory -Recurse -Force
        }
    }

    It 'writes both a CSV and a JSON file' {
        $result = Export-OpsReport -Name 'sample' -Record @([pscustomobject]@{ A = 1 }) -Directory $script:reportDirectory
        Test-Path -LiteralPath $result.CsvPath | Should -BeTrue
        Test-Path -LiteralPath $result.JsonPath | Should -BeTrue
        $result.Count | Should -Be 1
    }

    It 'still writes both files for an empty record set' {
        # A report that exists and is empty proves the check ran. A missing file is
        # ambiguous, and ambiguity is what turns into a false compliance claim.
        $result = Export-OpsReport -Name 'empty' -Record @() -Directory $script:reportDirectory
        Test-Path -LiteralPath $result.CsvPath | Should -BeTrue
        Test-Path -LiteralPath $result.JsonPath | Should -BeTrue
        $result.Count | Should -Be 0
    }

    It 'writes a JSON array even for a single record' {
        $result = Export-OpsReport -Name 'single' -Record @([pscustomobject]@{ A = 1 }) -Directory $script:reportDirectory
        (Get-Content -LiteralPath $result.JsonPath -Raw).TrimStart() | Should -BeLike '`[*'
    }

    It 'drops null records rather than exporting empty rows' {
        $result = Export-OpsReport -Name 'nulls' -Record @([pscustomobject]@{ A = 1 }, $null) -Directory $script:reportDirectory
        $result.Count | Should -Be 1
    }
}

Describe 'Resolve-OpsRunDirectory' {
    BeforeAll {
        $script:runParent = Join-Path ([System.IO.Path]::GetTempPath()) "ops-run-test-$([guid]::NewGuid().ToString('N'))"
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:runParent) {
            Remove-Item -LiteralPath $script:runParent -Recurse -Force
        }
    }

    It 'creates a timestamped directory under the parent' {
        $stamp = [datetime]::new(2026, 8, 14, 9, 30, 0)
        $path = Resolve-OpsRunDirectory -OutputDirectory $script:runParent -Prefix 'thing' -Timestamp $stamp
        Test-Path -LiteralPath $path | Should -BeTrue
        (Split-Path $path -Leaf) | Should -Be 'thing-20260814_093000'
    }

    It 'creates the parent directory when it does not exist' {
        $nested = Join-Path $script:runParent 'deeper\still'
        $path = Resolve-OpsRunDirectory -OutputDirectory $nested -Prefix 'x' -Timestamp ([datetime]::new(2026, 1, 1))
        Test-Path -LiteralPath $path | Should -BeTrue
    }
}
