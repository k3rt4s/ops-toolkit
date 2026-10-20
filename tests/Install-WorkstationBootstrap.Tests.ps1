#Requires -Modules Pester

# Install-WorkstationBootstrap.ps1 is a public, self-contained bootstrap. These specs pin
# the properties that must not regress: it parses, it is ASCII so Windows PowerShell 5.1
# reads it without a BOM, its winget catalog has no duplicate IDs, and a -WhatIf run
# changes nothing on the machine running the suite.

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\scripts\it-operations\workstation-setup\Install-WorkstationBootstrap.ps1'
}

Describe 'Install-WorkstationBootstrap' {
    It 'parses without errors' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$errors)
        @($errors).Count | Should -Be 0
    }

    It 'contains only ASCII characters' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'lists each winget package ID once' {
        $text = Get-Content -LiteralPath $script:ScriptPath -Raw
        $ids = [regex]::Matches($text, "New-Pkg\s+'[A-Za-z]+'\s+'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        @($ids).Count | Should -BeGreaterThan 20
        @($ids | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }

    It 'previews without changing the machine under -WhatIf' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('wb-' + [guid]::NewGuid().ToString('N'))
        try {
            $out = & pwsh -NoProfile -NonInteractive -File $script:ScriptPath -WhatIf -Phase '1' -SkipRepoClone `
                -ReportDirectory (Join-Path $root 'out') -WorkspaceRoot (Join-Path $root 'Code') -DataRoot (Join-Path $root 'Data') 2>&1
            $LASTEXITCODE | Should -Be 0
            Test-Path (Join-Path $root 'Code') | Should -BeFalse
        }
        finally {
            if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }
}
