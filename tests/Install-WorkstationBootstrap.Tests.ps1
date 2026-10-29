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

    It 'previews every hardening script in phase 8 and skips BitLocker without a recovery key folder' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('wb8-' + [guid]::NewGuid().ToString('N'))
        $hardening = Join-Path $root 'Code\projects\ops-toolkit\scripts\it-operations\windows-hardening'
        New-Item -ItemType Directory -Path $hardening -Force | Out-Null
        Copy-Item -Path (Join-Path $PSScriptRoot '..\scripts\it-operations\windows-hardening\*.ps1') -Destination $hardening
        try {
            $runs = @(
                @{ Name = 'nokey'; Extra = @() },
                @{ Name = 'key'; Extra = @('-BitLockerRecoveryKeyDirectory', (Join-Path $root 'usb')) }
            )
            $byRun = @{}
            foreach ($run in $runs) {
                $out = Join-Path $root ('out-' + $run.Name)
                $extra = $run.Extra
                $null = & pwsh -NoProfile -NonInteractive -File $script:ScriptPath -WhatIf -Phase '8' -SkipRepoClone `
                    -ReportDirectory $out -WorkspaceRoot (Join-Path $root 'Code') -DataRoot (Join-Path $root 'Data') @extra 2>&1
                $LASTEXITCODE | Should -Be 0
                $csv = Get-ChildItem -LiteralPath $out -Recurse -Filter results.csv | Select-Object -First 1
                $byRun[$run.Name] = @(Import-Csv -LiteralPath $csv.FullName | Where-Object { $_.Item -like 'Hardening preview *' })
            }

            $noKey = $byRun['nokey']
            @($noKey | Where-Object { $_.Detail -like 'script not found*' }).Count | Should -Be 0
            @($noKey | Where-Object Status -eq 'WhatIf').Count | Should -Be 14
            $bl = @($noKey | Where-Object Item -eq 'Hardening preview BitLocker OS volume')
            $bl.Count | Should -Be 1
            $bl[0].Status | Should -Be 'Skipped'
            $bl[0].Detail | Should -Match 'BitLockerRecoveryKeyDirectory'

            $withKey = $byRun['key']
            @($withKey | Where-Object Status -eq 'WhatIf').Count | Should -Be 15
            Test-Path (Join-Path $root 'usb') | Should -BeFalse
        }
        finally {
            if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }

    It 'completes phase 5 under strict mode when VS Code has no settings.json yet' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('wb5-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'appdata') -Force | Out-Null
        try {
            $cmd = '$env:APPDATA = ''{0}''; & ''{1}'' -WhatIf -Phase 5 -SkipRepoClone -ReportDirectory ''{2}'' -WorkspaceRoot ''{3}'' -DataRoot ''{4}''' -f `
                (Join-Path $root 'appdata'), $script:ScriptPath, (Join-Path $root 'out'), (Join-Path $root 'Code'), (Join-Path $root 'Data')
            $null = & pwsh -NoProfile -NonInteractive -Command $cmd 2>&1
            $results = Get-ChildItem -LiteralPath (Join-Path $root 'out') -Recurse -Filter results.csv | Select-Object -First 1
            $failed = @(Import-Csv -LiteralPath $results.FullName | Where-Object { $_.Item -like 'Phase 5 unexpected error*' })
            $failed.Count | Should -Be 0
        }
        finally {
            if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }
}
