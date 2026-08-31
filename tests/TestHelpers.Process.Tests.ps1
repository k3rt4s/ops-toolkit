#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-helper-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
}

AfterAll {
    if ($script:workRoot -and (Test-Path -LiteralPath $script:workRoot)) {
        Remove-Item -LiteralPath $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-ScriptUnderTest process bounds' {
    It 'returns Completed when the child finishes inside the bound' {
        $run = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\it-operations\utilities\Get-CurrentUserContext.ps1' `
            -TimeoutSeconds 30

        $run.Status | Should -Be 'Completed'
        $run.TimedOut | Should -BeFalse
        $run.ExitCode | Should -Be 0
        $run.Summary | Should -Not -BeNullOrEmpty
    }

    It 'returns NotRun and stops the descendant tree when the bound expires' {
        $childPidPath = Join-Path $script:workRoot 'descendant.pid'
        $setup = @"
`$child = Start-Process -FilePath (Get-Process -Id `$PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') -PassThru
Set-Content -LiteralPath '$childPidPath' -Value `$child.Id
Start-Sleep -Seconds 30
"@

        $run = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\it-operations\utilities\Get-CurrentUserContext.ps1' `
            -Setup $setup -TimeoutSeconds 2

        $run.Status | Should -Be 'NotRun'
        $run.TimedOut | Should -BeTrue
        $run.ExitCode | Should -BeNullOrEmpty
        $run.Note | Should -Match 'Timed out after 2 seconds'
        Test-Path -LiteralPath $childPidPath | Should -BeTrue

        $descendantPid = [int](Get-Content -LiteralPath $childPidPath -Raw)
        { Get-Process -Id $descendantPid -ErrorAction Stop } | Should -Throw
    }
}
