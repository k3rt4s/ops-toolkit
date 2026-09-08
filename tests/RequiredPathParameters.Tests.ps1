#Requires -Modules Pester

# Item C, 2026-09-06: every hard-coded absolute path default that used to point at this
# developer's workstation is now a required parameter with no default, across the five
# state-changing PowerShell scripts named on the work board. This is a public MIT
# repository, so the sharp case is Set-WorkstationPerformance.ps1 silently adding a
# Defender path exclusion nobody asked for on a stranger's machine.
#
# A mandatory PowerShell parameter with no value prompts, and a prompt hangs an
# unattended suite. So the "is it mandatory" assertion below reads parameter metadata
# through Get-Command rather than running the script, and the "does a no-argument run
# make no change" assertion runs the script only through Invoke-ScriptUnderTest, which
# always launches its child process with -NonInteractive. Under -NonInteractive,
# PowerShell fails a missing mandatory parameter with a terminating error instead of
# prompting, so the script under test never has a chance to change anything, and the
# suite never has a chance to hang. The script is still never invoked bare from this
# process.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    function Get-MandatoryParameterNames {
        <#
        .SYNOPSIS
        Return the names of every parameter Get-Command reports as Mandatory, without
        running the script.
        #>
        param([string]$RelativePath)

        $path = Get-RepositoryScriptPath -RelativePath $RelativePath
        $command = Get-Command -Name $path -CommandType ExternalScript
        @($command.Parameters.GetEnumerator() | Where-Object {
                $_.Value.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }
            } | ForEach-Object { $_.Key })
    }

    function Assert-NoArgumentRunMakesNoChange {
        <#
        .SYNOPSIS
        Run a script with no arguments through the non-interactive harness and assert
        it fails at parameter binding, before recording any mutation.
        #>
        param([string]$RelativePath, [string]$Tag)

        $log = Join-Path $script:workRoot "$Tag-noargs.log"
        $run = Invoke-ScriptUnderTest -RelativePath $RelativePath -ModulePath $script:systemModulePath `
            -Setup (Get-WindowsMutationStubText -MutationLogPath $log)

        $run.ExitCode | Should -Not -Be 0 -Because "a no-argument run must refuse rather than apply a default: $($run.Output)"
        $mutations = @(
            if (Test-Path -LiteralPath $log) {
                Get-Content -LiteralPath $log | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }
            }
        )
        $mutations.Count | Should -Be 0 -Because "a run that never got past parameter binding must not have changed anything: $($mutations | ConvertTo-Json -Compress)"
    }

    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-pathparams-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WorkstationPerformance path parameters' {
    It 'marks DefenderPathExclusion and ReportDirectory mandatory' {
        $mandatory = Get-MandatoryParameterNames -RelativePath 'scripts\it-operations\performance\Set-WorkstationPerformance.ps1'
        $mandatory | Should -Contain 'DefenderPathExclusion'
        $mandatory | Should -Contain 'ReportDirectory'
    }

    It 'makes no change on a no-argument run' {
        Assert-NoArgumentRunMakesNoChange -RelativePath 'scripts\it-operations\performance\Set-WorkstationPerformance.ps1' -Tag 'perf'
    }
}

Describe 'Set-BrowserCredentialPosture path parameters' {
    It 'marks ReportDirectory mandatory' {
        $mandatory = Get-MandatoryParameterNames -RelativePath 'scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1'
        $mandatory | Should -Contain 'ReportDirectory'
    }

    It 'makes no change on a no-argument run' {
        Assert-NoArgumentRunMakesNoChange -RelativePath 'scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1' -Tag 'browsercred'
    }
}

Describe 'Set-WorkstationLockPosture path parameters' {
    It 'marks ReportDirectory mandatory' {
        $mandatory = Get-MandatoryParameterNames -RelativePath 'scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1'
        $mandatory | Should -Contain 'ReportDirectory'
    }

    It 'makes no change on a no-argument run' {
        Assert-NoArgumentRunMakesNoChange -RelativePath 'scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1' -Tag 'lock'
    }
}

Describe 'Invoke-DiskSpaceReclaim path parameters' {
    It 'marks ReportDirectory mandatory' {
        $mandatory = Get-MandatoryParameterNames -RelativePath 'scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1'
        $mandatory | Should -Contain 'ReportDirectory'
    }

    It 'makes no change on a no-argument run' {
        Assert-NoArgumentRunMakesNoChange -RelativePath 'scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1' -Tag 'reclaim'
    }
}

Describe 'Analyze-C.py path parameters' {
    It 'does not carry this workstation path in the script body' {
        $body = Get-Content -LiteralPath (Get-RepositoryScriptPath -RelativePath 'scripts\it-operations\windows-file-cleanup\Analyze-C.py') -Raw
        $body | Should -Not -Match ([regex]::Escape('C:\Code_data'))
        $body | Should -Not -Match ([regex]::Escape('C:\Code\'))
    }
}
