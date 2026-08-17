#Requires -Modules Pester

# The two scripts that changed something with no way to rehearse it.
#
# Send-AdSecurityEmailReport sent mail and Invoke-DiskMaintenance ran chkdsk, a cipher
# free-space wipe, a defrag, and a benchmark write, none of them behind -WhatIf, in a
# repository whose own standing rule is that state-changing scripts support it. Both
# now do, and both are covered here on the same paired shape as the other 22: a preview
# run that must attempt nothing, and an executing run that must attempt exactly what the
# preview described.
#
# Invoke-DiskMaintenance is never allowed to execute for real here. Its executing path
# is proved through stubs; the preview path is what an operator actually reaches for,
# and that is checked on the real command resolution.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:adModulePath = Use-FakeActiveDirectory
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-nodry-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    function Get-MutationRecord {
        <#
        .SYNOPSIS
        Read the changes a run attempted, as objects.
        #>
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }
}

AfterAll {
    foreach ($p in $script:adModulePath, $script:workRoot) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Send-AdSecurityEmailReport' {
    BeforeAll {
        $script:reportFixture = @'
function Send-MailMessage {
    param($SmtpServer, $From, $To, $Subject, $Body, [switch]$BodyAsHtml)
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value (
        [pscustomobject]@{ Command = 'Send-MailMessage'; Recipients = ($To -join ';') } | ConvertTo-Json -Compress)
}
$global:FakeAdData = @{
    Users = @(
        [pscustomobject]@{ Name = 'Alice'; SamAccountName = 'alice'; Enabled = $true
            PasswordNeverExpires = $true; DistinguishedName = 'CN=Alice,OU=Users,DC=test,DC=local' }
        [pscustomobject]@{ Name = 'Bob'; SamAccountName = 'bob'; Enabled = $true
            PasswordNeverExpires = $false; DistinguishedName = 'CN=Bob,OU=Users,DC=test,DC=local' }
    )
}
'@

        function New-ReportRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            # Assign rather than use hashtable +, which throws on a duplicate key. The
            # caller has to be able to override a default, not just add to it.
            $argument = @{
                ReportType      = 'PasswordNeverExpires'
                OutputDirectory = (Join-Path $script:workRoot "$Tag-reports")
                SendEmail       = $true
                SmtpServer      = 'smtp.test.local'
                From            = 'noreply@test.local'
                To              = @('admins@test.local')
            }
            foreach ($key in $Extra.Keys) { $argument[$key] = $Extra[$key] }

            [pscustomobject]@{
                Run = Invoke-ScriptUnderTest -RelativePath 'scripts\active-directory\Send-AdSecurityEmailReport.ps1' `
                    -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'`n$($script:reportFixture)" `
                    -ModulePath $script:adModulePath -Argument $argument
                Log = $log
            }
        }

        $script:reportWhatIf = New-ReportRun -Tag 'report-whatif' -Extra @{ WhatIf = $true }
        $script:reportSend = New-ReportRun -Tag 'report-send' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:reportWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:reportWhatIf.Run.Output)"
        $script:reportSend.Run.ExitCode | Should -Be 0 -Because "the sending run failed: $($script:reportSend.Run.Output)"
    }

    It 'sends nothing under -WhatIf' {
        @(Get-MutationRecord -Path $script:reportWhatIf.Log).Count | Should -Be 0
        $script:reportWhatIf.Run.Summary.EmailResult | Should -Be 'Previewed'
        $script:reportWhatIf.Run.Summary.EmailSent | Should -BeFalse
    }

    It 'still writes the reports on a preview run' {
        # The report is the preview. Withholding it too would leave nothing to review,
        # and the summary resolves these paths, so a suppressed write is a crash.
        Test-Path $script:reportWhatIf.Run.Summary.CsvPath | Should -BeTrue
        Test-Path $script:reportWhatIf.Run.Summary.HtmlPath | Should -BeTrue
        @(Import-Csv $script:reportWhatIf.Run.Summary.CsvPath).Count | Should -Be 1
    }

    It 'sends to the given recipients when executing' {
        $mutations = @(Get-MutationRecord -Path $script:reportSend.Log)
        $mutations.Count | Should -Be 1
        $mutations[0].Recipients | Should -Be 'admins@test.local'
        $script:reportSend.Run.Summary.EmailResult | Should -Be 'Sent'
        $script:reportSend.Run.Summary.EmailSent | Should -BeTrue
    }

    It 'reports only the accounts whose passwords never expire' {
        # Bob's password does expire. A report that lists everyone is a report nobody
        # reads twice.
        $rows = @(Import-Csv $script:reportSend.Run.Summary.CsvPath)
        @($rows | ForEach-Object { $_.SamAccountName }) | Should -Be @('alice')
    }

    It 'distinguishes not requested from previewed and sent' {
        # Three states, not a boolean. Without -SendEmail nothing was withheld, so
        # calling that "previewed" would misdescribe the run.
        $run = New-ReportRun -Tag 'report-noemail' -Extra @{ SendEmail = $false; Confirm = $false }
        $run.Run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Run.Output)"
        $run.Run.Summary.EmailResult | Should -Be 'NotRequested'
        @(Get-MutationRecord -Path $run.Log).Count | Should -Be 0
    }
}

Describe 'Invoke-DiskMaintenance' {
    BeforeAll {
        # Start-Process is what launches chkdsk, cipher, and defrag, so stubbing it is
        # what keeps this test from wiping free space on the machine running the suite.
        # The elevation and fixed-disk preflight run for real against drive C.
        $script:diskFixture = @'
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$NoNewWindow, [switch]$PassThru)
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value (
        [pscustomobject]@{ Command = $FilePath; Arguments = ($ArgumentList -join ' ') } | ConvertTo-Json -Compress)
    [pscustomobject]@{ ExitCode = 0 }
}
'@

        function New-DiskRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            # SkipBenchmark on every run: the benchmark writes a real 10 MB file to the
            # root of a real drive through .NET, which no stub here intercepts.
            $argument = @{ Drive = 'C'; SkipBenchmark = $true }
            foreach ($key in $Extra.Keys) { $argument[$key] = $Extra[$key] }

            [pscustomobject]@{
                Run = Invoke-ScriptUnderTest -RelativePath 'scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1' `
                    -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'`n$($script:diskFixture)" `
                    -Argument $argument
                Log = $log
            }
        }

        $script:diskWhatIf = New-DiskRun -Tag 'disk-whatif' -Extra @{ WhatIf = $true }
        $script:diskExecute = New-DiskRun -Tag 'disk-execute' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:diskWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:diskWhatIf.Run.Output)"
        $script:diskExecute.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:diskExecute.Run.Output)"
    }

    It 'launches nothing under -WhatIf' {
        # Before this script had -WhatIf there was no way to find out what it would do
        # other than letting it do it, and one of the things it does is a free-space
        # wipe that can run for hours.
        $mutations = @(Get-MutationRecord -Path $script:diskWhatIf.Log)
        $mutations.Count | Should -Be 0 -Because "-WhatIf launched: $($mutations | ConvertTo-Json -Compress)"
    }

    It 'names each step it would take on a preview run' {
        # A preview that runs nothing and says nothing is indistinguishable from a
        # script that is broken.
        $output = $script:diskWhatIf.Run.Output
        $output | Should -Match 'chkdsk'
        $output | Should -Match 'cipher'
        $output | Should -Match 'defrag'
    }

    It 'launches chkdsk, cipher, and defrag when executing' {
        $launched = @(Get-MutationRecord -Path $script:diskExecute.Log | ForEach-Object { $_.Command })
        $launched | Should -Contain 'chkdsk'
        $launched | Should -Contain 'cipher.exe'
        $launched | Should -Contain 'defrag'
    }

    It 'honours a skip switch independently of -WhatIf' {
        # Skip and preview are different things, and a script that conflated them would
        # still pass every assertion above.
        $run = New-DiskRun -Tag 'disk-skip' -Extra @{ SkipCipherWipe = $true; SkipDefrag = $true; Confirm = $false }
        $run.Run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Run.Output)"

        $launched = @(Get-MutationRecord -Path $run.Log | ForEach-Object { $_.Command })
        $launched | Should -Contain 'chkdsk'
        $launched | Should -Not -Contain 'cipher.exe'
        $launched | Should -Not -Contain 'defrag'
    }

    It 'targets the drive it was given' {
        $arguments = (@(Get-MutationRecord -Path $script:diskExecute.Log | ForEach-Object { $_.Arguments })) -join ' '
        $arguments | Should -Match 'C:'
        $arguments | Should -Not -Match 'D:'
    }
}
