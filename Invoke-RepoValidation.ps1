<#
.SYNOPSIS
Run the ops-toolkit repository validation suite: parser, analyzer, help, shell syntax, and stale references.

.DESCRIPTION
Instructions:
- Run from anywhere. Paths resolve against this script's own location.
- Read-only. It reads repository files and writes nothing except optional reports.
- Requires PSScriptAnalyzer. Bash checks are skipped with a note when bash is absent.
- Exit code 0 means the gates passed, 1 means something failed, 2 means a required
  tool is missing. Warnings alone do not fail the run unless -Strict is used.
- Run this before every commit that touches a script, and before any push.

Purpose:
The README described a local validation ritual (parser check, full analyzer pass,
stale-reference search, bash syntax check) that lived only in that prose, so it was
run from memory and drifted. This is that ritual as one command, plus the
comment-based help gate, which exists because a non-standard help keyword silently
disabled Get-Help across the whole repo and nothing caught it for months.

Required syntax:
pwsh -File .\Invoke-RepoValidation.ps1
pwsh -File .\Invoke-RepoValidation.ps1 -Strict
pwsh -File .\Invoke-RepoValidation.ps1 -Gate Parser,Help -OutputDirectory .\reports\validation

.OUTPUTS
Writes a per-gate result table to the console. With -OutputDirectory, also writes
findings and a summary as CSV and JSON. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Parser', 'Analyzer', 'Help', 'Shell', 'StaleReference', 'Module', 'Test')]
    [string[]]$Gate = @('Parser', 'Analyzer', 'Help', 'Shell', 'StaleReference', 'Module', 'Test'),

    [Parameter()]
    [switch]$IncludeArchive,

    [Parameter()]
    [switch]$Strict,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$scriptRoot = Join-Path $repoRoot 'scripts'
$moduleRoot = Join-Path $repoRoot 'modules'

# Scripts that legitimately cannot pass a gate, with the reason. Anything not listed
# here is expected to pass, so a new exemption is a decision someone has to make.
$helpExempt = @{
    'Page-File-Bleed.ps1' = 'Legacy keep with no comment-based help block at all.'
}

$findings = [System.Collections.Generic.List[object]]::new()
$gateResults = [System.Collections.Generic.List[object]]::new()
$script:MissingTool = @()

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Gate,
        [Parameter(Mandatory = $true)][ValidateSet('Error', 'Warning', 'Information')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter()][object]$Line = $null,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $findings.Add([pscustomobject]@{
            Gate = $Gate
            Severity = $Severity
            File = $File
            Line = $Line
            Message = $Message
        })
}

function Add-GateResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][int]$Checked,
        [Parameter(Mandatory = $true)][int]$ErrorCount,
        [Parameter(Mandatory = $true)][int]$WarningCount,
        [Parameter()][string]$Note = ''
    )

    $gateResults.Add([pscustomobject]@{
            Gate = $Name
            Status = $Status
            Checked = $Checked
            Errors = $ErrorCount
            Warnings = $WarningCount
            Note = $Note
        })
}

function Get-RepoScript {
    param([Parameter(Mandatory = $true)][string]$Extension)

    $roots = @($scriptRoot, $moduleRoot) | Where-Object { Test-Path -LiteralPath $_ }
    if ($IncludeArchive) {
        $archive = Join-Path $repoRoot 'archive'
        if (Test-Path -LiteralPath $archive) {
            $roots += $archive
        }
    }

    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Filter $Extension -Recurse -File
    }
}

$relative = {
    param([string]$FullName)
    $FullName.Replace($repoRoot, '').TrimStart('\', '/')
}

if ($Gate -contains 'Parser') {
    $files = @(@(Get-RepoScript -Extension '*.ps1') + @(Get-RepoScript -Extension '*.psm1') | Sort-Object FullName -Unique)
    $errorCount = 0
    foreach ($file in $files) {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
        foreach ($parseError in @($parseErrors)) {
            $errorCount++
            Add-Finding -Gate 'Parser' -Severity 'Error' -File (& $relative $file.FullName) -Line $parseError.Extent.StartLineNumber -Message $parseError.Message
        }

        # PowerShell 7 reads a BOM-less file as UTF-8; Windows PowerShell 5.1, which
        # is what a scheduled task runs, reads it as the ANSI code page. A file with
        # non-ASCII characters and no BOM therefore fails to parse under 5.1 and the
        # whole script silently does nothing. This has cost real overnight runs.
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        if (-not $hasBom) {
            $nonAscii = @($bytes | Where-Object { $_ -gt 127 })
            if ($nonAscii.Count -gt 0) {
                $errorCount++
                Add-Finding -Gate 'Parser' -Severity 'Error' -File (& $relative $file.FullName) `
                    -Message "Contains $($nonAscii.Count) non-ASCII byte(s) with no UTF-8 BOM. Windows PowerShell 5.1 will fail to parse this file, so a scheduled task running it does nothing at all. Add a BOM or use ASCII only."
            }
        }
    }

    Add-GateResult -Name 'Parser' -Status $(if ($errorCount -eq 0) { 'PASS' } else { 'FAIL' }) -Checked $files.Count -ErrorCount $errorCount -WarningCount 0
}

if ($Gate -contains 'Analyzer') {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        # A requested gate that cannot run is a missing prerequisite, not a pass.
        $script:MissingTool += 'PSScriptAnalyzer'
        Add-GateResult -Name 'Analyzer' -Status 'SKIP' -Checked 0 -ErrorCount 0 -WarningCount 0 -Note 'PSScriptAnalyzer is not installed.'
    } else {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
        $targets = @($scriptRoot, $moduleRoot) | Where-Object { Test-Path -LiteralPath $_ }
        $results = @()
        foreach ($target in $targets) {
            $results += @(Invoke-ScriptAnalyzer -Path $target -Recurse -Settings $settings)
        }

        $analyzerErrors = 0
        $analyzerWarnings = 0
        foreach ($result in $results) {
            $severity = [string]$result.Severity
            if ($severity -eq 'Error') { $analyzerErrors++ } else { $analyzerWarnings++ }
            Add-Finding -Gate 'Analyzer' -Severity $(if ($severity -eq 'Error') { 'Error' } else { 'Warning' }) `
                -File (& $relative $result.ScriptPath) -Line $result.Line -Message "$($result.RuleName): $($result.Message)"
        }

        $status = if ($analyzerErrors -gt 0 -or ($Strict -and $analyzerWarnings -gt 0)) { 'FAIL' } elseif ($analyzerWarnings -gt 0) { 'WARN' } else { 'PASS' }
        Add-GateResult -Name 'Analyzer' -Status $status -Checked $results.Count -ErrorCount $analyzerErrors -WarningCount $analyzerWarnings
    }
}

if ($Gate -contains 'Help') {
    # A non-standard keyword such as .INSTRUCTIONS silently invalidates the entire
    # comment-based help block, leaving Get-Help with nothing but generated syntax.
    # That is invisible on inspection, so it is checked rather than trusted.
    $files = @(Get-RepoScript -Extension '*.ps1')
    $helpErrors = 0
    $exempted = 0
    foreach ($file in $files) {
        if ($helpExempt.ContainsKey($file.Name)) {
            $exempted++
            continue
        }

        $synopsis = ''
        try {
            $help = Get-Help $file.FullName -ErrorAction Stop
            $synopsis = [string]$help.Synopsis
        } catch {
            $synopsis = ''
        }

        if (-not $synopsis.Trim() -or $synopsis -match '^\s*\S+\.ps1\s') {
            $helpErrors++
            Add-Finding -Gate 'Help' -Severity 'Error' -File (& $relative $file.FullName) `
                -Message 'Comment-based help does not parse. Get-Help returns generated syntax, which usually means a non-standard dotted keyword in the header.'
        }
    }

    # Module functions carry help too, and modules\README.md claims they do. Checking
    # only .ps1 would let that claim rot. Get-Help on a .psm1 file does not work, so
    # the module is imported and its exported functions are checked individually.
    $moduleFunctionCount = 0
    if (Test-Path -LiteralPath $moduleRoot) {
        foreach ($manifest in (Get-ChildItem -LiteralPath $moduleRoot -Filter '*.psd1' -Recurse -File)) {
            try {
                Import-Module $manifest.FullName -Force -ErrorAction Stop
                $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($manifest.Name)
                foreach ($functionName in (Get-Module -Name $moduleName).ExportedFunctions.Keys) {
                    $moduleFunctionCount++
                    $functionHelp = Get-Help -Name $functionName -ErrorAction SilentlyContinue
                    $functionSynopsis = if ($functionHelp) { [string]$functionHelp.Synopsis } else { '' }
                    if (-not $functionSynopsis.Trim() -or $functionSynopsis -match '^\s*\S+\s+\[') {
                        $helpErrors++
                        Add-Finding -Gate 'Help' -Severity 'Error' -File (& $relative $manifest.FullName) `
                            -Message "Exported function $functionName has no usable comment-based help."
                    }
                }

                Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
            } catch {
                $helpErrors++
                Add-Finding -Gate 'Help' -Severity 'Error' -File (& $relative $manifest.FullName) -Message "Could not import to check function help: $($_.Exception.Message)"
            }
        }
    }

    Add-GateResult -Name 'Help' -Status $(if ($helpErrors -eq 0) { 'PASS' } else { 'FAIL' }) -Checked (($files.Count - $exempted) + $moduleFunctionCount) -ErrorCount $helpErrors -WarningCount 0 -Note "$exempted exempt, $moduleFunctionCount module functions"
}

if ($Gate -contains 'Shell') {
    # Lab shell scripts live under docs\, not scripts\, so this gate walks the repo.
    $files = @(Get-ChildItem -LiteralPath $repoRoot -Filter '*.sh' -Recurse -File |
            Where-Object { $IncludeArchive -or $_.FullName -notmatch '[\\/]archive[\\/]' })

    # On Windows, `bash` on PATH is usually the WSL relay, which fails with a
    # CreateProcessCommon error when no distro is installed. That is a broken tool,
    # not a broken script, so each candidate is probed before it is trusted.
    $candidates = @(
        @(Get-Command bash -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        'C:\Program Files\Git\bin\bash.exe'
        'C:\Program Files\Git\usr\bin\bash.exe'
    ) | Where-Object { $_ } | Select-Object -Unique

    $bashPath = $null
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }

        & $candidate -c 'exit 0' 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $bashPath = $candidate
            break
        }
    }

    if (-not $bashPath) {
        if ($files.Count -gt 0) {
            $script:MissingTool += 'bash'
        }

        Add-GateResult -Name 'Shell' -Status 'SKIP' -Checked $files.Count -ErrorCount 0 -WarningCount 0 -Note 'No working bash found. Install Git for Windows or a WSL distro.'
    } else {
        $shellErrors = 0
        foreach ($file in $files) {
            $output = & $bashPath -n $file.FullName 2>&1
            if ($LASTEXITCODE -ne 0) {
                $shellErrors++
                Add-Finding -Gate 'Shell' -Severity 'Error' -File (& $relative $file.FullName) -Message ($output -join ' ')
            }
        }

        Add-GateResult -Name 'Shell' -Status $(if ($shellErrors -eq 0) { 'PASS' } else { 'FAIL' }) -Checked $files.Count -ErrorCount $shellErrors -WarningCount 0 -Note "using $bashPath"
    }
}

if ($Gate -contains 'StaleReference') {
    # Docs name script paths. When a script is renamed or retired, the prose keeps
    # pointing at it and nothing complains until someone tries to run it.
    $docs = @(Get-ChildItem -LiteralPath $repoRoot -Filter '*.md' -Recurse -File |
            Where-Object { $_.FullName -notmatch '[\\/](archive|reports)[\\/]' })
    $staleCount = 0
    $referenceCount = 0

    foreach ($doc in $docs) {
        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadAllLines($doc.FullName)) {
            $lineNumber++
            foreach ($match in [regex]::Matches($line, '(?<![\w\\/.])((?:scripts|modules|data)[\\/][^\s`''")\]:,]+\.(?:ps1|psm1|psd1|sh|py))')) {
                $referenceCount++
                $reference = $match.Groups[1].Value -replace '/', '\'

                # A path in a nested README is normally relative to that README, not
                # to the repo root. Only a reference that resolves against neither is
                # actually stale.
                $resolved = @(@(
                        (Join-Path $repoRoot $reference)
                        (Join-Path $doc.DirectoryName $reference)
                    ) | Where-Object { Test-Path -LiteralPath $_ })

                if ($resolved.Count -eq 0) {
                    $staleCount++
                    Add-Finding -Gate 'StaleReference' -Severity 'Error' -File (& $relative $doc.FullName) -Line $lineNumber `
                        -Message "References a path that exists neither at the repo root nor beside this document: $reference"
                }
            }
        }
    }

    Add-GateResult -Name 'StaleReference' -Status $(if ($staleCount -eq 0) { 'PASS' } else { 'FAIL' }) -Checked $referenceCount -ErrorCount $staleCount -WarningCount 0 -Note "$($docs.Count) markdown files"
}

if ($Gate -contains 'Module') {
    $manifests = @()
    if (Test-Path -LiteralPath $moduleRoot) {
        $manifests = @(Get-ChildItem -LiteralPath $moduleRoot -Filter '*.psd1' -Recurse -File)
    }

    $moduleErrors = 0
    foreach ($manifest in $manifests) {
        try {
            $data = Test-ModuleManifest -Path $manifest.FullName -ErrorAction Stop
            Import-Module $manifest.FullName -Force -ErrorAction Stop

            # A function listed in the manifest but not exported by the module is a
            # silent break: callers fail at run time, not at import.
            $exported = (Get-Module -Name $data.Name).ExportedFunctions.Keys
            foreach ($declared in $data.ExportedFunctions.Keys) {
                if ($exported -notcontains $declared) {
                    $moduleErrors++
                    Add-Finding -Gate 'Module' -Severity 'Error' -File (& $relative $manifest.FullName) `
                        -Message "Manifest exports $declared but the module does not."
                }
            }

            Remove-Module -Name $data.Name -Force -ErrorAction SilentlyContinue
        } catch {
            $moduleErrors++
            Add-Finding -Gate 'Module' -Severity 'Error' -File (& $relative $manifest.FullName) -Message $_.Exception.Message
        }
    }

    Add-GateResult -Name 'Module' -Status $(if ($moduleErrors -eq 0) { 'PASS' } else { 'FAIL' }) -Checked $manifests.Count -ErrorCount $moduleErrors -WarningCount 0
}

if ($Gate -contains 'Test') {
    $testRoot = Join-Path $repoRoot 'tests'
    $pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' } | Sort-Object Version -Descending | Select-Object -First 1

    if (-not (Test-Path -LiteralPath $testRoot)) {
        Add-GateResult -Name 'Test' -Status 'SKIP' -Checked 0 -ErrorCount 0 -WarningCount 0 -Note 'No tests directory.'
    } elseif (-not $pester) {
        # Pester 3.4 ships with Windows and cannot run these specs. Treat its absence
        # as a missing tool rather than as a pass, or the suite silently stops running.
        $script:MissingTool += 'Pester 5+'
        Add-GateResult -Name 'Test' -Status 'SKIP' -Checked 0 -ErrorCount 0 -WarningCount 0 -Note 'Pester 5 or later is not installed. Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser'
    } else {
        # Pester runs in a child process so its module version cannot collide with
        # whatever Pester the caller already has loaded.
        $testLog = Join-Path ([System.IO.Path]::GetTempPath()) "ops-toolkit-pester-$([guid]::NewGuid().ToString('N')).xml"
        $command = @(
            "Import-Module Pester -MinimumVersion 5.0 -Force"
            "`$config = New-PesterConfiguration"
            "`$config.Run.Path = '$testRoot'"
            "`$config.Run.PassThru = `$true"
            "`$config.Output.Verbosity = 'None'"
            "`$config.TestResult.Enabled = `$true"
            "`$config.TestResult.OutputPath = '$testLog'"
            "`$r = Invoke-Pester -Configuration `$config"
            "exit `$r.FailedCount"
        ) -join '; '

        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $command) `
            -NoNewWindow -Wait -PassThru
        $failedCount = $process.ExitCode
        $totalCount = 0

        if (Test-Path -LiteralPath $testLog) {
            try {
                [xml]$results = Get-Content -LiteralPath $testLog -Raw
                $totalCount = [int]$results.'test-results'.total
                foreach ($testCase in $results.SelectNodes('//test-case[@success="False"]')) {
                    Add-Finding -Gate 'Test' -Severity 'Error' -File 'tests' -Message "$($testCase.name): $($testCase.failure.message -replace '\s+', ' ')"
                }
            } catch {
                Add-Finding -Gate 'Test' -Severity 'Error' -File 'tests' -Message "Could not read the Pester result file: $($_.Exception.Message)"
            }

            Remove-Item -LiteralPath $testLog -Force -ErrorAction SilentlyContinue
        }

        Add-GateResult -Name 'Test' -Status $(if ($failedCount -eq 0) { 'PASS' } else { 'FAIL' }) -Checked $totalCount -ErrorCount $failedCount -WarningCount 0 -Note "Pester $($pester.Version)"
    }
}

# Unconditional, not verbose-only: the point of running this is to see the table.
Write-Information ($gateResults | Format-Table Gate, Status, Checked, Errors, Warnings, Note -AutoSize | Out-String) -InformationAction Continue
$failed = @($gateResults | Where-Object { $_.Status -eq 'FAIL' })

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    RepositoryRoot = $repoRoot
    GatesRun = @($gateResults | ForEach-Object { $_.Gate })
    Strict = [bool]$Strict
    IncludedArchive = [bool]$IncludeArchive
    GateResults = @($gateResults)
    FindingCount = $findings.Count
    ErrorCount = @($findings | Where-Object { $_.Severity -eq 'Error' }).Count
    WarningCount = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
    FailedGates = @($failed | ForEach-Object { $_.Gate })
    MissingTools = @($script:MissingTool | Sort-Object -Unique)
    Passed = $failed.Count -eq 0
}

if ($OutputDirectory) {
    Import-Module (Join-Path $repoRoot 'modules\OpsToolkit.Reporting') -Force
    $runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix 'repo-validation'
    $exports = @(
        Export-OpsReport -Name 'findings' -Record @($findings) -Directory $runDirectory
        Export-OpsReport -Name 'gate-results' -Record @($gateResults) -Directory $runDirectory
    )
    $summary | Add-Member -NotePropertyName OutputDirectory -NotePropertyValue $runDirectory -Force
    $summary | Add-Member -NotePropertyName Exports -NotePropertyValue @($exports) -Force
    $summary = Export-OpsSummary -Summary $summary -Directory $runDirectory
}

$summary

# Exit 2 outranks exit 1: a gate that could not run is a worse answer than a gate
# that ran and failed, because it is not an answer at all.
if ($summary.MissingTools.Count -gt 0) {
    Write-Warning "A requested gate could not run because a tool is missing: $($summary.MissingTools -join ', '). Exiting 2."
    exit 2
}

if (-not $summary.Passed) {
    exit 1
}
