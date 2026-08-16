<#
.SYNOPSIS
Helpers that let tests exercise functions defined inside ops-toolkit scripts.

.DESCRIPTION
Instructions:
- Import from a Pester BeforeAll block:
  Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
- Use Get-ScriptFunctionScriptBlock to pull the functions out of a script, then
  dot-source the result so the tests can call them.

Purpose:
Every script in this repo is a script, not a module, so its functions cannot be
imported. They also cannot simply be dot-sourced, because running a script executes
it: it would try to reach Active Directory or Microsoft Graph and fail before
defining anything. These helpers parse the file and lift out only the function
definitions and script-scoped lookup tables, which is what makes the pure logic
testable without a domain, a tenant, or a network.

.NOTES
Status:
Active test support module kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Get-RepositoryRoot {
    <#
    .SYNOPSIS
    Return the absolute path of the repository root.

    .OUTPUTS
    String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}

function Get-RepositoryScriptPath {
    <#
    .SYNOPSIS
    Resolve a script path relative to the repository root, failing loudly if it moved.

    .PARAMETER RelativePath
    Path relative to the repository root, for example scripts\entra\Export-Foo.ps1.

    .OUTPUTS
    String. The absolute path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath
    )

    $path = Join-Path (Get-RepositoryRoot) $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Script not found: $path. If it was renamed, update the test rather than deleting it."
    }

    (Resolve-Path -LiteralPath $path).Path
}

function Get-ScriptFunctionScriptBlock {
    <#
    .SYNOPSIS
    Return a script block containing a script's function definitions and script-scoped tables.

    .DESCRIPTION
    Dot-source the returned block to bring the functions into scope without executing
    the script body. Script-scoped assignments are included because several scripts
    keep lookup tables there, such as userAccountControl flags or extended right
    GUIDs, and the functions read them.

    .PARAMETER RelativePath
    Script path relative to the repository root.

    .PARAMETER FunctionName
    Optional list of function names to include. All functions are included by default.

    .OUTPUTS
    ScriptBlock.
    #>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$FunctionName
    )

    $path = Get-RepositoryScriptPath -RelativePath $RelativePath
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors) {
        throw "$RelativePath does not parse: $(($errors | ForEach-Object { $_.Message }) -join '; ')"
    }

    $functions = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    if ($FunctionName) {
        $functions = @($functions | Where-Object { $FunctionName -contains $_.Name })
        $missing = @($FunctionName | Where-Object { $_ -notin @($functions | ForEach-Object { $_.Name }) })
        if ($missing.Count -gt 0) {
            throw "$RelativePath no longer defines: $($missing -join ', ')"
        }
    }

    $assignments = @($ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left.Extent.Text -like '$script:*'
            }, $true))

    $parts = @($assignments | ForEach-Object { $_.Extent.Text }) + @($functions | ForEach-Object { $_.Extent.Text })
    [scriptblock]::Create($parts -join [Environment]::NewLine)
}

function Import-ReportingModule {
    <#
    .SYNOPSIS
    Import OpsToolkit.Reporting from the repository into the global scope.

    .DESCRIPTION
    Scripts under test call the module's functions, so tests must load it too. The
    import is global because Pester runs BeforeAll and It in different scopes, and a
    plain import inside BeforeAll is not visible to the It blocks that need it.

    .OUTPUTS
    None.
    #>
    [CmdletBinding()]
    param()

    Import-Module (Join-Path (Get-RepositoryRoot) 'modules\OpsToolkit.Reporting') -Force -Global
}

function Import-ScriptFunction {
    <#
    .SYNOPSIS
    Load a script's functions into the global scope so tests can call them.

    .DESCRIPTION
    Wraps the extracted functions in a dynamic module and imports it globally. A bare
    dot-source inside a Pester BeforeAll block defines the functions in a scope the
    It blocks cannot see, which shows up as CommandNotFoundException on every test.

    .PARAMETER RelativePath
    Script path relative to the repository root.

    .PARAMETER FunctionName
    Optional list of function names to include. All are included by default.

    .OUTPUTS
    None.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$FunctionName
    )

    $parameters = @{ RelativePath = $RelativePath }
    if ($FunctionName) {
        $parameters['FunctionName'] = $FunctionName
    }

    $block = Get-ScriptFunctionScriptBlock @parameters

    # Export the variables too. Several scripts keep their lookup tables in script
    # scope, and a test that cannot see the tier-0 SID table or the extended right
    # GUID map cannot assert on the data those decisions are made from.
    $withExports = [scriptblock]::Create($block.ToString() + [Environment]::NewLine + 'Export-ModuleMember -Function * -Variable *')
    $moduleName = "UnderTest_$([System.IO.Path]::GetFileNameWithoutExtension($RelativePath))"
    New-Module -Name $moduleName -ScriptBlock $withExports | Import-Module -Force -Global
}

function Use-FakeActiveDirectory {
    <#
    .SYNOPSIS
    Stage the fake ActiveDirectory module and return the PSModulePath entry to use.

    .DESCRIPTION
    Copies the fixture into a temporary directory under the name ActiveDirectory,
    with a manifest, so that a script declaring #Requires -Modules ActiveDirectory
    will start on a machine with no RSAT. The caller prepends the returned path to
    PSModulePath in the child process that runs the script.

    Returns a path rather than importing, because the script under test has to run in
    its own process: #Requires is evaluated when the script is parsed, so the module
    must be discoverable before that process starts.

    .OUTPUTS
    String. The directory to prepend to PSModulePath.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "ops-fakead-$([guid]::NewGuid().ToString('N'))"
    $moduleDirectory = Join-Path $staging 'ActiveDirectory'
    New-Item -ItemType Directory -Path $moduleDirectory -Force | Out-Null

    $source = Join-Path $PSScriptRoot 'Fixtures\FakeActiveDirectory\FakeActiveDirectory.psm1'
    Copy-Item -LiteralPath $source -Destination (Join-Path $moduleDirectory 'ActiveDirectory.psm1') -Force

    # Export whatever the fixture exports. This was a hard-coded list, which silently
    # went stale the moment a cmdlet was added to the fixture: the manifest gates the
    # export, so the script under test called a command that did not exist, its own
    # try/catch recorded a failed action, and the run still exited 0 with a plausible
    # report. The fixture's Export-ModuleMember is the one place that decides.
    New-ModuleManifest -Path (Join-Path $moduleDirectory 'ActiveDirectory.psd1') `
        -RootModule 'ActiveDirectory.psm1' -ModuleVersion '1.0.0' `
        -FunctionsToExport '*'

    $staging
}

function Use-FakePlaceholderModule {
    <#
    .SYNOPSIS
    Stage empty modules under the given names so #Requires is satisfied.

    .DESCRIPTION
    For modules that are not installed and whose cmdlets are stubbed as global
    functions in the setup block. The staged module deliberately exports nothing: a
    module that exported stubs would be imported by the script's own #Requires and
    would replace the setup's functions, which is the trap documented in
    tests\README.md.

    #Requires -Modules checks that a module of that name is available, not what it
    contains, so an empty one is enough.

    .PARAMETER Name
    Module names to stage.

    .PARAMETER Path
    Optional existing staging directory to add to, so several modules share one
    PSModulePath entry.

    .OUTPUTS
    String. The directory to prepend to PSModulePath.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Path = ''
    )

    $staging = if ($Path) { $Path } else { Join-Path ([System.IO.Path]::GetTempPath()) "ops-fakemod-$([guid]::NewGuid().ToString('N'))" }

    foreach ($moduleName in $Name) {
        $moduleDirectory = Join-Path $staging $moduleName
        New-Item -ItemType Directory -Path $moduleDirectory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $moduleDirectory "$moduleName.psm1") -Encoding utf8 `
            -Value "# Placeholder so #Requires -Modules $moduleName is satisfied. Exports nothing`r`n# on purpose; the cmdlets are stubbed as global functions by the test setup.`r`nExport-ModuleMember -Function @()"
        New-ModuleManifest -Path (Join-Path $moduleDirectory "$moduleName.psd1") `
            -RootModule "$moduleName.psm1" -ModuleVersion '1.0.0' -FunctionsToExport @()
    }

    $staging
}

function Invoke-ScriptUnderTest {
    <#
    .SYNOPSIS
    Run a repository script in a child process with fixtures staged, and return its summary.

    .DESCRIPTION
    The script runs in its own process for two reasons: #Requires is evaluated at
    parse time so any stand-in module must be discoverable before the process starts,
    and a stubbed cmdlet must not leak into the test session or into other tests.

    The setup script block is dot-sourced into that process before the script under
    test, which is where fixture data and any stubbed cmdlets are defined.

    .PARAMETER RelativePath
    Script path relative to the repository root.

    .PARAMETER Setup
    Script text run before the script under test. Define stubs and fixture data here.

    .PARAMETER Argument
    Arguments passed to the script under test.

    .PARAMETER ModulePath
    Optional directory prepended to PSModulePath, from Use-FakeActiveDirectory.

    .OUTPUTS
    PSCustomObject with Summary (the script's returned object, round-tripped through
    JSON), ExitCode, and Output.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Setup,

        [Parameter()]
        [AllowEmptyCollection()]
        [hashtable]$Argument = @{},

        [Parameter()]
        [AllowEmptyString()]
        [string]$ModulePath = ''
    )

    $scriptPath = Get-RepositoryScriptPath -RelativePath $RelativePath
    $work = Join-Path ([System.IO.Path]::GetTempPath()) "ops-run-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $summaryPath = Join-Path $work 'summary-out.json'

    $splat = ($Argument.Keys | ForEach-Object {
            $value = $Argument[$_]
            if ($value -is [bool] -or $value -is [switch]) { "  $_ = `$$([bool]$value)" }
            elseif ($value -is [array]) { "  $_ = @($(($value | ForEach-Object { "'$_'" }) -join ','))" }
            else { "  $_ = '$value'" }
        }) -join "`n"

    $runner = Join-Path $work 'runner.ps1'
    Set-Content -LiteralPath $runner -Encoding utf8 -Value @"
`$ErrorActionPreference = 'Stop'
$Setup
`$splat = @{
$splat
}
`$result = & '$scriptPath' @splat
`$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath '$summaryPath' -Encoding utf8
"@

    $arguments = @('-NoProfile', '-NonInteractive', '-File', $runner)
    $stdout = Join-Path $work 'run.log'
    $stderr = Join-Path $work 'run.err.log'

    $previousModulePath = $env:PSModulePath
    if ($ModulePath) {
        $env:PSModulePath = $ModulePath + [System.IO.Path]::PathSeparator + $env:PSModulePath
    }

    try {
        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $exitCode = $process.ExitCode
    } finally {
        $env:PSModulePath = $previousModulePath
    }

    $summary = $null
    if (Test-Path -LiteralPath $summaryPath) {
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    }

    [pscustomobject]@{
        Summary = $summary
        ExitCode = $exitCode
        Output = (@(
                if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw }
                if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw }
            ) -join "`n")
        WorkDirectory = $work
    }
}

Export-ModuleMember -Function @(
    'Get-RepositoryRoot'
    'Get-RepositoryScriptPath'
    'Get-ScriptFunctionScriptBlock'
    'Import-ReportingModule'
    'Import-ScriptFunction'
    'Use-FakeActiveDirectory'
    'Use-FakePlaceholderModule'
    'Invoke-ScriptUnderTest'
)
