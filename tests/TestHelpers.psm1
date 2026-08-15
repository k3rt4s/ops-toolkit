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

Export-ModuleMember -Function @(
    'Get-RepositoryRoot'
    'Get-RepositoryScriptPath'
    'Get-ScriptFunctionScriptBlock'
    'Import-ReportingModule'
    'Import-ScriptFunction'
)
