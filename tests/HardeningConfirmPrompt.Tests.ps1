#Requires -Modules Pester

# A live run of a hardening script prompts per change unless -Confirm:$false is passed. The real script
# cannot show that in an unelevated session (it skips every admin item before the prompt), so this runs the
# script's own Invoke-PlanItem, cut out of Set-WindowsCredentialProtection.ps1 with the AST, inside a wrapper
# that declares the same CmdletBinding as the script, in a -NonInteractive child where a prompt cannot be
# answered. Elevation is faked and every registry write is a recorder, so nothing real is read or changed:
#   - no -Confirm:$false  -> ShouldProcess prompts, the child fails, no write is recorded, nothing is Applied.
#   - -Confirm:$false     -> the change is applied (recorded).
#   - -WhatIf             -> Previewed, nothing recorded, no prompt.

BeforeAll {
    $script:pwsh = (Get-Process -Id $PID).Path
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-confirmprompt-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:counter = 0

    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    $wanted = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('Invoke-PlanItem', 'Test-PlanItemUnread')
            }, $true))
    $script:functionText = ($wanted | ForEach-Object { $_.Extent.Text }) -join "`n`n"
    $script:bindingText = $ast.ParamBlock.Attributes.Extent.Text | Select-Object -First 1

    function Invoke-PromptChild {
        param([ValidateSet('Live', 'ConfirmFalse', 'WhatIf')][string]$Mode)
        $script:counter++
        $log = Join-Path $script:workRoot "m$($script:counter).log"
        $wrapper = Join-Path $script:workRoot "w$($script:counter).ps1"
        $runner = Join-Path $script:workRoot "r$($script:counter).ps1"
        $head = @"
$($script:bindingText)
param()
`$ErrorActionPreference = 'Stop'
function Test-IsAdministrator { `$true }
function Set-ItemProperty { param(`$Path, `$Name, `$Value, `$Type, [switch]`$Force) [System.IO.File]::AppendAllText('$log', "Set-ItemProperty `$Name`n") }
function New-Item { param(`$Path, [switch]`$Force) [System.IO.File]::AppendAllText('$log', "New-Item `$Path`n") }
function Remove-ItemProperty { param(`$Path, `$Name, `$ErrorAction) [System.IO.File]::AppendAllText('$log', "Remove-ItemProperty `$Name`n") }
function Test-Path { param(`$LiteralPath) `$true }
`$script:ChangedSettings = [System.Collections.ArrayList]::new()
`$Rollback = `$false
"@
        $tail = @'

$item = [pscustomobject]@{
    Category = 'LsaProtection'; Setting = 'RunAsPPL'; RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    DesiredValue = 2; CurrentValue = 'absent'; Action = 'Set RunAsPPL to 2'; RequiresAdmin = $true; RequiresReboot = $true
}
Write-Output ('RESULT=' + (Invoke-PlanItem -Item $item))
'@
        Set-Content -LiteralPath $wrapper -Encoding ascii -Value ($head + "`n" + $script:functionText + "`n" + $tail)
        $call = switch ($Mode) {
            'Live' { "& '$wrapper'" }
            'ConfirmFalse' { "& '$wrapper' -Confirm:`$false" }
            'WhatIf' { "& '$wrapper' -WhatIf" }
        }
        Set-Content -LiteralPath $runner -Encoding ascii -Value $call
        $output = & $script:pwsh -NoProfile -NonInteractive -File $runner 2>&1 | ForEach-Object { "$_" }
        [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = ($output -join "`n")
            Writes = @(if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log })
        }
    }
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) { Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'a live hardening run prompts per change unless -Confirm:$false' {
    It 'extracted the script CmdletBinding and Invoke-PlanItem' {
        $script:bindingText | Should -Match 'ConfirmImpact\s*=\s*.High.'
        $script:functionText | Should -Match 'function Invoke-PlanItem'
    }

    It 'without -Confirm:$false the prompt cannot be answered: the run fails, nothing is written, nothing is Applied' {
        $r = Invoke-PromptChild -Mode Live
        $r.ExitCode | Should -Not -Be 0 -Because $r.Output
        $r.Writes.Count | Should -Be 0
        $r.Output | Should -Not -Match 'RESULT=Applied'
    }

    It 'with -Confirm:$false it applies the change' {
        $r = Invoke-PromptChild -Mode ConfirmFalse
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'RESULT=Applied'
        $r.Writes | Should -Contain 'Set-ItemProperty RunAsPPL'
    }

    It 'under -WhatIf it previews and writes nothing' {
        $r = Invoke-PromptChild -Mode WhatIf
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'RESULT=Previewed'
        $r.Writes.Count | Should -Be 0
    }
}
