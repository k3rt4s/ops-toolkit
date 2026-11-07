#Requires -Modules Pester

# Static contract for every script that defines Invoke-PlanItem: the function (and any other nested function that
# calls $PSCmdlet.ShouldProcess) declares the same ConfirmImpact as its script's own CmdletBinding. A function
# left at the default Medium never prompts at the default $ConfirmPreference (High), so a live run without
# -Confirm:$false would change the machine with no per-change prompt. Parsed with the AST; nothing is run.

BeforeDiscovery {
    $root = Split-Path -Parent $PSScriptRoot
    $script:targets = @(Get-ChildItem -Path (Join-Path $root 'scripts') -Recurse -Filter '*.ps1' |
            Where-Object { Select-String -LiteralPath $_.FullName -Pattern '^function Invoke-PlanItem\b' -Quiet } |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    $script:targetCount = @(Get-ChildItem -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') -Recurse -Filter '*.ps1' |
            Where-Object { Select-String -LiteralPath $_.FullName -Pattern '^function Invoke-PlanItem\b' -Quiet }).Count

    function Get-ConfirmImpact {
        # The ConfirmImpact named in a CmdletBinding attribute, or 'Medium' (the default) when it names none.
        param($AttributeList)
        foreach ($attribute in $AttributeList) {
            if ($attribute.TypeName.Name -ne 'CmdletBinding') { continue }
            foreach ($named in $attribute.NamedArguments) {
                if ($named.ArgumentName -eq 'ConfirmImpact') { return $named.Argument.Extent.Text.Trim("'", '"') }
            }
            return 'Medium'
        }
        return $null
    }

    function Get-PlanItemContract {
        param([string]$Path)
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        $scriptImpact = Get-ConfirmImpact -AttributeList $ast.ParamBlock.Attributes
        $functions = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                ($node.Name -eq 'Invoke-PlanItem' -or $node.Body.FindAll({
                            param($inner)
                            $inner -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                            $inner.Member.Value -eq 'ShouldProcess'
                        }, $true).Count -gt 0)
            }, $true)
        $rows = foreach ($function in $functions) {
            [pscustomobject]@{
                Function = $function.Name
                Impact = Get-ConfirmImpact -AttributeList $function.Body.ParamBlock.Attributes
            }
        }
        [pscustomobject]@{ ScriptImpact = $scriptImpact; Functions = @($rows) }
    }
}

Describe 'Invoke-PlanItem ConfirmImpact contract' {
    It 'finds the fourteen scripts that define Invoke-PlanItem' {
        $script:targetCount | Should -Be 14
    }

    It '<Name> declares ConfirmImpact High on its script' -ForEach $script:targets {
        (Get-PlanItemContract -Path $Path).ScriptImpact | Should -Be 'High'
    }

    It '<Name> gives Invoke-PlanItem and every ShouldProcess caller the script ConfirmImpact' -ForEach $script:targets {
        $contract = Get-PlanItemContract -Path $Path
        @($contract.Functions | Where-Object { $_.Function -eq 'Invoke-PlanItem' }).Count | Should -Be 1
        foreach ($function in $contract.Functions) {
            $function.Impact | Should -Be $contract.ScriptImpact -Because "$($function.Function) in $Name must match the script"
        }
    }
}
