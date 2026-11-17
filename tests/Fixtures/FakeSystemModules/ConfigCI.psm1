<#
.SYNOPSIS
Stand-in for the ConfigCI module so scripts that author Windows Defender Application Control policy only touch files they are given.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- The functions edit only the policy XML or binary path they are passed, which is the
  behaviour of the real cmdlets, so a script can build its policy artifacts under test. None of
  them changes the machine; applying a policy is CiTool.exe's job and is stubbed by the test.
- Importing it while the global WhatIfPreference is on throws, the way the real module's
  compatibility-layer load fails under -WhatIf. A script must clear the preference at script scope
  (a function-local copy does not reach the module) for the import, then restore it. The fault shows
  only when the script is the process's own `pwsh -File script -WhatIf` entry point, so a test must
  start pwsh -File directly; the & runner used by Invoke-OpsWindowsScriptPair never sets it.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record each call.
- Set OPSTOOLKIT_TEST_CI_UNAVAILABLE to any value to make the import fail, as on a host without the module.
- Set OPSTOOLKIT_TEST_CI_IGNORE_OPTION to a rule option number to make Set-RuleOption accept that option
  and write nothing (add or delete).
- New-CIPolicy writes a base-format policy with OPSTOOLKIT_TEST_CI_ALLOW_COUNT allow rules (default 2).
  OPSTOOLKIT_TEST_CI_NEWPOLICY_FAIL makes it throw; OPSTOOLKIT_TEST_CI_NEWPOLICY_AUDIT_OPTION writes the
  Audit Mode rule option into what it builds.

Purpose:
Policy authoring is file work, but a fake still keeps the test from depending on whether the
ConfigCI module loads on the host (it is a Windows PowerShell module) and lets a test read back
what the script asked for: the new policy ID, the audit rule option and the binary path.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

# The real module loads in PowerShell 7 through the Windows PowerShell compatibility layer, whose proxy
# module copies a file as it loads. Under -WhatIf that Copy-Item is suppressed and the load fails
# (seen 2026-11-01), so a script that leaves ConfigCI to auto-load cannot find the cmdlets in a
# preview. This stand-in fails the same way: it creates an alias at import with a top-level
# Set-Alias, which -WhatIf suppresses, and refuses to load when the alias is missing. A module scope
# reads the global preference, so it fails only when the global WhatIfPreference is true at import.
Set-Alias -Name Read-FakeCiMarker -Value Write-FakeCiMutation
if ($env:OPSTOOLKIT_TEST_CI_UNAVAILABLE) { throw 'ConfigCI is unavailable (fake, OPSTOOLKIT_TEST_CI_UNAVAILABLE).' }
if (-not (Get-Alias -Name Read-FakeCiMarker -ErrorAction SilentlyContinue)) {
    throw 'ConfigCI import-time action suppressed under -WhatIf (fake of the compatibility-layer proxy Copy-Item).'
}

function Write-FakeCiMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Set-CIPolicyIdInfo {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$FilePath,
        [string]$PolicyName,
        [string]$PolicyId,
        [string]$SupplementsBasePolicyID,
        [switch]$ResetPolicyID
    )
    $newId = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    if ($env:OPSTOOLKIT_TEST_CI_POLICYID) { $newId = $env:OPSTOOLKIT_TEST_CI_POLICYID }
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($FilePath)
    if ($SupplementsBasePolicyID) {
        # A supplemental policy keeps its own PolicyID and names the base it supplements.
        $xml.SiPolicy.SetAttribute('PolicyType', 'Supplemental Policy')
        $xml.SiPolicy.BasePolicyID = $SupplementsBasePolicyID
        if ($ResetPolicyID) { $xml.SiPolicy.PolicyID = $newId }
    } elseif ($ResetPolicyID) {
        $xml.SiPolicy.PolicyID = $newId
        $xml.SiPolicy.BasePolicyID = $newId
    }
    $xml.Save($FilePath)
    Write-FakeCiMutation -Command 'Set-CIPolicyIdInfo' -Target $FilePath -Detail "name=$PolicyName;reset=$([bool]$ResetPolicyID);supplements=$SupplementsBasePolicyID"
    # The real cmdlet writes the new ID to the pipeline as one string (checked on Windows PowerShell
    # 5.1, 2026-11-02), so a caller that does not discard it returns that string as well.
    if ($ResetPolicyID) { "PolicyID = $newId" }
}

function Set-RuleOption {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$FilePath,
        [int]$Option,
        [switch]$Delete
    )
    $names = @{
        3 = 'Enabled:Audit Mode'; 6 = 'Enabled:Unsigned System Integrity Policy'; 0 = 'Enabled:UMCI'
        9 = 'Enabled:Advanced Boot Options Menu'; 10 = 'Enabled:Boot Audit on Failure'; 17 = 'Enabled:Allow Supplemental Policies'
    }
    # Simulates a cmdlet that reports success without writing the option, so a script's own check can be tested.
    if ($env:OPSTOOLKIT_TEST_CI_IGNORE_OPTION -and "$Option" -eq $env:OPSTOOLKIT_TEST_CI_IGNORE_OPTION) {
        Write-FakeCiMutation -Command 'Set-RuleOption' -Target $FilePath -Detail "option=$Option;delete=$([bool]$Delete);ignored=True"
        return
    }
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($FilePath)
    $ns = $xml.DocumentElement.NamespaceURI
    $text = $names[$Option]
    $present = $false
    foreach ($rule in @($xml.SiPolicy.Rules.Rule)) { if ($rule.Option -eq $text) { $present = $true } }
    if (-not $Delete -and -not $present) {
        $rule = $xml.CreateElement('Rule', $ns)
        $optionNode = $xml.CreateElement('Option', $ns)
        $optionNode.InnerText = $text
        [void]$rule.AppendChild($optionNode)
        [void]$xml.SiPolicy.Rules.AppendChild($rule)
    }
    if ($Delete) {
        # Like the real cmdlet, -Delete removes the rule option when it is present.
        foreach ($rule in @($xml.SiPolicy.Rules.Rule)) {
            if ($rule.Option -eq $text) { [void]$xml.SiPolicy.Rules.RemoveChild($rule) }
        }
    }
    $xml.Save($FilePath)
    Write-FakeCiMutation -Command 'Set-RuleOption' -Target $FilePath -Detail "option=$Option;delete=$([bool]$Delete)"
}

function New-CIPolicy {
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [string]$Level,
        [string[]]$Fallback,
        [switch]$UserPEs,
        [switch]$Audit,
        [switch]$MultiplePolicyFormat
    )
    # Stands in for building a policy from the Code Integrity audit events. The number of allow rules
    # comes from OPSTOOLKIT_TEST_CI_ALLOW_COUNT (default 2); OPSTOOLKIT_TEST_CI_NEWPOLICY_FAIL makes the
    # call throw, as the real cmdlet does when it finds nothing to build from; and
    # OPSTOOLKIT_TEST_CI_NEWPOLICY_AUDIT_OPTION writes the Audit Mode rule option into the policy.
    Write-FakeCiMutation -Command 'New-CIPolicy' -Target $FilePath -Detail "level=$Level;fallback=$($Fallback -join ',');audit=$([bool]$Audit);userpes=$([bool]$UserPEs);multi=$([bool]$MultiplePolicyFormat)"
    if ($env:OPSTOOLKIT_TEST_CI_NEWPOLICY_FAIL) { throw 'New-CIPolicy found no audit events to build a policy from (fake, OPSTOOLKIT_TEST_CI_NEWPOLICY_FAIL).' }
    $count = 2
    if ($env:OPSTOOLKIT_TEST_CI_ALLOW_COUNT) { $count = [int]$env:OPSTOOLKIT_TEST_CI_ALLOW_COUNT }
    $id = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    $auditRule = ''
    if ($env:OPSTOOLKIT_TEST_CI_NEWPOLICY_AUDIT_OPTION) { $auditRule = '<Rule><Option>Enabled:Audit Mode</Option></Rule>' }
    $allow = (@(if ($count -gt 0) { 1..$count }) | ForEach-Object { '<Allow ID="ID_ALLOW_A_' + $_ + '" FriendlyName="fake hash ' + $_ + '" Hash="00"/>' }) -join ''
    $text = '<?xml version="1.0" encoding="utf-8"?><SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy"><VersionEx>10.0.0.0</VersionEx><PolicyID>' + $id + '</PolicyID><BasePolicyID>' + $id + '</BasePolicyID><Rules><Rule><Option>Enabled:UMCI</Option></Rule>' + $auditRule + '</Rules><FileRules>' + $allow + '</FileRules></SiPolicy>'
    Set-Content -LiteralPath $FilePath -Value $text -Encoding utf8 -WhatIf:$false
}

function ConvertFrom-CIPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$XmlFilePath,
        [Parameter(Position = 1)][string]$BinaryFilePath
    )
    Set-Content -LiteralPath $BinaryFilePath -Value 'FAKE-CIP-BINARY' -Encoding ascii -WhatIf:$false
    Write-FakeCiMutation -Command 'ConvertFrom-CIPolicy' -Target $BinaryFilePath -Detail $XmlFilePath
    [pscustomobject]@{ BinaryFile = $BinaryFilePath }
}

Export-ModuleMember -Function 'Set-CIPolicyIdInfo', 'Set-RuleOption', 'ConvertFrom-CIPolicy', 'New-CIPolicy'
