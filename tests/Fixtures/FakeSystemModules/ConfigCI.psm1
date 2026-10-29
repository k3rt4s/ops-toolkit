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
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record each call.
- Set OPSTOOLKIT_TEST_CI_IGNORE_OPTION to a rule option number to make Set-RuleOption accept that option
  and write nothing.

Purpose:
Policy authoring is file work, but a fake still keeps the test from depending on whether the
ConfigCI module loads on the host (it is a Windows PowerShell module) and lets a test read back
what the script asked for: the new policy ID, the audit rule option and the binary path.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeCiMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Set-CIPolicyIdInfo {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$FilePath,
        [string]$PolicyName,
        [string]$PolicyId,
        [switch]$ResetPolicyID
    )
    $newId = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    if ($env:OPSTOOLKIT_TEST_CI_POLICYID) { $newId = $env:OPSTOOLKIT_TEST_CI_POLICYID }
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($FilePath)
    if ($ResetPolicyID) {
        $xml.SiPolicy.PolicyID = $newId
        $xml.SiPolicy.BasePolicyID = $newId
    }
    $xml.Save($FilePath)
    Write-FakeCiMutation -Command 'Set-CIPolicyIdInfo' -Target $FilePath -Detail "name=$PolicyName;reset=$([bool]$ResetPolicyID)"
}

function Set-RuleOption {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$FilePath,
        [int]$Option,
        [switch]$Delete
    )
    $names = @{ 3 = 'Enabled:Audit Mode'; 6 = 'Enabled:Unsigned System Integrity Policy'; 0 = 'Enabled:UMCI' }
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
    $xml.Save($FilePath)
    Write-FakeCiMutation -Command 'Set-RuleOption' -Target $FilePath -Detail "option=$Option;delete=$([bool]$Delete)"
}

function ConvertFrom-CIPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$XmlFilePath,
        [Parameter(Position = 1)][string]$BinaryFilePath
    )
    Set-Content -LiteralPath $BinaryFilePath -Value 'FAKE-CIP-BINARY' -Encoding ascii
    Write-FakeCiMutation -Command 'ConvertFrom-CIPolicy' -Target $BinaryFilePath -Detail $XmlFilePath
    [pscustomobject]@{ BinaryFile = $BinaryFilePath }
}

Export-ModuleMember -Function 'Set-CIPolicyIdInfo', 'Set-RuleOption', 'ConvertFrom-CIPolicy'
