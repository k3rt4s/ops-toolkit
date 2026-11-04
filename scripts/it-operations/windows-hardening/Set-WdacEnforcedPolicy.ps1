<#
.SYNOPSIS
Build reviewable allow rules from Windows Defender Application Control audit events, then enforce the toolkit's audit-mode base policy with them through a supplemental policy, or roll that back to audit mode; built and tested against fakes only.

.DESCRIPTION
Instructions:
- WARNING: this script was built and tested against fakes only. It has never been run on a real
  machine. A wrong enforced application control policy can stop a machine from starting normally
  or stop the tools people need from running. Try it first in a disposable virtual machine, or on
  a virtual desktop test host (an Azure Virtual Desktop session host that can be rebuilt), and
  only then on a physical Windows 11 machine you can reimage. Never run it on a machine that
  holds the only copy of anything.
- It is the reviewed path from the audit-only base policy that Set-WdacAuditPolicy.ps1 deploys to
  an enforced one. That script keeps no enforce switch; this one is separate on purpose, has its
  own rollback, and nothing else in the toolkit calls it.
- Three steps, each a separate run, with a person in between:
  1. -Mode BuildAllowRules builds a supplemental allow-rules policy from this machine's Code
     Integrity audit events and writes the XML to the report directory. It deploys nothing.
  2. A person reads that XML, removes what should not be allowed, and keeps the file.
  3. -Mode Enforce -AllowRulesPolicyPath <that reviewed XML> deploys the supplemental policy and
     then redeploys the toolkit base policy with Audit Mode removed, keeping its policy ID.
  -Rollback undoes step 3.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  workstation must never be applied to someone else's machine. -AuditReportDirectory is the
  report directory Set-WdacAuditPolicy.ps1 was run with. The script reads its newest unconsumed
  wdac-audit-rollback-<timestamp>.json there, which holds the ID and policy XML of the audit
  base, and never reads or changes that file.
- Run with -WhatIf first and review the generated plan CSV/JSON. Under -WhatIf the script still
  builds its policy files (XML and binary) in the report directory so you can inspect exactly
  what would be deployed; it deploys and removes nothing. Run elevated to deploy. A non-elevated
  live run marks each deploy step 'Skipped: requires elevation'. Run it in PowerShell 7.4 or
  later (the toolkit's reporting module requires it; the script does not start in Windows
  PowerShell 5.1). Policy authoring uses the ConfigCI cmdlets, which PowerShell 7 loads through
  the Windows PowerShell compatibility layer. The script imports ConfigCI itself, also under
  -WhatIf, because the compatibility layer's automatic load fails when -WhatIf suppresses the
  file copy it makes.
- -CiToolPath names the CiTool program the script runs (default CiTool.exe). Point it at another
  executable or script to run the plan against a stand-in that never touches the machine's
  policies; the script still reads and changes policy only through that program.
- BuildAllowRules source: New-CIPolicy -Audit -Level Publisher -Fallback Hash -UserPEs
  -MultiplePolicyFormat, then Set-CIPolicyIdInfo -SupplementsBasePolicyID <audit base ID>
  -ResetPolicyID, and Audit Mode (option 3) removed if present because a supplemental policy
  follows its base. -Audit makes New-CIPolicy build from the Code Integrity audit events instead
  of scanning the disk, so the rules cover what actually ran while the audit base was active.
  Publisher level allows everything signed by a certificate chain and publisher the events
  recorded, which is conservative (narrower than a whole-vendor rule, broader than a single
  file); a file with no usable signature falls back to a file hash rule. This script does not
  read Export-WdacAuditEvent.ps1 output for this, because that report carries paths and
  publisher names only, from which a valid rule cannot be written; use it to review the
  generated XML instead. No events found, or no rules in the result, is a failed build, not an
  empty pass. The generated rules are only as good as the audit period behind them: review a
  period that includes the monthly patch cycle and everything the machine is used for.
- Enforce refuses unless every one of these holds, and a refusal changes nothing, also under
  -WhatIf: an operator-supplied -AllowRulesPolicyPath that parses as a supplemental policy for
  the audit base's ID, carries at least one rule, and does not carry Audit Mode; the audit base
  record and its XML are readable, name 'ops-toolkit WDAC audit', and the XML is still in audit
  mode; the active policy list can be read (an unreadable list refuses, it is never a pass); the
  audit base is active under that exact name and does not already report as enforced; the base
  has option 17 (Allow Supplemental Policies); the base carries options 9 (Advanced Boot Options
  Menu) and 10 (Boot Audit on Failure), so a machine whose enforced policy blocks a boot driver
  can still be started; no supplemental policy named 'ops-toolkit WDAC allow rules' or with the
  reviewed file's ID is already active; and the enforced base built here has Audit Mode removed
  and everything else kept. Options 9, 10 and 17 are added by Set-WdacAuditPolicy.ps1 when it
  builds the audit base, never here, so a base deployed by an older version is refused: roll it
  back there and deploy it again.
- The two changes are, in this order: CiTool.exe --update-policy <supplemental.cip> --json, then
  CiTool.exe --update-policy <enforced base.cip> --json. The base is only touched if the
  supplemental policy deployed. The base is rebuilt from the audit XML that Set-WdacAuditPolicy.ps1
  recorded, with Set-RuleOption -Option 3 -Delete, and nothing else is changed: same policy ID, same
  name. Option 3 is removed only from that policy, never from any other. The reviewed file is
  copied into the report directory and given the name 'ops-toolkit WDAC allow rules' through
  Set-CIPolicyIdInfo -PolicyName, so the policy can be recognised in the active list; its rules
  are not edited. A restart may be needed for the enforced policy to take full effect.
- -Rollback puts the base back to audit mode and removes the supplemental policy this script
  deployed. It redeploys an audit-mode copy of the base that Enforce saved in the report
  directory (checked against a SHA-256 recorded at deploy time), and only then runs
  CiTool.exe --remove-policy <supplemental ID>, so the machine is never left enforcing a base
  with its supplemental rules gone. If the first step fails the second is skipped. The base
  policy is never removed by this script; remove it with Set-WdacAuditPolicy.ps1 -Rollback
  afterwards, if wanted. Before any plan is written or any change made, the whole rollback file is
  checked and refused, also under -WhatIf, with an error naming the file and the first bad entry
  (or the top-level fields), when the JSON does not parse, ChangedSettings is missing, not an
  array or empty, or any record has a policy name other than the two this script uses, an ID that
  is not a GUID, a .cip name that is not the one this script builds for that ID, a bad SHA-256, or
  a value that differs from the file's top level. A policy with a recorded ID that is active under
  any other name is refused too: it is not this script's. If the active policy list cannot be
  read, nothing is changed and the file is left unconsumed. The newest rollback file by name is
  used, and after an executing run in which every item was reverted or needed no change it is
  renamed wdac-enforce-rollback-<timestamp>.consumed-<timestamp>.json. Under -WhatIf, or when any
  item failed or was skipped, it is left in place. Move a refused file aside to roll back an
  older run.
- Order when undoing everything: this script's -Rollback first, then Set-WdacAuditPolicy.ps1
  -Rollback. The other way round removes the base and leaves the supplemental policy active
  without one.
- References (Microsoft Learn, read from memory of the page names, not re-read when this was
  written, so check them): App Control for Business, "Understand App Control policy rules and
  file rules" (policy rule options 3, 9, 10 and 17); "Use multiple App Control policies"
  (supplemental policies, which attach to one base by its ID and need option 17 in the base);
  "Create an App Control policy from audit events" and the ConfigCI New-CIPolicy reference
  (-Audit, -Level, -Fallback, -UserPEs, -MultiplePolicyFormat); "CiTool commands"
  (--update-policy, --remove-policy, --list-policies, --json).

Purpose:
Application control is the strongest control against unknown code on a workstation, and the one
most likely to break the machine if enforced blind. Audit mode shows what it would break; this is
the reviewed, reversible step after that.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -AuditReportDirectory <audit dir> -Mode BuildAllowRules -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -AuditReportDirectory <audit dir> -Mode BuildAllowRules   # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -AuditReportDirectory <audit dir> -Mode Enforce -AllowRulesPolicyPath <reviewed.xml> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -AuditReportDirectory <audit dir> -Mode Enforce -AllowRulesPolicyPath <reviewed.xml>   # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -Rollback -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1 -ReportDirectory <dir> -Rollback   # elevated

.OUTPUTS
Writes plan and state CSV/JSON, the policy XML and binary files, and on a live run that deployed a
policy a rollback JSON holding both policy IDs and the audit-restore binary's name and hash, all
under the report directory. Returns a summary object.

.NOTES
Status:
Active script in the ops-toolkit repo, tested against fakes only. Companion to
Set-WdacAuditPolicy.ps1 and Export-WdacAuditEvent.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Apply')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [ValidateSet('BuildAllowRules', 'Enforce')]
    [string]$Mode,

    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [ValidateNotNullOrEmpty()]
    [string]$AuditReportDirectory,

    [Parameter(ParameterSetName = 'Apply')]
    [ValidateNotNullOrEmpty()]
    [string]$AllowRulesPolicyPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [switch]$Rollback,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CiToolPath = 'CiTool.exe',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$script:Prefix = 'wdac-enforce'
$script:AuditPrefix = 'wdac-audit'
# The CiTool program every policy read and change goes through (-CiToolPath; default CiTool.exe).
$script:CiToolCommand = $CiToolPath
# The names Set-WdacAuditPolicy.ps1 gives its base and this script gives its supplemental policy.
$script:BaseName = 'ops-toolkit WDAC audit'
$script:SupplementalName = 'ops-toolkit WDAC allow rules'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:StopReason = $null
$script:PreconditionResult = @{}
$script:Artifact = $null
$script:RollbackSourceFile = $null
$script:RollbackCategories = @('DeploySupplementalPolicy', 'EnforceBasePolicy')
$script:RequiredOption = @{
    3 = 'Enabled:Audit Mode'
    6 = 'Enabled:Unsigned System Integrity Policy'
    9 = 'Enabled:Advanced Boot Options Menu'
    10 = 'Enabled:Boot Audit on Failure'
    17 = 'Enabled:Allow Supplemental Policies'
}

if ($PSCmdlet.ParameterSetName -eq 'Apply') {
    $script:AuditDirectory = $AuditReportDirectory
    if ($Mode -eq 'Enforce' -and [string]::IsNullOrWhiteSpace($AllowRulesPolicyPath)) {
        throw '-Mode Enforce requires -AllowRulesPolicyPath, the allow-rules XML a person reviewed (build it with -Mode BuildAllowRules). Nothing was changed.'
    }
    if ($Mode -eq 'BuildAllowRules' -and -not [string]::IsNullOrWhiteSpace($AllowRulesPolicyPath)) {
        throw '-AllowRulesPolicyPath applies to -Mode Enforce only; -Mode BuildAllowRules writes the file for review. Nothing was changed.'
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PlanItem {
    param(
        [string]$Category, [string]$Setting, [bool]$RequiresAdmin,
        $CurrentValue, $DesiredValue, [string]$Action
    )
    [pscustomobject]@{
        Category = $Category; Setting = $Setting; RequiresAdmin = $RequiresAdmin
        RequiresReboot = $false
        CurrentValue = "$CurrentValue"; DesiredValue = "$DesiredValue"; Action = $Action
        Detail = ''
    }
}

function ConvertTo-BarePolicyId {
    param([string]$Id)
    $Id.Trim().Trim('{', '}').ToLowerInvariant()
}

# Reads the active policy list. Unreadable is reported as such and never treated as empty.
function Get-ActivePolicyList {
    $result = [pscustomobject]@{ Readable = $false; Reason = ''; Policies = @() }
    if (-not (Get-Command -Name $script:CiToolCommand -ErrorAction SilentlyContinue)) {
        $result.Reason = 'CiTool.exe was not found (it ships with Windows 11 and Windows Server 2025)'
        return $result
    }
    try {
        $text = (& $script:CiToolCommand --list-policies --json 2>&1 | Out-String)
        $json = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $result.Reason = "CiTool --list-policies output could not be parsed: $($_.Exception.Message)"
        return $result
    }
    $op = Get-OpsPropertyValue -InputObject $json -Name 'OperationResult'
    if ($null -ne $op -and [int64]$op -ne 0) {
        $result.Reason = ('CiTool --list-policies returned OperationResult 0x{0:X8}' -f ([int64]$op -band 0xFFFFFFFF))
        return $result
    }
    $result.Readable = $true
    $result.Policies = @(Get-OpsPropertyValue -InputObject $json -Name 'Policies') | Where-Object { $_ }
    $result.Policies = @($result.Policies)
    $result
}

# Loads ConfigCI explicitly. Left to auto-load, the Windows PowerShell compatibility layer's proxy
# module copies a file as it loads, and under -WhatIf that Copy-Item is suppressed and the load
# fails. The preference is cleared at script scope, not function scope: the module's own import-time
# actions read the global preference (checked against the real module). Returns $null on success,
# otherwise the failure text; the caller still tests for the cmdlets, so a failed import is never
# read as a pass.
function Import-ConfigCIModule {
    $savedWhatIf = $WhatIfPreference
    $script:WhatIfPreference = $false
    try {
        Import-Module -Name ConfigCI -Global -ErrorAction Stop
    } catch {
        return ($_.Exception.Message -replace '\s+', ' ')
    } finally {
        $script:WhatIfPreference = $savedWhatIf
    }
    $null
}

# Reads what the plan needs from a policy XML file, with no DTD or external resolution because the
# file may come from a person. Ok is false, with a Reason, for anything that is not a readable SiPolicy.
function Read-PolicyXml {
    param([string]$Path)
    $r = [pscustomobject]@{ Ok = $false; Reason = ''; PolicyType = ''; PolicyId = ''; BasePolicyId = ''; Options = @(); RuleCount = 0 }
    try {
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create($Path, $settings)
        try {
            $doc = New-Object System.Xml.XmlDocument
            $doc.XmlResolver = $null
            $doc.Load($reader)
        } finally {
            $reader.Dispose()
        }
    } catch {
        $r.Reason = "could not be read as XML: $($_.Exception.Message -replace '\s+', ' ')"
        return $r
    }
    $root = $doc.DocumentElement
    if ($null -eq $root -or $root.LocalName -cne 'SiPolicy') {
        $r.Reason = 'its root element is not SiPolicy'
        return $r
    }
    $r.PolicyType = [string]$root.GetAttribute('PolicyType')
    $idNode = $doc.SelectSingleNode("/*[local-name()='SiPolicy']/*[local-name()='PolicyID']")
    $baseNode = $doc.SelectSingleNode("/*[local-name()='SiPolicy']/*[local-name()='BasePolicyID']")
    if ($null -ne $idNode) { $r.PolicyId = [string]$idNode.InnerText }
    if ($null -ne $baseNode) { $r.BasePolicyId = [string]$baseNode.InnerText }
    $r.Options = @($doc.SelectNodes("/*[local-name()='SiPolicy']/*[local-name()='Rules']/*[local-name()='Rule']/*[local-name()='Option']") | ForEach-Object { [string]$_.InnerText })
    $r.RuleCount = @($doc.SelectNodes("//*[local-name()='FileRules']/*[local-name()='Allow'] | //*[local-name()='AllowedSigners']/*[local-name()='AllowedSigner']")).Count
    $r.Ok = $true
    $r
}

function Test-PolicyGuid {
    param($Text)
    ($Text -is [string]) -and ($Text -match '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\z')
}

# The newest file in a directory for a prefix, by exact name. A '.consumed-' file and a '-rollback-plan-'
# file do not match.
function Get-LatestRollbackFileIn {
    param([string]$Directory, [string]$FilePrefix)
    if (-not (Test-Path -LiteralPath $Directory)) { return $null }
    $pattern = '^' + [regex]::Escape($FilePrefix) + '-rollback-\d{8}_\d{6}\.json$'
    Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# Finds and checks the audit base Set-WdacAuditPolicy.ps1 recorded: newest unconsumed rollback file,
# the toolkit policy name, a GUID ID, and the policy XML it names (taken from the audit directory by
# file name only, so a record cannot point this script at another path). The XML must be a base policy
# with that ID that is still in audit mode and unsigned. Pure reads.
function Get-AuditBaseRecord {
    $r = [pscustomobject]@{ Ok = $false; Reason = ''; File = $null; PolicyId = ''; XmlPath = ''; Options = @() }
    if (-not (Test-Path -LiteralPath $script:AuditDirectory -PathType Container)) {
        $r.Reason = "the audit report directory '$script:AuditDirectory' was not found"
        return $r
    }
    $file = Get-LatestRollbackFileIn -Directory $script:AuditDirectory -FilePrefix $script:AuditPrefix
    if (-not $file) {
        $r.Reason = "no unconsumed $($script:AuditPrefix)-rollback-<timestamp>.json in '$script:AuditDirectory'; run Set-WdacAuditPolicy.ps1 live first, with that report directory"
        return $r
    }
    $r.File = $file
    try {
        $data = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $r.Reason = "$($file.Name) could not be read as JSON ($($_.Exception.Message -replace '\s+', ' '))"
        return $r
    }
    if ($null -eq $data -or $data -isnot [pscustomobject]) { $r.Reason = "$($file.Name) is not a JSON object"; return $r }
    foreach ($field in 'PolicyName', 'PolicyId', 'XmlPath') {
        if (-not $data.PSObject.Properties[$field] -or $data.$field -isnot [string]) { $r.Reason = "$($file.Name) has no string $field"; return $r }
    }
    if ($data.PolicyName -cne $script:BaseName) { $r.Reason = "$($file.Name) names policy '$($data.PolicyName)', not '$($script:BaseName)'"; return $r }
    if (-not (Test-PolicyGuid $data.PolicyId)) { $r.Reason = "$($file.Name) has a PolicyId that is not a GUID"; return $r }
    $xmlName = [System.IO.Path]::GetFileName($data.XmlPath)
    if ($xmlName -cnotmatch ('^' + [regex]::Escape($script:AuditPrefix) + '-policy-\d{8}_\d{6}\.xml\z')) {
        $r.Reason = "$($file.Name) names an XmlPath that is not a $($script:AuditPrefix)-policy-<timestamp>.xml the audit script writes"
        return $r
    }
    $r.PolicyId = [string]$data.PolicyId
    $r.XmlPath = Join-Path $script:AuditDirectory $xmlName
    if (-not (Test-Path -LiteralPath $r.XmlPath -PathType Leaf)) { $r.Reason = "the audit policy XML $($r.XmlPath) was not found"; return $r }
    $info = Read-PolicyXml -Path $r.XmlPath
    if (-not $info.Ok) { $r.Reason = "the audit policy XML $($r.XmlPath) $($info.Reason)"; return $r }
    if ($info.PolicyType -ceq 'Supplemental Policy') { $r.Reason = 'the audit policy XML is a supplemental policy, not a base'; return $r }
    if ((ConvertTo-BarePolicyId $info.PolicyId) -ne (ConvertTo-BarePolicyId $r.PolicyId)) { $r.Reason = "the audit policy XML has policy ID $($info.PolicyId), not the recorded $($r.PolicyId)"; return $r }
    if ($info.Options -notcontains $script:RequiredOption[3]) { $r.Reason = 'the audit policy XML does not carry Audit Mode (option 3), so it is not the audit-mode policy this script moves to enforcement'; return $r }
    if ($info.Options -notcontains $script:RequiredOption[6]) { $r.Reason = 'the audit policy XML does not carry the Unsigned System Integrity Policy option (6)'; return $r }
    $r.Options = @($info.Options)
    $r.Ok = $true
    $r
}

# Builds the supplemental allow-rules XML from the Code Integrity audit events, in the report directory.
# Plan-artifact work on files in the run folder only, so it also runs under -WhatIf.
function Initialize-AllowRulesArtifact {
    param([string]$BaseId, [string]$Directory, [string]$Stamp)

    $WhatIfPreference = $false
    $xmlPath = Join-Path $Directory "$($script:Prefix)-allow-rules-$Stamp.xml"
    # Output is discarded: the cmdlets write status objects and strings, and the artifact must stay one object.
    $null = New-CIPolicy -FilePath $xmlPath -Level Publisher -Fallback Hash -UserPEs -Audit -MultiplePolicyFormat -ErrorAction Stop
    $null = Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName $script:SupplementalName -SupplementsBasePolicyID $BaseId -ResetPolicyID
    # A supplemental policy follows its base's mode; the option is not valid in one.
    $null = Set-RuleOption -FilePath $xmlPath -Option 3 -Delete

    $info = Read-PolicyXml -Path $xmlPath
    if (-not $info.Ok) { throw "the generated allow-rules policy $($info.Reason)" }
    if ($info.PolicyType -cne 'Supplemental Policy') { throw "the generated allow-rules policy is '$($info.PolicyType)', not a Supplemental Policy; refusing to continue." }
    if ((ConvertTo-BarePolicyId $info.BasePolicyId) -ne (ConvertTo-BarePolicyId $BaseId)) { throw "the generated allow-rules policy supplements $($info.BasePolicyId), not the audit base $BaseId; refusing to continue." }
    if ((ConvertTo-BarePolicyId $info.PolicyId) -eq (ConvertTo-BarePolicyId $BaseId) -or -not (Test-PolicyGuid $info.PolicyId)) { throw 'the generated allow-rules policy has no ID of its own; refusing to continue.' }
    if ($info.Options -contains $script:RequiredOption[3]) { throw 'the generated allow-rules policy still carries Audit Mode; refusing to continue.' }
    if ($info.RuleCount -lt 1) { throw 'the audit events produced no allow rules, so there is nothing to review; let the audit base run longer, or check the Code Integrity log.' }
    [pscustomobject]@{ XmlPath = $xmlPath; PolicyId = $info.PolicyId; RuleCount = $info.RuleCount }
}

function Get-BuildPlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $admin = Test-IsAdministrator
    $ciImportError = Import-ConfigCIModule
    $ciCmdlets = [bool]((Get-Command -Name 'New-CIPolicy' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Set-CIPolicyIdInfo' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Set-RuleOption' -ErrorAction SilentlyContinue))
    $audit = Get-AuditBaseRecord
    $pre = $script:PreconditionResult

    $pre['Elevated'] = if ($admin) { 'Met' } else { 'Skipped: requires elevation' }
    $pre['ConfigCI'] = if ($ciCmdlets) { 'Met' } else { "Failed: the ConfigCI cmdlets (New-CIPolicy, Set-CIPolicyIdInfo, Set-RuleOption) are not available$(if ($ciImportError) { " (importing ConfigCI said: $ciImportError)" }); run this script in PowerShell 7.4 or later, which loads ConfigCI through the Windows PowerShell compatibility layer" }
    $pre['AuditBaseRecord'] = if ($audit.Ok) { 'Met' } else { "Failed: $($audit.Reason)" }
    $pre['AllowsSupplementalPolicies'] = if (-not $audit.Ok) { 'Failed: not checked, the audit base record is not usable' } elseif ($audit.Options -contains $script:RequiredOption[17]) { 'Met' } else { 'Failed: the audit base does not carry option 17 (Allow Supplemental Policies), so rules built now could not be attached; roll it back with Set-WdacAuditPolicy.ps1 and deploy it again' }
    $pre['BootSafetyOptions'] = if (-not $audit.Ok) { 'Failed: not checked, the audit base record is not usable' } elseif (($audit.Options -contains $script:RequiredOption[9]) -and ($audit.Options -contains $script:RequiredOption[10])) { 'Met' } else { 'Failed: the audit base lacks option 9 (Advanced Boot Options Menu) or 10 (Boot Audit on Failure), which an enforced policy must carry; roll it back with Set-WdacAuditPolicy.ps1 and deploy it again' }

    $pre['AllowRulesBuilt'] = 'Failed: not built'
    if ($audit.Ok -and $ciCmdlets -and $pre['AllowsSupplementalPolicies'] -eq 'Met' -and $pre['BootSafetyOptions'] -eq 'Met') {
        try {
            $script:Artifact = Initialize-AllowRulesArtifact -BaseId $audit.PolicyId -Directory $resolvedReportDirectory -Stamp $timestamp
            $pre['AllowRulesBuilt'] = 'Met'
        } catch {
            $pre['AllowRulesBuilt'] = "Failed: building the allow rules failed: $($_.Exception.Message -replace '\s+', ' ')$(if (-not $admin) { ' (reading the audit events usually needs an elevated session)' })"
        }
    } else {
        $pre['AllowRulesBuilt'] = 'Failed: not built, a precondition above did not hold'
    }

    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false -CurrentValue $admin -DesiredValue 'True' -Action 'Precondition: session is elevated (New-CIPolicy -Audit reads the Code Integrity log)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'ConfigCI' -RequiresAdmin $false -CurrentValue $ciCmdlets -DesiredValue 'True' -Action 'Precondition: ConfigCI policy cmdlets are available'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'AuditBaseRecord' -RequiresAdmin $false -CurrentValue $audit.Ok -DesiredValue 'True' -Action "Precondition: the audit base recorded by Set-WdacAuditPolicy.ps1 in $script:AuditDirectory is usable"))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'AllowsSupplementalPolicies' -RequiresAdmin $false -CurrentValue ($pre['AllowsSupplementalPolicies'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: the audit base carries option 17 (Allow Supplemental Policies)'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'BootSafetyOptions' -RequiresAdmin $false -CurrentValue ($pre['BootSafetyOptions'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: the audit base carries options 9 and 10, the boot safety options'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'AllowRulesBuilt' -RequiresAdmin $false -CurrentValue ($pre['AllowRulesBuilt'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: a supplemental allow-rules policy was built from the audit events and has at least one rule'))

    $path = if ($script:Artifact) { $script:Artifact.XmlPath } else { '(not built)' }
    $count = if ($script:Artifact) { $script:Artifact.RuleCount } else { 0 }
    $item = Get-PlanItem -Category 'BuildAllowRules' -Setting $script:SupplementalName -RequiresAdmin $false `
        -CurrentValue 'not built' -DesiredValue "reviewable allow rules at $path" `
        -Action "No change to the machine (the allow-rules policy XML is written to $path for review; it has $count rules; nothing is deployed)"
    $item.Detail = "Path=$path;Rules=$count;AuditBase=$(if ($audit.Ok) { $audit.PolicyId } else { '(none)' })"
    $items.Add($item)
    $items
}

function Get-EnforcePlan {
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $admin = Test-IsAdministrator
    $ciImportError = Import-ConfigCIModule
    $ciCmdlets = [bool]((Get-Command -Name 'Set-CIPolicyIdInfo' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Set-RuleOption' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'ConvertFrom-CIPolicy' -ErrorAction SilentlyContinue))
    $ciTool = [bool](Get-Command -Name $script:CiToolCommand -ErrorAction SilentlyContinue)
    $list = Get-ActivePolicyList
    $audit = Get-AuditBaseRecord
    $pre = $script:PreconditionResult

    $pre['Elevated'] = if ($admin) { 'Met' } else { 'Skipped: requires elevation' }
    $pre['ConfigCI'] = if ($ciCmdlets) { 'Met' } else { "Failed: the ConfigCI cmdlets (Set-CIPolicyIdInfo, Set-RuleOption, ConvertFrom-CIPolicy) are not available$(if ($ciImportError) { " (importing ConfigCI said: $ciImportError)" }); run this script in PowerShell 7.4 or later, which loads ConfigCI through the Windows PowerShell compatibility layer" }
    $pre['CiTool'] = if ($ciTool) { 'Met' } else { 'Failed: CiTool.exe was not found (Windows 11 or Server 2025 required)' }
    $pre['AuditBaseRecord'] = if ($audit.Ok) { 'Met' } else { "Failed: $($audit.Reason)" }

    $pre['ActivePolicies'] = if ($list.Readable) { 'Met' } elseif (-not $admin) { 'Skipped: requires elevation' } else { "Failed: active policies could not be read: $($list.Reason)" }

    # The audit base must be active under its exact name and not already enforced.
    $baseMatch = @()
    if (-not $audit.Ok) {
        $pre['AuditBaseActive'] = 'Failed: not checked, the audit base record is not usable'
    } elseif ($list.Readable) {
        $baseMatch = @($list.Policies | Where-Object { (ConvertTo-BarePolicyId ([string](Get-OpsPropertyValue -InputObject $_ -Name 'PolicyID'))) -eq (ConvertTo-BarePolicyId $audit.PolicyId) })
        if ($baseMatch.Count -eq 0) {
            $pre['AuditBaseActive'] = "Failed: the audit base $($audit.PolicyId) is not an active policy"
        } elseif (@($baseMatch | Where-Object { [string](Get-OpsPropertyValue -InputObject $_ -Name 'FriendlyName') -cne $script:BaseName }).Count -gt 0) {
            $pre['AuditBaseActive'] = "Failed: policy $($audit.PolicyId) is active under another name, so it is not the toolkit's audit base"
        } elseif (@($baseMatch | Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'IsEnforced') -eq $true }).Count -gt 0) {
            $pre['AuditBaseActive'] = "Failed: the audit base $($audit.PolicyId) already reports as enforced; roll back first"
        } else {
            $pre['AuditBaseActive'] = 'Met'
        }
    } elseif (-not $admin) {
        $pre['AuditBaseActive'] = 'Skipped: requires elevation'
    } else {
        $pre['AuditBaseActive'] = "Failed: not verified because active policies could not be read: $($list.Reason)"
    }

    $pre['AllowsSupplementalPolicies'] = if (-not $audit.Ok) { 'Failed: not checked, the audit base record is not usable' } elseif ($audit.Options -contains $script:RequiredOption[17]) { 'Met' } else { 'Failed: the audit base does not carry option 17 (Allow Supplemental Policies); roll it back with Set-WdacAuditPolicy.ps1 and deploy it again, which adds it' }
    $pre['BootSafetyOptions'] = if (-not $audit.Ok) { 'Failed: not checked, the audit base record is not usable' } elseif (($audit.Options -contains $script:RequiredOption[9]) -and ($audit.Options -contains $script:RequiredOption[10])) { 'Met' } else { 'Failed: the audit base lacks option 9 (Advanced Boot Options Menu) or 10 (Boot Audit on Failure), without which an enforced policy that blocks a boot driver can leave the machine unable to start; roll it back with Set-WdacAuditPolicy.ps1 and deploy it again, which adds them' }

    # The reviewed allow-rules file: it must be a supplemental policy for this base, with rules in it.
    $supp = $null
    $pre['AllowRulesFile'] = 'Failed: no usable allow-rules file'
    if (-not (Test-Path -LiteralPath $AllowRulesPolicyPath -PathType Leaf)) {
        $pre['AllowRulesFile'] = "Failed: the allow-rules file '$AllowRulesPolicyPath' was not found"
    } else {
        $info = Read-PolicyXml -Path $AllowRulesPolicyPath
        if (-not $info.Ok) {
            $pre['AllowRulesFile'] = "Failed: the allow-rules file $($info.Reason)"
        } elseif ($info.PolicyType -cne 'Supplemental Policy') {
            $pre['AllowRulesFile'] = "Failed: the allow-rules file is '$($info.PolicyType)', not a Supplemental Policy"
        } elseif (-not $audit.Ok) {
            $pre['AllowRulesFile'] = 'Failed: not checked against the audit base, its record is not usable'
        } elseif ((ConvertTo-BarePolicyId $info.BasePolicyId) -ne (ConvertTo-BarePolicyId $audit.PolicyId)) {
            $pre['AllowRulesFile'] = "Failed: the allow-rules file supplements policy $($info.BasePolicyId), not the audit base $($audit.PolicyId)"
        } elseif (-not (Test-PolicyGuid $info.PolicyId) -or (ConvertTo-BarePolicyId $info.PolicyId) -eq (ConvertTo-BarePolicyId $audit.PolicyId)) {
            $pre['AllowRulesFile'] = 'Failed: the allow-rules file has no policy ID of its own'
        } elseif ($info.Options -contains $script:RequiredOption[3]) {
            $pre['AllowRulesFile'] = 'Failed: the allow-rules file carries Audit Mode (option 3), which a supplemental policy must not'
        } elseif ($info.RuleCount -lt 1) {
            $pre['AllowRulesFile'] = 'Failed: the allow-rules file has no allow rules, so nobody reviewed anything'
        } else {
            $pre['AllowRulesFile'] = 'Met'
            $supp = $info
        }
    }

    # No earlier allow-rules policy, and not the reviewed file's own ID, may already be active.
    if (-not $list.Readable) {
        $pre['NoActiveAllowRules'] = if (-not $admin) { 'Skipped: requires elevation' } else { "Failed: not verified because active policies could not be read: $($list.Reason)" }
    } else {
        $suppId = if ($supp) { ConvertTo-BarePolicyId $supp.PolicyId } else { '' }
        $dup = @($list.Policies | Where-Object {
                ([string](Get-OpsPropertyValue -InputObject $_ -Name 'FriendlyName') -eq $script:SupplementalName) -or
                ($suppId -and (ConvertTo-BarePolicyId ([string](Get-OpsPropertyValue -InputObject $_ -Name 'PolicyID'))) -eq $suppId)
            })
        $pre['NoActiveAllowRules'] = if ($dup.Count -gt 0) { "Failed: a policy named '$([string](Get-OpsPropertyValue -InputObject $dup[0] -Name 'FriendlyName')))' or with the reviewed file's ID is already active (policy ID $([string](Get-OpsPropertyValue -InputObject $dup[0] -Name 'PolicyID'))); run this script with -Rollback first" } else { 'Met' }
    }

    # Plan artifacts, built whenever the inputs allow, including under -WhatIf.
    $pre['EnforcedPolicyBuilt'] = 'Failed: not built, a precondition above did not hold'
    if ($audit.Ok -and $ciCmdlets -and $supp) {
        try {
            $script:Artifact = Initialize-EnforceArtifact -Audit $audit -Directory $resolvedReportDirectory -Stamp $timestamp
            $pre['EnforcedPolicyBuilt'] = 'Met'
        } catch {
            $script:Artifact = $null
            $pre['EnforcedPolicyBuilt'] = "Failed: building the enforced policy failed: $($_.Exception.Message -replace '\s+', ' ')"
        }
    }

    $a = $script:Artifact
    $baseCip = if ($a) { $a.EnforcedCipPath } else { '(not built)' }
    $suppCip = if ($a) { $a.SupplementalCipPath } else { '(not built)' }
    $suppIdText = if ($a) { $a.SupplementalPolicyId } else { '(not built)' }
    $baseIdText = if ($audit.Ok) { $audit.PolicyId } else { '(unknown)' }

    $rows = [ordered]@{
        Elevated = @($admin, 'True', 'Precondition: session is elevated')
        ConfigCI = @($ciCmdlets, 'True', 'Precondition: ConfigCI policy cmdlets are available')
        CiTool = @($ciTool, 'True', 'Precondition: CiTool.exe is present')
        AuditBaseRecord = @($audit.Ok, 'True', "Precondition: the audit base recorded by Set-WdacAuditPolicy.ps1 in $script:AuditDirectory is usable and still in audit mode")
        ActivePolicies = @($list.Readable, 'readable', 'Precondition: the active policy list can be read (unreadable refuses, it is never a pass)')
        AuditBaseActive = @(($pre['AuditBaseActive'] -eq 'Met'), 'active, named, not enforced', 'Precondition: the audit base is active under its exact name and not already enforced')
        AllowsSupplementalPolicies = @(($pre['AllowsSupplementalPolicies'] -eq 'Met'), 'True', 'Precondition: the audit base carries option 17 (Allow Supplemental Policies)')
        BootSafetyOptions = @(($pre['BootSafetyOptions'] -eq 'Met'), 'True', 'Precondition: the audit base carries options 9 (Advanced Boot Options Menu) and 10 (Boot Audit on Failure)')
        AllowRulesFile = @(($pre['AllowRulesFile'] -eq 'Met'), 'True', "Precondition: the reviewed file $AllowRulesPolicyPath is a supplemental policy for the audit base with at least one rule")
        NoActiveAllowRules = @(($pre['NoActiveAllowRules'] -eq 'Met'), 'none active', "Precondition: no policy named '$($script:SupplementalName)' or with the reviewed file's ID is already active")
        EnforcedPolicyBuilt = @(($pre['EnforcedPolicyBuilt'] -eq 'Met'), 'True', 'Precondition: the enforced base was built from the audit XML with only Audit Mode removed, and still carries options 6, 9, 10 and 17')
    }
    foreach ($key in $rows.Keys) {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting $key -RequiresAdmin $false -CurrentValue $rows[$key][0] -DesiredValue $rows[$key][1] -Action $rows[$key][2]))
    }

    $enforced = 'unreadable'
    if ($list.Readable) {
        $enforcedAll = @($list.Policies | Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'IsEnforced') -eq $true })
        $enforced = "total=$(@($list.Policies).Count);enforced=$($enforcedAll.Count)"
    }
    $items.Add((Get-PlanItem -Category 'Report' -Setting 'EnforcedPolicies' -RequiresAdmin $false -CurrentValue $enforced -DesiredValue 'report only' -Action 'No change (report only: active policies and how many are enforced)'))

    $one = Get-PlanItem -Category 'DeploySupplementalPolicy' -Setting $script:SupplementalName -RequiresAdmin $true `
        -CurrentValue 'not deployed' -DesiredValue "supplemental policy $suppIdText" `
        -Action "Deploy supplemental allow-rules policy $suppIdText from $suppCip with CiTool.exe --update-policy (first; only adds allowed code)"
    $one.Detail = "SupplementalPolicyId=$suppIdText;Cip=$suppCip"
    $items.Add($one)
    $two = Get-PlanItem -Category 'EnforceBasePolicy' -Setting $baseIdText -RequiresAdmin $true `
        -CurrentValue 'audit mode' -DesiredValue 'enforced (Audit Mode removed)' `
        -Action "Redeploy base policy $baseIdText from $baseCip with CiTool.exe --update-policy, Audit Mode removed, same ID (second; ENFORCES the policy: unreviewed code stops running)"
    $two.Detail = "BasePolicyId=$baseIdText;Cip=$baseCip"
    $items.Add($two)
    $items
}

# Builds the three binary policies in the report directory: the supplemental policy (the reviewed file,
# named for this script), the base with Audit Mode removed (same ID, same name), and an audit-mode copy
# of the base that -Rollback redeploys. Every check that fails throws, and nothing is deployed from a
# half-built set. Plan-artifact work in the run folder only, so it runs under -WhatIf too.
function Initialize-EnforceArtifact {
    param($Audit, [string]$Directory, [string]$Stamp)

    $WhatIfPreference = $false
    $bareBase = ConvertTo-BarePolicyId $Audit.PolicyId

    # The reviewed file, copied so what is deployed is a file in the run folder, named for this script.
    $suppXml = Join-Path $Directory "$($script:Prefix)-allow-rules-$Stamp.xml"
    Copy-Item -LiteralPath $AllowRulesPolicyPath -Destination $suppXml -Force
    $copy = Get-Item -LiteralPath $suppXml
    if ($copy.IsReadOnly) { $copy.IsReadOnly = $false }
    $null = Set-CIPolicyIdInfo -FilePath $suppXml -PolicyName $script:SupplementalName
    $suppInfo = Read-PolicyXml -Path $suppXml
    if (-not $suppInfo.Ok) { throw "the copied allow-rules file $($suppInfo.Reason)" }
    $bareSupp = ConvertTo-BarePolicyId $suppInfo.PolicyId
    $suppCip = Join-Path $Directory "$($script:Prefix)-allow-rules-$bareSupp.cip"
    $null = ConvertFrom-CIPolicy -XmlFilePath $suppXml -BinaryFilePath $suppCip
    if (-not (Test-Path -LiteralPath $suppCip)) { throw "ConvertFrom-CIPolicy did not produce $suppCip." }

    # The audit-mode copy of the base, for -Rollback.
    $restoreXml = Join-Path $Directory "$($script:Prefix)-audit-restore-$Stamp.xml"
    Copy-Item -LiteralPath $Audit.XmlPath -Destination $restoreXml -Force
    $copy = Get-Item -LiteralPath $restoreXml
    if ($copy.IsReadOnly) { $copy.IsReadOnly = $false }
    $restoreCip = Join-Path $Directory "$($script:Prefix)-audit-restore-$bareBase.cip"
    $null = ConvertFrom-CIPolicy -XmlFilePath $restoreXml -BinaryFilePath $restoreCip
    if (-not (Test-Path -LiteralPath $restoreCip)) { throw "ConvertFrom-CIPolicy did not produce $restoreCip." }
    $restoreHash = (Get-FileHash -LiteralPath $restoreCip -Algorithm SHA256).Hash.ToLowerInvariant()

    # The enforced base: Audit Mode removed from this one policy, nothing else touched.
    $enforcedXml = Join-Path $Directory "$($script:Prefix)-base-enforced-$Stamp.xml"
    Copy-Item -LiteralPath $Audit.XmlPath -Destination $enforcedXml -Force
    $copy = Get-Item -LiteralPath $enforcedXml
    if ($copy.IsReadOnly) { $copy.IsReadOnly = $false }
    $null = Set-RuleOption -FilePath $enforcedXml -Option 3 -Delete
    $info = Read-PolicyXml -Path $enforcedXml
    if (-not $info.Ok) { throw "the enforced base $($info.Reason)" }
    if ($info.Options -contains $script:RequiredOption[3]) { throw 'the enforced base still carries Enabled:Audit Mode (option 3) after Set-RuleOption -Delete; refusing to continue.' }
    foreach ($number in 6, 9, 10, 17) {
        if ($info.Options -notcontains $script:RequiredOption[$number]) { throw "the enforced base does not carry $($script:RequiredOption[$number]) (option $number); refusing to continue." }
    }
    if ((ConvertTo-BarePolicyId $info.PolicyId) -ne $bareBase) { throw "the enforced base has policy ID $($info.PolicyId), not the audit base's $($Audit.PolicyId); refusing to continue." }
    $enforcedCip = Join-Path $Directory "$($script:Prefix)-base-enforced-$bareBase.cip"
    $null = ConvertFrom-CIPolicy -XmlFilePath $enforcedXml -BinaryFilePath $enforcedCip
    if (-not (Test-Path -LiteralPath $enforcedCip)) { throw "ConvertFrom-CIPolicy did not produce $enforcedCip." }

    [pscustomobject]@{
        BasePolicyId = $Audit.PolicyId; SupplementalPolicyId = $suppInfo.PolicyId
        SupplementalXmlPath = $suppXml; SupplementalCipPath = $suppCip
        EnforcedXmlPath = $enforcedXml; EnforcedCipPath = $enforcedCip
        AuditRestoreXmlPath = $restoreXml; AuditRestoreCipPath = $restoreCip; AuditRestoreSha256 = $restoreHash
    }
}

function Get-LatestRollbackFile {
    Get-LatestRollbackFileIn -Directory $ReportDirectory -FilePrefix $script:Prefix
}

# Returns $null when the record is acceptable, otherwise a short text saying what is wrong with it.
# A record (the file's top level, or one ChangedSettings entry when -RequireCategory is set) must
# describe what the forward run deployed: the toolkit base name and a GUID ID, the supplemental name
# and a different GUID ID, the audit-restore and supplemental .cip named for those IDs, and a SHA-256.
# The rollback redeploys and removes by those values, so nothing but what this script wrote can pass.
# Pure: it reads nothing but its arguments.
function Get-RollbackEntryProblem {
    param(
        $Entry,
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string]$SupplementalName,
        [Parameter(Mandatory = $true)]$Categories,
        [bool]$RequireCategory
    )
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($field in 'PolicyName', 'BasePolicyId', 'SupplementalPolicyName', 'SupplementalPolicyId', 'AuditCipPath', 'AuditCipSha256', 'SupplementalCipPath') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
        if ($Entry.$field -isnot [string]) { return "$field is not a string" }
    }
    if ($RequireCategory) {
        if (-not $Entry.PSObject.Properties['Category']) { return 'the entry has no Category' }
        if ($Entry.Category -isnot [string] -or @($Categories) -cnotcontains $Entry.Category) { return "Category '$($Entry.Category)' is not one this script records" }
    }
    if ($Entry.PolicyName -cne $BaseName) { return "PolicyName '$($Entry.PolicyName)' is not '$BaseName'" }
    if ($Entry.SupplementalPolicyName -cne $SupplementalName) { return "SupplementalPolicyName '$($Entry.SupplementalPolicyName)' is not '$SupplementalName'" }
    $guid = '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\z'
    if ($Entry.BasePolicyId -notmatch $guid) { return "BasePolicyId '$($Entry.BasePolicyId)' is not a policy GUID" }
    if ($Entry.SupplementalPolicyId -notmatch $guid) { return "SupplementalPolicyId '$($Entry.SupplementalPolicyId)' is not a policy GUID" }
    $bareBase = $Entry.BasePolicyId.Trim('{', '}').ToLowerInvariant()
    $bareSupp = $Entry.SupplementalPolicyId.Trim('{', '}').ToLowerInvariant()
    if ($bareBase -eq $bareSupp) { return 'the base and supplemental policy IDs are the same' }
    if ([System.IO.Path]::GetFileName($Entry.AuditCipPath) -cne "$Prefix-audit-restore-$bareBase.cip") { return "AuditCipPath '$($Entry.AuditCipPath)' is not the $Prefix-audit-restore-$bareBase.cip this script builds for that base" }
    if ([System.IO.Path]::GetFileName($Entry.SupplementalCipPath) -cne "$Prefix-allow-rules-$bareSupp.cip") { return "SupplementalCipPath '$($Entry.SupplementalCipPath)' is not the $Prefix-allow-rules-$bareSupp.cip this script builds for that policy" }
    if ($Entry.AuditCipSha256 -notmatch '^[0-9a-fA-F]{64}\z') { return 'AuditCipSha256 is not a SHA-256 hash' }
    $null
}

# True only for an executing rollback in which nothing failed, was skipped or was merely previewed.
# Only then is the rollback file spent; anything less leaves it for a retry. 'Met' is a precondition
# that held.
function Test-RollbackFileConsumable {
    param($State, [bool]$Preview)
    if ($Preview) { return $false }
    if ($null -eq $State) { return $true }
    foreach ($item in @($State)) {
        if ($null -eq $item) { return $false }
        if ("$($item.Result)" -notin @('Reverted', 'NoChange', 'Met')) { return $false }
    }
    $true
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:Prefix)-rollback-<timestamp>.json found in $ReportDirectory. Nothing to roll back." }
    $advice = 'Nothing was changed. Move this file aside (out of the report directory) to roll back an older run.'
    try {
        $data = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Rollback file '$($file.FullName)' refused: it could not be read as JSON ($($_.Exception.Message)). $advice"
    }
    if ($null -eq $data -or $data -isnot [pscustomobject] -or -not $data.PSObject.Properties['ChangedSettings']) {
        throw "Rollback file '$($file.FullName)' refused: it has no ChangedSettings array. $advice"
    }
    if ($data.ChangedSettings -isnot [array]) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is not an array. $advice"
    }
    $entries = @($data.ChangedSettings)
    if ($entries.Count -eq 0) {
        throw "Rollback file '$($file.FullName)' refused: ChangedSettings is empty. $advice"
    }
    $problem = Get-RollbackEntryProblem -Entry $data -Prefix $script:Prefix -BaseName $script:BaseName `
        -SupplementalName $script:SupplementalName -Categories $script:RollbackCategories -RequireCategory $false
    if ($problem) {
        throw "Rollback file '$($file.FullName)' refused at the top-level fields: $problem. $advice"
    }
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $problem = Get-RollbackEntryProblem -Entry $entries[$i] -Prefix $script:Prefix -BaseName $script:BaseName `
            -SupplementalName $script:SupplementalName -Categories $script:RollbackCategories -RequireCategory $true
        if (-not $problem) {
            foreach ($field in 'PolicyName', 'BasePolicyId', 'SupplementalPolicyName', 'SupplementalPolicyId', 'AuditCipPath', 'AuditCipSha256', 'SupplementalCipPath') {
                if ([string]$entries[$i].$field -cne [string]$data.$field) { $problem = "$field '$($entries[$i].$field)' differs from the file's $field '$($data.$field)'"; break }
            }
        }
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    $script:RollbackSourceFile = $file

    $baseId = [string]$data.BasePolicyId
    $suppId = [string]$data.SupplementalPolicyId
    # Taken from the rollback file's own directory by file name, so the file cannot point at another path.
    $restoreCip = Join-Path (Split-Path -Parent $file.FullName) ([System.IO.Path]::GetFileName([string]$data.AuditCipPath))
    $script:Artifact = [pscustomobject]@{ AuditRestoreCipPath = $restoreCip; BasePolicyId = $baseId; SupplementalPolicyId = $suppId }

    $admin = Test-IsAdministrator
    $list = Get-ActivePolicyList
    $script:PreconditionResult['Elevated'] = if ($admin) { 'Met' } else { 'Skipped: requires elevation' }
    $script:PreconditionResult['CiTool'] = if (Get-Command -Name $script:CiToolCommand -ErrorAction SilentlyContinue) { 'Met' } else { 'Failed: CiTool.exe was not found' }

    $baseState = 'unknown'
    $suppState = 'unknown'
    $baseAction = "Refused: the base policy $baseId is not redeployed because the active policy list could not be read, so it cannot be verified as the toolkit's audit base ($($list.Reason))"
    $suppAction = "Refused: removal of supplemental policy $suppId is not attempted because the active policy list could not be read ($($list.Reason))"
    $needRestoreFile = $false
    if ($list.Readable) {
        $baseMatch = @($list.Policies | Where-Object { (ConvertTo-BarePolicyId ([string](Get-OpsPropertyValue -InputObject $_ -Name 'PolicyID'))) -eq (ConvertTo-BarePolicyId $baseId) })
        $suppMatch = @($list.Policies | Where-Object { (ConvertTo-BarePolicyId ([string](Get-OpsPropertyValue -InputObject $_ -Name 'PolicyID'))) -eq (ConvertTo-BarePolicyId $suppId) })
        # A policy with a recorded ID under any other name is not one this script deployed.
        foreach ($pair in @(@{ Match = $baseMatch; Name = $script:BaseName; Id = $baseId }, @{ Match = $suppMatch; Name = $script:SupplementalName; Id = $suppId })) {
            $foreign = @($pair.Match | Where-Object { [string](Get-OpsPropertyValue -InputObject $_ -Name 'FriendlyName') -cne $pair.Name })
            if ($foreign.Count -gt 0) {
                $script:RollbackSourceFile = $null
                throw "Rollback file '$($file.FullName)' refused: policy $($pair.Id) is active under the name '$([string](Get-OpsPropertyValue -InputObject $foreign[0] -Name 'FriendlyName'))', not '$($pair.Name)', so this script did not deploy it and will not change it. $advice"
            }
        }
        if ($baseMatch.Count -eq 0) {
            $baseState = 'not active'
            $baseAction = "No change (base policy $baseId is not active; it is not redeployed)"
        } else {
            $baseState = 'active'
            $needRestoreFile = $true
            $baseAction = "Redeploy base policy $baseId in audit mode from $restoreCip with CiTool.exe --update-policy (first, so nothing is enforced while the supplemental policy is removed)"
        }
        if ($suppMatch.Count -eq 0) {
            $suppState = 'not active'
            $suppAction = "No change (supplemental policy $suppId is not active)"
        } else {
            $suppState = 'active'
            $suppAction = "Remove supplemental policy $suppId with CiTool.exe --remove-policy (second; a restart may be needed to finish)"
        }
    } else {
        $script:PreconditionResult['ActivePolicies'] = "Failed: active policies could not be read: $($list.Reason)"
    }

    $restoreProblem = $null
    if ($needRestoreFile) {
        if (-not (Test-Path -LiteralPath $restoreCip -PathType Leaf)) {
            $restoreProblem = "the audit-mode binary $restoreCip was not found next to the rollback file"
        } elseif ((Get-FileHash -LiteralPath $restoreCip -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string]$data.AuditCipSha256).ToLowerInvariant()) {
            $restoreProblem = "the audit-mode binary $restoreCip does not match the SHA-256 recorded when it was built, so it is not redeployed"
        }
    }
    $script:PreconditionResult['AuditRestoreFile'] = if ($restoreProblem) { "Failed: $restoreProblem" } else { 'Met' }

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false -CurrentValue $admin -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'CiTool' -RequiresAdmin $false -CurrentValue ($script:PreconditionResult['CiTool'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: CiTool.exe is present'))
    if ($script:PreconditionResult.ContainsKey('ActivePolicies')) {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'ActivePolicies' -RequiresAdmin $false -CurrentValue 'unreadable' -DesiredValue 'readable' -Action 'Precondition: the active policy list can be read, to verify the policies are the ones this script deployed'))
    }
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'AuditRestoreFile' -RequiresAdmin $false -CurrentValue ($script:PreconditionResult['AuditRestoreFile'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: the audit-mode binary saved by Enforce is present and matches its recorded SHA-256 (when the base is active)'))
    $items.Add((Get-PlanItem -Category 'RestoreAuditBase' -Setting $baseId -RequiresAdmin $true -CurrentValue $baseState -DesiredValue 'audit mode' -Action $baseAction))
    $items.Add((Get-PlanItem -Category 'RemoveSupplementalPolicy' -Setting $suppId -RequiresAdmin $true -CurrentValue $suppState -DesiredValue 'removed' -Action $suppAction))
    $items
}

function Invoke-CiToolJson {
    param([string[]]$Argument)
    $text = (& $script:CiToolCommand @Argument --json 2>&1 | Out-String)
    try {
        $json = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Ok = $false; Message = "CiTool output could not be parsed: $($text.Trim())" }
    }
    $op = Get-OpsPropertyValue -InputObject $json -Name 'OperationResult'
    if ($null -eq $op) { return [pscustomobject]@{ Ok = $false; Message = 'CiTool returned no OperationResult' } }
    if ([int64]$op -ne 0) {
        return [pscustomobject]@{ Ok = $false; Message = ('CiTool returned OperationResult 0x{0:X8}' -f ([int64]$op -band 0xFFFFFFFF)) }
    }
    [pscustomobject]@{ Ok = $true; Message = '' }
}

# One rollback-file entry for a deployment attempt, recorded before CiTool is called: if CiTool reports
# failure the policy may still have been applied, and -Rollback is a no-op for one that is not active.
function Add-ChangedSetting {
    param([string]$Category)
    $a = $script:Artifact
    [void]$script:ChangedSettings.Add([pscustomobject]@{
            Category = $Category; PolicyName = $script:BaseName; BasePolicyId = $a.BasePolicyId
            SupplementalPolicyName = $script:SupplementalName; SupplementalPolicyId = $a.SupplementalPolicyId
            AuditCipPath = $a.AuditRestoreCipPath; AuditCipSha256 = $a.AuditRestoreSha256; SupplementalCipPath = $a.SupplementalCipPath
        })
}

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Precondition') {
        $r = $script:PreconditionResult[$Item.Setting]
        if ($r -like 'Failed:*' -and -not $script:StopReason) { $script:StopReason = ($r -replace '^Failed:\s*', '') }
        return $r
    }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($script:StopReason) { return "Skipped: precondition failed ($($script:StopReason))" }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    switch ($Item.Category) {
        'DeploySupplementalPolicy' {
            if (-not $script:Artifact) { return 'Failed: the policies were not built' }
            Add-ChangedSetting -Category 'DeploySupplementalPolicy'
            $r = Invoke-CiToolJson -Argument @('--update-policy', $script:Artifact.SupplementalCipPath)
            if (-not $r.Ok) { $script:StopReason = $r.Message; return "Failed: $($r.Message)" }
            return 'Applied'
        }
        'EnforceBasePolicy' {
            if (-not $script:Artifact) { return 'Failed: the policies were not built' }
            Add-ChangedSetting -Category 'EnforceBasePolicy'
            $r = Invoke-CiToolJson -Argument @('--update-policy', $script:Artifact.EnforcedCipPath)
            if (-not $r.Ok) { $script:StopReason = $r.Message; return "Failed: $($r.Message)" }
            return 'Applied'
        }
        'RestoreAuditBase' {
            $r = Invoke-CiToolJson -Argument @('--update-policy', $script:Artifact.AuditRestoreCipPath)
            if (-not $r.Ok) { $script:StopReason = $r.Message; return "Failed: $($r.Message)" }
            return 'Reverted'
        }
        'RemoveSupplementalPolicy' {
            $r = Invoke-CiToolJson -Argument @('--remove-policy', $Item.Setting)
            if (-not $r.Ok) { $script:StopReason = $r.Message; return "Failed: $($r.Message)" }
            return 'Reverted'
        }
    }
    "Failed: unknown category $($Item.Category)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$modeName = if ($Rollback) { 'rollback' } elseif ($Mode -eq 'BuildAllowRules') { 'build' } else { 'apply' }
$plan = @(if ($Rollback) { Get-RollbackPlan } elseif ($Mode -eq 'BuildAllowRules') { Get-BuildPlan } else { Get-EnforcePlan })

$planPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$modeName-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$modeName-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$modeName-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$modeName-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = Invoke-PlanItem -Item $item -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

$rollbackSourcePath = $null
$rollbackConsumedPath = $null
$rollbackNote = $null
if ($Rollback -and $script:RollbackSourceFile) {
    $rollbackSourcePath = $script:RollbackSourceFile.FullName
    if (Test-RollbackFileConsumable -State $state -Preview ([bool]$WhatIfPreference)) {
        # Bookkeeping after a real change, not a previewed one: -WhatIf:$false on purpose.
        $consumedName = $script:RollbackSourceFile.Name -replace '\.json$', ".consumed-$timestamp.json"
        try {
            Rename-Item -LiteralPath $rollbackSourcePath -NewName $consumedName -WhatIf:$false -ErrorAction Stop
            $rollbackConsumedPath = Join-Path (Split-Path -Parent $rollbackSourcePath) $consumedName
            $rollbackNote = 'Rollback file consumed; the next -Rollback undoes the previous run.'
        } catch {
            $rollbackNote = "Rollback file could not be marked consumed ($($_.Exception.Message)); move it aside before the next -Rollback or it is replayed."
            Write-Warning $rollbackNote
        }
    } elseif ($WhatIfPreference) {
        $rollbackNote = 'Rollback file left unconsumed: -WhatIf changes nothing.'
    } else {
        $rollbackNote = 'Rollback file left unconsumed: at least one item failed or was skipped, so -Rollback can be run again.'
    }
}

$rollbackPath = $null
if ($modeName -eq 'apply' -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-rollback-$timestamp.json"
    $first = $script:ChangedSettings[0]
    [pscustomobject]@{
        Timestamp = $timestamp
        PolicyName = $first.PolicyName
        BasePolicyId = $first.BasePolicyId
        SupplementalPolicyName = $first.SupplementalPolicyName
        SupplementalPolicyId = $first.SupplementalPolicyId
        AuditCipPath = $first.AuditCipPath
        AuditCipSha256 = $first.AuditCipSha256
        SupplementalCipPath = $first.SupplementalCipPath
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$artifact = $script:Artifact
$summary = [pscustomobject]@{
    Operation = "WdacEnforcedPolicy ($modeName)"
    IsElevated = (Test-IsAdministrator)
    BasePolicyId = $(if ($artifact -and $artifact.PSObject.Properties['BasePolicyId']) { $artifact.BasePolicyId } else { $null })
    SupplementalPolicyId = $(if ($artifact -and $artifact.PSObject.Properties['SupplementalPolicyId']) { $artifact.SupplementalPolicyId } else { $null })
    AllowRulesXmlPath = $(if ($artifact -and $artifact.PSObject.Properties['XmlPath']) { $artifact.XmlPath } else { $null })
    SupplementalCipPath = $(if ($artifact -and $artifact.PSObject.Properties['SupplementalCipPath']) { $artifact.SupplementalCipPath } else { $null })
    EnforcedCipPath = $(if ($artifact -and $artifact.PSObject.Properties['EnforcedCipPath']) { $artifact.EnforcedCipPath } else { $null })
    AuditRestoreCipPath = $(if ($artifact -and $artifact.PSObject.Properties['AuditRestoreCipPath']) { $artifact.AuditRestoreCipPath } else { $null })
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    RollbackJsonPath = $rollbackPath
    RollbackSourcePath = $rollbackSourcePath
    RollbackConsumedPath = $rollbackConsumedPath
    RollbackNote = $rollbackNote
    RebootRequired = $false
    StoppedReason = $script:StopReason
    AppliedCount = @($state | Where-Object { $_.Result -in @('Applied', 'Reverted') }).Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    SkippedCount = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Items = @($state)
}

# A live run that stopped on a failed precondition or a failed step must not exit 0. The reports
# are already written. A -WhatIf run only previews, so it exits 0.
$failedItem = @($state | Where-Object { $_.Result -like 'Failed:*' }) | Select-Object -First 1
if (-not $WhatIfPreference -and ($script:StopReason -or $failedItem)) {
    $why = if ($script:StopReason) { $script:StopReason } else { $failedItem.Result }
    throw "WDAC enforced policy change did not complete: $why. Reports: $resolvedReportDirectory"
}

$summary
