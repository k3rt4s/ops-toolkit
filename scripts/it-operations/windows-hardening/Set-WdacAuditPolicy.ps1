<#
.SYNOPSIS
Plan, apply, and roll back a Windows Defender Application Control base policy in audit mode only, built from a Microsoft in-box example policy, so would-be blocks are logged and nothing is blocked.

.DESCRIPTION
Instructions:
- Run with -WhatIf first and review the generated plan CSV/JSON. Under -WhatIf the script still
  builds the policy files (XML and binary) in the report directory so you can inspect exactly
  what would be deployed; it deploys nothing.
- -ReportDirectory is mandatory: this is a public repository and a path that defaulted to one
  workstation must never be applied to someone else's machine. Generated reports belong under a
  data root outside the repo.
- Run elevated to deploy. A non-elevated live run marks the deploy step 'Skipped: requires
  elevation'. Policy authoring uses the ConfigCI cmdlets, which load in Windows PowerShell 5.1
  and, through the compatibility layer, in PowerShell 7; if they do not load the plan says so
  and stops.
- The base is a Microsoft example policy copied from
  %windir%\schemas\CodeIntegrity\ExamplePolicies (override the folder with
  -ExamplePolicyDirectory). -BasePolicy DefaultWindows (the default) starts from
  DefaultWindows_Audit.xml; AllowMicrosoft starts from AllowMicrosoft.xml. Either way the copy
  gets a new policy ID, the name 'ops-toolkit WDAC audit', and two rule options forced on
  before it is converted to a binary policy: Audit Mode (Set-RuleOption -Option 3) and Unsigned
  System Integrity Policy (Set-RuleOption -Option 6, because the policy is deployed unsigned).
- The single change is: CiTool.exe --update-policy <policy.cip> --json. Before it, the script
  lists active policies (CiTool.exe --list-policies --json) and refuses if a policy with the
  same name from a previous run is already active; roll that one back first. A policy list that
  cannot be read is a stop, never a pass.
- There is NO enforce switch in this script, by design. Audit mode logs what an enforced policy
  would have blocked to the Microsoft-Windows-CodeIntegrity/Operational log (Export-WdacAuditEvent.ps1
  reads those events). Enforcement is a later, separate decision to take only after reviewing
  audit events for a representative period, because an enforced policy that misses a needed
  driver or tool can stop the machine from booting or an application from running.
- Report-only: Smart App Control state when the registry value is readable, and how many
  enforced policies are already active. Neither is changed.
- -Rollback runs CiTool.exe --remove-policy <PolicyID> for the policy ID in the newest unconsumed
  rollback file (newest by name), if that policy is still active. A restart may be needed for the
  removal to finish.
- If the active policy list cannot be read, -Rollback does not run CiTool.exe --remove-policy: the
  plan shows a failed ActivePolicies precondition and a refused removal, the summary reports the
  stop, and the rollback file is left unconsumed. -WhatIf still writes its plan and summary.
- Rollback can only remove the policy this script deployed. Before any plan is written or any
  change made, the whole file is checked and refused, also under -WhatIf, with an error naming the
  file and the first bad entry (or the top-level fields), when the JSON does not parse,
  ChangedSettings is missing, not an array or empty, or any record has a PolicyName other than
  'ops-toolkit WDAC audit', a PolicyId that is not a GUID, a BasePolicy this script does not offer,
  a CipPath that is not <PolicyId>.cip, an XmlPath that is not a wdac-audit-policy-<timestamp>.xml
  name, a value that is not a string, or a PolicyId that differs between the records. If the
  policy with that ID is active under any other name it is refused too: it is not this script's.
  Move a refused file aside (out of the report directory) to roll back an older run. After an
  executing -Rollback in which every item was reverted or needed no change, the file is renamed
  wdac-audit-rollback-<timestamp>.consumed-<timestamp>.json and is no longer picked; under -WhatIf,
  or when any item failed or was skipped, it is left in place and the summary says so.

Purpose:
Application control is the strongest control against unknown code on a workstation, and the one
most likely to break the machine if enforced blind. Audit mode first shows what it would break.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1 -ReportDirectory <dir> -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1 -ReportDirectory <dir>                        # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1 -ReportDirectory <dir> -BasePolicy AllowMicrosoft  # elevated
pwsh -File .\scripts\it-operations\windows-hardening\Set-WdacAuditPolicy.ps1 -ReportDirectory <dir> -Rollback -WhatIf

.OUTPUTS
Writes plan and state CSV/JSON, the audit policy XML and binary, and on a live run that deployed
the policy a rollback JSON holding the policy ID, all under the report directory. Returns a
summary object.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Export-WdacAuditEvent.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('DefaultWindows', 'AllowMicrosoft')]
    [string]$BasePolicy = 'DefaultWindows',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExamplePolicyDirectory = (Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies'),

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory,

    [Parameter()]
    [switch]$Rollback
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$script:Prefix = 'wdac-audit'
$script:PolicyName = 'ops-toolkit WDAC audit'
$script:ChangedSettings = [System.Collections.Generic.List[pscustomobject]]::new()
$script:StopReason = $null
$script:PreconditionResult = @{}
$script:Artifact = $null
$script:RollbackSourceFile = $null
# The category of the one change this script makes, and the base policies it offers with the example
# file each starts from. The forward plan and the rollback validator both read these.
$script:DeployCategory = 'DeployAuditPolicy'
$script:BaseExampleFiles = [ordered]@{ DefaultWindows = 'DefaultWindows_Audit.xml'; AllowMicrosoft = 'AllowMicrosoft.xml' }

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
    if (-not (Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue)) {
        $result.Reason = 'CiTool.exe was not found (it ships with Windows 11 and Windows Server 2025)'
        return $result
    }
    try {
        $text = (& CiTool.exe --list-policies --json 2>&1 | Out-String)
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

function Get-SmartAppControlState {
    $props = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue
    $value = Get-OpsPropertyValue -InputObject $props -Name 'VerifiedAndReputablePolicyState'
    if ($null -eq $value) { return 'unreadable or absent' }
    switch ([int]$value) {
        0 { 'Off' }
        1 { 'On (enforced)' }
        2 { 'Evaluation' }
        default { "unrecognized value $value" }
    }
}

# Builds the XML and binary policy in the report directory. This is plan-artifact work on files in
# the run folder only, so it runs under -WhatIf too: the operator reviews the exact policy that a
# live run would deploy. $WhatIfPreference is cleared for this scope so the file-writing cmdlets
# are not suppressed by the preview.
function Initialize-AuditPolicyArtifact {
    param([string]$BaseXmlPath, [string]$Directory, [string]$Stamp)

    $WhatIfPreference = $false
    $xmlPath = Join-Path $Directory "$($script:Prefix)-policy-$Stamp.xml"
    Copy-Item -LiteralPath $BaseXmlPath -Destination $xmlPath -Force
    $copy = Get-Item -LiteralPath $xmlPath
    if ($copy.IsReadOnly) { $copy.IsReadOnly = $false }

    Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName $script:PolicyName -ResetPolicyID
    Set-RuleOption -FilePath $xmlPath -Option 3
    Set-RuleOption -FilePath $xmlPath -Option 6

    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($xmlPath)
    $policyId = [string]$doc.SiPolicy.PolicyID
    if ([string]::IsNullOrWhiteSpace($policyId)) { throw 'The generated policy has no PolicyID.' }
    $options = @(@($doc.SiPolicy.Rules.Rule) | ForEach-Object { [string]$_.Option })
    if ($options -notcontains 'Enabled:Audit Mode') { throw 'The generated policy does not carry the Enabled:Audit Mode rule option; refusing to continue.' }
    # The policy is deployed unsigned; one without this option expects a signature it does not have.
    if ($options -notcontains 'Enabled:Unsigned System Integrity Policy') { throw 'The generated policy does not carry the Enabled:Unsigned System Integrity Policy rule option (6) and would be deployed unsigned; refusing to continue.' }

    $cipPath = Join-Path $Directory ("{0}.cip" -f (ConvertTo-BarePolicyId $policyId))
    ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath | Out-Null
    if (-not (Test-Path -LiteralPath $cipPath)) { throw "ConvertFrom-CIPolicy did not produce $cipPath." }

    [pscustomobject]@{ XmlPath = $xmlPath; CipPath = $cipPath; PolicyId = $policyId }
}

function Get-ForwardPlan {
    param([string]$ExampleDirectory)
    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $admin = Test-IsAdministrator

    $exampleName = $script:BaseExampleFiles[$BasePolicy]
    $basePath = Join-Path $ExampleDirectory $exampleName
    $baseExists = Test-Path -LiteralPath $basePath -PathType Leaf
    $ciCmdlets = [bool]((Get-Command -Name 'Set-CIPolicyIdInfo' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Set-RuleOption' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'ConvertFrom-CIPolicy' -ErrorAction SilentlyContinue))
    $ciTool = [bool](Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue)
    $list = Get-ActivePolicyList

    $script:PreconditionResult['Elevated'] = if ($admin) { 'Met' } else { 'Skipped: requires elevation' }
    $script:PreconditionResult['ConfigCI'] = if ($ciCmdlets) { 'Met' } else { 'Failed: the ConfigCI cmdlets (Set-CIPolicyIdInfo, Set-RuleOption, ConvertFrom-CIPolicy) are not available; try Windows PowerShell 5.1' }
    $script:PreconditionResult['CiTool'] = if ($ciTool) { 'Met' } else { 'Failed: CiTool.exe was not found (Windows 11 or Server 2025 required)' }
    $script:PreconditionResult['BasePolicyFile'] = if ($baseExists) { 'Met' } else { "Failed: example policy $basePath was not found" }

    $sameName = @()
    if ($list.Readable) {
        $sameName = @($list.Policies | Where-Object { [string](Get-OpsPropertyValue -InputObject $_ -Name 'FriendlyName') -eq $script:PolicyName })
        $script:PreconditionResult['NoActiveAuditPolicy'] = if ($sameName.Count -gt 0) {
            "Failed: a policy named '$($script:PolicyName)' is already active (policy ID $([string](Get-OpsPropertyValue -InputObject $sameName[0] -Name 'PolicyID'))); run this script with -Rollback first"
        } else { 'Met' }
    } elseif (-not $admin) {
        $script:PreconditionResult['NoActiveAuditPolicy'] = 'Skipped: requires elevation'
    } else {
        $script:PreconditionResult['NoActiveAuditPolicy'] = "Failed: active policies could not be read: $($list.Reason)"
    }

    # Plan artifacts: built whenever the inputs allow, including under -WhatIf.
    if ($baseExists -and $ciCmdlets) {
        try {
            $script:Artifact = Initialize-AuditPolicyArtifact -BaseXmlPath $basePath -Directory $resolvedReportDirectory -Stamp $timestamp
        } catch {
            $script:PreconditionResult['BasePolicyFile'] = "Failed: building the audit policy failed: $($_.Exception.Message)"
        }
    }

    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false -CurrentValue $admin -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'ConfigCI' -RequiresAdmin $false -CurrentValue $ciCmdlets -DesiredValue 'True' -Action 'Precondition: ConfigCI policy cmdlets are available'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'CiTool' -RequiresAdmin $false -CurrentValue $ciTool -DesiredValue 'True' -Action 'Precondition: CiTool.exe is present'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'BasePolicyFile' -RequiresAdmin $false -CurrentValue $baseExists -DesiredValue $basePath -Action "Precondition: example policy $exampleName exists and the audit policy builds from it"))
    $activeValue = if ($list.Readable) { "$($sameName.Count) policy named '$($script:PolicyName)'" } else { 'unreadable' }
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'NoActiveAuditPolicy' -RequiresAdmin $false -CurrentValue $activeValue -DesiredValue '0 active' -Action "Precondition: no policy named '$($script:PolicyName)' is already active"))

    $enforced = 'unreadable'
    if ($list.Readable) {
        $enforcedAll = @($list.Policies | Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'IsEnforced') -eq $true })
        $enforcedUser = @($enforcedAll | Where-Object { (Get-OpsPropertyValue -InputObject $_ -Name 'IsSystemPolicy') -ne $true })
        $enforced = "total=$(@($list.Policies).Count);enforced=$($enforcedAll.Count);enforced non-system=$($enforcedUser.Count)"
    }
    $items.Add((Get-PlanItem -Category 'Report' -Setting 'EnforcedPolicies' -RequiresAdmin $false -CurrentValue $enforced -DesiredValue 'report only' -Action 'No change (report only: active policies and how many are enforced)'))
    $items.Add((Get-PlanItem -Category 'Report' -Setting 'SmartAppControl' -RequiresAdmin $false -CurrentValue (Get-SmartAppControlState) -DesiredValue 'report only' -Action 'No change (report only: Smart App Control state)'))

    $cip = if ($script:Artifact) { $script:Artifact.CipPath } else { '(not built)' }
    $pid2 = if ($script:Artifact) { $script:Artifact.PolicyId } else { '(not built)' }
    $item = Get-PlanItem -Category $script:DeployCategory -Setting $script:PolicyName -RequiresAdmin $true `
        -CurrentValue 'not deployed' -DesiredValue "audit-mode policy $pid2" `
        -Action "Deploy audit-mode policy $pid2 from $cip with CiTool.exe --update-policy (audit only; nothing is blocked)"
    $item.Detail = "BasePolicy=$BasePolicy;PolicyId=$pid2;Cip=$cip"
    $items.Add($item)
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # Exact name: the wildcard form would also match the rollback-plan file a -Rollback run writes,
    # and a '.consumed-' file does not match, so a used file is never picked again.
    $pattern = '^' + [regex]::Escape($script:Prefix) + '-rollback-\d{8}_\d{6}\.json$'
    Get-ChildItem -LiteralPath $ReportDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Sort-Object Name -Descending | Select-Object -First 1
}

# Returns $null when the record is acceptable, otherwise a short text saying what is wrong with it.
# A record (the file's top level, or one ChangedSettings entry when -RequireCategory is set) must
# describe exactly what the forward run deploys: this script's policy name, a GUID policy ID, a base
# policy the script offers, the .cip named for that ID and a policy XML name this script writes. The
# rollback removes the policy by that ID, so nothing but the ID of a policy this script deployed
# can pass. Pure: it reads nothing but its arguments.
function Get-RollbackEntryProblem {
    param(
        $Entry,
        [Parameter(Mandatory = $true)][string]$PolicyName,
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)]$BaseExampleFiles,
        [Parameter(Mandatory = $true)][string]$DeployCategory,
        [bool]$RequireCategory
    )
    if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { return 'the entry is not an object' }
    foreach ($field in 'PolicyName', 'PolicyId', 'CipPath', 'XmlPath', 'BasePolicy') {
        if (-not $Entry.PSObject.Properties[$field]) { return "the entry has no $field" }
        if ($Entry.$field -isnot [string]) { return "$field is not a string" }
    }
    if ($RequireCategory) {
        if (-not $Entry.PSObject.Properties['Category']) { return 'the entry has no Category' }
        if ($Entry.Category -isnot [string] -or $Entry.Category -cne $DeployCategory) { return "Category '$($Entry.Category)' is not $DeployCategory" }
    }
    if ($Entry.PolicyName -cne $PolicyName) { return "PolicyName '$($Entry.PolicyName)' is not '$PolicyName'" }
    if ($Entry.PolicyId -notmatch '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\z') { return "PolicyId '$($Entry.PolicyId)' is not a policy GUID" }
    if ($Entry.BasePolicy -cnotin @($BaseExampleFiles.Keys)) { return "BasePolicy '$($Entry.BasePolicy)' is not one this script offers" }
    $bare = $Entry.PolicyId.Trim('{', '}').ToLowerInvariant()
    if ([System.IO.Path]::GetFileName($Entry.CipPath) -cne "$bare.cip") { return "CipPath '$($Entry.CipPath)' is not the $bare.cip this script builds for that policy" }
    if ([System.IO.Path]::GetFileName($Entry.XmlPath) -cnotmatch ('^' + [regex]::Escape($Prefix) + '-policy-\d{8}_\d{6}\.xml\z')) { return "XmlPath '$($Entry.XmlPath)' is not a $Prefix-policy-<timestamp>.xml this script writes" }
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
    $problem = Get-RollbackEntryProblem -Entry $data -PolicyName $script:PolicyName -Prefix $script:Prefix `
        -BaseExampleFiles $script:BaseExampleFiles -DeployCategory $script:DeployCategory -RequireCategory $false
    if ($problem) {
        throw "Rollback file '$($file.FullName)' refused at the top-level fields: $problem. $advice"
    }
    $policyId = [string]$data.PolicyId
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $problem = Get-RollbackEntryProblem -Entry $entries[$i] -PolicyName $script:PolicyName -Prefix $script:Prefix `
            -BaseExampleFiles $script:BaseExampleFiles -DeployCategory $script:DeployCategory -RequireCategory $true
        if (-not $problem -and (ConvertTo-BarePolicyId ([string]$entries[$i].PolicyId)) -ne (ConvertTo-BarePolicyId $policyId)) {
            $problem = "PolicyId '$($entries[$i].PolicyId)' differs from the file's PolicyId '$policyId'"
        }
        if ($problem) {
            throw "Rollback file '$($file.FullName)' refused at ChangedSettings entry $i (zero-based): $problem. $advice"
        }
    }
    $script:RollbackSourceFile = $file

    $admin = Test-IsAdministrator
    $list = Get-ActivePolicyList
    $script:PreconditionResult['Elevated'] = if ($admin) { 'Met' } else { 'Skipped: requires elevation' }
    $script:PreconditionResult['CiTool'] = if (Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue) { 'Met' } else { 'Failed: CiTool.exe was not found' }

    $active = 'unknown'
    $action = "Remove audit-mode policy $policyId with CiTool.exe --remove-policy (a restart may be needed to finish)"
    if ($list.Readable) {
        $match = @($list.Policies | Where-Object { (ConvertTo-BarePolicyId ([string](Get-OpsPropertyValue -InputObject $_ -Name 'PolicyID'))) -eq (ConvertTo-BarePolicyId $policyId) })
        if ($match.Count -eq 0) {
            $active = 'not active'
            $action = "No change (policy $policyId is not active)"
        } else {
            # A policy with this ID under any other name is not the one this script deployed.
            $foreign = @($match | Where-Object { [string](Get-OpsPropertyValue -InputObject $_ -Name 'FriendlyName') -cne $script:PolicyName })
            if ($foreign.Count -gt 0) {
                $script:RollbackSourceFile = $null
                throw "Rollback file '$($file.FullName)' refused: policy $policyId is active under the name '$([string](Get-OpsPropertyValue -InputObject $foreign[0] -Name 'FriendlyName'))', not '$($script:PolicyName)', so this script did not deploy it and will not remove it. $advice"
            }
            $active = 'active'
        }
    } else {
        # An unreadable list cannot show that the policy is the one this script deployed, so the
        # removal is refused (a Failed precondition stops the run), never attempted.
        $script:PreconditionResult['ActivePolicies'] = "Failed: active policies could not be read: $($list.Reason)"
        $action = "Refused: removal of policy $policyId is not attempted because the active policy list could not be read, so it cannot be verified as the policy this script deployed ($($list.Reason))"
    }

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false -CurrentValue $admin -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'CiTool' -RequiresAdmin $false -CurrentValue ($script:PreconditionResult['CiTool'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: CiTool.exe is present'))
    if ($script:PreconditionResult.ContainsKey('ActivePolicies')) {
        $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'ActivePolicies' -RequiresAdmin $false -CurrentValue 'unreadable' -DesiredValue 'readable' -Action 'Precondition: the active policy list can be read, to verify the policy is the one this script deployed'))
    }
    $items.Add((Get-PlanItem -Category 'RemoveAuditPolicy' -Setting $policyId -RequiresAdmin $true -CurrentValue $active -DesiredValue 'removed' -Action $action))
    $items
}

function Invoke-CiToolJson {
    param([string[]]$Argument)
    $text = (& CiTool.exe @Argument --json 2>&1 | Out-String)
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

function Invoke-PlanItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][pscustomobject]$Item)

    if ($Item.Category -eq 'Precondition') {
        $r = $script:PreconditionResult[$Item.Setting]
        if ($r -like 'Failed:*') { $script:StopReason = ($r -replace '^Failed:\s*', '') }
        return $r
    }
    if ($Item.Action -like 'No change*') { return 'NoChange' }
    if ($Item.RequiresAdmin -and -not (Test-IsAdministrator)) { return 'Skipped: requires elevation' }
    if ($script:StopReason) { return "Skipped: precondition failed ($($script:StopReason))" }
    if (-not $PSCmdlet.ShouldProcess($Item.Setting, $Item.Action)) { return 'Previewed' }

    switch ($Item.Category) {
        { $_ -eq $script:DeployCategory } {
            if (-not $script:Artifact) { return 'Failed: the audit policy was not built' }
            $r = Invoke-CiToolJson -Argument @('--update-policy', $script:Artifact.CipPath)
            if (-not $r.Ok) { return "Failed: $($r.Message)" }
            [void]$script:ChangedSettings.Add([pscustomobject]@{
                    Category = $script:DeployCategory; PolicyName = $script:PolicyName; PolicyId = $script:Artifact.PolicyId
                    CipPath = $script:Artifact.CipPath; XmlPath = $script:Artifact.XmlPath; BasePolicy = $BasePolicy
                })
            return 'Applied'
        }
        'RemoveAuditPolicy' {
            $r = Invoke-CiToolJson -Argument @('--remove-policy', $Item.Setting)
            if (-not $r.Ok) { return "Failed: $($r.Message)" }
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

$mode = if ($Rollback) { 'rollback' } else { 'apply' }
$plan = @(if ($Rollback) { Get-RollbackPlan } else { Get-ForwardPlan -ExampleDirectory $ExamplePolicyDirectory })

$planPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-$mode-state-$timestamp.json"

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
if (-not $Rollback -and -not $WhatIfPreference -and $script:ChangedSettings.Count -gt 0) {
    $rollbackPath = Join-Path $resolvedReportDirectory "$($script:Prefix)-rollback-$timestamp.json"
    $first = $script:ChangedSettings[0]
    [pscustomobject]@{
        Timestamp = $timestamp
        PolicyName = $first.PolicyName
        PolicyId = $first.PolicyId
        CipPath = $first.CipPath
        XmlPath = $first.XmlPath
        BasePolicy = $first.BasePolicy
        ChangedSettings = @($script:ChangedSettings)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollbackPath -Encoding utf8 -WhatIf:$false
}

$summary = [pscustomobject]@{
    Operation = "WdacAuditPolicy ($mode)"
    IsElevated = (Test-IsAdministrator)
    BasePolicy = $BasePolicy
    PolicyId = $(if ($script:Artifact) { $script:Artifact.PolicyId } else { $null })
    PolicyXmlPath = $(if ($script:Artifact) { $script:Artifact.XmlPath } else { $null })
    PolicyBinaryPath = $(if ($script:Artifact) { $script:Artifact.CipPath } else { $null })
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
    throw "WDAC audit policy change did not complete: $why. Reports: $resolvedReportDirectory"
}

$summary
