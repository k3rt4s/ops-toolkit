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
  gets a new policy ID, the name 'ops-toolkit WDAC audit', and the Audit Mode rule option
  forced on (Set-RuleOption -Option 3) before it is converted to a binary policy.
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
- -Rollback runs CiTool.exe --remove-policy <PolicyID> for the policy ID in the latest rollback
  file, if that policy is still active. A restart may be needed for the removal to finish.

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

    $exampleName = if ($BasePolicy -eq 'AllowMicrosoft') { 'AllowMicrosoft.xml' } else { 'DefaultWindows_Audit.xml' }
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
    $item = Get-PlanItem -Category 'DeployAuditPolicy' -Setting $script:PolicyName -RequiresAdmin $true `
        -CurrentValue 'not deployed' -DesiredValue "audit-mode policy $pid2" `
        -Action "Deploy audit-mode policy $pid2 from $cip with CiTool.exe --update-policy (audit only; nothing is blocked)"
    $item.Detail = "BasePolicy=$BasePolicy;PolicyId=$pid2;Cip=$cip"
    $items.Add($item)
    $items
}

function Get-LatestRollbackFile {
    if (-not (Test-Path -LiteralPath $ReportDirectory)) { return $null }
    # Exact name: the wildcard form would also match the rollback-plan file a -Rollback run writes.
    $pattern = '^' + [regex]::Escape($script:Prefix) + '-rollback-\d{8}_\d{6}\.json$'
    Get-ChildItem -LiteralPath $ReportDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern } |
        Sort-Object LastWriteTime, Name -Descending | Select-Object -First 1
}

function Get-RollbackPlan {
    $file = Get-LatestRollbackFile
    if (-not $file) { throw "No $($script:Prefix)-rollback-<timestamp>.json found in $ReportDirectory. Nothing to roll back." }
    $data = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $policyId = [string](Get-OpsPropertyValue -InputObject $data -Name 'PolicyId')
    if (-not $policyId) { throw "Rollback file $($file.Name) holds no PolicyId." }

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
            $active = 'active'
        }
    }

    $items = [System.Collections.Generic.List[pscustomobject]]::new()
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'Elevated' -RequiresAdmin $false -CurrentValue $admin -DesiredValue 'True' -Action 'Precondition: session is elevated'))
    $items.Add((Get-PlanItem -Category 'Precondition' -Setting 'CiTool' -RequiresAdmin $false -CurrentValue ($script:PreconditionResult['CiTool'] -eq 'Met') -DesiredValue 'True' -Action 'Precondition: CiTool.exe is present'))
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
        'DeployAuditPolicy' {
            if (-not $script:Artifact) { return 'Failed: the audit policy was not built' }
            $r = Invoke-CiToolJson -Argument @('--update-policy', $script:Artifact.CipPath)
            if (-not $r.Ok) { return "Failed: $($r.Message)" }
            [void]$script:ChangedSettings.Add([pscustomobject]@{
                    Category = $Item.Category; PolicyName = $script:PolicyName; PolicyId = $script:Artifact.PolicyId
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
