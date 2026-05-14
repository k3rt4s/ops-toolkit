<#
.SYNOPSIS
Find stale Active Directory computer accounts, write review reports, and optionally disable or move them.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires the ActiveDirectory PowerShell module.
- Always run with -WhatIf first and review the generated plan/state reports.
- Pass -SearchBase and -TargetOu explicitly to keep the update scope clear.
- Use -Rollback with a prior state CSV only after reviewing the generated state report.
- Generated reports are written under reports\active-directory by default.

.PURPOSE
Use this script to identify stale AD computer accounts, preserve before-state
data, and then optionally disable accounts, move them to a disabled-computers
OU, or both. Each run writes CSV, JSON, and HTML artifacts so the operator can
review planned changes, completed actions, and rollback inputs.

.REQUIRED SYNTAX
pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -WhatIf
pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 120 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -Action DisableAndMove -WhatIf
pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -Rollback -RollbackStatePath .\reports\active-directory\ad-stale-computers-state-20260506_120000.csv -WhatIf

.OUTPUTS
Writes plan, state, rollback, and HTML report files under
reports\active-directory by default. Returns a summary object with output paths
and action counts.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [Parameter()]
    [ValidateSet('ReportOnly', 'DisableOnly', 'MoveOnly', 'DisableAndMove')]
    [string]$Action = 'DisableAndMove',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOu,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LdapFilter,

    [Parameter()]
    [switch]$IncludeDisabledComputers,

    [Parameter()]
    [switch]$IncludeNeverLoggedOn,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\active-directory'),

    [Parameter()]
    [switch]$Rollback,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RollbackStatePath,

    [Parameter()]
    [switch]$SendEmail,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$From,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$To,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ContactEmail
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -WhatIf
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 120 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -Action DisableAndMove -WhatIf
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -Action ReportOnly -SearchBase "OU=Workstations,DC=example,DC=com"
  pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -Rollback -RollbackStatePath .\reports\active-directory\ad-stale-computers-state-20260506_120000.csv -WhatIf

Options:
  -InactiveDays              Minimum days since last logon. Defaults to 90.
  -Action                    ReportOnly, DisableOnly, MoveOnly, or DisableAndMove.
  -TargetOu                  Distinguished name of the OU where stale computers are moved.
  -SearchBase                Optional distinguished name used to limit the AD search scope.
  -SearchScope               AD search scope: Base, OneLevel, or Subtree. Defaults to Subtree.
  -Server                    Optional domain controller to target.
  -LdapFilter                Optional additional LDAP filter, for example "(operatingSystem=*Windows*)".
  -IncludeDisabledComputers  Include already-disabled computer accounts in the plan.
  -IncludeNeverLoggedOn      Include computer accounts where LastLogonDate is empty.
  -ReportDirectory           Plan, state, rollback, and HTML output directory.
  -Rollback                  Restore original enabled state and DN from a previous state CSV.
  -RollbackStatePath         State CSV created by a prior run. Required with -Rollback.
  -SendEmail                 Email the HTML report after processing.
  -SmtpServer                SMTP server required with -SendEmail.
  -From                      Sender address required with -SendEmail.
  -To                        Recipient address list required with -SendEmail.
  -ContactEmail              Optional contact mailbox included in the report text.
  -WhatIf                    Preview disables, moves, rollback, and email sends without changing AD.
'@
}

function Resolve-ReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Get-AdComputerQueryParameter {
    param(
        [Parameter()]
        [string]$AdditionalLdapFilter
    )

    $filter = if ($IncludeDisabledComputers) { '*' } else { 'Enabled -eq $true' }
    $queryParameters = @{
        Filter = $filter
        Properties = @(
            'Created',
            'Description',
            'Enabled',
            'LastLogonDate',
            'OperatingSystem',
            'SamAccountName',
            'whenChanged'
        )
    }

    if ($SearchBase) {
        $queryParameters.SearchBase = $SearchBase
        $queryParameters.SearchScope = $SearchScope
    }
    if ($Server) {
        $queryParameters.Server = $Server
    }
    if ($AdditionalLdapFilter) {
        $normalizedLdapFilter = if ($AdditionalLdapFilter.StartsWith('(')) { $AdditionalLdapFilter } else { "($AdditionalLdapFilter)" }
        $enabledFilter = if ($IncludeDisabledComputers) { '' } else { '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' }
        $queryParameters.Remove('Filter')
        $queryParameters.LDAPFilter = "(&${normalizedLdapFilter}(objectClass=computer)${enabledFilter})"
    }

    $queryParameters
}

function Get-ComputerCommonName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    ($DistinguishedName -split ',', 2)[0]
}

function Get-PlannedDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OriginalDistinguishedName
    )

    if (-not $TargetOu -or $Action -notin @('MoveOnly', 'DisableAndMove')) {
        return $OriginalDistinguishedName
    }

    '{0},{1}' -f (Get-ComputerCommonName -DistinguishedName $OriginalDistinguishedName), $TargetOu
}

function Get-StaleComputerPlan {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Computer,

        [Parameter(Mandatory = $true)]
        [datetime]$Cutoff
    )

    foreach ($adComputer in $Computer) {
        $lastLogon = $adComputer.LastLogonDate
        $isNeverLoggedOn = $null -eq $lastLogon
        $isStale = ($lastLogon -and $lastLogon -lt $Cutoff) -or ($IncludeNeverLoggedOn -and $isNeverLoggedOn)
        $needsDisable = $Action -in @('DisableOnly', 'DisableAndMove') -and [bool]$adComputer.Enabled
        $needsMove = $Action -in @('MoveOnly', 'DisableAndMove') -and $TargetOu -and $adComputer.DistinguishedName -notlike "*,$TargetOu"
        $plannedDistinguishedName = Get-PlannedDistinguishedName -OriginalDistinguishedName $adComputer.DistinguishedName
        $planAction = if (-not $isStale) {
            'Skipped'
        } elseif ($Action -eq 'ReportOnly') {
            'ReportOnly'
        } elseif ($needsDisable -and $needsMove) {
            'DisableAndMove'
        } elseif ($needsDisable) {
            'Disable'
        } elseif ($needsMove) {
            'Move'
        } else {
            'NoChange'
        }

        [pscustomobject]@{
            Action = $planAction
            Name = $adComputer.Name
            SamAccountName = $adComputer.SamAccountName
            Enabled = [bool]$adComputer.Enabled
            LastLogonDate = $lastLogon
            Created = $adComputer.Created
            WhenChanged = $adComputer.whenChanged
            OperatingSystem = $adComputer.OperatingSystem
            Description = $adComputer.Description
            OriginalDistinguishedName = $adComputer.DistinguishedName
            PlannedDistinguishedName = $plannedDistinguishedName
            OriginalEnabled = [bool]$adComputer.Enabled
            PlannedEnabled = if ($Action -in @('DisableOnly', 'DisableAndMove')) { $false } else { [bool]$adComputer.Enabled }
            InactiveDaysThreshold = $InactiveDays
            CutoffDate = $Cutoff
            TargetOu = $TargetOu
            Reason = switch ($planAction) {
                'DisableAndMove' { 'Computer is stale, enabled, and outside the target OU.' }
                'Disable' { 'Computer is stale and enabled.' }
                'Move' { 'Computer is stale and outside the target OU.' }
                'NoChange' { 'Computer is stale but already matches the requested state.' }
                'ReportOnly' { 'Computer is stale; report-only mode was requested.' }
                'Skipped' {
                    if ($isNeverLoggedOn -and -not $IncludeNeverLoggedOn) {
                        'Computer has never logged on and IncludeNeverLoggedOn was not requested.'
                    } else {
                        'Computer is not older than the inactive-days threshold.'
                    }
                }
            }
        }
    }
}

function Invoke-StaleComputerAction {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    $results = [System.Collections.Generic.List[string]]::new()
    $currentDistinguishedName = $Item.OriginalDistinguishedName

    if ($Item.Action -in @('ReportOnly', 'Skipped', 'NoChange')) {
        return [pscustomobject]@{
            Result = $Item.Action
            ResultDetail = $Item.Reason
            CurrentDistinguishedName = $currentDistinguishedName
        }
    }

    if ($Item.Action -in @('Disable', 'DisableAndMove')) {
        if ($PSCmdlet.ShouldProcess($currentDistinguishedName, 'Disable AD computer account')) {
            $disableParameters = @{ Identity = $currentDistinguishedName }
            if ($Server) {
                $disableParameters.Server = $Server
            }
            Disable-ADAccount @disableParameters
            $results.Add('Disabled')
        } else {
            $results.Add('DisablePreviewed')
        }
    }

    if ($Item.Action -in @('Move', 'DisableAndMove')) {
        if ($PSCmdlet.ShouldProcess($currentDistinguishedName, "Move AD computer account to $TargetOu")) {
            $moveParameters = @{
                Identity = $currentDistinguishedName
                TargetPath = $TargetOu
            }
            if ($Server) {
                $moveParameters.Server = $Server
            }
            Move-ADObject @moveParameters
            $currentDistinguishedName = $Item.PlannedDistinguishedName
            $results.Add('Moved')
        } else {
            $results.Add('MovePreviewed')
        }
    }

    [pscustomobject]@{
        Result = ($results -join ';')
        ResultDetail = 'Completed planned action steps.'
        CurrentDistinguishedName = $currentDistinguishedName
    }
}

function Invoke-StaleComputerRollback {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    $results = [System.Collections.Generic.List[string]]::new()
    $currentDistinguishedName = if ($Item.CurrentDistinguishedName) { $Item.CurrentDistinguishedName } else { $Item.PlannedDistinguishedName }
    if (-not $currentDistinguishedName) {
        $currentDistinguishedName = $Item.OriginalDistinguishedName
    }

    if ($currentDistinguishedName -and $Item.OriginalDistinguishedName -and $currentDistinguishedName -ne $Item.OriginalDistinguishedName) {
        $originalParent = ($Item.OriginalDistinguishedName -split ',', 2)[1]
        if ($PSCmdlet.ShouldProcess($currentDistinguishedName, "Move AD computer account back to $originalParent")) {
            $moveParameters = @{
                Identity = $currentDistinguishedName
                TargetPath = $originalParent
            }
            if ($Server) {
                $moveParameters.Server = $Server
            }
            Move-ADObject @moveParameters
            $currentDistinguishedName = $Item.OriginalDistinguishedName
            $results.Add('MovedBack')
        } else {
            $results.Add('MoveBackPreviewed')
        }
    }

    $originalEnabled = [System.Convert]::ToBoolean($Item.OriginalEnabled)
    if ($originalEnabled) {
        if ($PSCmdlet.ShouldProcess($currentDistinguishedName, 'Enable AD computer account')) {
            $enableParameters = @{ Identity = $currentDistinguishedName }
            if ($Server) {
                $enableParameters.Server = $Server
            }
            Enable-ADAccount @enableParameters
            $results.Add('Enabled')
        } else {
            $results.Add('EnablePreviewed')
        }
    }

    if ($results.Count -eq 0) {
        $results.Add('NoRollbackNeeded')
    }

    [pscustomobject]@{
        Result = ($results -join ';')
        CurrentDistinguishedName = $currentDistinguishedName
    }
}

function ConvertTo-StaleComputerHtml {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Item,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedAt,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter()]
        [string]$ReportContactEmail
    )

    $contactLine = if ($ReportContactEmail) { "<p>Contact <a href=`"mailto:$ReportContactEmail`">$ReportContactEmail</a> if an account was disabled or moved in error.</p>" } else { '' }
    @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>$Title</title>
</head>
<body>
  <h1>$Title</h1>
  <p>Generated on $GeneratedAt. Threshold: $InactiveDays days. Action: $Action.</p>
  $contactLine
  $($Item | ConvertTo-Html -Fragment)
</body>
</html>
"@
}

function Send-HtmlReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$Body
    )

    if ($PSCmdlet.ShouldProcess(($To -join ', '), "Send email report: $Subject")) {
        Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $Body -BodyAsHtml
        return 'Sent'
    }

    'Previewed'
}

$willMove = $Action -in @('MoveOnly', 'DisableAndMove')
if ((-not $Rollback -and $willMove -and -not $TargetOu) -or
    ($Rollback -and -not $RollbackStatePath) -or
    ($SendEmail -and (-not $SmtpServer -or -not $From -or -not $To))) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop
$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$generatedAt = Get-Date

if ($Rollback) {
    $rollbackInput = @(Import-Csv -LiteralPath $RollbackStatePath)
    $rollbackStatePath = Join-Path $resolvedReportDirectory "ad-stale-computers-rollback-state-$timestamp.csv"
    $rollbackJsonPath = Join-Path $resolvedReportDirectory "ad-stale-computers-rollback-state-$timestamp.json"
    $rollbackHtmlPath = Join-Path $resolvedReportDirectory "ad-stale-computers-rollback-state-$timestamp.html"

    $rollbackState = foreach ($item in $rollbackInput) {
        $result = try {
            Invoke-StaleComputerRollback -Item $item -WhatIf:$WhatIfPreference
        } catch {
            [pscustomobject]@{
                Result = "Failed: $($_.Exception.Message)"
                CurrentDistinguishedName = if ($item.CurrentDistinguishedName) { $item.CurrentDistinguishedName } else { $item.PlannedDistinguishedName }
            }
        }

        $item | Add-Member -NotePropertyName RollbackResult -NotePropertyValue $result.Result -Force
        $item | Add-Member -NotePropertyName RollbackCurrentDistinguishedName -NotePropertyValue $result.CurrentDistinguishedName -Force
        $item
    }

    $rollbackState | Export-Csv -Path $rollbackStatePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
    Set-Content -LiteralPath $rollbackJsonPath -Value (@($rollbackState) | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false
    $rollbackHtml = ConvertTo-StaleComputerHtml -Item $rollbackState -GeneratedAt $generatedAt -Title 'AD stale computer rollback state' -ReportContactEmail $ContactEmail
    Set-Content -LiteralPath $rollbackHtmlPath -Value $rollbackHtml -Encoding utf8 -WhatIf:$false
    $emailResult = if ($SendEmail) { Send-HtmlReport -Subject "AD stale computer rollback report $generatedAt" -Body $rollbackHtml -WhatIf:$WhatIfPreference } else { 'NotRequested' }

    [pscustomobject]@{
        Mode = 'Rollback'
        RollbackInputPath = (Resolve-Path -LiteralPath $RollbackStatePath).Path
        RollbackStateCsvPath = (Resolve-Path -LiteralPath $rollbackStatePath).Path
        RollbackStateJsonPath = (Resolve-Path -LiteralPath $rollbackJsonPath).Path
        RollbackStateHtmlPath = (Resolve-Path -LiteralPath $rollbackHtmlPath).Path
        EmailResult = $emailResult
        RollbackItemCount = @($rollbackState).Count
        RolledBackCount = @($rollbackState | Where-Object { $_.RollbackResult -match 'MovedBack|Enabled' }).Count
        PreviewedCount = @($rollbackState | Where-Object { $_.RollbackResult -match 'Previewed' }).Count
        FailedCount = @($rollbackState | Where-Object { $_.RollbackResult -like 'Failed:*' }).Count
        Results = @($rollbackState)
    }
    return
}

$cutoff = (Get-Date).AddDays(-$InactiveDays)
$planPath = Join-Path $resolvedReportDirectory "ad-stale-computers-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "ad-stale-computers-plan-$timestamp.json"
$planHtmlPath = Join-Path $resolvedReportDirectory "ad-stale-computers-plan-$timestamp.html"
$statePath = Join-Path $resolvedReportDirectory "ad-stale-computers-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "ad-stale-computers-state-$timestamp.json"
$stateHtmlPath = Join-Path $resolvedReportDirectory "ad-stale-computers-state-$timestamp.html"
$rollbackPath = Join-Path $resolvedReportDirectory "ad-stale-computers-rollback-input-$timestamp.csv"

$queryParameters = Get-AdComputerQueryParameter -AdditionalLdapFilter $LdapFilter
$computers = @(Get-ADComputer @queryParameters | Sort-Object Name)
$plan = @(Get-StaleComputerPlan -Computer $computers -Cutoff $cutoff)
$planHtml = ConvertTo-StaleComputerHtml -Item $plan -GeneratedAt $generatedAt -Title 'AD stale computer plan' -ReportContactEmail $ContactEmail
$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $planJsonPath -Value (@($plan) | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $planHtmlPath -Value $planHtml -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $result = try {
        Invoke-StaleComputerAction -Item $item -WhatIf:$WhatIfPreference
    } catch {
        [pscustomobject]@{
            Result = "Failed: $($_.Exception.Message)"
            ResultDetail = $_.Exception.Message
            CurrentDistinguishedName = $item.OriginalDistinguishedName
        }
    }

    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result.Result -Force
    $item | Add-Member -NotePropertyName ResultDetail -NotePropertyValue $result.ResultDetail -Force
    $item | Add-Member -NotePropertyName CurrentDistinguishedName -NotePropertyValue $result.CurrentDistinguishedName -Force
    $item
}

$stateHtml = ConvertTo-StaleComputerHtml -Item $state -GeneratedAt $generatedAt -Title 'AD stale computer state' -ReportContactEmail $ContactEmail
$rollbackInput = @($state | Where-Object { $_.Result -match 'Disabled|Moved' })
$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $stateJsonPath -Value (@($state) | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $stateHtmlPath -Value $stateHtml -Encoding utf8 -WhatIf:$false
$rollbackInput | Export-Csv -Path $rollbackPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$emailResult = if ($SendEmail) { Send-HtmlReport -Subject "AD stale computer report $generatedAt" -Body $stateHtml -WhatIf:$WhatIfPreference } else { 'NotRequested' }

[pscustomobject]@{
    Mode = 'PlanAndApply'
    InactiveDays = $InactiveDays
    CutoffDate = $cutoff
    Action = $Action
    SearchBase = $SearchBase
    SearchScope = if ($SearchBase) { $SearchScope } else { $null }
    Server = $Server
    TargetOu = $TargetOu
    IncludeDisabledComputers = [bool]$IncludeDisabledComputers
    IncludeNeverLoggedOn = [bool]$IncludeNeverLoggedOn
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    PlanHtmlPath = (Resolve-Path -LiteralPath $planHtmlPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    StateHtmlPath = (Resolve-Path -LiteralPath $stateHtmlPath).Path
    RollbackInputPath = (Resolve-Path -LiteralPath $rollbackPath).Path
    EmailResult = $emailResult
    ComputerCount = @($computers).Count
    PlannedChangeCount = @($plan | Where-Object { $_.Action -in @('Disable', 'Move', 'DisableAndMove') }).Count
    ChangedCount = @($state | Where-Object { $_.Result -match 'Disabled|Moved' }).Count
    PreviewedCount = @($state | Where-Object { $_.Result -match 'Previewed' }).Count
    SkippedCount = @($state | Where-Object Result -eq 'Skipped').Count
    NoChangeCount = @($state | Where-Object Result -eq 'NoChange').Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    Results = @($state)
}
