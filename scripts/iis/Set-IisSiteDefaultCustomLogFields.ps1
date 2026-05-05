<#
.SYNOPSIS
Set IIS site-default custom logging fields.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Confirm the server should apply these fields to IIS site defaults, not one site.
- Run from an elevated shell on the IIS server.
- Run with -WhatIf first before making live changes.
- Review the summary output before rerunning without -WhatIf.

.PURPOSE
Use this when IIS should log reverse-proxy or load-balancer request headers,
such as X-Forwarded-For, through site-default custom logging fields.

.REQUIRED SYNTAX
pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -WhatIf

Custom field example:
pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -CustomField @{ logFieldName = "X-Real-IP"; sourceName = "X-Real-IP"; sourceType = "RequestHeader" } -WhatIf

.OUTPUTS
Returns one summary object containing the IIS configuration target,
changed/skipped counts, and per-field results with old value, new value, action,
and reason.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [hashtable[]]$CustomField = @(
        @{
            logFieldName = 'X-Forwarded-For'
            sourceName = 'X-Forwarded-For'
            sourceType = 'RequestHeader'
        }
    )
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Invalid custom field input.

Usage:
  pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -WhatIf
  pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -CustomField @{ logFieldName = "X-Real-IP"; sourceName = "X-Real-IP"; sourceType = "RequestHeader" } -WhatIf

Required hashtable keys:
  logFieldName  IIS custom log field name.
  sourceName    Source header or server variable name.
  sourceType    IIS source type, for example RequestHeader.

Options:
  -CustomField  One or more custom log field hashtables. Defaults to X-Forwarded-For.
  -WhatIf       Preview IIS changes and summary output without applying them.
'@
}

function ConvertTo-CustomLogField {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Field
    )

    foreach ($key in @('logFieldName', 'sourceName', 'sourceType')) {
        if (-not $Field.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$Field[$key])) {
            Show-Usage
            throw "CustomField is missing required key '$key'."
        }
    }

    $logFieldName = [string]$Field.logFieldName
    $sourceName = [string]$Field.sourceName
    $sourceType = [string]$Field.sourceType

    if ($logFieldName -notmatch "^[A-Za-z0-9_.:-]+$") {
        throw "Custom log field name '$logFieldName' contains unsupported characters."
    }

    [pscustomobject]@{
        logFieldName = $logFieldName
        sourceName = $sourceName
        sourceType = $sourceType
    }
}

$filter = 'system.applicationHost/sites/siteDefaults/logFile/customFields'
$psPath = 'MACHINE/WEBROOT/APPHOST'
$target = 'IIS siteDefaults custom log fields'

$changedCount = 0
$skippedCount = 0
$fields = @($CustomField | ForEach-Object { ConvertTo-CustomLogField -Field $_ })

Import-Module WebAdministration -ErrorAction Stop

$existingFields = @(Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection)

$results = foreach ($field in $fields) {
    $existing = $existingFields | Where-Object { $_.logFieldName -eq $field.logFieldName } | Select-Object -First 1
    $oldSourceName = if ($existing) { [string]$existing.sourceName } else { $null }
    $oldSourceType = if ($existing) { [string]$existing.sourceType } else { $null }
    $action = if ($existing) { 'Update' } else { 'Add' }
    $changed = $false

    if ($existing -and $oldSourceName -eq $field.sourceName -and $oldSourceType -eq $field.sourceType) {
        $skippedCount++
        [pscustomobject]@{
            LogFieldName = $field.logFieldName
            OldSourceName = $oldSourceName
            NewSourceName = $field.sourceName
            OldSourceType = $oldSourceType
            NewSourceType = $field.sourceType
            Action = 'None'
            Changed = $false
            Reason = 'Already set'
        }
        continue
    }

    if ($existing) {
        if ($PSCmdlet.ShouldProcess($target, "Update custom log field $($field.logFieldName)")) {
            Set-WebConfigurationProperty -PSPath $psPath -Filter "$filter/add[@logFieldName='$($field.logFieldName)']" -Name sourceName -Value $field.sourceName
            Set-WebConfigurationProperty -PSPath $psPath -Filter "$filter/add[@logFieldName='$($field.logFieldName)']" -Name sourceType -Value $field.sourceType
            $changed = $true
            $changedCount++
        }
    } elseif ($PSCmdlet.ShouldProcess($target, "Add custom log field $($field.logFieldName)")) {
        Add-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name '.' -Value @{
            logFieldName = $field.logFieldName
            sourceName = $field.sourceName
            sourceType = $field.sourceType
        }
        $changed = $true
        $changedCount++
    }

    [pscustomobject]@{
        LogFieldName = $field.logFieldName
        OldSourceName = $oldSourceName
        NewSourceName = $field.sourceName
        OldSourceType = $oldSourceType
        NewSourceType = $field.sourceType
        Action = $action
        Changed = $changed
        Reason = if ($changed) { 'Updated' } else { 'Previewed' }
    }
}

[pscustomobject]@{
    Target = $target
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    Results = @($results)
}
