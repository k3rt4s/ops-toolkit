<#
.SYNOPSIS
Map or remove a persistent Windows drive connection to an Azure Files share.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Run in the Windows user context that should receive the mapped drive.
- Always run with -WhatIf first and review the generated plan/state reports.
- Pass storage account keys at runtime only; they are never written to reports.
- Generated reports are written under reports\azure by default.

.PURPOSE
Use this script to create or remove a persistent mapped drive for Azure Files.
It stores the Azure Files credential in Windows Credential Manager when mapping,
optionally removes an existing mapping first, and writes plan/state reports that
do not include the storage account key.

.REQUIRED SYNTAX
pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -DriveLetter Z -StorageAccountName examplestorage -ShareName data -StorageAccountKey "<key>" -WhatIf
pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -Action Remove -DriveLetter Z -StorageAccountName examplestorage -RemoveCredential -WhatIf

.OUTPUTS
Writes plan/state JSON reports under reports\azure by default. Returns a
summary object with the target UNC path, report paths, and result.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateSet('Map', 'Remove')]
    [string]$Action = 'Map',

    [Parameter()]
    [ValidatePattern('^[A-Z]$')]
    [string]$DriveLetter,

    [Parameter()]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ShareName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$StorageAccountKey,

    [Parameter()]
    [switch]$ReplaceExisting,

    [Parameter()]
    [switch]$RemoveCredential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -DriveLetter Z -StorageAccountName examplestorage -ShareName data -StorageAccountKey "<key>" -WhatIf
  pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -Action Remove -DriveLetter Z -StorageAccountName examplestorage -RemoveCredential -WhatIf

Options:
  -Action              Map or Remove. Defaults to Map.
  -DriveLetter         Drive letter to map or remove, without a colon.
  -StorageAccountName  Azure Storage account name.
  -ShareName           Azure file share name. Required when Action is Map.
  -StorageAccountKey   Storage account key. Required when Action is Map.
  -ReplaceExisting     Remove an existing mapping before creating the new one.
  -RemoveCredential    Remove the Windows Credential Manager entry.
  -ReportDirectory     Plan/state output directory.
  -WhatIf              Preview credential and drive changes.
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

function Invoke-CredentialManagerCommand {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Add', 'Delete')]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$TargetName,

        [Parameter()]
        [string]$UserName,

        [Parameter()]
        [string]$Secret
    )

    if ($Mode -eq 'Add') {
        if ($PSCmdlet.ShouldProcess($TargetName, 'Store Azure Files credential in Windows Credential Manager')) {
            cmdkey.exe /add:$TargetName /user:$UserName /pass:$Secret | Out-Null
            return 'CredentialStored'
        }
        return 'CredentialStorePreviewed'
    }

    if ($PSCmdlet.ShouldProcess($TargetName, 'Remove Azure Files credential from Windows Credential Manager')) {
        cmdkey.exe /delete:$TargetName | Out-Null
        return 'CredentialRemoved'
    }

    'CredentialRemovePreviewed'
}

if (-not $DriveLetter -or -not $StorageAccountName -or
    ($Action -eq 'Map' -and (-not $ShareName -or -not $StorageAccountKey))) {
    Show-Usage
    exit 2
}

$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$planPath = Join-Path $resolvedReportDirectory "azure-files-mapped-drive-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "azure-files-mapped-drive-state-$timestamp.json"
$target = "$DriveLetter`:"
$credentialTarget = "$StorageAccountName.file.core.windows.net"
$userName = "Azure\$StorageAccountName"
$root = if ($ShareName) { "\\$StorageAccountName.file.core.windows.net\$ShareName" } else { $null }
$existingDrive = Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue

$plan = [pscustomobject]@{
    GeneratedAt = Get-Date
    Action = $Action
    DriveLetter = $DriveLetter
    Target = $target
    Root = $root
    StorageAccountName = $StorageAccountName
    CredentialTarget = $credentialTarget
    ShareName = $ShareName
    ReplaceExisting = [bool]$ReplaceExisting
    RemoveCredential = [bool]$RemoveCredential
    ExistingDriveRoot = if ($existingDrive) { $existingDrive.Root } else { $null }
    StorageAccountKeyWrittenToReports = $false
}
Set-Content -LiteralPath $planPath -Value ($plan | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false

$results = [System.Collections.Generic.List[string]]::new()
if ($existingDrive -and ($Action -eq 'Remove' -or $ReplaceExisting)) {
    if ($PSCmdlet.ShouldProcess($target, 'Remove existing mapped drive')) {
        Remove-PSDrive -Name $DriveLetter -Force
        $results.Add('DriveRemoved')
    } else {
        $results.Add('DriveRemovePreviewed')
    }
} elseif ($existingDrive -and $Action -eq 'Map') {
    throw "Drive $target already exists. Re-run with -ReplaceExisting to remove it before mapping."
}

if ($Action -eq 'Map') {
    $credentialResult = Invoke-CredentialManagerCommand -Mode Add -TargetName $credentialTarget -UserName $userName -Secret $StorageAccountKey -WhatIf:$WhatIfPreference
    $results.Add($credentialResult)

    if ($PSCmdlet.ShouldProcess($target, "Map Azure file share $root")) {
        New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $root -Persist | Out-Null
        $results.Add('DriveMapped')
    } else {
        $results.Add('DriveMapPreviewed')
    }
}

if ($RemoveCredential -or $Action -eq 'Remove') {
    $credentialResult = Invoke-CredentialManagerCommand -Mode Delete -TargetName $credentialTarget -WhatIf:$WhatIfPreference
    $results.Add($credentialResult)
}

$driveAfter = Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue
$state = [pscustomobject]@{
    GeneratedAt = Get-Date
    Action = $Action
    DriveLetter = $DriveLetter
    Target = $target
    Root = $root
    StorageAccountName = $StorageAccountName
    CredentialTarget = $credentialTarget
    Results = $results -join ';'
    DriveExistsAfterRun = [bool]$driveAfter
    DriveRootAfterRun = if ($driveAfter) { $driveAfter.Root } else { $null }
    StorageAccountKeyWrittenToReports = $false
}
Set-Content -LiteralPath $statePath -Value ($state | ConvertTo-Json -Depth 5) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    Action = $Action
    DriveLetter = $DriveLetter
    Root = $root
    Results = $state.Results
    PlanPath = (Resolve-Path -LiteralPath $planPath).Path
    StatePath = (Resolve-Path -LiteralPath $statePath).Path
    StorageAccountKeyWrittenToReports = $false
}
