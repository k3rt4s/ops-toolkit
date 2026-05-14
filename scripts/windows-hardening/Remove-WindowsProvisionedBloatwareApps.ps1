<#
.SYNOPSIS
Plan, remove, and partially roll back Windows 11 AppX bloatware packages.

.INSTRUCTIONS
- Read the root README.md before running this script.
- This script is scoped to Windows 11. It exits on older Windows builds unless -SkipWindows11Check is used.
- Run with -WhatIf first and review the generated inventory, plan, and state CSV/JSON files.
- Run from an elevated shell before applying live removal or rollback changes.
- Keep the protected list conservative. Do not remove Store, App Installer, Winget, WebView, UI runtimes, codecs, security UI, shell packages, or common dependencies.
- Use -Rollback with a prior state CSV to re-register packages that still have a local AppxManifest.xml and to generate restore guidance for packages that must be restored from Store/winget/media.

.PURPOSE
Use this to remove consumer, promotional, gaming, social, and optional inbox
AppX packages from Windows 11 while preserving core platform packages. The
package list is informed by Microsoft AppX servicing documentation, common
Windows 11 debloat tooling, and infosec/admin community guidance.

.REQUIRED SYNTAX
pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -WhatIf
pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -RemoveProvisionedPackages -InstalledPackageScope AllUsers -WhatIf
pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -Rollback -RollbackStatePath .\reports\windows-hardening\windows11-appx-removal-state-YYYYMMDD_HHMMSS.csv -WhatIf

.OUTPUTS
Writes inventory, plan, state, and rollback guidance CSV/JSON files under
reports\windows-hardening by default. Returns a summary object with report
paths, changed/skipped counts, removed items, protected matches, and rollback
guidance.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RemoveListPath = (Join-Path $PSScriptRoot '..\..\data\windows-hardening\windows11-appx-remove.txt'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ProtectedListPath = (Join-Path $PSScriptRoot '..\..\data\windows-hardening\windows11-appx-protected.txt'),

    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers', 'None')]
    [string]$InstalledPackageScope = 'CurrentUser',

    [Parameter()]
    [switch]$RemoveProvisionedPackages,

    [Parameter()]
    [switch]$Rollback,

    [Parameter()]
    [string]$RollbackStatePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\windows-hardening'),

    [Parameter()]
    [switch]$SkipWindows11Check
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows 11 AppX bloatware removal.

Usage:
  pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -WhatIf
  pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -RemoveProvisionedPackages -InstalledPackageScope AllUsers -WhatIf
  pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -Rollback -RollbackStatePath .\reports\windows-hardening\windows11-appx-removal-state-YYYYMMDD_HHMMSS.csv -WhatIf

Options:
  -RemoveListPath             Text file of package-name patterns to remove.
  -ProtectedListPath          Text file of package-name patterns that must be preserved.
  -InstalledPackageScope      CurrentUser, AllUsers, or None. Default: CurrentUser.
  -RemoveProvisionedPackages  Also remove matching provisioned packages so new profiles do not receive them.
  -Rollback                   Re-register packages from a prior state CSV when local package manifests still exist.
  -RollbackStatePath          Prior state CSV. If omitted with -Rollback, the newest removal state CSV is used.
  -ReportDirectory            Report output directory.
  -SkipWindows11Check         Allow execution on non-Windows 11 builds.
  -WhatIf                     Write reports and preview removals or rollback actions.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsBuildNumber {
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    [int]$currentVersion.CurrentBuildNumber
}

function Import-PatternList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Pattern list not found: $Path"
    }

    @(Get-Content -LiteralPath $Path |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') } |
            Sort-Object -Unique)
}

function Test-PatternMatch {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Pattern
    )

    foreach ($item in $Pattern) {
        if ($Value -like "*$item*") {
            return $true
        }
    }

    $false
}

function Get-MatchingPattern {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Pattern
    )

    foreach ($item in $Pattern) {
        if ($Value -like "*$item*") {
            return $item
        }
    }

    ''
}

function Get-InstalledAppxInventory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'AllUsers', 'None')]
        [string]$Scope
    )

    if ($Scope -eq 'None') {
        return @()
    }

    $query = @{}
    if ($Scope -eq 'AllUsers') {
        $query.AllUsers = $true
    }

    @(Get-AppxPackage @query | ForEach-Object {
            [pscustomobject]@{
                SourceKind = 'Installed'
                Scope = $Scope
                DisplayName = $_.Name
                PackageName = $_.PackageFullName
                PackageFullName = $_.PackageFullName
                PackageFamilyName = $_.PackageFamilyName
                PublisherId = $_.PublisherId
                Version = $_.Version
                Architecture = $_.Architecture
                InstallLocation = $_.InstallLocation
                SignatureKind = $_.SignatureKind
                IsFramework = $_.IsFramework
                IsResourcePackage = $_.IsResourcePackage
                IsBundle = $_.IsBundle
                NonRemovable = $_.NonRemovable
            }
        })
}

function Initialize-AppxModule {
    Import-Module Appx -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}

function Get-ProvisionedAppxInventory {
    $dismOutput = & dism.exe /Online /Get-ProvisionedAppxPackages /English 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "DISM provisioned AppX inventory failed with exit code $LASTEXITCODE. Output: $($dismOutput -join ' ')"
    }

    $packages = [System.Collections.Generic.List[object]]::new()
    $current = @{}
    foreach ($line in $dismOutput) {
        if ($line -match '^\s*$') {
            if ($current.ContainsKey('PackageName')) {
                $packages.Add([hashtable]$current)
                $current = @{}
            }
            continue
        }

        if ($line -match '^\s*([^:]+)\s*:\s*(.*)$') {
            $current[$matches[1].Trim()] = $matches[2].Trim()
        }
    }

    if ($current.ContainsKey('PackageName')) {
        $packages.Add([hashtable]$current)
    }

    @($packages | ForEach-Object {
            [pscustomobject]@{
                SourceKind = 'Provisioned'
                Scope = 'OnlineImage'
                DisplayName = $_['DisplayName']
                PackageName = $_['PackageName']
                PackageFullName = $_['PackageName']
                PackageFamilyName = ''
                PublisherId = ''
                Version = $_['Version']
                Architecture = $_['Architecture']
                InstallLocation = ''
                SignatureKind = ''
                IsFramework = $false
                IsResourcePackage = $false
                IsBundle = ''
                NonRemovable = $false
            }
        })
}

function Get-AppxRemovalPlan {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Inventory,

        [Parameter(Mandatory = $true)]
        [string[]]$RemovePattern,

        [Parameter(Mandatory = $true)]
        [string[]]$ProtectedPattern
    )

    foreach ($item in $Inventory) {
        $removeMatch = Get-MatchingPattern -Value $item.DisplayName -Pattern $RemovePattern
        if (-not $removeMatch) {
            $removeMatch = Get-MatchingPattern -Value $item.PackageName -Pattern $RemovePattern
        }

        $protectedMatch = Get-MatchingPattern -Value $item.DisplayName -Pattern $ProtectedPattern
        if (-not $protectedMatch) {
            $protectedMatch = Get-MatchingPattern -Value $item.PackageName -Pattern $ProtectedPattern
        }

        $isDependency = [bool]$item.IsFramework -or [bool]$item.IsResourcePackage
        $isProtected = [bool]$protectedMatch -or [bool]$item.NonRemovable -or $isDependency
        $action = if (-not $removeMatch) {
            'NoMatch'
        } elseif ($isProtected) {
            'Protected'
        } elseif ($item.SourceKind -eq 'Provisioned') {
            'RemoveProvisionedPackage'
        } else {
            'RemoveInstalledPackage'
        }

        [pscustomobject]@{
            SourceKind = $item.SourceKind
            Scope = $item.Scope
            DisplayName = $item.DisplayName
            PackageName = $item.PackageName
            PackageFullName = $item.PackageFullName
            PackageFamilyName = $item.PackageFamilyName
            Version = $item.Version
            Architecture = $item.Architecture
            InstallLocation = $item.InstallLocation
            IsFramework = $item.IsFramework
            IsResourcePackage = $item.IsResourcePackage
            NonRemovable = $item.NonRemovable
            RemovePattern = $removeMatch
            ProtectedPattern = $protectedMatch
            Action = $action
            Reason = switch ($action) {
                'NoMatch' { 'Package does not match the Windows 11 removal list.' }
                'Protected' { 'Package matched the protected list, is non-removable, or is a framework/resource package.' }
                'RemoveProvisionedPackage' { 'Provisioned package matches the Windows 11 removal list.' }
                'RemoveInstalledPackage' { 'Installed package matches the Windows 11 removal list.' }
            }
        }
    }
}

function Remove-PlannedAppxItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -eq 'RemoveProvisionedPackage') {
        if ($PSCmdlet.ShouldProcess($Item.PackageName, 'Remove provisioned AppX package from the online Windows 11 image')) {
            $dismOutput = & dism.exe /Online /Remove-ProvisionedAppxPackage /PackageName:$($Item.PackageName) /English 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "DISM failed to remove provisioned package $($Item.PackageName). Exit code $LASTEXITCODE. Output: $($dismOutput -join ' ')"
            }
            return 'Removed'
        }

        return 'Previewed'
    }

    if ($Item.Action -eq 'RemoveInstalledPackage') {
        if ($PSCmdlet.ShouldProcess($Item.PackageFullName, "Remove installed AppX package for scope $($Item.Scope)")) {
            if ($Item.Scope -eq 'AllUsers') {
                Remove-AppxPackage -Package $Item.PackageFullName -AllUsers -ErrorAction Stop
            } else {
                Remove-AppxPackage -Package $Item.PackageFullName -ErrorAction Stop
            }

            return 'Removed'
        }

        return 'Previewed'
    }

    'Skipped'
}

function Get-LatestRemovalStatePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $latest = Get-ChildItem -LiteralPath $Directory -Filter 'windows11-appx-removal-state-*.csv' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latest) {
        throw "No prior removal state CSV found in $Directory. Pass -RollbackStatePath explicitly."
    }

    $latest.FullName
}

function Get-RollbackPlan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StatePath
    )

    if (-not (Test-Path -LiteralPath $StatePath)) {
        throw "Rollback state CSV not found: $StatePath"
    }

    $rows = @(Import-Csv -LiteralPath $StatePath | Where-Object {
            $_.Result -in @('Removed', 'Previewed') -and $_.Action -in @('RemoveInstalledPackage', 'RemoveProvisionedPackage')
        })

    foreach ($row in $rows) {
        $manifestPath = if ($row.InstallLocation) { Join-Path $row.InstallLocation 'AppxManifest.xml' } else { '' }
        $canRegister = $row.Action -eq 'RemoveInstalledPackage' -and $manifestPath -and (Test-Path -LiteralPath $manifestPath)
        [pscustomobject]@{
            SourceKind = $row.SourceKind
            Scope = $row.Scope
            DisplayName = $row.DisplayName
            PackageName = $row.PackageName
            PackageFullName = $row.PackageFullName
            PackageFamilyName = $row.PackageFamilyName
            InstallLocation = $row.InstallLocation
            ManifestPath = $manifestPath
            Action = if ($canRegister) { 'RegisterLocalManifest' } else { 'RestoreFromStoreOrSource' }
            RestoreCommand = if ($canRegister) { "Add-AppxPackage -DisableDevelopmentMode -Register `"$manifestPath`"" } else { "Review package '$($row.DisplayName)' and reinstall from Microsoft Store, winget, OEM media, or business app source." }
            Reason = if ($canRegister) { 'Local package manifest still exists and can be re-registered.' } else { 'No local manifest is available for automatic restore, or the item was provisioned in the image.' }
        }
    }
}

function Invoke-AppxRollbackItem {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -ne 'RegisterLocalManifest') {
        return 'GuidanceOnly'
    }

    if ($PSCmdlet.ShouldProcess($Item.ManifestPath, 'Re-register AppX package from local manifest')) {
        Add-AppxPackage -DisableDevelopmentMode -Register $Item.ManifestPath -ErrorAction Stop
        return 'Registered'
    }

    'Previewed'
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$buildNumber = Get-WindowsBuildNumber
if (-not $SkipWindows11Check -and $buildNumber -lt 22000) {
    throw "This script is scoped to Windows 11. Detected build $buildNumber. Use -SkipWindows11Check only after reviewing the plan for this OS."
}

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw 'Run from an elevated PowerShell session before applying live Windows 11 AppX removal or rollback changes. Use -WhatIf to generate review reports without elevation.'
}

Initialize-AppxModule

if ($Rollback) {
    $statePath = if ($RollbackStatePath) { $RollbackStatePath } else { Get-LatestRemovalStatePath -Directory $resolvedReportDirectory }
    $rollbackPlan = @(Get-RollbackPlan -StatePath $statePath)
    $rollbackPlanPath = Join-Path $resolvedReportDirectory "windows11-appx-rollback-plan-$timestamp.csv"
    $rollbackPlanJsonPath = Join-Path $resolvedReportDirectory "windows11-appx-rollback-plan-$timestamp.json"

    $rollbackResults = foreach ($item in $rollbackPlan) {
        $result = Invoke-AppxRollbackItem -Item $item -WhatIf:$WhatIfPreference
        $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
        $item
    }

    $rollbackResults | Export-Csv -Path $rollbackPlanPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
    Set-Content -LiteralPath $rollbackPlanJsonPath -Value (@($rollbackResults) | ConvertTo-Json -Depth 4) -Encoding utf8 -WhatIf:$false

    [pscustomobject]@{
        TargetOs = 'Windows 11'
        Operation = 'Rollback'
        DetectedBuild = $buildNumber
        RollbackStatePath = (Resolve-Path -LiteralPath $statePath).Path
        RollbackPlanCsvPath = (Resolve-Path -LiteralPath $rollbackPlanPath).Path
        RollbackPlanJsonPath = (Resolve-Path -LiteralPath $rollbackPlanJsonPath).Path
        PlannedRollbackCount = @($rollbackPlan).Count
        RegisteredCount = @($rollbackResults | Where-Object Result -eq 'Registered').Count
        GuidanceOnlyCount = @($rollbackResults | Where-Object Result -eq 'GuidanceOnly').Count
        PreviewedCount = @($rollbackResults | Where-Object Result -eq 'Previewed').Count
        RestoreGuidance = @($rollbackResults)
        Notes = 'Rollback can only re-register packages whose local manifest still exists. Provisioned packages usually require Store, winget, OEM media, or business app source restore.'
    }
    return
}

$removePatterns = Import-PatternList -Path $RemoveListPath
$protectedPatterns = Import-PatternList -Path $ProtectedListPath
$installedInventory = @(Get-InstalledAppxInventory -Scope $InstalledPackageScope)
$provisionedInventory = if ($RemoveProvisionedPackages) { @(Get-ProvisionedAppxInventory) } else { @() }
$inventory = @($installedInventory + $provisionedInventory)
$plan = @(Get-AppxRemovalPlan -Inventory $inventory -RemovePattern $removePatterns -ProtectedPattern $protectedPatterns)

$inventoryPath = Join-Path $resolvedReportDirectory "windows11-appx-inventory-$timestamp.csv"
$inventoryJsonPath = Join-Path $resolvedReportDirectory "windows11-appx-inventory-$timestamp.json"
$planPath = Join-Path $resolvedReportDirectory "windows11-appx-removal-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "windows11-appx-removal-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "windows11-appx-removal-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "windows11-appx-removal-state-$timestamp.json"

$inventory | Export-Csv -Path $inventoryPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$inventoryJson = if (@($inventory).Count) { @($inventory) | ConvertTo-Json -Depth 4 } else { '[]' }
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $inventoryJsonPath -Value $inventoryJson -Encoding utf8 -WhatIf:$false
$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

Write-Information "Windows 11 AppX inventory written to $inventoryPath" -InformationAction Continue
Write-Information "Windows 11 AppX removal plan written to $planPath" -InformationAction Continue

$state = foreach ($item in $plan) {
    $result = if ($item.Action -in @('RemoveInstalledPackage', 'RemoveProvisionedPackage')) {
        try {
            Remove-PlannedAppxItem -Item $item -WhatIf:$WhatIfPreference
        } catch {
            "Failed: $($_.Exception.Message)"
        }
    } else {
        'Skipped'
    }

    $item | Add-Member -NotePropertyName Result -NotePropertyValue $result -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

Write-Information "Windows 11 AppX removal state written to $statePath" -InformationAction Continue

[pscustomobject]@{
    TargetOs = 'Windows 11'
    Operation = 'Remove'
    DetectedBuild = $buildNumber
    InstalledPackageScope = $InstalledPackageScope
    RemoveProvisionedPackages = [bool]$RemoveProvisionedPackages
    RemoveListPath = (Resolve-Path -LiteralPath $RemoveListPath).Path
    ProtectedListPath = (Resolve-Path -LiteralPath $ProtectedListPath).Path
    InventoryCsvPath = (Resolve-Path -LiteralPath $inventoryPath).Path
    InventoryJsonPath = (Resolve-Path -LiteralPath $inventoryJsonPath).Path
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    InventoryCount = @($inventory).Count
    PlannedRemovalCount = @($plan | Where-Object Action -in @('RemoveInstalledPackage', 'RemoveProvisionedPackage')).Count
    RemovedCount = @($state | Where-Object Result -eq 'Removed').Count
    PreviewedCount = @($state | Where-Object Result -eq 'Previewed').Count
    ProtectedCount = @($plan | Where-Object Action -eq 'Protected').Count
    SkippedCount = @($state | Where-Object Result -eq 'Skipped').Count
    FailedCount = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    RemovedOrPreviewedItems = @($state | Where-Object Result -in @('Removed', 'Previewed'))
    ProtectedItems = @($plan | Where-Object Action -eq 'Protected')
    Notes = 'Review state CSV before using -Rollback. Rollback is best-effort because deprovisioned Windows Store apps usually need Store, winget, OEM media, or business app source restore.'
}
