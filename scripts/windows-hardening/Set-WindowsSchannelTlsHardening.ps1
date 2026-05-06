<#
.SYNOPSIS
Plan and apply a Windows Schannel TLS hardening baseline.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\ops-toolkit\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell before applying live registry changes.
- Backups are written before live registry changes unless -SkipRegistryBackup is used.
- Reboot after applying changes so Schannel consumers reacquire TLS settings.

.PURPOSE
Use this to apply a TLS 1.2-only Windows Schannel baseline that disables legacy
SSL/TLS protocol versions, sets a hardened cipher suite order, and enables
strong .NET and WinHTTP TLS defaults.

.REQUIRED SYNTAX
pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1 -WhatIf
pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1

.OUTPUTS
Writes a plan CSV and JSON under reports\windows-hardening by default. Live runs
also export relevant registry branches to .reg files before changes unless
-SkipRegistryBackup is used. Returns a summary object with report and backup
paths, changed/skipped counts, and restart-required status.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Tls12Only')]
    [string]$Baseline = 'Tls12Only',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\windows-hardening'),

    [Parameter()]
    [switch]$SkipRegistryBackup,

    [Parameter()]
    [switch]$SkipCipherSuiteOrder,

    [Parameter()]
    [switch]$SkipDotNetStrongCrypto,

    [Parameter()]
    [switch]$SkipWinHttpDefaults,

    [Parameter()]
    [switch]$IncludeCurrentUserInternetSettings
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Windows Schannel TLS hardening.

Usage:
  pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1 -WhatIf
  pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1

Options:
  -Baseline                           Baseline to apply. Currently: Tls12Only.
  -ReportDirectory                    Plan and backup output directory.
  -SkipRegistryBackup                 Do not export registry backup files before live changes.
  -SkipCipherSuiteOrder               Do not set the cipher suite order policy registry value.
  -SkipDotNetStrongCrypto             Do not set .NET strong crypto defaults.
  -SkipWinHttpDefaults                Do not set WinHTTP default secure protocol values.
  -IncludeCurrentUserInternetSettings Also set HKCU Internet Settings\SecureProtocols.
  -WhatIf                             Write the plan and preview registry changes.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $property) {
        return $null
    }

    $property.$Name
}

function Get-RegistryPlanItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'String')]
        [string]$PropertyType,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$DesiredValue,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $currentValue = Get-RegistryValue -Path $Path -Name $Name
    $exists = $null -ne $currentValue
    $valueMatches = $exists -and ([string]$currentValue -eq [string]$DesiredValue)

    [pscustomobject]@{
        Category = $Category
        RegistryPath = $Path
        ValueName = $Name
        PropertyType = $PropertyType
        CurrentValue = $currentValue
        DesiredValue = $DesiredValue
        Action = if ($valueMatches) { 'NoChange' } elseif ($exists) { 'SetValue' } else { 'CreateValue' }
        Reason = $Reason
    }
}

function Add-DWordPlanItem {
    param(
        [Parameter()]
        [System.Collections.Generic.List[object]]$Plan,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $Plan.Add((Get-RegistryPlanItem -Category $Category -Path $Path -Name $Name -PropertyType DWord -DesiredValue $Value -Reason $Reason))
}

function Add-StringPlanItem {
    param(
        [Parameter()]
        [System.Collections.Generic.List[object]]$Plan,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $Plan.Add((Get-RegistryPlanItem -Category $Category -Path $Path -Name $Name -PropertyType String -DesiredValue $Value -Reason $Reason))
}

function Get-CipherSuiteOrder {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ([System.Version]$os.Version -lt [System.Version]'10.0') {
        return @(
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_CBC_SHA'
        )
    }

    @(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
    )
}

function Get-TlsHardeningPlan {
    param(
        [Parameter()]
        [switch]$SkipCipherSuiteOrder,

        [Parameter()]
        [switch]$SkipDotNetStrongCrypto,

        [Parameter()]
        [switch]$SkipWinHttpDefaults,

        [Parameter()]
        [switch]$IncludeCurrentUserInternetSettings
    )

    $plan = [System.Collections.Generic.List[object]]::new()
    $protocolRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

    $disabledProtocols = @(
        'Multi-Protocol Unified Hello',
        'PCT 1.0',
        'SSL 2.0',
        'SSL 3.0',
        'TLS 1.0',
        'TLS 1.1'
    )

    foreach ($protocol in $disabledProtocols) {
        foreach ($role in @('Client', 'Server')) {
            $path = Join-Path $protocolRoot "$protocol\$role"
            Add-DWordPlanItem -Plan $plan -Category 'Protocol' -Path $path -Name Enabled -Value 0 -Reason "Disable legacy protocol $protocol for $role."
            Add-DWordPlanItem -Plan $plan -Category 'Protocol' -Path $path -Name DisabledByDefault -Value 1 -Reason "Disable legacy protocol $protocol by default for $role."
        }
    }

    foreach ($role in @('Client', 'Server')) {
        $path = Join-Path $protocolRoot "TLS 1.2\$role"
        Add-DWordPlanItem -Plan $plan -Category 'Protocol' -Path $path -Name Enabled -Value 1 -Reason "Enable TLS 1.2 for $role."
        Add-DWordPlanItem -Plan $plan -Category 'Protocol' -Path $path -Name DisabledByDefault -Value 0 -Reason "Allow TLS 1.2 by default for $role."
    }

    if (-not $SkipCipherSuiteOrder) {
        $cipherSuitePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
        Add-StringPlanItem -Plan $plan -Category 'CipherSuiteOrder' -Path $cipherSuitePath -Name Functions -Value ([string]::Join(',', (Get-CipherSuiteOrder))) -Reason 'Set hardened TLS cipher suite order.'
    }

    if (-not $SkipDotNetStrongCrypto) {
        foreach ($path in @(
                'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
                'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            )) {
            Add-DWordPlanItem -Plan $plan -Category 'DotNet' -Path $path -Name SystemDefaultTlsVersions -Value 1 -Reason '.NET should use OS TLS defaults.'
            Add-DWordPlanItem -Plan $plan -Category 'DotNet' -Path $path -Name SchUseStrongCrypto -Value 1 -Reason '.NET should prefer strong cryptography.'
        }
    }

    if (-not $SkipWinHttpDefaults) {
        foreach ($path in @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            )) {
            Add-DWordPlanItem -Plan $plan -Category 'WinHttp' -Path $path -Name DefaultSecureProtocols -Value 2048 -Reason 'Set WinHTTP default secure protocol to TLS 1.2.'
        }
    }

    if ($IncludeCurrentUserInternetSettings) {
        Add-DWordPlanItem -Plan $plan -Category 'CurrentUserInternetSettings' -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name SecureProtocols -Value 2048 -Reason 'Set current-user Internet Settings secure protocol value to TLS 1.2.'
    }

    @($plan)
}

function Export-RegistryBackup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirectory
    )

    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null

    $exports = @(
        @{
            Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
            File = 'schannel.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL'
            File = 'cipher-suite-policy.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Microsoft\.NETFramework'
            File = 'dotnet-framework.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            File = 'internet-settings.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework'
            File = 'wow6432-dotnet-framework.reg'
        },
        @{
            Key = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings'
            File = 'wow6432-internet-settings.reg'
        }
    )

    $results = foreach ($export in $exports) {
        $path = Join-Path $BackupDirectory $export.File
        $exitCode = $null
        $status = 'Skipped'

        if ($PSCmdlet.ShouldProcess($export.Key, "Export registry backup to $path")) {
            $process = Start-Process -FilePath reg.exe -ArgumentList @('export', $export.Key, $path, '/y') -NoNewWindow -Wait -PassThru
            $exitCode = $process.ExitCode
            $status = if ($exitCode -eq 0) { 'Exported' } else { 'Failed' }
        }

        [pscustomobject]@{
            RegistryKey = $export.Key
            BackupPath = $path
            Status = $status
            ExitCode = $exitCode
        }
    }

    @($results)
}

function Set-PlannedRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Item
    )

    if ($Item.Action -eq 'NoChange') {
        return $false
    }

    if ($PSCmdlet.ShouldProcess("$($Item.RegistryPath)\$($Item.ValueName)", "Set $($Item.PropertyType) to $($Item.DesiredValue)")) {
        New-Item -Path $Item.RegistryPath -Force | Out-Null
        New-ItemProperty -Path $Item.RegistryPath -Name $Item.ValueName -Value $Item.DesiredValue -PropertyType $Item.PropertyType -Force | Out-Null
        return $true
    }

    $false
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$plan = Get-TlsHardeningPlan -SkipCipherSuiteOrder:$SkipCipherSuiteOrder -SkipDotNetStrongCrypto:$SkipDotNetStrongCrypto -SkipWinHttpDefaults:$SkipWinHttpDefaults -IncludeCurrentUserInternetSettings:$IncludeCurrentUserInternetSettings
$planCsvPath = Join-Path $resolvedReportDirectory "schannel-tls-hardening-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "schannel-tls-hardening-plan-$timestamp.json"

$plan | Export-Csv -Path $planCsvPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$plan | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $planJsonPath -Encoding utf8 -WhatIf:$false

Write-Information "TLS hardening plan written to $planCsvPath" -InformationAction Continue
Write-Information "TLS hardening plan JSON written to $planJsonPath" -InformationAction Continue

if (-not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw 'Run from an elevated PowerShell session before applying live Schannel registry changes. Use -WhatIf to generate a review plan without elevation.'
}

$backupDirectory = $null
$backupResults = @()
if (-not $WhatIfPreference -and -not $SkipRegistryBackup) {
    $backupDirectory = Join-Path $resolvedReportDirectory "schannel-registry-backup-$timestamp"
    $backupResults = Export-RegistryBackup -BackupDirectory $backupDirectory
}

$changedCount = 0
$skippedCount = 0
foreach ($item in $plan) {
    if ($item.Action -eq 'NoChange') {
        $skippedCount++
        continue
    }

    if (Set-PlannedRegistryValue -Item $item -WhatIf:$WhatIfPreference) {
        $changedCount++
    }
}

[pscustomobject]@{
    Baseline = $Baseline
    PlanCsvPath = (Resolve-Path -LiteralPath $planCsvPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    RegistryBackupDirectory = if ($backupDirectory) { (Resolve-Path -LiteralPath $backupDirectory).Path } else { $null }
    RegistryBackupResults = @($backupResults)
    PlannedChangeCount = @($plan | Where-Object { $_.Action -ne 'NoChange' }).Count
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    RestartRequired = $true
    Notes = 'Review reports before live runs. Reboot after applying live Schannel changes.'
}
