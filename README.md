# SecOps

> **AI reviewer - read before editing.** Start at the master `Code/README.md` ("AI Session Rules" section) and `Code/Instructions_AI_Plugin.md`. Those files are the single source of truth for path conventions, archive/backup rules, markdown conventions, and repo-wide workflow rules.

**Location:** `C:\Code\projects\SecOps\`
**Owner:** k3rt4s
**Purpose:** Security operations scripts for Azure, Active Directory, IIS, Microsoft 365, Windows hardening, and general IT administration.
**Last Updated:** 2026-05-04

## What Changed

This repo was reviewed and reorganized in place. Files remain inside the SecOps repo; retired material is kept under `archive\` with a documented reason instead of being deleted.

The review answers five maintenance questions:

1. What is no longer relevant and should be retired: see [docs/retirement-review.md](docs/retirement-review.md).
2. What we are keeping and how it is organized: see [Layout](#layout) and [Contents](#contents).
3. Which scripts needed updates: see [Updated Scripts](#updated-scripts).
4. What instructions belong at the top of kept scripts: see [Script Header Standard](#script-header-standard).
5. How future readers should work in this repo: see [Script Standards](#script-standards).

## Layout

```text
SecOps\
├── archive\                 Retired legacy scripts and supporting files
├── data\                    Package lists and non-secret script input data
├── docs\                    Labs, diagrams, review notes, and reference material
├── notes\                   CherryTree and other notebook exports
├── reports\                 Generated script output, ignored by git
├── scripts\                 Runnable automation grouped by platform/domain
├── .editorconfig
├── .gitignore
├── PSScriptAnalyzerSettings.psd1
└── README.md
```

## Retired

The current retire-now items are:

| Path                                                               | Why retired                                                                                   |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `archive\windows-hardening\retired-2026-05-04\Disable-Cortana.ps1` | Cortana in Windows standalone app is deprecated/retired.                                      |
| `archive\windows-hardening\retired-2026-05-04\Enable-Cortana.ps1`  | Same Cortana retirement reason.                                                               |
| `archive\windows-hardening\Bloat-Remove-Replace.ps1`               | Historical bloat-removal script superseded by the active Windows hardening script.            |
| `archive\windows-hardening\Bloat-Server-Removal.ps1`               | Historical bloat-removal script superseded by the active Windows hardening script.            |
| Old AzureRM-style NSG export snippets                              | Replaced with `scripts\azure\Export-AzNetworkInventory.ps1` using the supported `Az` modules. |

See [docs/retirement-review.md](docs/retirement-review.md) for the full keep/retire rationale and sources.

## Contents

| Path                            | Purpose                                                |
| ------------------------------- | ------------------------------------------------------ |
| `scripts\active-directory\`     | AD reports, exports, and password notification scripts |
| `scripts\azure\`                | Azure PowerShell and Azure CLI automation              |
| `scripts\iis\`                  | IIS setup and HTTP security header configuration       |
| `scripts\microsoft-365\`        | Exchange Online and Microsoft 365 administration       |
| `scripts\pentesting\`           | AutoRecon workstation/lab setup helper                 |
| `scripts\printers\`             | Printer connection helpers                             |
| `scripts\utilities\`            | General utilities and CSV comparison helpers           |
| `scripts\windows-file-cleanup\` | File and folder cleanup helpers                        |
| `scripts\windows-hardening\`    | Windows telemetry, bloatware, and cipher hardening     |
| `data\windows-hardening\`       | Bloatware allow/remove package lists                   |
| `docs\labs\`                    | Azure and ELK lab materials                            |
| `docs\iis\`                     | IIS header notes                                       |
| `notes\`                        | CherryTree notes database                              |
| `archive\`                      | Retired material retained inside the SecOps repo       |

## Updated Scripts

| Script                                                                    | Update                                                                                            |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `scripts\azure\Export-AzNetworkInventory.ps1`                             | Replaced broken AzureRM-era snippets with an `Az`-based NSG and optional VM inventory exporter.   |
| `scripts\azure\Initialize-AzPowerShellSession.ps1`                        | Removed AzureRM uninstall behavior; now safely imports or optionally installs `Az.Accounts`.      |
| `scripts\azure\New-AzFileShareMappedDrive.ps1`                            | Replaced invalid `.bat` content with a parameterized PowerShell drive mapper.                     |
| `scripts\azure\New-AzKeyVaultServicePrincipal.ps1`                        | Parameterized subscription, environment, app name, Key Vault, and permissions.                    |
| `scripts\azure\Set-AzAppGatewayHardenedTlsPolicy.ps1`                     | Replaced placeholders with parameters and `-WhatIf` support.                                      |
| `scripts\azure\Restore-AzAppGatewayPredefinedTlsPolicy.ps1`               | Replaced placeholders with parameters for applying a predefined TLS policy.                       |
| `scripts\iis\Set-IisRecommendedSecurityHeaders.ps1`                       | Removed automatic rollback execution and added per-site targeting, custom headers, and `-WhatIf`. |
| `scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1` | Parameterized lookback and output path; fixed active-recipient matching.                          |
| `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1`                | Fixed CSV join logic and made input/output paths parameters.                                      |
| `scripts\pentesting\Install-AutoReconDependencies.sh`                     | Fixed shebang, apt continuation syntax, `pipx` flow, and shell safety options.                    |

## Modernized Legacy Scripts

The remaining VBScript/CMD entry points were replaced with PowerShell equivalents and the originals were moved to `archive\legacy-scripts\retired-2026-05-04\`.

| Replacement                                                         | Replaces                                     |
| ------------------------------------------------------------------- | -------------------------------------------- |
| `scripts\active-directory\Export-AdUserAttributesToCsv.ps1`         | `Export-AdUserAttributesToExcel.vbs`         |
| `scripts\active-directory\Export-AdUserDistinguishedNamesToCsv.ps1` | `Export-AdUserDistinguishedNamesToExcel.vbs` |
| `scripts\printers\Add-WindowsPrinterConnections.ps1`                | `Add-LegacyPrinterConnections.vbs`           |
| `scripts\printers\Remove-WindowsPrinterConnections.ps1`             | `Remove-LegacyPrinterConnection.vbs`         |
| `scripts\utilities\Convert-IpAddressToDecimalAndBinary.ps1`         | `Convert-IpAddressToDecimalAndBinary.vbs`    |
| `scripts\utilities\Get-CurrentUserContext.ps1`                      | `Show-CurrentUser.vbs`                       |
| `scripts\utilities\Set-WindowsVolumeProductKey.ps1`                 | `Set-WindowsVolumeProductKey.vbs`            |
| `scripts\utilities\Start-BgInfo.ps1`                                | `Start-BgInfoForLegacyWindows.cmd`           |
| `scripts\windows-file-cleanup\Clear-TempFolders.ps1`                | `Clear-UserAndDriveTempFolders.vbs`          |
| `scripts\windows-file-cleanup\Remove-OldFilesRecursively.ps1`       | `Remove-OldFilesRecursively.vbs`             |

## Script Header Standard

Every kept script should start with instructions in the native comment format for its language:

- PowerShell: comment-based help with `.SYNOPSIS`, `.INSTRUCTIONS`, and `.STATUS`.
- Bash: shebang first, then an `# Instructions` block.
- Batch/CMD: `REM Instructions` block.
- VBScript: `' Instructions` block.

The header should tell the operator to read this README, review parameters or variables, run with admin rights only when needed, use `-WhatIf` when supported, and note whether the script is active, lab-only, or legacy keep.

## Script Standards

- Prefer PowerShell 7.4+ and current modules for new work; keep Windows PowerShell 5.1 compatibility only where the target platform requires it.
- Use `Az` cmdlets for Azure PowerShell. Do not add new `AzureRM` automation.
- New or updated PowerShell scripts should use `[CmdletBinding()]`, named parameters, explicit output paths, and `Set-StrictMode -Version 3.0` where compatible.
- State-changing scripts should support `-WhatIf` and `-Confirm` through `SupportsShouldProcess`.
- Avoid hard-coded customer domains, email addresses, tenant IDs, subscription IDs, storage keys, and local output paths. Pass them as parameters.
- Use `PSScriptAnalyzerSettings.psd1` when linting PowerShell scripts.
- Treat VBScript/CMD as archived reference only. Active automation should be PowerShell unless a target system requires another shell.
- Put generated reports under `reports\`; do not commit generated output.

## Validation

Last local validation performed on 2026-05-04:

- PowerShell parser check across all kept `.ps1` files.
- `PSScriptAnalyzerSettings.psd1` parse check.
- Markdown cleanup with `Code\scripts\fix_md.py`.
- Stale reference search for old top-level folders and retired AzureRM script content.

Not run locally:

- Full PSScriptAnalyzer rule pass, because `Invoke-ScriptAnalyzer` was not installed.
- Bash syntax check, because WSL/bash was not available in this shell environment.
