# ops-toolkit

> **AI reviewer - read before editing.** Start at the master `Code/README.md` ("AI Session Rules" section) and `Code/Instructions_AI_Plugin.md`. Those files are the single source of truth for path conventions, archive/backup rules, markdown conventions, and repo-wide workflow rules.

**Location:** `C:\Code\projects\ops-toolkit\`
**Owner:** ops-toolkit maintainers
**Purpose:** Operations and security administration scripts for Azure, Active Directory, IIS, Microsoft 365, Windows hardening, IT operations, labs, and reporting.
**Last Updated:** 2026-05-06

## What Changed

This repo was reviewed and reorganized in place. Files remain inside the ops-toolkit repo; retired material is kept under `archive\` with a documented reason instead of being deleted.

The review answers five maintenance questions:

1. What is no longer relevant and should be retired: see [docs/retirement-review.md](docs/retirement-review.md) and [docs/legacy-script-inventory.md](docs/legacy-script-inventory.md).
2. What we are keeping and how it is organized: see [Layout](#layout) and [Contents](#contents).
3. Which scripts needed updates: see [Updated Scripts](#updated-scripts).
4. What instructions belong at the top of kept scripts: see [Script Header Standard](#script-header-standard).
5. How future readers should work in this repo: see [Script Standards](#script-standards).

## Layout

```text
ops-toolkit\
├── archive\                 Retired legacy scripts and supporting files
├── data\                    Package lists and non-secret script input data
├── docs\                    Labs, diagrams, review notes, and reference material
├── reports\                 Generated script output, ignored by git
├── scripts\                 Runnable automation grouped by platform/domain
├── .editorconfig
├── .gitignore
├── PSScriptAnalyzerSettings.psd1
└── README.md
```

## Retired

The current retire-now items are:

| Path                                                 | Why retired                                                                                   |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `archive\windows-hardening\Bloat-Remove-Replace.ps1` | Historical bloat-removal script superseded by the active Windows hardening script.            |
| `archive\windows-hardening\Bloat-Server-Removal.ps1` | Historical bloat-removal script superseded by the active Windows hardening script.            |
| Deleted Cortana enable/disable archive scripts       | Cortana in Windows standalone app is deprecated/retired.                                      |
| Deleted old bloatware CSV archives                   | Superseded by `data\windows-hardening\` package lists.                                        |
| Old AzureRM-style NSG export snippets                | Replaced with `scripts\azure\Export-AzNetworkInventory.ps1` using the supported `Az` modules. |

See [docs/retirement-review.md](docs/retirement-review.md) for the full keep/retire rationale and sources.

## Contents

| Path                                          | Purpose                                                |
| --------------------------------------------- | ------------------------------------------------------ |
| `scripts\active-directory\`                   | AD reports, exports, and password notification scripts |
| `scripts\azure\`                              | Azure PowerShell and Azure CLI automation              |
| `scripts\iis\`                                | IIS setup and HTTP security header configuration       |
| `scripts\it-operations\printers\`             | Windows printer connection helpers                     |
| `scripts\it-operations\utilities\`            | General endpoint and admin utilities                   |
| `scripts\it-operations\windows-file-cleanup\` | File and temp-folder cleanup helpers                   |
| `scripts\microsoft-365\`                      | Exchange Online and Microsoft 365 administration       |
| `scripts\pentesting\`                         | AutoRecon workstation/lab setup helper                 |
| `scripts\utilities\`                          | General utilities and CSV comparison helpers           |
| `scripts\windows-hardening\`                  | Windows telemetry, bloatware, and cipher hardening     |
| `data\it-operations\printers\`                | Example non-secret printer input files                 |
| `data\windows-hardening\`                     | Bloatware allow/remove package lists                   |
| `docs\labs\`                                  | Azure and ELK lab materials                            |
| `docs\iis\`                                   | IIS header notes                                       |
| `archive\`                                    | Retired material retained inside the ops-toolkit repo  |

## Examples

Preview disabling and moving stale AD computer accounts:

```powershell
pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -WhatIf
```

Generate an AD security report without sending email:

```powershell
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PrivilegedGroupMembership -GroupName "Domain Admins"
```

Export AD user inventory reports:

```powershell
pwsh -File .\scripts\active-directory\Export-AdUserInventory.ps1 -ReportType All -OutputDirectory .\reports\active-directory
```

Initialize an Az PowerShell session and write a session report:

```powershell
pwsh -File .\scripts\azure\Initialize-AzPowerShellSession.ps1 -TenantId "<tenant-id>" -SubscriptionId "<subscription-id>" -UseDeviceAuthentication
```

Export Azure network inventory reports:

```powershell
pwsh -File .\scripts\azure\Export-AzNetworkInventory.ps1 -SubscriptionId "<subscription-id>" -IncludeVirtualMachines
```

Preview creating or reusing a Key Vault service principal:

```powershell
pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -EnvironmentName prod -ApplicationShortName app -KeyVaultName kv-prod-app -WhatIf
```

Preview mapping an Azure Files share to a Windows drive:

```powershell
pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -DriveLetter Z -StorageAccountName examplestorage -ShareName data -StorageAccountKey "<key>" -WhatIf
```

Preview importing an Azure VPN Client XML profile on Windows 11:

```powershell
pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig.xml -WhatIf
```

Preview applying a hardened Application Gateway TLS policy:

```powershell
pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode CustomHardened -WhatIf
```

Export Microsoft 365 distribution group usage from message traces:

```powershell
pwsh -File .\scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1 -Connect -Organization "<tenant-domain>"
```

Join application inventory rows to endpoint site data:

```powershell
pwsh -File .\scripts\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv -IncludeUnmatchedApplications
```

Preview installing AutoRecon dependencies on a lab workstation:

```bash
./scripts/pentesting/Install-AutoReconDependencies.sh --dry-run
```

Preview AD user UPN suffix updates:

```powershell
pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf
```

Add printer connections from a text file after previewing the action:

```powershell
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\data\it-operations\printers\printers.example.txt -WhatIf
```

Preview recursive file cleanup:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf
```

Preview adding a custom IIS response header:

```powershell
pwsh -File .\scripts\iis\Set-IisSiteCustomHeader.ps1 -SiteName "Default Web Site" -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf
```

Preview adding IIS site-default custom logging fields:

```powershell
pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -WhatIf
```

Preview replacing IIS custom headers with the recommended preset and write a before/after review CSV:

```powershell
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -RemoveExisting -WhatIf
```

Preview Windows Schannel/TLS hardening and write plan reports:

```powershell
pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1 -WhatIf
```

Preview Windows 11 privacy hardening and write plan reports:

```powershell
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
```

Preview rolling back Windows 11 privacy hardening:

```powershell
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -Rollback -WhatIf
```

Preview Windows 11 AppX bloatware removal and write inventory/plan/state reports:

```powershell
pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -RemoveProvisionedPackages -InstalledPackageScope AllUsers -WhatIf
```

## Updated Scripts

| Script                                                                     | Update                                                                                                                                                           |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts\azure\Export-AzNetworkInventory.ps1`                              | Expanded reporting-only Azure network inventory for NSGs, rules, VNets, subnets, NICs, public IPs, optional VMs, CSV/JSON exports, and run summaries.            |
| `scripts\azure\Initialize-AzPowerShellSession.ps1`                         | Hardened Az session bootstrap with explicit tenant/subscription/environment options, optional module install, context selection, and session reports.            |
| `scripts\azure\Import-AzureVpnClientXmlProfile.ps1`                        | Hardened Windows 11 Azure VPN Client XML import with XML validation, optional profile backup, `-WhatIf`, and plan/state reports.                                 |
| `scripts\azure\New-AzFileShareMappedDrive.ps1`                             | Hardened Azure Files mapped-drive workflow with map/remove modes, credential cleanup, `-WhatIf`, plan/state reports, and no storage-key report writes.           |
| `scripts\azure\New-AzKeyVaultServicePrincipal.ps1`                         | Rebuilt Key Vault service-principal creation with Az cmdlets, reuse mode, `-WhatIf`, plan/state reports, rollback guidance, and no secret writes to reports.     |
| `scripts\azure\Set-AzAppGatewayTlsPolicy.ps1`                              | Combined hardened and predefined Application Gateway TLS policy updates with mode selection, `-WhatIf`, plan/state reports, and rollback guidance.               |
| `scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1`  | Rebuilt stale-computer disable/move workflow with explicit action modes, plan/state/rollback reports, scoped AD filters, optional email, and `-WhatIf`.          |
| `scripts\active-directory\Send-AdSecurityEmailReport.ps1`                  | Combined privileged-group and password-never-expires AD security reports with HTML/CSV/JSON output and optional email.                                           |
| `scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1`         | Rebuilt password-expiry reminders with HTML/CSV/JSON output, email plan/state reports, `-WhatIf`, and explicit send switches.                                    |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | Combined AD user attribute and distinguished-name exports into one report-driven inventory command.                                                              |
| `scripts\active-directory\Set-AdUserUpnSuffix.ps1`                         | Combined mailbox-enabled and OU-scoped AD user UPN suffix updates with `-WhatIf`, plan/state reports, and explicit scope controls.                               |
| `scripts\iis\Set-IisSiteCustomHeader.ps1`                                  | Renamed and hardened single-site IIS custom header updates with safer preview and summary output.                                                                |
| `scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1`                       | Renamed and hardened all-site IIS custom header updates with safer preview and summary output.                                                                   |
| `scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1`                        | Renamed and hardened IIS site-default custom log field updates with duplicate detection and summaries.                                                           |
| `scripts\iis\Set-IisRecommendedSecurityHeaders.ps1`                        | Hardened the IIS security header preset with validation, replacement review reports, and summary output.                                                         |
| `scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1`  | Hardened Exchange Online distribution group usage reporting with `Get-MessageTraceV2`, 10-day query windows, continuation keys, CSV/JSON outputs, and summaries. |
| `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1`                 | Rebuilt CSV join utility with configurable join columns, case handling, matched/unmatched reports, duplicate-key summaries, and output paths under reports.      |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | Combined Windows printer add/remove helpers into one report-first command with data-file input and `-WhatIf`.                                                    |
| `scripts\it-operations\utilities\Get-CurrentUserContext.ps1`               | Rebuilt current-user context reporting with optional group expansion and JSON/CSV outputs.                                                                       |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | Combined temp cleanup and stale-file cleanup with guarded paths, plan/state reports, and `-WhatIf`.                                                              |
| `scripts\pentesting\Install-AutoReconDependencies.sh`                      | Rebuilt AutoRecon lab installer with `--dry-run`, package-group switches, Debian-family guardrails, pipx install flow, and safer shell behavior.                 |
| `scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1`            | Renamed and rebuilt Schannel TLS hardening with `-WhatIf`, plan reports, registry backups, and summaries.                                                        |
| `scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1`              | Renamed and rebuilt Windows 11 privacy/AI hardening with `-WhatIf`, rollback, plan/state reports, registry backups, and summaries.                               |
| `scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1`     | Rebuilt Windows 11 AppX bloatware removal with clean data lists, `-WhatIf`, rollback guidance, inventory/plan/state reports, and protected package enforcement.  |

## Modernized Legacy Scripts

The remaining VBScript/CMD entry points were replaced with PowerShell equivalents and the originals were moved to `archive\legacy-scripts\retired-2026-05-04\`.

| Replacement                                                                | Replaces                                     |
| -------------------------------------------------------------------------- | -------------------------------------------- |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | `Export-AdUserAttributesToExcel.vbs`         |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | `Export-AdUserDistinguishedNamesToExcel.vbs` |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | `Add-LegacyPrinterConnections.vbs`           |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | `Remove-LegacyPrinterConnection.vbs`         |
| `scripts\it-operations\utilities\Get-CurrentUserContext.ps1`               | `Show-CurrentUser.vbs`                       |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | `Clear-UserAndDriveTempFolders.vbs`          |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | `Remove-OldFilesRecursively.vbs`             |

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
- Do not use interactive menus or mandatory prompts for automation. If required arguments are missing, print usage and exit with code `2`.
- Avoid hard-coded customer domains, email addresses, tenant IDs, subscription IDs, storage keys, and local output paths. Pass them as parameters.
- Use `PSScriptAnalyzerSettings.psd1` when linting PowerShell scripts.
- Treat VBScript/CMD as archived reference only. Active automation should be PowerShell unless a target system requires another shell.
- Put generated reports under `reports\`; do not commit generated output.

## Validation

Last local validation performed on 2026-05-06:

- PowerShell parser check across all kept `.ps1` files.
- Full PSScriptAnalyzer rule pass with `PSScriptAnalyzerSettings.psd1`.
- Markdown cleanup with `Code\scripts\fix_md.py`.
- Stale reference search for old repo-name and staging-folder active-path references.
- Bash syntax check for lab and pentesting shell scripts with Git Bash.
