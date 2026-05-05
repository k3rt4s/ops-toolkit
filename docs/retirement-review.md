# Retirement Review

This review identifies what should be retired, what should stay active, and what should stay only as legacy reference.

## Retire Now

| Item                                                 | Decision                  | Reason                                                                                                                                                               |
| ---------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `archive\windows-hardening\Bloat-Remove-Replace.ps1` | Retired historical script | Superseded by `scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1` and retained only for comparison.                                               |
| `archive\windows-hardening\Bloat-Server-Removal.ps1` | Retired historical script | Superseded by `scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1` and retained only for comparison.                                               |
| Deleted Cortana enable/disable archive scripts       | Deleted                   | Cortana in Windows as a standalone app is deprecated/retired, so Cortana-specific enable/disable registry toggles are no longer useful for modern Windows hardening. |
| Deleted old bloatware CSV archives                   | Deleted                   | Superseded by `data\windows-hardening\` package lists.                                                                                                               |
| Old AzureRM-style NSG export snippets                | Retired by replacement    | AzureRM is deprecated; the active replacement is `scripts\azure\Export-AzNetworkInventory.ps1` using `Az` modules.                                                   |

## Keep Active

| Area              | Kept path                    | Notes                                                                                                                           |
| ----------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Azure             | `scripts\azure\`             | Updated toward `Az` cmdlets, parameters, explicit output paths, and `-WhatIf` where changes are made.                           |
| IIS               | `scripts\iis\`               | Kept for Windows Server IIS administration; security header script was updated to avoid automatic rollback execution.           |
| Microsoft 365     | `scripts\microsoft-365\`     | Kept for Exchange Online administration; message-trace usage now targets current Exchange Online `Get-MessageTraceV2` behavior. |
| Active Directory  | `scripts\active-directory\`  | Kept for on-prem AD operations; several scripts are legacy but still relevant in hybrid environments.                           |
| Windows hardening | `scripts\windows-hardening\` | Kept, except Cortana-specific scripts. High-impact scripts should be run first with `-WhatIf` when supported.                   |
| Utilities         | `scripts\utilities\`         | Kept; CSV comparison script was fixed and parameterized.                                                                        |
| Pen testing setup | `scripts\pentesting\`        | Kept as workstation/lab bootstrap, not as production server automation.                                                         |

## Legacy Keep / Replacement Recommended

| Item                                                 | Status             | Recommendation                                                                              |
| ---------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------- |
| `archive\legacy-scripts\retired-2026-05-04\**\*.vbs` | Archived reference | Replaced with PowerShell equivalents under `scripts\`; keep only for historical comparison. |
| `archive\legacy-scripts\retired-2026-05-04\**\*.cmd` | Archived reference | Replaced with PowerShell equivalents under `scripts\`; keep only for historical comparison. |
| `docs\labs\elk-lab\scripts\*.sh`                     | Lab reference      | Keep with lab docs; scripts are named and maintained as lab-only class setup helpers.       |

## Sources Checked

- Microsoft AzureRM retirement overview: <https://learn.microsoft.com/en-us/powershell/azure/azurerm-retirement-overview>
- Microsoft Windows deprecated features: <https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features>
- Microsoft Cortana support retirement note: <https://support.microsoft.com/en-us/surface/set-up-surface-headphones-with-cortana-72369518-4e31-fcd5-82ee-163156cc8bac>
- Microsoft Exchange Online message trace docs: <https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/new-message-trace>
