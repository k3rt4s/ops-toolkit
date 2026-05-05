# Reorganization Map

This repo was reorganized on 2026-05-04 to separate runnable automation from documentation, data, notes, and archived legacy material.

## Top-Level Moves

| Old area                    | New area                                                                                  |
| --------------------------- | ----------------------------------------------------------------------------------------- |
| `Azure\`                    | `scripts\azure\`                                                                          |
| `IIS Configuration\`        | `scripts\iis\` and `docs\iis\`                                                            |
| `IIS-Headers\`              | `scripts\iis\` and `docs\iis\`                                                            |
| `Labs\`                     | `docs\labs\`                                                                              |
| `Misc\`                     | `scripts\utilities\`                                                                      |
| `Office365\`                | `scripts\microsoft-365\` and `docs\`                                                      |
| `PenTesting\`               | `scripts\pentesting\`                                                                     |
| `Printers\`                 | `ITOps\scripts\printers\`                                                                 |
| `Windows Active Directory\` | `scripts\active-directory\`                                                               |
| `Windows File Cleanup\`     | `ITOps\scripts\windows-file-cleanup\`                                                     |
| `Windows Hardening\`        | `scripts\windows-hardening\`, `data\windows-hardening\`, and `archive\windows-hardening\` |
| `File Check.ps1`            | `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1`                                |

## Modernized Scripts

- `scripts\azure\Export-AzNetworkInventory.ps1` replaces the broken `AzureRM` NSG export snippets with an `Az`-based inventory exporter.
- `scripts\azure\New-AzKeyVaultServicePrincipal.ps1` parameterizes subscription, environment, app name, and Key Vault policy assignment.
- `scripts\iis\Set-IisRecommendedSecurityHeaders.ps1` removes the embedded rollback block and supports `-WhatIf`, per-site targeting, optional IIS restart, validation, and summary output.
- `scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1` uses current Exchange Online `Get-MessageTraceV2` behavior, 10-day query windows, and report output parameters.
- `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1` fixes the CSV join logic and exposes paths as parameters.
- `scripts\pentesting\Install-AutoReconDependencies.sh` fixes the shebang, package continuation, `pipx` install flow, and shell safety options.
- `docs\labs\elk-lab\scripts\*.sh` were renamed into explicit lab setup helpers for Elastic/Kibana, Filebeat, and DVWA.
