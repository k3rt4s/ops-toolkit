# Legacy Script Inventory

These files were retired from active use on 2026-05-04 and kept under `archive\legacy-scripts\retired-2026-05-04\` for traceability. Active replacements are PowerShell scripts under `scripts\`.

| Archived script                                                       | What it did                                                                              | Active replacement                                                  |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `scripts\active-directory\Export-AdUserAttributesToExcel.vbs`         | Exported detailed AD user attributes to an Excel workbook through legacy COM automation. | `scripts\active-directory\Export-AdUserAttributesToCsv.ps1`         |
| `scripts\active-directory\Export-AdUserDistinguishedNamesToExcel.vbs` | Exported AD user distinguished names to an Excel workbook.                               | `scripts\active-directory\Export-AdUserDistinguishedNamesToCsv.ps1` |
| `scripts\printers\Add-LegacyPrinterConnections.vbs`                   | Added a hard-coded set of Windows network printer connections.                           | `ITOps\scripts\printers\Add-WindowsPrinterConnections.ps1`          |
| `scripts\printers\Remove-LegacyPrinterConnection.vbs`                 | Enumerated and removed Windows network printer connections.                              | `ITOps\scripts\printers\Remove-WindowsPrinterConnections.ps1`       |
| `scripts\utilities\Convert-IpAddressToDecimalAndBinary.vbs`           | Converted an IPv4 address to binary and decimal formats, with an optional ping check.    | Removed from SecOps; no active replacement.                         |
| `scripts\utilities\Set-WindowsVolumeProductKey.vbs`                   | Installed a Windows volume product key through WMI.                                      | Removed from SecOps; no active replacement.                         |
| `scripts\utilities\Show-CurrentUser.vbs`                              | Reported current user and logon context details from a legacy workstation script.        | `ITOps\scripts\utilities\Get-CurrentUserContext.ps1`                |
| `scripts\utilities\Start-BgInfoForLegacyWindows.cmd`                  | Started BGInfo from legacy local or network paths.                                       | Removed from SecOps; no active replacement.                         |
| `scripts\windows-file-cleanup\Clear-UserAndDriveTempFolders.vbs`      | Cleared user and drive temp folders after an interactive confirmation prompt.            | `ITOps\scripts\windows-file-cleanup\Clear-TempFolders.ps1`          |
| `scripts\windows-file-cleanup\Remove-OldFilesRecursively.vbs`         | Removed files older than a configured age from a folder tree.                            | `ITOps\scripts\windows-file-cleanup\Remove-OldFilesRecursively.ps1` |

## Retirement Notes

- VBScript and CMD entry points are kept as historical reference only.
- Active scripts should be run from `scripts\` and should receive environment-specific values through command-line parameters or input files.
- Do not add new operational logic to the archived scripts.
