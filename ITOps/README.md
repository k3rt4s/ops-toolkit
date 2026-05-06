# ITOps

This folder is a temporary staging area for useful IT operations scripts that do not belong in the active SecOps script tree.

If this area grows enough to justify its own repository, move this folder into a dedicated `ITOps` repo and keep the paths documented in this README.

## Contents

| Path                            | Purpose                                 |
| ------------------------------- | --------------------------------------- |
| `scripts\printers\`             | Windows printer connection helpers.     |
| `scripts\utilities\`            | General endpoint and admin utilities.   |
| `scripts\windows-file-cleanup\` | File and temp-folder cleanup helpers.   |
| `data\printers\`                | Example non-secret printer input files. |

## Examples

Preview adding printer connections from a text file:

```powershell
pwsh -File .\ITOps\scripts\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\ITOps\data\printers\printers.example.txt -WhatIf
```

Preview removing all Windows connection printers:

```powershell
pwsh -File .\ITOps\scripts\printers\Set-WindowsPrinterConnections.ps1 -Action Remove -AllConnectionPrinters -WhatIf
```

Preview recursive file cleanup:

```powershell
pwsh -File .\ITOps\scripts\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf
```

Preview temp folder cleanup:

```powershell
pwsh -File .\ITOps\scripts\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode Temp -Path $env:TEMP -WhatIf
```

Show current Windows user and network context:

```powershell
pwsh -File .\ITOps\scripts\utilities\Get-CurrentUserContext.ps1 -OutputDirectory .\reports\itops\user-context
```
