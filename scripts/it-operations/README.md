# IT Operations Scripts

This folder contains active endpoint and general IT operations scripts for the ops-toolkit repo.

## Contents

| Path                            | Purpose                                 |
| ------------------------------- | --------------------------------------- |
| `printers\`                     | Windows printer connection helpers.     |
| `utilities\`                    | General endpoint and admin utilities.   |
| `windows-file-cleanup\`         | File and temp-folder cleanup helpers.   |
| `..\..\data\it-operations\`     | Example non-secret input data.          |

## Examples

Preview adding printer connections from a text file:

```powershell
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\data\it-operations\printers\printers.example.txt -WhatIf
```

Preview removing all Windows connection printers:

```powershell
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Remove -AllConnectionPrinters -WhatIf
```

Preview recursive file cleanup:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf
```

Preview temp folder cleanup:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode Temp -Path $env:TEMP -WhatIf
```

Show current Windows user and network context:

```powershell
pwsh -File .\scripts\it-operations\utilities\Get-CurrentUserContext.ps1 -OutputDirectory .\reports\it-operations\user-context
```
