# ITOps

This folder is a temporary staging area for useful IT operations scripts that do not belong in the active SecOps script tree.

If this area grows enough to justify its own repository, move this folder into a dedicated `ITOps` repo and keep the paths documented in this README.

## Contents

| Path                | Purpose                                 |
| ------------------- | --------------------------------------- |
| `scripts\printers\` | Windows printer connection helpers.     |
| `data\printers\`    | Example non-secret printer input files. |

## Examples

Preview adding printer connections from a text file:

```powershell
pwsh -File .\ITOps\scripts\printers\Add-WindowsPrinterConnections.ps1 -PrinterListPath .\ITOps\data\printers\printers.example.txt -WhatIf
```

Preview removing all Windows connection printers:

```powershell
pwsh -File .\ITOps\scripts\printers\Remove-WindowsPrinterConnections.ps1 -AllConnectionPrinters -WhatIf
```
