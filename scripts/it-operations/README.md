# IT Operations Scripts

This folder contains active endpoint and general IT operations scripts for the ops-toolkit repo.

## Contents

| Path                            | Purpose                                          |
| ------------------------------- | ------------------------------------------------ |
| `networking\`                   | Network adapter MAC address helpers.             |
| `performance\`                  | Workstation performance posture helpers.         |
| `printers\`                     | Windows printer connection helpers.              |
| `utilities\`                    | General endpoint and admin utilities.            |
| `windows-file-cleanup\`         | File, temp-folder, and cache reclaim helpers.    |
| `windows-hardening\`            | Workstation idle-lock and sleep posture helpers. |
| `..\..\data\it-operations\`     | Example non-secret input data.                   |

## Examples

Preview randomizing the MAC address of every physical adapter:

```powershell
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1 -WhatIf
```

Restore the hardware MAC on a single adapter:

```powershell
pwsh -File .\scripts\it-operations\networking\Set-NetworkAdapterRandomMac.ps1 -Name "Wi-Fi" -Rollback
```

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

Preview reclaiming developer and Windows caches (pip, Docker, Recycle Bin, WinSxS):

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
```

## Inventory a Windows drive

Writes a junction-safe, detailed path inventory under `C:\Code_data` by
default. The report contains sensitive full paths, so `--root` is required.

```powershell
python .\scripts\it-operations\windows-file-cleanup\Analyze-C.py --root C:\
```

## Temporarily cycle page-file configuration

This is a high-impact administrator operation. It is dry-run-only unless
`-Execute` is supplied, supports `-WhatIf`/`-Confirm`, snapshots every page-file
setting, restores them in `finally`, and validates the restored names and sizes.
Run from an elevated PowerShell session. Windows may require a reboot before
page-file configuration changes fully take effect.

```powershell
pwsh -File .\scripts\it-operations\utilities\Page-File-Bleed.ps1
pwsh -File .\scripts\it-operations\utilities\Page-File-Bleed.ps1 -Execute -WhatIf
```

Preview setting the workstation performance posture (power plan plus Defender exclusions):

```powershell
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -WhatIf
```

Roll back the performance posture (restore previous power plan and remove added exclusions):

```powershell
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -Rollback -WhatIf
```

Preview applying the workstation idle-lock and sleep posture (10-minute screensaver lock, never sleep on AC):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -WhatIf
```

Apply the lock posture with the optional power-scheme password-on-wake flag (elevated):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableConsoleLock
```

Roll back the lock posture:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -Rollback -WhatIf
```
