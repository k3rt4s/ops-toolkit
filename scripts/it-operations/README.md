# IT Operations Scripts

This folder contains active endpoint and general IT operations scripts for the ops-toolkit repo.

## Contents

| Path                        | Purpose                                                                                                                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `networking\`               | Network adapter MAC address helpers.                                                                                                                             |
| `performance\`              | Workstation performance posture helpers.                                                                                                                         |
| `printers\`                 | Windows printer connection helpers.                                                                                                                              |
| `utilities\`                | General endpoint and admin utilities, CSV joins, folder comparison, and the retired-API scanner.                                                                 |
| `windows-file-cleanup\`     | File, temp-folder, and cache reclaim helpers.                                                                                                                    |
| `windows-hardening\`        | Workstation idle-lock and sleep posture, browser credential-theft surface hardening, plus system-level TLS/privacy/bloatware hardening and its compliance check. |
| `..\..\data\it-operations\` | Example non-secret input data.                                                                                                                                   |

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

Preview reclaiming developer and Windows caches. The default set is pip, Docker build
cache and dangling images, Recycle Bin, and WinSxS:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -ReportDirectory <dir> -WhatIf
```

Other caches are reachable by name and none of them is in the default set: npm, torch,
pre-commit, Codex runtimes, NVIDIA shaders, Playwright browsers, Hugging Face, stopped
containers, unused volumes, superseded image tags, and the Windows Update cache. Pruning
inside Docker frees space within its virtual disk without shrinking the file, so
`DockerVhdxCompact` is what returns that space to the host volume. It needs an elevated
shell and stops Docker Desktop and every WSL distro for several minutes:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -ReportDirectory <dir> -Target DockerVhdxCompact -WhatIf
```

## Inventory a Windows drive

Writes a junction-safe, detailed path inventory. The report contains sensitive full
paths, so `--root` is required, and `--output-dir` and `--notindexed-script` are
required too: this is a public repository, so no workstation path is assumed. Point
`--notindexed-script` only at a trusted local `.ps1` helper, because the inventory
script executes it after the report is written.

```powershell
python .\scripts\it-operations\windows-file-cleanup\Analyze-C.py --root C:\ --output-dir <dir> --notindexed-script <path>
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
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -DefenderPathExclusion <path> -ReportDirectory <dir> -WhatIf
```

Roll back the performance posture (restore previous power plan and remove added exclusions):

```powershell
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -DefenderPathExclusion <path> -ReportDirectory <dir> -Rollback -WhatIf
```

Preview applying the workstation idle-lock and sleep posture (10-minute screensaver lock, never sleep on AC):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -ReportDirectory <dir> -WhatIf
```

Apply the lock posture with the optional power-scheme password-on-wake flag (elevated):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -ReportDirectory <dir> -EnableConsoleLock
```

Roll back the lock posture:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -ReportDirectory <dir> -Rollback -WhatIf
```

Preview hardening the browser credential-theft surface (block authenticator browser extensions in
Chrome and Edge by default, add `-IncludePasswordManagerExtensions` to also block password-manager
extensions, pin Chrome Application-Bound Encryption on):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -WhatIf
```

Apply the browser credential posture (elevated; every enforced setting is an HKLM machine policy):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir>
```

Roll back the browser credential posture:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-BrowserCredentialPosture.ps1 -ReportDirectory <dir> -Rollback -WhatIf
```

Apply the TLS 1.2-only Schannel baseline (elevated; live run, then preview only):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsSchannelTlsHardening.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Set-WindowsSchannelTlsHardening.ps1 -WhatIf
```

Preview Windows 11 privacy/telemetry hardening, then apply and roll back:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Set-Windows11PrivacyHardening.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Set-Windows11PrivacyHardening.ps1 -Rollback -WhatIf
```

Preview removing provisioned AppX bloatware, then apply and roll back from a saved state file:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -RemoveProvisionedPackages -InstalledPackageScope AllUsers -WhatIf
pwsh -File .\scripts\it-operations\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -Rollback -RollbackStatePath .\reports\windows-hardening\windows11-appx-removal-state-YYYYMMDD_HHMMSS.csv -WhatIf
```

Check compliance against the hardening baselines above (registry state plus a live TLS handshake probe):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1 -Target SchannelTls -ProbeEndpoint 'www.microsoft.com:443'
pwsh -File .\scripts\it-operations\windows-hardening\Test-WindowsHardeningState.ps1 -Target Privacy -FailOnDrift
```

Join an applications CSV to an endpoints CSV on agent/endpoint name:

```powershell
pwsh -File .\scripts\it-operations\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv
pwsh -File .\scripts\it-operations\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv -IncludeUnmatchedApplications
```

Scan a folder tree for retired or soon-to-be-retired Microsoft APIs:

```powershell
pwsh -File .\scripts\it-operations\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts
pwsh -File .\scripts\it-operations\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts,D:\Share -Severity Broken
```

Compare two folder trees by BLAKE3 content hash with optional SHA-256 verification:

```powershell
python .\scripts\it-operations\utilities\compare_folders.py --folder-a D:\Source --folder-b E:\Backup --label-a source --label-b backup --sha256
```
