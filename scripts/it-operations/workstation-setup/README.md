# Workstation Setup

Bootstraps a fresh Windows 11 workstation from nothing but Windows PowerShell and winget, mirroring a reference machine's apps and configuration.

## Contents

| Path                            | Purpose                                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `Install-WorkstationBootstrap.ps1` | One self-contained script, nine resumable phases, idempotent, `-WhatIf` supported, no secrets inside. |

## Phases

| Phase | Does                                                                                                     |
| ----- | -------------------------------------------------------------------------------------------------------- |
| 1     | Preflight: admin, winget, internet, report folder                                                        |
| 2     | Windows settings (file extensions, long paths, developer mode) and user environment variables            |
| 3     | winget packages by group (Core, Comms, AiContainers)                                                     |
| 4     | Git identity, VS Code extensions and settings merge, PowerShell modules                                  |
| 5     | PowerShell profile block, Windows Terminal settings if absent                                            |
| 6     | `gh` login, workspace folders, clone of ops-toolkit, your owned repos, and the workspace repo            |
| 7     | Directory layout under the workspace and data roots                                                      |
| 8     | Runs the windows-hardening scripts in `-WhatIf` preview only, then prints the apply commands             |
| 9     | Summary and manual steps                                                                                 |

## Run it

From an elevated Windows PowerShell, preview first:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/k3rt4s/ops-toolkit/master/scripts/it-operations/workstation-setup/Install-WorkstationBootstrap.ps1 -OutFile $env:TEMP\Install-WorkstationBootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\Install-WorkstationBootstrap.ps1 -WhatIf
```

Then run it for real:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\Install-WorkstationBootstrap.ps1 -GitUserName "Your Name" -GitUserEmail you@example.com -WorkspaceRepo https://github.com/<owner>/<workspace>.git
```

Re-run any time; finished steps report `AlreadyPresent`. `-Phase 3,4` or `-Group Core,Comms` limit the run.

## Hardening

The bootstrap never applies hardening. Phase 8 previews each script in `..\windows-hardening\` and prints the apply commands for you to run after reading the preview.

## Not mirrored

Vendor and gaming utilities, GPU drivers, Chocolatey duplicates, credentials, and `~\.claude`. Copy those by hand.

Reports land in `%USERPROFILE%\workstation-bootstrap\` (`run.log`, `results.csv`, `summary.json`).
