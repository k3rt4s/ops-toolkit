# SecOps Scripts

Runnable automation lives under this folder, grouped by platform or operational domain.

## Areas

- `active-directory/` - AD inventory and notification scripts.
- `azure/` - Azure and Azure CLI automation.
- `iis/` - IIS configuration and HTTP response header scripts.
- `microsoft-365/` - Exchange Online and Microsoft 365 administration.
- `pentesting/` - Lab or workstation setup helpers for security testing.
- `utilities/` - Small workstation and CSV utilities.
- `windows-file-cleanup/` - File cleanup helpers.
- `windows-hardening/` - Windows telemetry, bloatware, and cipher hardening.

## Header Rule

Kept scripts must start with a short instruction header in the language's native comment style. The header should state how to review/run the script, whether admin rights are likely required, whether `-WhatIf` is supported, and whether the script is active, legacy, or lab-only.

Prefer PowerShell 7.4+ for new scripts unless a script is explicitly Windows PowerShell 5.1 only. Use `PSScriptAnalyzerSettings.psd1` from the repo root for linting.
