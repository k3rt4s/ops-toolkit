# ops-toolkit Scripts

Runnable automation lives under this folder, grouped by platform or operational domain.

## Areas

- `active-directory/` - AD inventory and notification scripts.
- `azure/` - Azure and Azure CLI automation.
- `certificates/` - Certificate expiry across stores, IIS bindings, and TLS endpoints.
- `entra/` - Microsoft Entra ID identity reporting through Microsoft Graph.
- `iis/` - IIS configuration and HTTP response header scripts.
- `it-operations/` - Endpoint administration, printers, user context, cleanup, and OS lifecycle helpers.
- `logging/` - Whether the security telemetry a hunt or detection needs is switched on, and how long it survives.
- `microsoft-365/` - Exchange Online and Microsoft 365 administration.
- `pentesting/` - Lab or workstation setup helpers for security testing.
- `reporting/` - Cross-cutting reporting that runs other collectors and assembles their output.
- `utilities/` - Small workstation and CSV utilities, plus the retired-API scanner.
- `windows-hardening/` - Windows telemetry, bloatware, and cipher hardening.

## Header Rule

Kept scripts must start with a short instruction header in the language's native comment style. The header should state how to review/run the script, whether admin rights are likely required, whether `-WhatIf` is supported, and whether the script is active, legacy, or lab-only.

Prefer PowerShell 7.4+ for new scripts unless a script is explicitly Windows PowerShell 5.1 only. Use `PSScriptAnalyzerSettings.psd1` from the repo root for linting.
