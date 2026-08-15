# ops-toolkit Modules

Shared PowerShell modules imported by ops-toolkit scripts by relative path.

These are not installed to a `PSModulePath`. Scripts import them from their own
location so the repo stays self-contained and a clone runs without a setup step:

```powershell
Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force
```

## Contents

- `OpsToolkit.Reporting/` - report-writing helpers: output and run directory
  resolution, CSV plus JSON export, run summaries, safe property reads under strict
  mode, value flattening, byte-to-hex conversion, age-in-days with the Windows
  never-set sentinels handled, and severity ranking.

## Rules

- Modules hold shape and file handling, not domain logic. Nothing here should know
  about Active Directory, Azure, Exchange, or Windows specifics.
- Every exported function carries comment-based help using only standard keywords,
  so `Get-Help` works. See the root README Script Header Standard.
- `Invoke-RepoValidation.ps1` validates every manifest here and fails if a manifest
  declares a function the module does not export.
