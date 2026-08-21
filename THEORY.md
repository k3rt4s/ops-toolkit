# ops-toolkit theory

What a session needs to believe before it changes this repo's scripts or tests.

## Invariants

- Every state-changing script writes `<prefix>-yyyyMMdd_HHmmss\` with a CSV and JSON
  per report plus `summary.json`. `scripts\reporting\Compare-OpsToolkitRun.ps1` can
  only diff that exact layout; changing it breaks the diff tool silently.
- A check that could not run is never folded into a pass. `Export-CoverageReconciliation.ps1`
  and `Export-SecurityControlEvidencePack.ps1` report `NotAssessed` separately from
  `NotMet`: "we did not check" presented as "we are fine" is worse than no report.
- Every state-changing script is tested as a pair, `-WhatIf` and executing
  (`tests\Integration.StateChanging.*.Tests.ps1`); "`-WhatIf` changed nothing" is
  unfalsifiable alone, a broken script passes it too.

## Load-bearing constraints

- The scheduled-task host is Windows PowerShell 5.1, which reads a BOM-less file as
  the ANSI code page and fails to parse it silently, so the task still reports
  success. `Invoke-RepoValidation.ps1`'s Encoding gate (~line 252) fails any script
  with non-ASCII bytes and no BOM; `??` and `?.` are pwsh-7-only for the same reason.
- One non-standard comment-based-help keyword silently invalidates the entire help
  block; `Get-Help` falls back to generated syntax with no error. The Help gate
  (~line 300) catches this now; `.INSTRUCTIONS` hit 30 of 31 scripts before it did.
- Report and rollback writes, and the run directory itself, carry `-WhatIf:$false` on
  purpose: writing the plan *is* the preview, not the change being previewed. Without
  it, `Resolve-Path` throws and a `-WhatIf` run produces nothing to review.
- A Graph field that exists only in beta returns `$null`, not an error, as
  `servicePrincipalCredentialKeyId` and `defaultMfaMethod` (`scripts\entra\`) both
  did. Check a new field against the installed SDK model type before trusting it.

## Decisions that look wrong

- The shared test stub (`tests\TestHelpers.psm1` ~line 295) shadows
  `Microsoft.PowerShell.Management` cmdlets but deliberately excludes `Get-Process`,
  `Start-Process`, `Stop-Process`: scripts use them to find their own interpreter or
  read `reg.exe`'s exit code, and a global stub would break them, not protect the
  machine. Real-process tests stage a local fixture instead.
- `ScheduledTasks`, `Defender`, and `PrintManagement` cmdlets are not covered by that
  stub trick, because a same-named function only shadows commands from its own
  module. Trusting it once disabled four real scheduled tasks and added three real
  Defender exclusions on the dev machine. Fixed with staged fake modules at
  `tests\Fixtures\FakeSystemModules\`, loaded ahead of the real ones, plus a
  `MachineState` gate in `Invoke-RepoValidation.ps1` that snapshots Defender
  exclusions, tasks, printers, and drives around the test run and fails on drift.

## Known soft spots

- Emptiness, not malformed data, is where scripts break: seven shipped bugs traced to
  fixtures with data in every field against an estate whose ordinary case is null.
  `@($null)` is a one-element array, so `@($Param)` on an unbound `[string[]]` has
  `Count` 1 and a `Count -eq 0` guard never fires. An `if` without a matching branch
  unrolls a function's return down the pipeline, so `[byte[]]` can silently become
  `[object[]]`; both Azure collectors did this and scanned nothing on an empty
  resource group. Strict mode throws on a property read through a null; use
  `Get-OpsPropertyValue` (`modules\OpsToolkit.Reporting\`) instead of dotted access.
- `$LASTEXITCODE = 0` inside a function creates a shadowing local a later native
  call never updates, so the exit code checked afterward reads as a constant;
  reset with `Set-Variable -Scope Global` (`Invoke-DiskSpaceReclaim.ps1`).
