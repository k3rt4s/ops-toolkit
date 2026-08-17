# ops-toolkit Theory

Constraints that look arbitrary until you know why, and traps a fresh thread would
otherwise re-derive the hard way. Read before changing anything structural.

## Load-bearing constraints

**Never invent a comment-based help keyword.** One unrecognised keyword such as
`.INSTRUCTIONS` silently invalidates the whole block, as was true of 30 of 31 scripts.

**Non-ASCII needs a BOM.** The scheduled-task host is Windows PowerShell 5.1, which
reads a BOM-less file as the ANSI code page and fails to parse it, so the script does
nothing while the task reports success; an em-dash is enough, and `Set-Content -Encoding
utf8`in pwsh 7 strips the BOM. Likewise`??`and`?.` are pwsh-7 only.

**Run directories are not cosmetic.** Every script writes `<prefix>-yyyyMMdd_HHmmss\`
with a CSV and JSON per report plus `summary.json`, the only layout
`Compare-OpsToolkitRun.ps1` can diff. Report writes and the directory itself carry
`-WhatIf:$false`: writing the plan is the preview, not the change being previewed, and
without it `Resolve-Path` throws and the script cannot be rehearsed at all.

**Undetermined is never folded into a pass.** A check that could not run is reported as
not having run: the evidence pack counts NotAssessed separately from NotMet, because "we
did not check" presented as "we are fine" is worse than no pack at all. Same for
unelevated reads, unreachable machines, and missing modules.

## Traps that have already cost time

**A Graph field that exists only in beta returns null, it does not error.** Both
`servicePrincipalCredentialKeyId` and `defaultMfaMethod` did this, producing confidently
wrong reports. Check any Graph field against the installed SDK model type.

**Emptiness is the blind spot.** Seven shipped bugs, one cause: fixtures with data in
every field, against an estate whose ordinary case is a null. Each produced a clean,
plausible, wrong report rather than an error.

- `@($null)` is a **one-element** array and an unbound `[string[]]` parameter is
  `$null`, so `@($Param)` has `Count` 1 when nothing was passed and a `Count -eq 0`
  guard never fires. Filter with `| Where-Object { $_ }` first.
- An `if` emits its result down the **pipeline, which unrolls it**, so
  `$x = if (...) { } else { @($null) }` leaves a bare `$null`, and `foreach ($i in
  $null)`runs **zero** times where`@($null)` runs once. Both Azure collectors were
  written this way and scanned nothing when given no resource group. A function's
  return unrolls the same way, so a `[byte[]]` becomes `[object[]]`.
- Strict mode throws reading a property **through** a null (`$subnet.RouteTable.Id`)
  and on member enumeration over an **empty** collection while a populated one works
  (`$nsg.NetworkInterfaces.Id`). Use `Get-OpsPropertyValue` and `ForEach-Object`.
- `@($x) | Sort-Object` wraps the **input**, so zero rows gives `$null`;
  `@($rows | Select -First 1).PSObject.Properties.Name` returns the array's members.

## Testing

Every state-changing script is tested as a pair, `-WhatIf` and executing, because
"`-WhatIf` changed nothing" is unfalsifiable alone: a broken script passes it too.
**A function stub does not isolate every command.** It shadows the
`Microsoft.PowerShell.Management` cmdlets, but not commands from `ScheduledTasks`,
`Defender`, or `PrintManagement`; trusting it disabled four real scheduled tasks and
added three real Defender exclusions on the build machine. Stage a replacement module
ahead of the real one. The `MachineState` gate snapshots the machine around the test run
and fails on drift, because the test result was green throughout. See `tests\README.md`.
