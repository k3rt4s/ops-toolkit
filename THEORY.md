# ops-toolkit Theory

Constraints that look arbitrary until you know why, and traps a fresh thread will
otherwise re-derive the hard way. Read before changing anything structural.

## Load-bearing constraints

**Never invent a comment-based help keyword.** One unrecognised keyword such as
`.INSTRUCTIONS` silently invalidates the whole block, leaving `Get-Help` with only
generated syntax, as was true of 30 of 31 scripts for months. Put custom sections
inside `.DESCRIPTION` or `.NOTES` as labelled text.

**Non-ASCII needs a BOM.** The scheduled-task host is Windows PowerShell 5.1, which
reads a BOM-less file as the ANSI code page and fails to parse it, so the script does
nothing while the task reports success; an em-dash is enough. Likewise `??` and `?.`
are pwsh-7 only, so the three scripts using them carry `#requires -Version 7` to turn
a parse error into a plain version message.

**Run directories are not cosmetic.** Every script writes `<prefix>-yyyyMMdd_HHmmss\`
with a CSV and JSON per report plus `summary.json`, the only layout
`Compare-OpsToolkitRun.ps1` can diff.

**Undetermined is never folded into a pass.** A check that could not run is reported
as not having run: the evidence pack counts NotAssessed separately from NotMet, because
"we did not check" presented as "we are fine" is worse than no pack at all. Same rule
for unelevated reads, unreachable machines, and missing modules.

## Traps that have already cost time

**A Graph field that exists only in beta returns null, it does not error.**
`servicePrincipalCredentialKeyId` and `defaultMfaMethod` both did this, producing
confidently wrong reports. Check any Graph field against the installed SDK model type.

**Emptiness is the blind spot.** Seven shipped bugs, one cause: fixtures with data in
every field, against an estate whose ordinary case is a null. Each produced a clean,
plausible, wrong report rather than an error.

- `@($null)` is a **one-element** array, and an unbound `[string[]]` parameter is
  `$null`, so `@($Param)` has `Count` 1 when nothing was passed and a `Count -eq 0`
  guard never fires. Filter with `| Where-Object { $_ }` first.
- An `if` emits its result down the **pipeline, which unrolls it**, so
  `$x = if (...) { } else { @($null) }` leaves `$x` a bare `$null`, and
  `foreach ($i in $null)` runs **zero** times where `@($null)` runs once. Both Azure
  collectors were written this way and scanned nothing when given no resource group.
  A function's return unrolls the same way, so a `[byte[]]` becomes `[object[]]`.
- Strict mode throws reading a property **through** a null (`$subnet.RouteTable.Id`,
  no route table) and on member enumeration over an **empty** collection while a
  populated one works (`$nsg.NetworkInterfaces.Id`, no NIC attached). Use
  `Get-OpsPropertyValue` and `ForEach-Object` respectively.
- `@($x) | Sort-Object` wraps the **input**, so zero rows gives `$null` and `.Count`
  throws. `@($rows | Select -First 1).PSObject.Properties.Name` returns the **array's**
  members, not the record's, poisoning column names.

## Testing

Scripts are not modules, so tests cannot import them and dot-sourcing would run them.
`tests\TestHelpers.psm1` parses out their functions and imports them as a dynamic module
**globally**, because Pester runs `BeforeAll` and `It` in different scopes. Whole scripts
run end to end against stubs; **import the real module before defining a stub**, or the
later import replaces it. Fixtures must plant the null shapes a real service returns, or
they prove only the happy path. Tests pass vacuously the same way scripts fail quietly:
`foreach` over a null summary asserts nothing and `-Not -Contain` on a misspelled column
always succeeds, so assert the count first. Detail in `tests\README.md`.
