# ops-toolkit Theory

Constraints that look arbitrary until you know why, and traps a fresh thread will
otherwise re-derive the hard way. Read before changing anything structural.

## Load-bearing constraints

**Never invent a comment-based help keyword.** One unrecognised keyword such as
`.INSTRUCTIONS` silently invalidates the whole block, leaving `Get-Help` with nothing
but generated syntax. This was true of 30 of 31 scripts and went unnoticed for
months. Custom sections go inside `.DESCRIPTION` or `.NOTES` as labelled text.

**Non-ASCII needs a BOM.** The scheduled-task host is Windows PowerShell 5.1, which
reads a BOM-less file as the ANSI code page and fails to parse it. The script then
silently does nothing while the task reports success. An em-dash in a comment is
enough.

**`??` and `?.` make a script pwsh-7 only.** Three scripts use them deliberately and
carry `#requires -Version 7`, turning a confusing parse error into a plain version
message. Ergonomics while collectors are run by hand; correctness the moment anything
is scheduled, because the task host is 5.1.

**Run directories are not cosmetic.** Every script writes
`<prefix>-yyyyMMdd_HHmmss\` with a CSV and JSON per report plus `summary.json`.
`Compare-OpsToolkitRun.ps1` can only diff that layout, so a script writing loose
timestamped files can never have its history compared.

**Undetermined is never folded into a pass.** A check that could not run is reported
as not having run. The evidence pack counts NotAssessed separately from NotMet,
because a pack that converts "we did not check" into "we are fine" is worse than no
pack. Same rule for unelevated reads, unreachable machines, and missing modules.

## Traps that have already cost time

**A Graph field that exists only in beta returns null, it does not error.** This bit
twice: `servicePrincipalCredentialKeyId` on the v1.0 sign-in resource, and
`defaultMfaMethod` on `userRegistrationDetails`. Both produced confidently wrong
reports. Check any Graph field against the installed SDK model type first; the
offline check is fast and has a hit rate.

**`@($x) | Sort-Object` wraps the input, not the output.** Zero rows gives `$null`
and every `.Count` throws under strict mode. Zero rows is the ordinary case for a
healthy estate, so fixtures that always have data will not catch it.

**`@($rows | Select-Object -First 1).PSObject.Properties.Name` returns the array's
members** (`Length`, `Rank`, `Count`), not the record's. Pipe through
`ForEach-Object`, or it silently poisons whatever uses them as column names.

**`@($null)` is a one-element array containing null.** Passes a count check, then
fails validation somewhere less obvious. **PowerShell also unrolls an array returned
from a function**, so a `[byte[]]` arrives as `[object[]]` and a type test misses it.

## Testing

Scripts are scripts, not modules, so tests cannot import them and dot-sourcing would
execute them. `tests\TestHelpers.psm1` parses the file, lifts out the functions and
script-scoped tables, and imports them as a dynamic module **globally**, because
Pester runs `BeforeAll` and `It` in different scopes. Coverage is decision logic;
Graph, directory, CIM and registry calls are unproven and recorded as such on the
work board rather than assumed to work.
