# ops-toolkit Tests

Pester specs covering the ops-toolkit scripts, in two layers: unit specs over the
decision logic, and integration specs that run whole scripts end to end against
stubbed back ends.

Run them directly, or through the validation suite which runs them as a gate:

```powershell
Invoke-Pester -Path .\tests -Output Detailed
pwsh -File .\Invoke-RepoValidation.ps1 -Gate Test
```

Requires Pester 5 or later. The Pester 3.4.0 that ships with Windows cannot run these
specs:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
```

## Unit specs

`TestHelpers.psm1` parses a script, lifts out its function definitions and
script-scoped lookup tables, wraps them in a dynamic module, and imports it
**globally**. Global matters: Pester runs `BeforeAll` and `It` in different scopes, so
a plain import inside `BeforeAll` is invisible to the tests that need it.

```powershell
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\entra\Export-EntraAppCredentialExpiry.ps1'
}
```

`Import-ScriptFunction` throws if a named function has disappeared, so a rename breaks
the test loudly rather than silently testing nothing.

## Integration specs

`Integration.*.Tests.ps1` run a whole script end to end against a stubbed tenant or
domain with known facts planted, and assert the reports it writes. This exercises
everything the unit specs cannot: query, classify, aggregate, sort, write, summarise.

`Invoke-ScriptUnderTest` runs the script in a child process. Two reasons that is not
optional:

- `#Requires` is evaluated when the script is parsed, so any stand-in module has to be
  discoverable before the process starts.
- A stubbed cmdlet must not leak into the test session or into other specs.

**Stub after importing, not before.** A module imported after a function of the same
name replaces it, and a script's own `#Requires` triggers that import. Stubs defined
first are silently clobbered and the real cmdlet runs, which presents as the stub
being ignored for no visible reason.

**Type switch parameters as switches.** A stub declaring `param($All)` fails with
"Missing an argument for parameter 'All'" when the script calls `-All`.

**Give a fixture the null shapes the real service returns.** A subnet with no route
table, a NIC attached to no VM, a public IP associated with nothing, an NSG on no
interface: those are ordinary Azure, and under `Set-StrictMode -Version 3.0` reading
through them throws. A fixture where every optional property is populated proves only
that the happy path works. `Integration.RetrofittedScripts.Tests.ps1` plants each of
those, which is how two shipped crashes were found.

**Standing in for a module that is not installed.** `Use-FakePlaceholderModule` stages
named modules on `PSModulePath` that export nothing, which satisfies `#Requires` for a
module this machine does not have (`Az.Network`, `Az.Compute`) without replacing the
stubs already defined in the setup block.

**A function stub does not isolate every command, and the difference is not
cosmetic.** Defining a same-named function in the caller's scope does shadow the
cmdlets in `Microsoft.PowerShell.Management`, so registry, service, and file writes are
reliably intercepted. It does **not** shadow the commands exported by `ScheduledTasks`,
`Defender`, or `PrintManagement`. Relying on it disabled four real scheduled tasks and
added three real Defender path exclusions on the development machine, and the printer
connection only failed to apply because the spooler happened to be unreachable.

Anything touching those three goes through `Use-FakeSystemModule`, which stages
replacements ahead of the real modules so the real ones are never loaded and there is
nothing left to shadow. If you add a script that reaches a new subsystem, stage a
module for it rather than trusting a function stub, and then **verify the machine
afterwards** rather than trusting the test result.

**Type switch parameters as switches, in fixtures too.** This is the same trap as
above and it has now been introduced twice. A stub declaring a plain `$Force` swallows
the following argument and fails with "Missing an argument for parameter 'Force'",
which reads like a fault in the script under test.

**A fake module must not declare `$ErrorAction` alongside `[CmdletBinding()]`.**
`CmdletBinding` already supplies it, and redeclaring it fails every call with "A
parameter with the name 'ErrorAction' was defined multiple times for the command."

**Some commands cannot be stubbed by name at all.** `Import-AzureVpnClientXmlProfile`
resolves its command through `Get-Command` and then reads `.Source`, which is empty for
a function, so a function stub resolves to an empty string. That one is driven by a
real command file on disk.

### Standing in for the ActiveDirectory module

The directory scripts declare `#Requires -Modules ActiveDirectory`, so without RSAT
they refuse to start and none of their logic can run. `Use-FakeActiveDirectory` stages
`Fixtures\FakeActiveDirectory` on `PSModulePath` under that name, which satisfies the
requirement and supplies the cmdlets the scripts call. Populate `$global:FakeAdData`
in the setup block.

Add a cmdlet to that fixture only when a script under test actually calls it, and make
it behave like the real one in the cases that matter, including the failure cases. The
fake `Get-ADGroup` throws on an unknown identity precisely because the audit relies on
that to skip forest-root-only groups in a child domain.

### Scripts that change something

`Integration.StateChanging.*.Tests.ps1` cover the 22 scripts that modify Active
Directory, Azure, IIS, or Windows. Every one runs **twice** against the same fixture:
once with `-WhatIf`, where the mutation log must stay empty, and once executing, where
it must fill with exactly the changes the plan described.

The second run is the point. On its own, "`-WhatIf` attempted nothing" is
unfalsifiable, because a script that has quietly stopped working attempts nothing
either, and this repository has shipped that exact failure before. The paired run is
what proves the suppressed path was reachable at all. For the same reason the shared
`-WhatIf` assertion checks the exit code first: a run that died before reaching any
change also leaves an empty log.

Nothing is really changed. Write commands record the attempt to a log named by
`OPSTOOLKIT_TEST_MUTATION_LOG` and return, which is what turns "changed nothing" from
an assumption into a checkable claim.

Fixtures are arranged so exactly one item reaches each decision path: one stale
computer among fresh ones, one site whose header is wrong among sites that are already
right, one log field that already exists. A script that rewrote everything indiscriminately
would then fail rather than merely look busy in a summary count.

### Running against the real machine

`Integration.LocalCollectors.Tests.ps1` is the exception to all of the above: it runs
`Export-SecurityControlEvidencePack.ps1` and `Test-WindowsHardeningState.ps1` against
this actual machine, with no stub anywhere. It is the slowest spec in the suite,
because the evidence pack runs six collectors.

It asserts invariants, never values. How many volumes are encrypted or what Defender
reports is a property of whichever machine runs the suite. What has to hold everywhere
is that the arithmetic is honest: the four outcome counts sum to the control count,
the named control lists match their counts, a collector that failed is reported as
failed rather than dropped, and nothing passes on an absence of evidence. Both scripts
have previously got exactly that wrong, in the same direction.

## What is and is not proven

Proven: the full pipeline of every script, including the six that cannot reach a live
system from this machine. Planted faults are detected, planted non-faults are not, and
the reports and summary counts agree. For the two local collectors, proven against the
real system rather than a stub.

Not proven: that a real Graph endpoint, domain controller, or Exchange Online tenant
returns the shapes the stubs return. That is the residual risk, and it is narrowed
separately by checking each field against the installed SDK model types, which is how
two beta-only fields were caught returning null instead of erroring.

What that residual risk actually looks like is now on record rather than hypothetical.
The Azure specs found two defects that no stub with fully-populated fixtures would have
found, both of which made a script report a clean estate for an estate it had never
successfully read. Shape mismatches do not announce themselves; they produce a plausible
empty report.

## Conventions

- One behaviour per `It`, named as a promise, so a failure reads as a broken one.
- Where a test encodes a judgment call, the reason is in a comment. Someone changing
  the behaviour should have to argue with the reason rather than guess at it.
- Assert the negatives too. Several real bugs here were things being reported that
  should not have been, not things being missed.
- Fixtures are created under the temp directory and removed in `AfterAll`. Nothing
  writes into the repository.
