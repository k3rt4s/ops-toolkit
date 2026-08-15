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

## What is and is not proven

Proven: the full pipeline of every script, including the six that cannot reach a live
system from this machine. Planted faults are detected, planted non-faults are not, and
the reports and summary counts agree.

Not proven: that a real Graph endpoint, domain controller, or Exchange Online tenant
returns the shapes the stubs return. That is the residual risk, and it is narrowed
separately by checking each field against the installed SDK model types, which is how
two beta-only fields were caught returning null instead of erroring.

## Conventions

- One behaviour per `It`, named as a promise, so a failure reads as a broken one.
- Where a test encodes a judgment call, the reason is in a comment. Someone changing
  the behaviour should have to argue with the reason rather than guess at it.
- Assert the negatives too. Several real bugs here were things being reported that
  should not have been, not things being missed.
- Fixtures are created under the temp directory and removed in `AfterAll`. Nothing
  writes into the repository.
