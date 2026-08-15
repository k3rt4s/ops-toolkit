# ops-toolkit Tests

Pester specs covering the pure logic inside the ops-toolkit scripts.

Run them directly, or through the validation suite which runs them as a gate:

```powershell
Invoke-Pester -Path .\tests -Output Detailed
pwsh -File .\Invoke-RepoValidation.ps1 -Gate Test
```

Requires Pester 5 or later. The Pester 3.4 that ships with Windows cannot run these
specs:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
```

## How these tests reach into scripts

Every runnable thing in this repo is a script, not a module, so its functions cannot
be imported, and dot-sourcing would execute the script and try to reach Active
Directory or Microsoft Graph before defining anything.

`TestHelpers.psm1` parses the file instead and lifts out only the function
definitions and script-scoped lookup tables, wraps them in a dynamic module, and
imports it globally. Global matters: Pester runs `BeforeAll` and `It` in different
scopes, so a plain import inside `BeforeAll` is invisible to the tests that need it.

```powershell
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\entra\Export-EntraAppCredentialExpiry.ps1'
}
```

`Import-ScriptFunction` throws if a named function has disappeared, so a rename
breaks the test loudly rather than silently testing nothing.

## What is and is not covered

Covered: classification and decision logic. Expiry and severity classification, the
sign-in usage match and its paging, userAccountControl bit decoding, the gMSA
exclusion, AD access-mask and extended-right decoding, expected-principal
suppression, LDAP event message parsing, Conditional Access policy signatures, report
writing, and the legacy API scanner end to end against a fixture.

Not covered: the calls to Microsoft Graph, Active Directory, CIM, and the registry
themselves. Those need a tenant, a domain, or a specific machine state. The scripts
that talk to them are marked in the work board as unproven against a live system, and
that distinction is deliberate: these tests prove the reasoning, not the plumbing.

## Conventions

- One assertion per `It`, with a name that states the behaviour rather than the
  method, so a failure reads as a broken promise.
- Where a test encodes a judgment call, the reason is in a comment. A future reader
  changing the behaviour should have to argue with the reason, not guess at it.
- Fixtures are created under the temp directory and removed in `AfterAll`. Nothing
  writes into the repository.
