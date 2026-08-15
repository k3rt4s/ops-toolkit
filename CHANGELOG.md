# Changelog

Notable changes to the ops-toolkit. Newest first.

This file starts on 2026-08-15. Earlier history is in the git log; the reorganization
that produced the current layout is described in the README under "What Changed".

## 2026-08-15

Twenty new scripts, a shared module, a validation suite with seven gates, and a
257-test Pester suite. `Invoke-RepoValidation.ps1 -Strict` passes, which it never did
before: no analyzer findings, no help exemptions.

### Added

- **Identity.** `Export-EntraAppCredentialExpiry.ps1` reports app registration and
  service principal secrets and certificates by days to expiry, and matches each
  credential against service principal sign-ins so an expiry alert says whether the
  credential is still authenticating. `Export-EntraAuthMethodReadiness.ps1` finds
  users whose only registered method is SMS or voice.
  `Export-EntraConditionalAccessBaseline.ps1` exports policies, gap-analyses them,
  and diffs against a saved baseline.
- **Active Directory.** `Export-AdPrivilegedAccessAudit.ps1` covers AS-REP roastable
  and Kerberoastable accounts, all four delegation types, PASSWD_NOTREQD, reversible
  encryption, orphaned adminCount, krbtgt age, and nested tier-0 membership.
  `Export-AdAclRiskReport.ps1` reports who can take over a privileged object or
  replicate the directory. `Test-LdapSigningReadiness.ps1` lists clients that LDAP
  signing enforcement will break.
- **Endpoint.** OS support lifecycle, Windows 11 upgrade readiness, update health,
  BitLocker escrow, and local administrator and LAPS posture.
- **Certificates.** `Export-CertificateExpiryInventory.ps1` across machine stores,
  IIS bindings, and live TLS endpoints.
- **Microsoft 365.** `Export-M365MailboxSecurityPosture.ps1` for mailbox and inbox
  rule forwarding, legacy protocol exposure, and EWS use.
- **Azure.** `Export-AzOrphanedResource.ps1` for resources that bill and are attached
  to nothing. Deletes nothing; tags only, with `-WhatIf`.
- **Reporting.** `Export-SecurityControlEvidencePack.ps1` assembles a dated bundle
  answering the control questions insurers and assessors ask, and
  `Compare-OpsToolkitRun.ps1` diffs a collector run against the previous one.
- **Hardening verification.** `Test-WindowsHardeningState.ps1` checks applied
  hardening against the Set- scripts' own plans and proves the TLS client policy with
  real handshakes.
- **Utilities.** `Find-LegacyApiUsage.ps1` scans for retired and expiring Microsoft
  APIs with deadlines and replacements.
- **Plumbing.** `modules\OpsToolkit.Reporting`, `Invoke-RepoValidation.ps1`, and a
  Pester suite with unit specs over the decision logic and integration specs that run
  whole scripts end to end against stubbed back ends. A fake `ActiveDirectory` module
  staged on `PSModulePath` lets the directory scripts run on a machine with no RSAT.
- `THEORY.md`, `FUTURE_FEATURES.md`, and this changelog.

### Fixed

- **Comment-based help did not parse in 30 of 31 scripts.** The documented header
  standard used keywords PowerShell does not accept, and one unrecognised keyword
  invalidates the entire block. Headers folded into standard keywords; content
  preserved verbatim.
- **`Invoke-DiskMaintenance.ps1` would have silently done nothing as a scheduled
  task.** It contained non-ASCII characters with no BOM, which Windows PowerShell 5.1
  cannot parse, and the task would still have reported success. BOM added and the
  parser gate now enforces it.
- **`Export-M365MailboxSecurityPosture.ps1` never read accepted domains and reported
  every mail forward as leaving the organisation.** An unbound `[string[]]` parameter
  is `$null` and `@($null)` has `Count` 1, so the `Count -eq 0` guard that triggers
  the tenant lookup could never fire. `InternalDomainsKnown` reported true while
  nothing was known. Found only by running the script end to end. The same pattern
  caused `EndpointsProbed = 1` on a certificate run that probed none, and a `[null]`
  entry in the Azure summary. The codebase was swept; the remaining instances are
  guarded.
- **Two Graph fields that exist only in beta were read from v1.0 responses**, where
  they return null rather than erroring: the sign-in credential key id, which made
  every live credential report as unused, and `defaultMfaMethod`, which left a column
  empty on every row.
- **The OS lifecycle staleness warning measured the data file's `LastWriteTime`**,
  which git resets on checkout, so a fresh clone of stale support dates reported them
  as verified today. Rows now carry `VerifiedOn` and `Source`.
- **`Compare-OpsRecordSet` disabled change detection globally** as soon as any key was
  duplicated anywhere. Duplicates are now handled per key.
- 27 `Write-Host` calls became `Write-Information`, clearing the last analyzer
  findings.
- **Both Azure collectors scanned nothing at all unless given `-ResourceGroupName`,
  and reported success.** The unfiltered case was built as
  `$filter = if ($ResourceGroupName) { ... } else { @($null) }`, but an `if` emits its
  result down the pipeline, which unrolls the one-element array back to a bare `$null`,
  and `foreach` over `$null` iterates zero times. Every collection loop was skipped.
  `Export-AzNetworkInventory.ps1` wrote six empty reports and exited 0, and
  `Export-AzOrphanedResource.ps1` reported no orphaned resources, so an unscanned
  subscription was indistinguishable from a clean one. Both now build the filter list
  explicitly. Predates the module retrofit; found by the new end-to-end coverage.
- **`Export-AzNetworkInventory.ps1` crashed on ordinary Azure shapes.** Under
  `Set-StrictMode -Version 3.0`, member enumeration over an empty collection throws
  while a populated one succeeds, so an NSG attached to no network interface killed the
  run; and reading a property through a null throws, so a subnet with no route table, a
  NIC on no VM, or a public IP associated with nothing did the same. The last of those
  is precisely what an orphan review is looking for. Optional nested reads now go
  through `Get-OpsPropertyValue` and collections through `ForEach-Object`.

### Changed

- Four scripts moved from loose timestamped files to run directories:
  `Export-AdUserInventory`, `Export-AzNetworkInventory`,
  `Export-M365DistributionGroupMessageTraceUsage`, and
  `Join-ApplicationsWithEndpointSites`. Anything consuming their old output paths
  needs updating. The layout is what `Compare-OpsToolkitRun.ps1` requires.
- Every script now writes reports through `OpsToolkit.Reporting` rather than a local
  copy of the same helpers.
- `Page-File-Bleed.ps1` gained a header and is no longer exempt from the help gate.
- Three pwsh-7-only scripts carry `#requires -Version 7`, turning a parse error under
  5.1 into a plain version message.

### Verification status

257 tests pass and `Invoke-RepoValidation.ps1 -Strict` exits 0 across all seven gates.

Every script runs end to end in the test suite, including the six that cannot reach a
live system from the build workstation: their back ends are stubbed and their reports
asserted against planted faults and planted non-faults. Fixtures now deliberately plant
the null shapes a real service returns, which is what surfaced the two Azure defects
above; a fixture with every optional field populated proves only the happy path.

Eight scripts were additionally run for real against this workstation and their output
checked against its actual state: the five Windows collectors, the certificate
inventory, the hardening verifier, and the evidence pack, which drove all six
collectors to completion and reported eight controls as NotAssessed rather than folding
them into a pass. `Integration.LocalCollectors.Tests.ps1` keeps the evidence pack and
the hardening verifier under real-system coverage, asserting the arithmetic rather than
machine-specific values.

What remains unproven is that a real Microsoft Graph endpoint, domain controller, or
Exchange Online tenant returns the shapes the stubs return. That risk is narrowed by
checking each field against the installed SDK model types, which is how the two
beta-only fields above were caught, but it is not eliminated. No live tenant or
domain run has been performed.
