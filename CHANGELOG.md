# Changelog

Notable changes to the ops-toolkit. Newest first.

This file starts on 2026-08-15. Earlier history is in the git log; the reorganization
that produced the current layout is described in the README under "What Changed".

## 2026-08-15

Twenty new scripts, a shared module, a validation suite, and a test suite. The
repository went from no automated gates to seven, and `Invoke-RepoValidation.ps1
-Strict` passes.

### Added

- **Identity.** `Export-EntraAppCredentialExpiry.ps1` reports app registration and
  service principal secrets and certificates by days to expiry, and matches each
  credential against service principal sign-ins so an expiry alert says whether the
  credential is still authenticating. `Export-EntraAuthMethodReadiness.ps1` finds
  users whose only registered method is SMS or voice. `Export-EntraConditionalAccessBaseline.ps1`
  exports policies, gap-analyses them, and diffs against a saved baseline.
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
- **Plumbing.** `modules\OpsToolkit.Reporting`, `Invoke-RepoValidation.ps1` with
  seven gates, and a 167-test Pester suite under `tests\`.
- `THEORY.md`, `FUTURE_FEATURES.md`, and this changelog.

### Fixed

- Comment-based help did not parse in 30 of 31 scripts. The documented header
  standard used keywords PowerShell does not accept, and one unrecognised keyword
  invalidates the entire block. Headers folded into standard keywords; content
  preserved verbatim.
- `Invoke-DiskMaintenance.ps1` contained non-ASCII characters with no BOM, so
  Windows PowerShell 5.1 could not parse it and a scheduled run would have done
  nothing while reporting success. BOM added and the parser gate now enforces this.
- The OS lifecycle staleness warning measured the data file's `LastWriteTime`, which
  git resets on checkout, so a fresh clone of stale support dates reported them as
  verified today. Rows now carry `VerifiedOn` and `Source`.
- Two Graph fields that exist only in beta were being read from v1.0 responses,
  returning null silently: the sign-in credential key id, and `defaultMfaMethod`.
- `Compare-OpsRecordSet` disabled change detection globally as soon as any key was
  duplicated anywhere. Duplicates are now handled per key.
- 27 `Write-Host` calls became `Write-Information`, clearing the last analyzer
  findings.

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

### Not verified

The three Entra scripts, the two Active Directory scripts, and the Microsoft 365
collector have never run against a live tenant or domain. Their logic is unit-tested
and their Graph and Exchange field usage was checked against the installed SDK
models, but no real call has been made. The work board records which is which.
