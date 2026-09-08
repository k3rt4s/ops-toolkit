# Changelog

Notable changes to the ops-toolkit. Newest first.

This file starts on 2026-08-15. Earlier history is in the git log; the reorganization
that produced the current layout is described in the README under "What Changed".

## 2026-09-08

### Fixed: drive inventory source-tree guard portability

- `Analyze-C.py` now derives the repository root from its own file location instead
  of hard-coding `C:\Code` when refusing to write generated inventory under the
  source tree, passes string paths to the optional not-indexed helper, and reports
  helper failures instead of swallowing them. If the repository root cannot be
  identified, the script refuses to run rather than risk writing under source. The
  required not-indexed helper must now be a trusted, existing `.ps1` file and its
  resolved path is printed before execution. `tests\RequiredPathParameters.Tests.ps1`
  covers the absence of this workstation-specific path in that script body.
- `Export-SecurityControlEvidencePack.ps1` now normalizes newlines in input-source
  table cells and escapes literal pipes before writing `summary.md`, so a source-read
  note cannot split a Markdown row without losing the pipe character.
- Management-plane-only scope exclusions now stay relaxed only when no explicit
  endpoint scope was supplied; an explicitly supplied but empty target list still
  rejects exclusions as out of scope. The reconciliation-gap test now reads its
  gap count through a local regex match instead of `$Matches`.
- The top-level README examples now include the required path arguments for the
  scripts whose workstation-specific defaults were removed.

## 2026-09-07

### Added: end-to-end ungraded reconciliation-gap coverage

- `tests\Integration.LocalCollectors.Tests.ps1` now covers an evidence pack whose
  coverage manifest finds a reconciliation gap while the Defender inventory is not
  one of the required reconciliation authorities, asserting that `EDR-01` remains
  `NotAssessed` while still showing the ungraded gap count and limitation.

### Changed: evidence-pack input hash explanation

- `Export-SecurityControlEvidencePack.ps1` now explains the one legitimate
  `SourceSHA256` versus `SHA256` difference for the coverage manifest input: the
  pack copy rewrites authority paths to pack-relative form after hashing the
  source so the manifest can be re-run from the pack root. The note is written
  to `input-sources.csv` and repeated in the new `summary.md` input sources
  table without changing either hash calculation.

### Fixed: scope exclusion on a management-plane-only evidence pack

- `Export-SecurityControlEvidencePack.ps1` no longer throws when a
  `-ScopeExclusion` names a target that is not in `-ComputerName` or
  `-TargetListPath`, provided the requested target list is empty and either
  `-DefenderDeviceInventoryPath` or `-CoverageManifestPath` was supplied. The
  exclusion is carried into the excluded-key set exactly as an endpoint
  exclusion is today, so the named machine is subtracted from the Defender and
  reconciled populations and still appears in `summary.md` under "Excluded
  endpoints" and in every endpoint control's scope fields. The throw remains
  for the case where no management-plane input was supplied at all, because
  there an exclusion really would invent scope.

### Fixed: test harness null ExitCode and missing return

- Cached the process handle immediately after `Start-Process` so `ExitCode` reads back
  after process exit, preventing spurious `Failed` status on runs that actually succeeded.
  Without caching, .NET can return null for ExitCode, and null is graded as Failed rather
  than Completed.
- Added missing `return` statement after `Set-ItResult -Skipped` in `Confirm-LiveScriptRun`,
  preventing execution from falling through to the Failed check below.
- Both changes in `tests/TestHelpers.psm1`. The harness verifies every integration test
  in the suite, so these fixes prevent false negatives that would mask real issues.
- Strict validation passes all eight gates with unchanged test count (465 tests).

## 2026-09-06

### Changed: hard-coded absolute path defaults replaced with required parameters

- Removed every hard-coded absolute-path default from the five state-changing scripts
  that carried one: `Set-WorkstationPerformance.ps1` (`-DefenderPathExclusion`,
  `-ReportDirectory`), `Set-BrowserCredentialPosture.ps1` (`-ReportDirectory`),
  `Set-WorkstationLockPosture.ps1` (`-ReportDirectory`), `Invoke-DiskSpaceReclaim.ps1`
  (`-ReportDirectory`), `Analyze-C.py` (`--output-dir`, plus a new required
  `--notindexed-script`), and `compare_folders.py` (`--output-dir`). Each is now a
  required parameter with no default: `[Parameter(Mandatory = $true)]` in PowerShell,
  `required=True` in argparse. This is a public MIT repository, so an unattended run
  with no arguments now refuses before changing anything, instead of writing into a
  data tree that does not exist on the operator's machine or, for
  `Set-WorkstationPerformance.ps1`, silently adding a Defender path exclusion nobody
  asked for.
- Updated the `Required syntax` header block in each of the five scripts and
  `scripts/it-operations/README.md`'s command examples to show the new mandatory
  arguments; `scripts/it-operations/README.md` no longer names an absolute workstation
  path.
- Added `tests/RequiredPathParameters.Tests.ps1`, asserting via `Get-Command` parameter
  metadata (never by running the script) that each named parameter is mandatory, and
  that a no-argument run through the existing `Invoke-ScriptUnderTest` harness
  (`-NonInteractive`, so a missing mandatory parameter fails immediately instead of
  prompting) makes no mutation.

### Changed: board and backlog scored

- Scored every live item on the work board and every unshipped feature in
  `FUTURE_FEATURES.md` under `ai_development/docs/board-scoring.md`, added a `Scored index`
  to the top of `FUTURE_FEATURES.md`, and saved the ranked review to
  `C:\Code_data\ops-toolkit\board_review_2026-09-06.md`. No code changed.

## 2026-09-01

### Added: browser credential-theft surface hardening

- Added `Set-BrowserCredentialPosture.ps1` under `it-operations\windows-hardening`, which
  reduces the surface an information stealer harvests from a browser in a single pass.
- Enforces, with a rollback record, the two browser policies that a local machine policy
  can pin: blocking the configured authenticator browser extensions in Chrome and Edge by
  default (via `ExtensionSettings`, merged into any existing policy), and pinning Chrome
  Application-Bound Encryption on (`ApplicationBoundEncryptionEnabled`).
- Blocks the well-known password-manager browser extensions only when the operator opts in
  with `-IncludePasswordManagerExtensions`; they are not a default because blocking one can
  push a user back to browser-saved passwords, a net loss on its own. `-ExtensionBlockId`
  still supplies any custom set on top of the default.
- Reports, without changing, the talk defenses that are not a single machine-policy value:
  Edge cookie protection, Device-Bound Session Credentials, SmartScreen state, and local
  administrator rights (deferring the full membership and LAPS view to the companion
  `Export-LocalAdminAndLapsPosture.ps1` rather than duplicating it).
- Mirrors the plan/apply/rollback and `ShouldProcess` structure of
  `Set-WorkstationLockPosture.ps1`: `-WhatIf` writes the plan and previews without
  touching the registry, and `-Rollback` restores every value a prior run changed.
- Made the registry read helper robust under `Set-StrictMode 3.0` for the common case of a
  browser policy key that exists with only some values set, which a bare property access
  would have thrown on.
- Added a paired `-WhatIf`/executing Pester block asserting the preview writes nothing and
  the executing run blocks the extensions and pins ABE; the state-changing Windows suite is
  now eleven scripts.

## 2026-08-31

### Fixed: bounded live-integration validation

- Moved every live-machine integration setup into a bounded child process and stopped
  the whole descendant tree when its limit expires, preventing blocked WMI or WUA
  calls from hanging the repository validation run indefinitely.
- Added an explicit `NotRun` result for timed-out setups. Pester assertions fed by an
  unavailable setup are skipped, and the validator reports their count separately
  from both executed checks and failures.
- Added regression coverage for completed child runs, timeout classification,
  descendant cleanup, and Pester XML failure-versus-NotRun parsing.
- Recorded the separate collector-level Windows Update hang as backlog work; no
  collector script was changed.

## 2026-08-30

### Added: evidence scope and traceability

- Extended `Export-SecurityControlEvidencePack.ps1` with per-control intended,
  attempted, observed, failed, and explicitly excluded populations; evidence-language
  conclusions; limitations; exact artifact paths; observation times; freshness; and
  SHA-256 hashes.
- Added an evidence manifest, operator-input inventory, and redacted run context with
  the assembly script hash and toolkit revision.
- Added optional Defender management-plane inventory and coverage-manifest inputs so
  estate endpoint protection is based on reconciled evidence instead of one local
  Defender reading. Unread required sources remain `NotAssessed`.
- Added synthetic decision tests and end-to-end bundle assertions for exclusions,
  provenance, artifact integrity, reconciliation, and non-conformity report language.
- Corrected the independent-review findings before closeout: population failures no
  longer mix endpoints with unread authorities, excluded endpoints are removed before
  EDR grading, freshness uses the oldest supporting artifact, and local-only evidence
  cannot produce an estate-wide `Met`.
- The pack now requires PowerShell 7, snapshots and hashes sanitized authority inputs,
  requires two readable required authorities including Defender for a clean EDR result,
  records input-driven collector scope accurately, and includes `summary.md` plus every
  nested collector summary in the evidence manifest.

## 2026-08-29

### Added: evidence-pack feasibility review

- Investigated the Certified Information Security assessment platform using anonymous
  synthetic NIST CSF 2.0 and ISO 27001 sessions and public documentation only.
- Recorded independent evidence gaps, candidate controls, report-language improvements,
  rejected directions, and a proposed evidence scope and traceability user story in
  `docs\certified-information-security-assessment-value-check.md`.
- No proprietary methodology, mapping, scoring model, question set, UI, or report
  format was copied or adapted.

## 2026-08-20

Ten new reclaim targets covering the developer caches and Docker layers that a manual
cleanup session actually recovered space from, an opt-in switch for the one temp folder
the cleanup script never reached, and the test stubs that let any of it be tested.

### Added: developer cache and Docker targets in `Invoke-DiskSpaceReclaim.ps1`

- **Seven cache targets.** `NpmCache`, `TorchCache`, `PreCommitCache`,
  `CodexRuntimeCache`, `NvidiaShaderCache`, `PlaywrightBrowsers`, and the existing
  `HuggingFaceCache` are now all reachable by name. Each honours the tool's own override
  variable (`npm_config_cache`, `TORCH_HOME`, `PRE_COMMIT_HOME`,
  `PLAYWRIGHT_BROWSERS_PATH`, `HF_HOME`) before falling back to the platform default, so
  a redirected cache is cleaned where it actually lives rather than reported as absent.
- **Three Docker targets.** `DockerStoppedContainers`, `DockerUnusedVolumes`, and
  `DockerOldImageTags`. The last keeps the newest `-KeepTagsPerRepository` tags per
  repository, default two: two keeps the shipped tag and the one before it, which is
  what a rollback needs, and one leaves nothing to roll back to.
- **Tag retention sorts on a parsed date, not on the printed string.** Docker prints
  `CreatedAt` as `2026-06-01 10:00:00 +0000 UTC`, which `[datetime]::TryParse` rejects
  outright over the trailing zone name, so a fallback to string order is chronological
  only while every row carries the same offset. The cost of being wrong is deleting the
  tag still in production rather than the one before it. A tag docker refuses to remove
  because a container still references it is now reported as `Partial` with a count,
  rather than counted as a removal.
- **`DockerVhdxCompact`, opt-in and elevated.** Pruning inside Docker frees space within
  the virtual disk without shrinking the file, so the host volume sees nothing back
  until the disk is compacted; on the machine this was built from, that was 4.76 GB the
  prunes alone did not return. It is never in the default target set, it runs last
  whatever order it was asked in so it compacts a disk the other targets have already
  emptied, and it proves the file is released with an exclusive open before handing it
  to `diskpart`, because `diskpart` reports success on a no-op.
- **Partial is counted apart from Reclaimed.** A path cache that still has bytes in it
  afterwards reports `Partial:` with the residue, and the summary carries its own
  `PartialTargets` count. A locked cache silently counted as cleared is how a disk that
  is still full gets signed off as cleaned.
- **The default target set is unchanged.** All ten are selected explicitly, so every
  existing caller and scheduled task does exactly what it did before.
- **`Get-CommandPath` no longer reports a resolved command as missing.** It returned
  `.Source`, which is empty for anything that is not an external file, so a command
  resolved as a function or an alias read as not installed.

### Added: `-IncludeWindowsTemp` in `Invoke-WindowsFileCleanup.ps1`

- `C:\Windows\Temp` is now reachable, opt-in and requiring elevation. It stays out of
  the default temp set because it is machine-wide and services write to it, and a
  default that quietly grew to include it would make every already-scheduled call of
  this script a different command than the reviewed one.

### Added: test stubs for the tool CLIs

- `pip`, `npm`, `docker`, `wsl`, `diskpart.exe`, and `Dism.exe` are stubbed in the
  shared Windows mutation stub set. Unstubbed, a test run purges this machine's real
  package caches, stops every WSL distro, and attaches a virtual disk. `docker` is not
  a pure recorder: the tag-retention logic decides what to remove from what `image ls`
  answers, so it replays a fixture, and a stub answering nothing would have made that
  logic look correct by removing nothing.
- `Get-Process`, `Start-Process`, and `Stop-Process` are deliberately not in the shared
  set, because other scripts use them legitimately; the one test that needs them stubs
  them itself.
- The new coverage runs every cache target against a redirected `USERPROFILE` and
  `LOCALAPPDATA` sandbox, and asserts no removal ever reached a real cache path. Every
  other assertion in that block would pass just as well while the run deleted the real
  caches on the machine.

### Changed: documentation caught up with the new targets

- The root README capability table, the README example, and the it-operations README
  all described the original five-target script. They now name the default set and the
  opt-in targets separately, because the distinction is the whole safety property here:
  a reader who believes the new targets are in the default set will schedule this
  script expecting it to compact a virtual disk unattended.
- The shipped user story for this script now carries acceptance criteria for tag
  retention, partial results, and the elevated compaction path, and lists
  `DockerVhdxCompact` among the targets that need elevation.

## 2026-08-17

Full script coverage, a validation gate that catches the suite changing the machine,
`-WhatIf` on the last two scripts that lacked it, and a new collector answering whether
the logging a hunt would need is switched on at all.

### Added: endpoint telemetry posture

- **`scripts\logging\Export-EndpointTelemetryPosture.ps1`.** Reports whether PowerShell
  script-block, module, and transcription logging are on, whether process creation
  events include the command line, which of nine audit subcategories are auditing,
  whether Sysmon is running and under which config, whether an event-forwarding
  subscription manager is configured, and the state of eleven security-relevant event
  channels.
- **Retention is measured, not inferred.** Each channel's retention comes from the
  oldest record still in it, not from its configured maximum size. On the development
  workstation that distinction is the whole finding: the Security log is capped at
  20 MB, sits at 100% of it, and holds six hours. A report reading configured size
  would have called that 20 MB of coverage.
- A channel below the required window is Insufficient only when it is full. One that is
  simply younger than the window is Building, so a machine built last week is not
  reported as misconfigured. Unknown fullness is treated as full, because assuming the
  generous case is how a rolling log gets reported as fine.
- Audit subcategories are matched by GUID rather than by display name. The names are
  localized, so a name match on a non-English Windows silently finds nothing and every
  subcategory reads as absent.
- Sysmon is found by service image path rather than by service name, because the name
  is chosen at install time.
- Sysmon and event forwarding are Conditional by default, so an estate that runs
  neither is not reported as having holes where they would be. `-RequireSysmon` and
  `-RequireEventForwarding` make their absence a finding.

### Added: two evidence pack controls

- **LOG-01 and LOG-02** in `Export-SecurityControlEvidencePack.ps1`, covering whether
  security-relevant activity is logged and whether it is retained long enough to
  investigate an incident found late. They are asked separately because they fail
  separately: a machine can be generating everything and keeping six hours of it. Any
  setting the collector could not read takes LOG-01 to NotAssessed outright rather
  than to a verdict drawn from the settings that were read.

### Added: Defender for Endpoint device inventory

- **`scripts\logging\Export-DefenderEndpointDeviceInventory.ps1`.** The device list with
  onboarding coverage and how long each agent has been silent. Separates a Silent agent
  from an Inactive machine, because ten days quiet is an agent that stopped talking on a
  machine that still exists and sixty days is a machine that has gone, and those need
  different actions.
- **A device with no last-contact time is Unmeasured, never Protected.** An unread
  contact time and a recent one are opposite facts that look identical in a count, which
  is how a silenced agent stays inside the managed device count for as long as anyone
  cares to look.
- **Every page is followed, or the run fails.** A collector that reads page one and
  stops writes a short inventory that reads as a complete one, and the reconciliation
  below would then report every machine on page two as a coverage gap. A page error and
  the page cap both throw before anything is written.
- The token and client secret are held as `SecureString`, exist in plain text on one
  line, and are asserted absent from every written report. A failed token request
  surfaces only its status line, because some error shapes echo the secret back.

### Added: coverage reconciliation

- **`scripts\reporting\Export-CoverageReconciliation.ps1`.** Reconciles any number of
  exported inventories against each other and reports which machines only some of them
  know about. Each authority is a CSV plus a key column, so any console that can export
  a device list is covered without a per-product integration.
- **An authority that could not be read is NotRead, not an authority that returned
  nothing.** Graded as Absent, every machine becomes a gap; skipped, every machine
  becomes covered. Both are confident and wrong and the input looks identical, so an
  unread authority instead sets every machine to NotAssessed against it and takes the
  run verdict to Undetermined.
- A gap found against the authorities that were read is still reported while another is
  unread, because it is true regardless of what the unread source would have said.
- Names are normalised before matching, so PC01 and pc01.contoso.com are one machine
  rather than two false gaps. An authority marked not required, such as a subnet scan,
  is reported without inventing a gap for every machine it does not contain.
- Fewer than two readable authorities fails the run. One source can only agree with
  itself, and the report it would write says every machine is covered.

### Fixed: a column check that read the wrong object

- The reconciliation script's key-column validation used
  `@($rows | Select-Object -First 1).PSObject.Properties.Name`, which reads the wrapping
  array's own members. Every column check failed, reporting `Length, Rank, SyncRoot` as
  the columns found in the CSV. This is the trap already recorded in `THEORY.md`, caught
  here by the tests before it shipped rather than after.

### Changed: test helper

- `Invoke-ScriptUnderTest` gained `-RawArgument`, whose values are emitted into the
  splat verbatim as expressions rather than quoted. A `SecureString` parameter has no
  literal form and could not otherwise be passed to a script under test.

### Coverage note on the telemetry collector

- The paths where a reading is null, meaning audit policy or the Security log could not
  be read, occur only in an unelevated session, and the validation suite is normally
  run elevated. They are therefore covered by unit specs over the grading functions
  rather than by the live run. If those paths were wrong the script would report a
  clean posture for a machine it never read, and no elevated run here would show it.

### Fixed: Sysmon detection matched too loosely

- `Export-EndpointTelemetryPosture.ps1` found the Sysmon service by matching `Sysmon`
  anywhere in the service image path, which also matches a service that merely lives in
  a directory with Sysmon in its name, such as a log viewer, and would report Sysmon as
  running on a machine where it is not installed. It now matches the executable,
  `Sysmon.exe` or `Sysmon64.exe`. Raised by `pre_push_review.py`.

### Added: the machine-state gate

- **`Invoke-RepoValidation.ps1` gained a `MachineState` gate.** It snapshots Defender
  exclusions, the scheduled tasks this repository's scripts name, printers, and drives
  before and after the test run, and fails on any difference. This exists because the
  suite once changed all of that while every test reported green, so noticing is no
  longer left to whoever remembers to look.
- The gate's own comparison is unit-tested against a synthetic added exclusion, a
  changed task state, several probes at once, and a probe that stops reporting. A drift
  detector never shown to detect drift is a green light nobody has checked.

### Added: full coverage

- **Coverage reached 48 of 48 scripts**, and the suite 381 tests. The last seven were
  the two below plus five read-only utilities, four of which are now run for real
  against the machine and asserted on invariants rather than on this machine's values.

### Fixed: the last two scripts with no dry run

- **`Send-AdSecurityEmailReport.ps1` sent mail with no way to rehearse it.** It now
  supports `-WhatIf`, still writes its reports on a preview run, and returns an
  `EmailResult` of NotRequested, Previewed, or Sent. `EmailSent` stays a boolean for
  anything already reading it and is true only when a message really went out.
- **`Invoke-DiskMaintenance.ps1` ran chkdsk, a cipher free-space wipe, a defrag, and a
  benchmark write with no dry run.** Every step is now behind `ShouldProcess` and named
  on a preview. The free-space wipe alone can run for hours.

### Fixed: fixture honesty

- The fake `Get-ADComputer` returned every computer for any filter it did not
  understand, so a script asking the directory for something entirely different would
  still have passed. It now interprets `*` and `Enabled -eq $true` and throws on
  anything else.
- The fake `WebAdministration` module kept its `IIS:` drive root in its own temp
  directory, which nothing removed. It now lives inside the staged module directory the
  caller already deletes.
- `tests/README.md` documents the eight `OPSTOOLKIT_TEST_*` variables the fixtures read.

Both fixture faults were raised by `pre_push_review.py`, run retroactively over the
2026-08-16 batch.

## 2026-08-16

Coverage for all 22 state-changing scripts, which had none, and an incident during that
work that changed the machine the tests were written on.

### Added: state-changing coverage

- **Every script that modifies Active Directory, Azure, IIS, or Windows is now tested.**
  Coverage went from 17 of 48 scripts to 41 of 48; the suite went from 257 tests to 345.
  Each state-changing script runs twice against one fixture: with `-WhatIf`, where the
  mutation log must stay empty, and executing, where it must fill with exactly the
  changes the plan described. The paired run is the point, because "`-WhatIf` attempted
  nothing" is unfalsifiable on its own: a script that has quietly stopped working
  satisfies it perfectly, which is a failure this repository has shipped before.
- Fixtures for `WebAdministration`, `ScheduledTasks`, `Defender`, and `PrintManagement`,
  joining the existing `ActiveDirectory` one. The IIS scripts could not previously be run
  here at all, stopping at `Import-Module WebAdministration -ErrorAction Stop`.
- Secret-handling assertions on the two Azure scripts that produce credentials. The
  storage account key and the generated client secret must not appear in any report
  file; the check reads every file in the report directory rather than the paths the
  summary names.

### Fixed: rehearsal and fixture faults

- **`Send-AdPasswordExpiryReminderEmails.ps1` could not be rehearsed.** `New-Item`
  honours `ShouldProcess`, so under `-WhatIf` the output directory was never created and
  the `Resolve-Path` after it threw. The one thing its header tells you to do first
  failed unless the directory already existed. Its report writes had the same problem.
  Both now pass `-WhatIf:$false`, matching every sibling script.
- `Use-FakeActiveDirectory` hard-coded `FunctionsToExport`, so a cmdlet added to the
  fixture was never exported: the script called a command that did not exist, its own
  try/catch recorded a failed action, and the run still exited 0 with a plausible
  report. The fixture's own `Export-ModuleMember` now decides.

### Incident

Writing these tests disabled four real scheduled tasks and added three real Defender
path exclusions on the development machine. The exclusions have been removed; the tasks
were left as they were found, on the developer's decision, since they are telemetry
tasks this repository's own hardening script disables by design.

The cause was an assumption that a same-named function in the caller's scope shadows any
command. It shadows the `Microsoft.PowerShell.Management` cmdlets, so registry, service,
and file writes were correctly intercepted, and it does not shadow the commands exported
by `ScheduledTasks`, `Defender`, or `PrintManagement`. The printer connection reached the
real cmdlet too and failed only because the spooler happened to be unreachable, which is
luck rather than isolation.

Isolation is now by staged module for those subsystems: the real module is never loaded,
so there is nothing left to shadow. The verification that matters is the machine's own
state afterwards, not the test result, and that is now checked.

### Known and not fixed

- **Nine hard-coded absolute paths** across four scripts, in a repository whose standing
  rules say parameters only: `C:\Code_data` defaults in `Invoke-DiskSpaceReclaim`,
  `Set-WorkstationLockPosture`, and `Set-WorkstationPerformance`, which also defaults a
  Defender exclusion to `C:\Code_data`; and `C:\Temp`, `D:\Temp`, `E:\Temp`, `I:\Temp`,
  `C:\Code` inside `Invoke-WindowsFileCleanup`. Changing a default changes behaviour for
  anyone already running these, so it is recorded rather than done.

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
