# ops-toolkit Future Features

Backlog for the ops-toolkit. Items flow from here onto the work board when picked up,
and off the board into the repository history when done. Shipped work and its
acceptance criteria live in [USER_STORIES.md](USER_STORIES.md), not here.

## Scored index

No live repo-fit backlog item remains here as of 2026-09-08. The two scored items that
were still indexed, `net-hygiene` and `mcp-tool-ladder`, were cut on the developer's
approval because they do not belong in this repo.

Two items were filed on 2026-09-24 from the Azure incident-readiness talk and are not
yet scored; score them per `ai_development/docs/board-scoring.md` before either moves
to the work board. Detail is under "Ingested 2026-09-24: Azure incident-readiness
talk" below.

- **cloud-ir-ready** Read-only Azure/M365 incident-readiness collector.
  - `worker: sonnet 3/6/12 h` (estimate, unscored)

- **entra-contain** `-WhatIf`-guarded Entra identity containment script.
  - `worker: sonnet 3/6/10 h` (estimate, unscored)

## Moved to the work board

Five features left this index on 2026-09-06 when the developer approved them. Their
score and return blocks, and the full build detail, are on the work board under
Pending. This heading is a record, not a live section; nothing here is scored twice.

- **paths-default** Replace the hard-coded absolute paths in five scripts with something
  a machine other than this one can run. See "Hard-coded absolute paths".
  - `worker: sonnet 1.5/3/6 h`
  Moved to the work board Pending section on 2026-09-06.

- **wu-hang** Bound the live Windows Update calls in `Export-WindowsUpdateHealth.ps1` and
  report the update-history section `Unmeasured` on timeout. See
  "Export-WindowsUpdateHealth hangs on a busy update stack".
  - `worker: sonnet 2/4/8 h`
  Moved to the work board Pending section on 2026-09-06.

- **pack-scope-excl** Allow `-ScopeExclusion` when the evidence pack's scope comes only
  from management-plane inputs. See "Evidence-pack follow-ups".
  - `worker: sonnet 1/2/4 h`
  Moved to the work board Pending section on 2026-09-06.

- **pack-manifest-doc** Explain the coverage-manifest `SourceSHA256` and `SHA256`
  difference in the input-sources row and document that the sanitized manifest re-runs
  only from the pack root. See "Evidence-pack follow-ups".
  - `worker: haiku 0.5/1/2 h`
  Moved to the work board Pending section on 2026-09-06.

- **pack-recon-test** Add an end-to-end regression test for reconciliation gaps with the
  Defender inventory absent from the coverage manifest. See "Evidence-pack follow-ups".
  - `worker: sonnet 1.5/3/5 h`
  Moved to the work board Pending section on 2026-09-06.

## Ready to pick up

No unshipped feature is ready to pick up from this backlog. Five features moved to the
work board on 2026-09-06 and all five have since shipped, the last being lane A
(`Export-WindowsUpdateHealth` bounding) on 2026-09-08. No open question for the
developer remains; the one that stood here, the `windows-hardening`/`utilities`
folder duplication, was decided and resolved on 2026-09-13. See "Resolved:
windows-hardening and utilities folder duplication" below.

The three items filed on 2026-08-17 from a threat-hunting conference transcript were all
built the same day and are shipped: the endpoint telemetry and audit-logging posture
collector, the Defender for Endpoint device collector, and the coverage reconciliation
report. See `CHANGELOG.md` and `USER_STORIES.md`. The rejected candidates from the same
review stay under "Considered and not queued" so the reasoning is not re-derived.

Two of the three carry a live-verification debt, recorded with the rest of it on the
work board rather than as separate backlog items:

- `Export-DefenderEndpointDeviceInventory.ps1` has never run against a licensed
  Defender for Endpoint tenant. There is no such tenant available. Its stub specs prove
  the paging, the grading, and the refusals; they cannot prove that
  api.securitycenter.microsoft.com returns the shapes they stub.
- `Export-EndpointTelemetryPosture.ps1` has been run for real against this workstation
  and its output checked against actual machine state, which is how the six-hour
  Security log was found. What has not run is its unelevated path, because the
  validation suite runs elevated. That path is covered by unit specs over the grading
  functions instead, and it is the path where a wrong answer would report a clean
  posture for a machine nobody read.

The `#requires -Version 7` item filed from the workspace lane on 2026-08-15 is done.
`Test-LdapSigningReadiness.ps1`, `Export-AzOrphanedResource.ps1`, and
`Export-LocalAdminAndLapsPosture.ps1` each carry the directive. Confirmed under the
real Windows PowerShell 5.1 that all three now fail with the plain version message
rather than `Unexpected token '??'`. Pair this with the Scheduling item below when
that is picked up: the task host is 5.1, which is where it stops being ergonomics.

The four items opened on 2026-08-15 were all completed the same day:

- Remote support for the last two collectors. `Export-CertificateExpiryInventory.ps1`
  and `Test-WindowsHardeningState.ps1` both take `-ComputerName`, and the evidence
  pack now fans out to all six collectors with none reported LocalMachineOnly.
- The four remaining scripts were retrofitted onto `OpsToolkit.Reporting`. No script
  in the repo defines its own report helpers any more.
- The analyzer findings were cleared. `Invoke-RepoValidation.ps1 -Strict` passes.
- `Page-File-Bleed.ps1` was kept rather than retired, and given a header. The help
  gate has no exemptions left.

## Considered and rejected

Recorded so the reasoning is not re-derived later.

- **RITA-style network hygiene self-audit.** Cut from the scored index on 2026-09-08.
  Direct-IP HTTP and abnormal subdomain-count DNS require a network event stream over
  time. That collides with the standing 2026-08-17 decision that OpsToolkit reads
  point-in-time configuration and report data rather than becoming a detection engine
  or SIEM competitor.
- **Internal-MCP tool ladder.** Cut from the scored index on 2026-09-08. The practice
  note about internal MCP servers, least-privilege scopes, and deterministic gates on
  mutating verbs is useful, but it belongs in framework or internal tooling material,
  not in this PowerShell operations toolkit.
- **Scheduling.** Every collector is run by hand. Scheduling them is what makes the
  change detection in `Compare-OpsToolkitRun.ps1` worth having, since comparing two
  runs needs two runs. Not queued because it should follow the live verification, not
  precede it: scheduling unproven collectors just produces unproven reports faster.
  When it happens, note that the task host runs Windows PowerShell 5.1, which is why
  the validation suite fails any script with non-ASCII bytes and no BOM.
- **Backup verification.** The evidence pack reports BCK-01 as NotAssessed and says
  what to attach. A restore test is an operational exercise rather than a
  configuration read, and no amount of reading state can evidence it. Deliberately
  left unautomated rather than faked from configuration.
- **Third-party EDR detection.** The evidence pack reads Microsoft Defender only. A
  tenant running something else gets NotAssessed for EDR-01, which is correct but
  unhelpful. Worth adding if a specific product needs covering; not worth a generic
  abstraction first.
- **Per-machine parallelism.** Collectors that take `-ComputerName` walk their target
  list one machine at a time. That is fine for a small estate and slow for a large
  one. Worth revisiting only once someone has actually run this against enough
  machines to be annoyed by it, because a throttled parallel implementation is easy
  to get subtly wrong and hard to debug remotely.
- **Behavioural detection signals.** Reviewed 2026-08-17 and rejected as a product
  direction: abnormal access to systems a user does not normally touch,
  role-inappropriate LOLBin execution, after-hours authentication volume, privileged
  cloud API calls, DNS tunnelling patterns, and rare or limited-use protocols. Every
  one needs an event stream over time plus a baseline of what is normal for that user
  or role. This toolkit reads configuration state at a point in time and diffs two
  runs of the same collector; it has no log ingestion, no time-series store, and no
  baseline. Building these turns it into a detection engine competing with whatever
  SIEM the estate already has, which is a different product. What was kept from this
  group is the precondition rather than the detections: whether the telemetry those
  detections need is being generated and retained at all. That is the endpoint
  telemetry posture collector below.
- **Detection signals already covered.** Three items from the same review need no work
  because a shipped collector already answers them. Long-lived credentials:
  `Export-EntraAppCredentialExpiry.ps1` reports `ExceedsRecommendedLifetimeCount` and
  whether the credential is still authenticating. Stale accounts and last login:
  `Export-AdUserInventory.ps1` and `Disable-AdStaleComputerAccountsAndMoveToOu.ps1`.
  Standing privilege and escalation paths: `Export-AdPrivilegedAccessAudit.ps1` and
  `Export-AdAclRiskReport.ps1`.
- **EDR silence delta check.** How long since each EDR agent last checked in, against a
  threshold. Not filed separately because it is a read of the EDR management plane and
  falls out almost free once the Defender for Endpoint device collector below exists.
  Build it there rather than as its own item.

## Shipped 2026-08-17: endpoint telemetry and audit-logging posture

A read-only collector answering the question that has to be answered before any hunt or
detection is worth writing: is the logging that would ever show you an attacker actually
switched on, on every machine, with a retention window that outlives your time to
detect. The estate this matters to is the one that believes it is covered.

What it reads, all configuration state, all local or over `-ComputerName` like the other
collectors: PowerShell script-block and module logging, process-creation auditing and
whether command line is included, the advanced audit policy subcategories that matter,
Sysmon presence and its config, DNS client logging, per-channel event log size and
retention mode, and event-forwarding subscription state.

The pattern is already proven in this repo and should be copied rather than reinvented.
`Test-LdapSigningReadiness.ps1` reports the NTDS diagnostic setting first and returns
`Unmeasured` rather than a clean result when per-client logging is off, and its header
says outright that the most important output is not the client list but whether the
logging that would produce it is on at all. That is this collector generalised to one
script. Same discipline applies: a channel whose configuration could not be read is
reported as unread, never as compliant.

Feeds a new logging control into `Export-SecurityControlEvidencePack.ps1`, and
`Compare-OpsToolkitRun.ps1` then shows coverage improving run over run without new
machinery.

## Shipped 2026-08-17: coverage reconciliation

Pull an inventory from each independent authority that should know about a device or an
identity, differential them, and report what only one of them knows about. A machine in
Active Directory with no EDR agent, an EDR agent on a machine no inventory system lists,
an IP in the static server range that answers to nothing.

The mechanic already exists in pieces. `Export-SecurityControlEvidencePack.ps1` fans out
to collectors and rolls up, `Join-ApplicationsWithEndpointSites.ps1` is a working
matched/unmatched join with duplicate-key handling, and the pack's NotAssessed
discipline is exactly how a blind spot should be reported. What is missing is a script
that treats the collectors as authorities to be reconciled against each other rather
than as separate reports.

Authorities readable today: AD computer and user accounts, Entra through Graph, Azure IP
space through `Export-AzNetworkInventory.ps1`, and which machines actually answered a
pack fan-out. Authorities with no reader: EDR, VPN, and the log pipeline.

Those three are covered two ways, decided 2026-08-17. Both are wanted, not one or the
other.

1. An operator-supplied CSV export from whatever EDR, VPN, or SIEM console is in use.
   Product-agnostic, no new API surface, works on day one against any vendor.
2. The Defender for Endpoint collector below, for the Microsoft case natively.

Any authority with neither a CSV nor a collector reports NotAssessed for its leg. A
reconciliation that quietly drops the authority it could not read reports a clean
estate, which is the same failure mode as an evidence pack folding "we did not check"
into "we are fine."

## Shipped 2026-08-17: Defender for Endpoint device collector

A read-only device-list collector against Defender for Endpoint: the enrolled devices,
their onboarding and health state, and last check-in time. It is the missing EDR
authority for the reconciliation above, and it is also what makes the EDR silence delta
check possible, so build that into the same script rather than filing it separately.

Two cautions from this repo's own history. Check every field against the installed SDK
model type before reading it: two beta-only Graph fields have already shipped as
confidently empty columns because a beta field returns null instead of erroring. And
plant the null shapes in the fixtures, a device that has never checked in, a device with
no onboarding state, because a fully-populated fixture proves only the happy path and
that is how both Azure collectors shipped scanning nothing.

## Hard-coded absolute paths

Ten of them across five scripts as of 2026-09-06, in a public repository whose standing
rules say parameters only. `Invoke-DiskSpaceReclaim`, `Set-WorkstationLockPosture`,
`Set-WorkstationPerformance`, and now `Set-BrowserCredentialPosture` default their report
directory to `C:\Code_data`, and `Set-WorkstationPerformance` also defaults a **Defender
exclusion** to `C:\Code_data`, which is a security setting pointed at one particular
machine's layout. `Invoke-WindowsFileCleanup` carries `C:\Temp`, `D:\Temp`, `E:\Temp`,
`I:\Temp`, and `C:\Code` in its own lists.

It was nine across four when this was filed. `Set-BrowserCredentialPosture.ps1` shipped
on 2026-09-01 with the same `C:\Code_data` default, so the count grows by one with each
new state-changing script rather than holding still.

Not done in the same pass that found them, because changing a default changes behaviour
for anyone already running these, and what the replacement should be is a product
decision rather than a cleanup: an environment variable, a required parameter, or a
per-install config file. The Defender one is the sharpest and could reasonably go first.

**Shipped 2026-09-07 as `59b9237`.** Every path parameter that carried a hard-coded
default (`Set-WorkstationPerformance.ps1`, `Set-BrowserCredentialPosture.ps1`,
`Set-WorkstationLockPosture.ps1`, `Invoke-DiskSpaceReclaim.ps1`, `Analyze-C.py`, and
`compare_folders.py`) is now a required parameter with no default, including the
Defender exclusion default in `Set-WorkstationPerformance.ps1`. A no-argument run now
refuses before changing anything. This paragraph and the two above are the original
finding, kept as the record of what was wrong; the fix is done, not queued.

## Implemented 2026-08-30: evidence scope and traceability

The investigation is complete. The platform added value as a comparison point for
evidence scope, provenance, coverage, and report language, not as a methodology or
integration target. The feasibility note is
[docs/certified-information-security-assessment-value-check.md](docs/certified-information-security-assessment-value-check.md).

Jon approved the note's evidence scope and traceability story on 2026-08-30. The
evidence pack now records actual population and exclusions, exact evidence artifacts,
observation time, freshness, limitations, hashes, toolkit revision, and collection
context. Estate endpoint-protection coverage can use both Defender management-plane
inventory and the existing two-authority reconciliation report. Unread required sources
remain `NotAssessed`, and the summary explicitly disclaims maturity, conformity, audit,
and certification conclusions.

An independent read-only review was applied before closeout. Its confirmed population,
scope, freshness, portability, PowerShell-version, and manifest-completeness findings
were corrected and covered by regression tests.

The deferred `LOG-03`, `LOG-04`, and `VULN-01` ideas remain candidates only. They still
need a named data source and operator need before they become stories.

## Evidence-pack follow-ups

**Shipped 2026-09-07.** All three items below are done:

- Allow `-ScopeExclusion` when scope comes only from management-plane inputs. Today,
  any exclusion without `-ComputerName` throws at the target-validation gate.
  Shipped as `6e7126f`.
- Note in the input-sources row that the coverage-manifest snapshot is rewritten with
  pack-relative paths, so the `SourceSHA256`/`SHA256` difference is explained, and
  document that the sanitized manifest re-runs only from the pack root.
  Shipped as `2ab7be4`.
- Add a regression test for reconciliation gaps with the Defender inventory absent
  from the manifest. The display fix shipped 2026-08-30. This test shipped as `b82f5c2`.

## Export-WindowsUpdateHealth hangs on a busy update stack

Proven 2026-08-31 by a bounded standalone run, no Pester involved: the collector hung
past a 15-minute cap with zero output while MoUsoCoreWorker held an active update
orchestration session on the workstation. The hang site is the script's unbounded
synchronous live calls, `Get-HotFix` (WMI QFE) and the WUA COM chain
(`Microsoft.Update.Session`, `CreateUpdateSearcher`, `GetTotalHistoryCount`,
`QueryHistory`); none can be interrupted by try/catch. A health check that hangs on
exactly the unhealthy condition it measures reports nothing. Fix shape: bound those
calls (run them in a child with a timeout, or move to an interruptible pattern) and
report the update-history section `Unmeasured` on timeout, per the standing rule that
a check that could not run is reported as not having run. Evidence:
`C:\Code_data\ops-toolkit\wu-health-diagnostic-2026-08-31\run.log`. The separate
test-harness side, bounding live-integration setups, was completed on 2026-08-31; it
does not resolve this collector-level defect.

**Shipped 2026-09-08.** `e5283d3` added `-HistoryTimeoutSeconds` plus `Unmeasured`
history signals, and `73b1b57` isolated the WUA history probe in a child PowerShell
process so it can be bounded and killed. Strict passed all eight gates on the merged
result. This collector-level defect is resolved.

## Resolved: windows-hardening and utilities folder duplication

**Shipped 2026-09-13.** `windows-hardening` and `utilities` used to exist at two levels
of `scripts\`, once at the top and once under `it-operations\`, with no principle
separating them. Jon chose to fold the top level into `it-operations\`: the 4 top-level
scripts under the old `scripts\windows-hardening\` directory and the 4 top-level
`scripts\utilities\*` files (3 scripts plus `requirements.txt`) moved into `scripts\it-operations\windows-hardening\`
and `scripts\it-operations\utilities\`, and the emptied top-level directories were
removed. Every documentation reference (both READMEs, the top-level README's Areas and
Updated Scripts tables, `USER_STORIES.md`) and every test `-RelativePath` were updated to
the new locations. `docs\retirement-review.md` and `docs\reorganization-map.md` cite
specific script paths that `Invoke-RepoValidation.ps1`'s StaleReference gate checks for
resolvability, so their citations were updated to the new locations too (reorganization-map.md
keeps its dated 2026-05-04 move table as a literal historical record, with a note pointing
to this section for the later move). `docs\legacy-script-inventory.md` and
`archive\legacy-scripts\` were left untouched as historical record of the repo's state at
the time each was written.

## Residual risk, not a backlog item

All 48 scripts have automated coverage, including all 24 that change something.
`Send-AdSecurityEmailReport` and `Invoke-DiskMaintenance` gained `-WhatIf` on
2026-08-17, which is what made the last two coverable.

Every covered script runs end to end in the test suite against a stubbed back end. What
no test here can establish is that a real Graph endpoint, domain controller, or Exchange
Online tenant returns the shapes those stubs return.

For the state-changing scripts there is a second, sharper limit. The tests prove what
each script decides to do and that `-WhatIf` suppresses all of it. They cannot prove
that the real registry, service manager, print subsystem, or Azure control plane accepts
those calls, and the isolation is only as good as the list of subsystems someone
remembered to stage a module for. That list was wrong once already, and it changed the
machine rather than failing a test.

That risk is narrowed three ways and is not reducible further without credentials:
fields are checked against the installed SDK model types, which caught two beta-only
fields returning null instead of erroring; the stubs are written to behave like the
real thing in the cases that matter, including failing the way it fails; and fixtures
deliberately plant the null shapes a real service returns rather than populating every
field, which is what caught both Azure defects logged in the changelog.

That last point is the lesson worth keeping. Both Azure collectors had been scanning
nothing at all in their default configuration and exiting 0, and no unit test, model
check, or fully-populated fixture would ever have shown it. A wrong answer that looks
like good news does not announce itself.

It is recorded here rather than as work because there is nothing to build. It closes
the first time someone runs the six scripts against a live system, which the work
board carries as the standing next action.

## Known deviations

Things that look like gaps and are not.

- **`Export-EndpointTelemetryPosture.ps1` grades an absent PowerShell policy key as
  Disabled rather than Undetermined.** `Get-RegValue` returns null both for a value that
  is not there and for a read that failed, so the two are not distinguished. That looks
  like it contradicts the script's own Undetermined rule and does not: these are
  `HKLM\SOFTWARE\Policies` keys, readable by any account, so null means the policy is
  Not Configured, which is to say the logging really is off. Reporting Undetermined
  instead would turn every unhardened machine into a shrug and hide the finding the
  script exists to make. The Undetermined rule applies where it was written for, audit
  policy and the Security log, which genuinely cannot be read unelevated and which do
  pass null. Raised by `pre_push_review.py` on 2026-08-19 and rejected with this
  reasoning; the proposed fix would have been a regression.

- `Page-File-Bleed.ps1` gates on `-Execute` rather than on `-WhatIf` alone, and
  writes no plan or state report. Its header says so. Changing that is a behaviour
  change to a working script, not a cleanup, so it was left as it is.
- TLS endpoint probes in `Export-CertificateExpiryInventory.ps1` always run from the
  machine the script was started on, even with `-ComputerName`. What a certificate
  looks like on the wire is a property of the endpoint, so probing it from every
  target would return the same answer N times.
- `Test-WindowsHardeningState.ps1` reads desired state locally even when checking
  remote machines, because desired state comes from the hardening scripts rather than
  from any machine. Remote targets therefore do not need a copy of this repo.

## Ingested 2026-09-24: Azure incident-readiness talk

Source: Gerard Johansen, "Is Your Azure Environment Incident-Ready?", BHIS Anti-Cast,
YouTube swEKKlN5BMA. Digest and portfolio evaluation:
`C:\Code_data\ingested_public_sources\digest_johansen_azure_incident_readiness.md`.

- **cloud-ir-ready** A read-only collector, `scripts\microsoft-365\` or `scripts\entra\`
  (placement decided at pickup), that answers "could we investigate an incident here
  today": Unified Audit Log ingestion enabled; Entra sign-in and audit logs and each
  subscription's Activity Log exported by a diagnostic setting, and to where; the
  destination Log Analytics workspace retention against a `-TargetRetentionDays`
  parameter (the talk's rule of thumb is 90 days UAL and about 180 days Activity Log,
  the speaker's own view and not a Microsoft default, so it is a parameter, not a
  constant); Graph activity logs enabled; responder roles (Global Reader, Security
  Reader, Security Operator) assigned and PIM-eligible rather than standing; break-glass
  account count and FIDO2 registration; the user-consent setting and existing
  delegated OAuth grants; Conditional Access coverage of legacy authentication and the
  device code flow. Every read that fails or lacks permission reports `NotAssessed`, never
  pass. Output through `OpsToolkit.Reporting`, and it feeds the evidence pack as a new
  logging control beside the LOG-01/LOG-02 rows `Export-EndpointTelemetryPosture.ps1`
  supplies. Uses the repo's existing `Connect-MgGraph` plus `Invoke-MgGraphRequest`
  pattern from `scripts\entra\Export-EntraConditionalAccessBaseline.ps1`; the Azure
  diagnostic-setting reads need Az.Monitor or ARM REST, which no script here uses yet,
  so that dependency is decided at pickup. Stays inside the "Considered and rejected"
  line: it reads configuration once, it never ingests or queries the logs themselves.
- **entra-contain** A `SupportsShouldProcess` containment script for one or more UPNs:
  revoke sign-in sessions, disable the account, and export (not delete) the user's inbox
  rules and mailbox forwarding so the responder decides what to remove. Plan/state CSV
  plus rollback JSON (re-enable) per the repo's state-changing standard, with a Pester
  WhatIf-plus-execute pair. The talk's most common post-incident lesson is that
  responders cannot revoke sessions without a ticket; this makes it one pre-approved
  command. Password reset is left out for now: no script here resets passwords today and
  a reset has to hand the new secret to someone, so include it only by decision at
  pickup. Higher risk than `cloud-ir-ready` because it changes identity state, so it
  goes second.
- Not queued: a UAL or Activity Log extractor. Invictus-IR Microsoft Extractor Suite and
  SANS SOF-ELK already do this, and log pulling is the ingestion work this repo has
  rejected.

## Ingested 2026-08-31: Flare info-stealers talk

Source: Flare "How Information Stealers Work" talk, YouTube FmF8cjViSlI.

- Browser and credential hardening posture for workstation endpoints against infostealers.
  Enforce the blockable defenses the talk names and report the rest: block
  authenticator and password-manager browser extensions by policy (they live inside the
  stealer's blast radius, so a browser-extension authenticator is not a second factor),
  confirm Chrome Application-Bound Encryption is not disabled, and report Device-Bound
  Session Credentials support, SmartScreen state, and any unnecessary local-admin
  membership as posture. Enforce/report split follows the repo's own line between
  `Set-WorkstationLockPosture.ps1` (enforces, `SupportsShouldProcess`) and
  `Test-WindowsHardeningState.ps1` (reads). Copy the ShouldProcess skeleton from
  `Set-WorkstationLockPosture.ps1`, write timestamped plan/state CSV plus rollback JSON
  to `C:\Code_data\ops-toolkit\<domain>`, and pair with a Pester WhatIf-plus-execute test
  via `Invoke-WindowsScriptPair`. Folder placement, top-level `scripts\windows-hardening\`
  versus `scripts\it-operations\windows-hardening\`; Jon chose `it-operations\windows-hardening\`,
  and the same choice resolved the standing top-level/it-operations duplication for the
  rest of the tree on 2026-09-13 (see "Resolved" section above).
- Shipped 2026-09-01 as `Set-BrowserCredentialPosture.ps1` under
  `it-operations\windows-hardening\`; see CHANGELOG. The enforce/report split narrowed to
  what a local machine policy can actually pin (Chrome and Edge extension block, Chrome
  Application-Bound Encryption), with everything else reported. The default block list was
  narrowed from the talk's blanket recommendation: authenticator extensions are blocked by
  default, but the password-manager extensions are opt-in via `-IncludePasswordManagerExtensions`,
  because for a public tool a default that blocks a password-manager extension can push a user
  back to browser-saved passwords (Jon's call, 2026-09-01). This item is done; it stays here only
  as the ingestion record for the talk.

## Ingested 2026-08-21: public talk and summit digests

- Internal MCP servers in Go with the tool-ladder pattern; treat agent-reachable endpoints as new unvetted employees, least-privilege scopes and deterministic gates on mutating verbs. Source: Infosec Age of AI Summit 2026, talks 11 and AMA, digest_infosec_age_of_ai_summit_2026.md. Cut from the OpsToolkit scored index on 2026-09-08 because it belongs to framework or internal tooling material, not this repo.
- EDR coverage differential hunt, diff EDR endpoint count vs inventory vs AD vs IP space, as a coverage-gap-report script. Source: Threat Hunting Summit 2026, Hartman 04:10:20-04:12:00, digest_threat_hunting_summit_2026.md. Covered: this is what `Export-CoverageReconciliation.ps1` and the Defender device collector shipped on 2026-08-17 already do, so it is not indexed as unshipped work.
- RITA-style network hygiene self-audit (direct-IP HTTP, abnormal subdomain-count DNS). Source: Threat Hunting Summit 2026, Kidane 03:44:00-03:50:00, digest_threat_hunting_summit_2026.md. Cut from the OpsToolkit scored index on 2026-09-08 because it requires a time-series network event stream, outside this repo's point-in-time reporting scope.
