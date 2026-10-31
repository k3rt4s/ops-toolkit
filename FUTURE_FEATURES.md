# ops-toolkit Future Features

Backlog for the ops-toolkit. Items flow from here onto the work board when picked up,
and off the board into the repository history when done. Shipped work and its
acceptance criteria live in [USER_STORIES.md](USER_STORIES.md), not here.

## Scored index

No live repo-fit backlog item remains here as of 2026-09-08. The two scored items that
were still indexed, `net-hygiene` and `mcp-tool-ladder`, were cut on the developer's
approval because they do not belong in this repo.

Two items were filed on 2026-09-24 from the Azure incident-readiness talk and scored
the same day per `ai_development/docs/board-scoring.md`. `cloud-ir-ready` moved to the
work board on 2026-09-24 on the developer's approval and shipped 2026-09-25 (see "Moved
to the work board");
`entra-contain` stays here and goes second. Detail is under "Ingested 2026-09-24:
Azure incident-readiness talk" below.

`pack-fanout-bind` was added on 2026-09-25 from the `cloud-ir-ready` landing review, on the
developer's decision to backlog it rather than fix it in that cycle. It shipped on
2026-09-29 and has left this index; see the Shipped 2026-09-29 heading below.
`entra-contain` moved to the work board on 2026-10-02 on the developer's approval (see
"Moved to the work board"). The same day the what's-left report indexed and scored the
five open follow-ups below: three from the
`cloud-ir-ready` landing review (see "Ingested 2026-09-24: Azure incident-readiness
talk") and two from the `pack-fanout-bind` landing review (see "Shipped 2026-09-29:
evidence-pack estate fan-out"). The declined empty-split wording item is a record, not
work, and is not indexed.

- **split-list-outputs** Fold the script-local `ConvertTo-OpsSplitList` in `Export-CloudIncidentReadiness.ps1` onto the `OpsToolkit.Reporting` copy and make its `.OUTPUTS` match what it returns. See "Shipped 2026-09-29: evidence-pack estate fan-out". `score: kind=debt gain=0.25/0.5/2 p=0.5 freq=1 hours=0.5/1/2 risk=0.1x1 rev=two-way conf=assessed id=split-list-outputs` `return: likelihood the function is touched about once a year, p 0.5, estimated, nothing counted; impact each touch costs about half an hour keeping two copies and an AST-lifting test in step, and a caller that skips the @() idiom hits a StrictMode error on an empty list; evidence the module copy and scripts\entra\Export-CloudIncidentReadiness.ps1 line 946, tests\Export-SecurityControlEvidencePack.Tests.ps1 lines 248-251 lift it from the script AST`
  - `worker: sonnet 1.5/3/5 h`

Six items were filed on 2026-10-29 when the standalone Windows 11 hardening scripts landed.
Five are below; the sixth, domain-joined variants (hard-domain, score 0.0), went to
`BOARD_DEFERRED_2026.md` beside the board. pack-unread and the seven items after
hard-omitted-settings came out of the pre-push review the same day. Detail, and the list of
facts the scripts assume but nobody has checked on a real machine, is under "Ingested
2026-10-29: standalone Windows 11 hardening follow-ups" below.

- **hard-elevated-run** Run every hardening spec elevated on a disposable Windows 11 VM, then run each script for real there and check the unverified facts listed below. `score: kind=prevent gain=2/6/20 p=0.5 hours=2/4/8 risk=0.1x2 rev=two-way conf=assessed flags=security id=hard-elevated-run` `return: likelihood the scripts are applied to at least one real machine soon, p 0.5 that one of the 22 unverified facts is wrong in a way that matters, estimated, nothing run; impact a wrong registry value, cmdlet shape or event field means a control reads compliant when it is not, or a rollback that does not restore, about 2 to 20 hours to find and repair on a live machine; evidence the elevated It blocks in tests\Integration.StateChanging.Hardening*.Tests.ps1 are skipped on the unelevated runner on 2026-10-29, and the unverified list below`
  - `worker: sonnet 2/4/8 h, on a VM the developer provides`

- **wdac-enforce** Add a reviewed path from the audit-only WDAC policy to an enforced one: supplemental allow rules from `Export-WdacAuditEvent.ps1` output, then an explicit enforce step with its own rollback. `score: kind=feature gain=2/4/10 p=0.4 hours=4/8/16 risk=0.2x4 rev=two-way conf=opinion flags=security id=wdac-enforce` `return: likelihood wanted once the audit policy has run a few weeks, p 0.4, opinion; impact enforcement blocks unapproved executables, but a wrong policy can stop the machine booting into a usable state, about 4 hours to recover; evidence Set-WdacAuditPolicy.ps1 has no enforce switch by the developer's 2026-10-29 decision`
  - `worker: sonnet 4/8/16 h`

- **bitlocker-tpm-pin** Offer a TPM plus PIN protector on `Enable-BitLockerOsVolume.ps1`, behind a switch, with the PIN taken as a SecureString and never logged. `score: kind=feature gain=1/2/6 p=0.3 hours=1.5/3/6 risk=0.1x2 rev=two-way conf=opinion flags=security id=bitlocker-tpm-pin` `return: likelihood wanted for a laptop that travels, p 0.3, opinion; impact pre-boot authentication closes the stolen-laptop cold-boot and DMA paths a TPM-only protector leaves open, a few hours of exposure analysis per incident avoided; evidence the script adds TPM only, and the fake BitLocker module already accepts -TpmAndPinProtector`
  - `worker: sonnet 1.5/3/6 h`

- **pack-unread** Have `Export-SecurityControlEvidencePack.ps1` read the hardening checker's `UnreadCount` and `Passed`, report CFG-01 as NotAssessed or Partial while items are unread, and then pass the standalone-machine targets to the checker. `score: kind=prevent gain=1/3/8 p=0.3 hours=1.5/3/6 risk=0.1x2 rev=two-way conf=opinion flags=security id=pack-unread` `return: likelihood the pack is run on a machine hardened by the new scripts, p 0.3, opinion; impact today CFG-01 reads Met from TotalDrift, ItemsChecked and CompliantCount alone, so if the new targets were added without this an unread control would vanish from the counts and the control would read as met in a questionnaire; evidence Export-SecurityControlEvidencePack.ps1 lines 1110-1123 and the checker's default kept at SchannelTls and Privacy on 2026-10-29 for that reason`
  - `worker: sonnet 1.5/3/6 h`

- **hard-offhost** Off-host copies of what the scripts produce on the machine: forward the new audit and Code Integrity events, and record where the BitLocker recovery key was moved. `score: kind=prevent gain=1/3/10 p=0.2 hours=3/6/12 rev=two-way conf=opinion flags=security id=hard-offhost` `return: likelihood an incident on a hardened machine, p 0.2 a year, opinion; impact logs that live only on the compromised machine can be cleared, and a key file nobody can find makes recovery a rebuild, several hours either way; evidence Set-WindowsAuditLogging.ps1 sizes local logs only and Enable-BitLockerOsVolume.ps1 writes one key file to the operator's folder`
  - `worker: sonnet 3/6/12 h`

- **hard-omitted-settings** Add the settings left out because no supported value could be verified: WPAD on a standalone machine, the 24H2 Administrator Protection value, and ASR rules beyond the fourteen documented ones. `score: kind=feature gain=0.5/1/4 p=0.3 hours=1/2/4 rev=two-way conf=opinion flags=security id=hard-omitted-settings` `return: likelihood Microsoft documents each setting, p 0.3 within a year, opinion; impact each closes one more path, under an hour of exposure each; evidence the WPAD and Administrator Protection omissions are stated in the help of Set-WindowsNetworkProtocolHardening.ps1 and Set-WindowsLocalAccountPolicy.ps1, and Set-WindowsDefenderHardening.ps1 plans fourteen rules, on 2026-10-29`
  - `worker: sonnet 1/2/4 h`

- **legacy-undetermined-pass** Make `Test-WindowsHardeningState.ps1` count a local legacy row it cannot classify as unread: the Privacy plan's service and scheduled-task actions map to `Other:*` and a legacy `Skipped` row stays `Skipped`, and neither keeps `Passed` false. Pre-dates this branch; the developer decides whether an unclassified row should fail the run. `score: kind=prevent gain=1/3/8 p=0.4 hours=1/2/4 risk=0.1x2 rev=two-way conf=assessed flags=security id=legacy-undetermined-pass` `return: likelihood a Privacy run hits a service or task row, p 0.4, estimated from the plan emitting DisableService, EnableService, Missing, DisableScheduledTask and EnableScheduledTask; impact an undetermined row folds into a pass, so a drifted service reads compliant in a report; evidence the legacy mapping in Test-WindowsHardeningState.ps1 around lines 524-531 and Passed on master read driftCount, notEnforced and unchecked only, on 2026-10-29`
  - `worker: sonnet 1/2/4 h`

- **hard-rollback-validate** Validate each rollback JSON entry against the control set the script manages (registry path and value name, service, rule id) before an elevated `-Rollback` applies it, and refuse the file on any entry outside that set. `score: kind=prevent gain=1/3/10 p=0.15 hours=1.5/3/6 risk=0.1x2 rev=two-way conf=opinion flags=security id=hard-rollback-validate` `return: likelihood a rollback file is edited or replaced in the report folder, p 0.15, opinion; impact an elevated rollback writes whatever the file names, so a tampered file becomes an arbitrary elevated registry write; evidence the ten state-changing hardening scripts read the newest *rollback*.json under -ReportDirectory and apply its entries as recorded, on 2026-10-29`
  - `worker: sonnet 1.5/3/6 h`

- **hard-rollback-chain** Mark a rollback file consumed after it applies, or pick it by the run it belongs to rather than `LastWriteTime`, so a second `-Rollback` does not replay the first one. `score: kind=prevent gain=0.5/1/3 p=0.2 hours=1/2/4 rev=two-way conf=opinion id=hard-rollback-chain` `return: likelihood an operator runs -Rollback twice or after a later apply, p 0.2, opinion; impact the replay restores values from before an earlier run, undoing a later deliberate change, about an hour to notice and redo; evidence the rollback file is chosen by LastWriteTime and left in place after use in the hardening scripts on 2026-10-29`
  - `worker: sonnet 1/2/4 h`

- **hard-whatif-unelevated** Let an unelevated `-WhatIf` show each planned change as `Previewed` instead of `Skipped: requires elevation`, by reading what can be read unelevated and marking the rest unread. `score: kind=feature gain=0.25/0.5/2 p=0.5 hours=1/2/4 rev=two-way conf=opinion id=hard-whatif-unelevated` `return: likelihood the bootstrap's phase 8 preview runs unelevated, p 0.5, opinion; impact the preview lists skips rather than the planned changes, so the operator learns less before applying; evidence elevation is checked before ShouldProcess in the hardening scripts, the same order as the five older ones, on 2026-10-29`
  - `worker: sonnet 1/2/4 h`

- **hard-confirm-impact** Make `ConfirmImpact = 'High'` prompt as declared: `Invoke-PlanItem` calls `ShouldProcess` at its own Medium default, so the declared impact never raises a prompt. `score: kind=debt gain=0.1/0.25/1 p=0.3 hours=0.5/1/2 rev=two-way conf=assessed id=hard-confirm-impact` `return: likelihood an operator relies on a confirmation prompt, p 0.3, estimated; impact a High-impact change applies without the prompt the attribute promises, minutes of surprise each time; evidence the hardening scripts declare High and route through Invoke-PlanItem, the same pattern as the existing ones, on 2026-10-29`
  - `worker: sonnet 0.5/1/2 h`

- **file-comma-validateset** Fix the `pwsh -File` examples that pass a comma list to a `ValidateSet` parameter, which `-File` passes as one string and the set rejects: `Invoke-DiskSpaceReclaim.ps1` lines 46, 51 and 105 (`-Target`), `New-AzKeyVaultServicePrincipal.ps1` lines 23 and 105 (`-CertificatePermissions`), and `Invoke-RepoValidation.ps1` line 24 (`-Gate`). `score: kind=debt gain=0.1/0.25/0.5 p=0.6 hours=0.25/0.5/1 rev=two-way conf=assessed id=file-comma-validateset` `return: likelihood someone copies an example, p 0.6, estimated; impact the copied command fails with a validation error, a few minutes to rewrite it; evidence pwsh -File with -T Aa,Bb rejected by ValidateSet in both pwsh and powershell.exe on 2026-10-29, and the hardening README examples moved to the -Command form the same day`
  - `worker: haiku 0.25/0.5/1 h`

- **fake-contracts** Make the test fake modules behave like the cmdlets they stand in for: a consistent `ShouldProcess` rule across the fakes, and read fakes that honour their filter parameters instead of returning everything. `score: kind=debt gain=0.25/1/3 p=0.3 hours=1.5/3/6 rev=two-way conf=opinion id=fake-contracts` `return: likelihood a test passes against a fake that a real cmdlet would fail, p 0.3, opinion; impact a defect ships behind a green suite, an hour or more to find on a machine; evidence the fakes under tests handle ShouldProcess differently from one another and the read fakes ignore filters, found in the 2026-10-29 review`
  - `worker: sonnet 1.5/3/6 h`

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

- cloud-ir-ready, read-only Azure/M365 incident-readiness collector. See "Ingested
  2026-09-24: Azure incident-readiness talk". Moved to the work board In Progress
  section on 2026-09-24 as lane `cloud-ir-ready`, with its score block, on the developer's approval.
  Shipped 2026-09-25 as `scripts\entra\Export-CloudIncidentReadiness.ps1`, evidence-pack
  control IR-02.

- entra-contain, `-WhatIf`-guarded Entra identity containment script. See "Ingested
  2026-09-24: Azure incident-readiness talk". Moved to the work board In Progress section
  on 2026-10-02, with its score block, on the developer's approval.

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

## Shipped 2026-09-29: evidence-pack estate fan-out

`pack-fanout-bind` shipped as `a303916`, merged as `380bdff`. What changed is in
`CHANGELOG.md` under 2026-09-29 and the mechanism is in `THEORY.md` under Load-bearing
constraints. Strict validation passed all eight gates on the branch: 60 parser, 0
analyzer, 72 help, 4 shell, 110 stale-reference, 1 module, 611 Pester tests, MachineState
clean, 0 warnings, 12 NotRun from an unelevated session.

Four low follow-ups came out of the landing review. None is queued work. The first two
are one item, `split-list-outputs`, and the last is `laps-typo`, both scored in the Scored
index on 2026-10-02; the third was declined and stays here as the record.

- Dedupe the script-local `ConvertTo-OpsSplitList` in
  `scripts\entra\Export-CloudIncidentReadiness.ps1` onto the exported
  `OpsToolkit.Reporting` function. The blocker is
  `tests\Export-SecurityControlEvidencePack.Tests.ps1`, which lifts that function from
  the script's AST, so that test has to change with it. Settle the return shape at the
  same time, for both copies at once (see the next bullet).
- The function's `[OutputType([string[]])]` and `.OUTPUTS` say `System.String[]`, but an
  empty result emits nothing, so a caller doing `$x = ConvertTo-OpsSplitList ...` gets
  `$null` rather than a zero-length array, and `.Count` on it under
  `Set-StrictMode -Version 3.0` is a runtime error. A comma-prefixed return fixes that
  and was tried on 2026-09-29, but it breaks the `@()` capture idiom every caller in this
  repository uses, including `Export-CloudIncidentReadiness.ps1` line 985, by yielding a
  one-element nested array instead of the list. Trading a loud error for a silent wrong
  result is the wrong direction, so it was reverted. Either settle on one idiom across
  both copies, or correct the documented `.OUTPUTS` to match what the function does.
- The empty-split failure message is PowerShell's own: it names the parameter, which is
  the bar the fix was held to, but shows a blank value. On the fan-out path that text
  lands in a collector's `run.err.log` and then in the pack's result note, where an
  operator sees a variable-validation complaint rather than a statement that
  `-ComputerName` held no computer names. A per-script throw would fix the wording at
  the cost of a duplicated block in each of ten scripts, which is why it was declined.

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

## Ingested 2026-10-29: standalone Windows 11 hardening follow-ups

The eleven scripts that landed on 2026-10-29 were built and tested against fake modules and
stubs on an unelevated runner. The developer chose to build only, so nothing was applied to
any machine. The scored items are in the index above. These are the facts the scripts rely
on that nobody has checked against a real Windows 11 machine; `hard-elevated-run` checks them.

Defender, credentials, protocols, exploit and audit (`Set-WindowsDefenderHardening.ps1`
through `Set-WindowsAuditLogging.ps1`):

- `Add-MpPreference` adds one ASR rule id and action without disturbing the other rules.
- The Smart App Control `VerifiedAndReputablePolicyState` values read as reported.
- `Dnscache` `EnableMDNS` turns off the mDNS responder.
- The text a missing optional feature returns from `Get-WindowsOptionalFeature`.
- The nested HVCI key path for memory integrity.
- The object shapes `Get-ProcessMitigation -System` returns.
- Module Logging's `*` value name under `ModuleNames`.
- Office Click-to-Run detection through the 16.0 install roots.
- `auditpol` current-setting parsing, which matches English words only.

Remote access, accounts and firewall:

- The WinRM listener registry path read for the report-only row.
- `AllowInboundRules False` on the local persistent store.
- Application filter binding when a program rule's path is missing.
- `netsh advfirewall export` failing unelevated, which the script treats as a warning.

BitLocker and WDAC:

- The JSON shape `CiTool --list-policies --json` returns, whether `--update-policy` and
  `--remove-policy` also answer in JSON, and which GUID form, braced or bare, each accepts.
- `Set-CIPolicyIdInfo -ResetPolicyID` giving the base and policy IDs the script expects.
- The Code Integrity event field names `Export-WdacAuditEvent.ps1` reads for 3076, 3077 and 3089.
- The ConfigCI module loading under PowerShell 7.
- `Add-BitLockerKeyProtector` on a fully decrypted volume.
- The restart the BitLocker hardware test needs, and the state the volume reads in until then.
- Whether removing a WDAC policy with CiTool needs a restart to take effect.
- The `HvciOptions` value in the in-box example policies on current builds, and
  `Set-RuleOption -Option 6` taking on them.
- Whether `Get-BitLockerVolume` needs elevation (the script assumes it does).

Two omissions are deliberate and stay out until a supported value is documented: WPAD and
the 24H2 Administrator Protection setting (`hard-omitted-settings`).

## Residual risk, not a backlog item

All 48 scripts had automated coverage on 2026-08-17, including all 24 that change
something; `Send-AdSecurityEmailReport` and `Invoke-DiskMaintenance` gained `-WhatIf` that
day, which is what made the last two coverable. The eleven hardening scripts added on
2026-10-29 each have an integration test file, but their elevated halves have not run.

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

The cloud incident readiness collector, `Export-CloudIncidentReadiness.ps1` (shipped
2026-09-25), carries the same limit in its sharpest form: it has never run against a
live tenant, on the developer's stub-only decision. Its specs stub
`Invoke-MgGraphRequest` and `Invoke-AzRestMethod` against shapes read from Microsoft's
documented Graph and ARM schemas, not captured from a real response, so an
undocumented or beta-only field shape could still surface a gap the stubs did not
cover. Verify it against a real tenant, with and without an Azure session, before
treating an IR-02 Met or NotMet as authoritative for a real readiness decision.

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

Follow-ups from the `cloud-ir-ready` landing review, 2026-09-25. Low severity, each errs
conservative (a pass is never overstated); scored in the Scored index on 2026-10-02. All three (responder roles, user consent, UAL session source) shipped 2026-10-07 and
landed on master 2026-10-30; see CHANGELOG.md, 2026-10-07.

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
