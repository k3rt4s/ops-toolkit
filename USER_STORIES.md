# ops-toolkit User Stories

User-value master for the ops-toolkit scripts. Sits above the per-script
comment-based help (the "how"). Stories follow the form "As a `<persona>`, I
want `<outcome>`, so that `<value>`" with Given/When/Then acceptance criteria.

This repo is script-based and unversioned, so shipped stories use a dated ship
marker (`shipped 2026-06-06`) instead of a semver string. This file was seeded
on 2026-06-06 covering the performance and disk-space tooling, and backfilled on
2026-08-14 to cover the remaining families: Active Directory, Azure, IIS,
Microsoft 365, Windows hardening, endpoint lifecycle, certificates, identity,
evidence reporting, and the repository tooling.

Backfilled stories carry the ship date of the backfill, not of the original
script, because that is when the acceptance criteria were written down. Where a
criterion describes behaviour that was verified by running the script, it says so.

## Personas

- Workstation operator: runs a single heavy local workstation (builds, media
  encode/transcode, transcription) and wants it fast and clean without losing data.
- IT administrator: maintains Windows endpoints and wants repeatable, previewable,
  reversible automation with an audit trail.
- Security-conscious operator: a CISO/security owner who will only accept changes
  that are explicit, narrowly scoped, and reversible, and never silently weaken AV.

## Epic: Reclaim disk space

### Story: Reclaim developer and Windows caches

As a workstation operator, I want to reclaim space from package-manager, container,
Recycle Bin, and Windows component caches, so that a near-full system drive returns
to a healthy free-space margin without deleting source code or data.

Status: shipped 2026-06-06 (`scripts/it-operations/windows-file-cleanup/Invoke-DiskSpaceReclaim.ps1`)

Acceptance criteria:

- Given the script is run with `-WhatIf`, When it executes, Then it writes plan and
  state CSV/JSON and previews every target without deleting anything.
- Given a target requires elevation (ComponentStore, WindowsUpdateCache) and the
  shell is not elevated, When the script runs, Then that target is skipped with a
  "requires elevation" result and other targets still run.
- Given the HuggingFace model cache, When the default target set is used, Then it is
  not touched unless explicitly requested via `-Target HuggingFaceCache`.
- Given a live run, When it completes, Then a state CSV/JSON records each target's
  result and a system-drive free-space before/after delta.

## Epic: Sustained performance posture

### Story: Set and roll back a workstation performance posture

As a workstation operator, I want to switch to a high/ultimate performance power plan
and exclude a trusted data location from real-time antivirus scanning, so that long
local batch jobs are not throttled or taxed by background scanning.

Status: shipped 2026-06-06 (`scripts/it-operations/performance/Set-WorkstationPerformance.ps1`)

Acceptance criteria:

- Given `-WhatIf`, When the script runs, Then it writes a plan CSV/JSON and applies
  no changes.
- Given a live forward run that changes settings, When it completes, Then it writes a
  rollback JSON capturing the previous active power scheme and the exclusions it added.
- Given a later `-Rollback`, When it runs, Then it restores the previous power scheme
  and removes only the exclusions this script added, leaving pre-existing exclusions intact.

## Epic: Workstation security posture

### Story: Lock the workstation on idle without disabling overnight jobs

As a security-conscious operator, I want the workstation to lock after a configurable idle
timeout while staying awake to run overnight pipelines, so that the screen locks if I step away
without interrupting builds, encodes, or transcription runs.

Status: shipped 2026-06-07 (`scripts/it-operations/windows-hardening/Set-WorkstationLockPosture.ps1`)

Acceptance criteria:

- Given the script is run with `-WhatIf`, When it executes, Then it writes plan and state
  CSV/JSON and previews every change without modifying any setting.
- Given a live forward run, When it completes, Then AC sleep, hibernate, and display
  power-off (monitor-timeout-ac) are set to Never, the screensaver is enabled with a
  password-protected timeout at the requested interval, and a rollback JSON is written
  capturing every prior value. Setting monitor-timeout-ac to Never prevents S0 Low Power
  Idle on Modern Standby systems where S0 is triggered by the display powering off, not
  by the standby timer. The screensaver still blanks and locks the screen visually.
- Given a later `-Rollback`, When it runs, Then every changed setting is restored to its
  captured prior value and no other settings are touched.
- Given elevation-only settings (-EnableConsoleLock, -EnableMachineWideLock), When the shell is
  not elevated, Then those settings are skipped with a "requires elevation" result and all
  non-elevated settings still apply.

### Story: Keep antivirus changes safe and reversible

As a security-conscious operator, I want any Defender exclusion to be explicit,
narrowly scoped, and reversible, so that a performance change never silently and
permanently weakens endpoint protection.

Status: shipped 2026-06-06

Acceptance criteria:

- Given the default parameters, When the script runs, Then only the data path
  `C:\Code_data` is proposed for exclusion and no process exclusions are added.
- Given Defender changes require elevation, When the shell is not elevated, Then those
  changes are skipped rather than partially applied.
- Given exclusions were added by a forward run, When `-Rollback` runs, Then exactly
  those exclusions are removed.

## Epic: Identity credential hygiene

### Story: Find expiring Entra ID credentials before they cause an outage

As an IT administrator, I want a dated report of every Entra ID app registration and
service principal secret and certificate with its days to expiry, so that a credential
is renewed on a schedule instead of being discovered when the integration it
authenticates stops working.

Status: shipped 2026-08-14 (`scripts/entra/Export-EntraAppCredentialExpiry.ps1`)

Acceptance criteria:

- Given a connected Graph session, When the script runs, Then it writes a full
  credential CSV/JSON, an attention-only subset, a per-application rollup, and a
  summary, and changes nothing in the tenant.
- Given a credential with no end date, When it is exported, Then its status is
  Unknown and its days to expiry is empty rather than a misleading number.
- Given any credential, When it is exported, Then no secret value appears in any
  output file. Only key IDs, certificate thumbprints, dates, and display names do.
- Given `-RecommendedSecretLifetimeDays`, When credentials are classified, Then only
  client secrets are flagged for over-long lifetime, because certificates
  legitimately run one to two years.

### Story: Know whether an expiring credential is actually still used

As a security-conscious operator, I want each expiring credential matched against
recent service principal sign-ins, so that I renew what is live and remove what is
dead instead of rotating every credential defensively.

Status: shipped 2026-08-14 (`scripts/entra/Export-EntraAppCredentialExpiry.ps1 -IncludeSignInUsage`)

Acceptance criteria:

- Given `-IncludeSignInUsage`, When a credential key ID appears in the sign-in
  window, Then it is reported InUse with its last sign-in time.
- Given the application signed in on a different credential, When the report is
  written, Then the credential is reported AppActiveOnOtherCredential rather than
  unused, so a live app is never mistaken for a dead one.
- Given the tenant lacks the licence or the scope for sign-in log access, When the
  lookup fails, Then the usage columns report Unavailable, a warning names the
  reason, and the expiry report still completes.
- Given `-IncludeSignInUsage` is not passed, When the report is written, Then usage
  columns read NotChecked rather than implying the credential is unused.

## Epic: Directory attack surface

### Story: See the standing privilege and delegation exposure in a domain

As a security-conscious operator, I want one read-only pass that lists the AD
misconfigurations attackers actually use, with a severity and a recommendation on
each, so that a domain review produces a work list instead of a raw attribute dump.

Status: shipped 2026-08-14 (`scripts/active-directory/Export-AdPrivilegedAccessAudit.ps1`)

Acceptance criteria:

- Given a domain, When the audit runs, Then it reports AS-REP roastable accounts,
  Kerberoastable accounts, unconstrained, constrained, protocol-transition and
  resource-based delegation, PASSWD_NOTREQD, reversible encryption, orphaned
  adminCount, krbtgt password age, and tier-0 membership, each with a severity and a
  recommendation, sorted worst first.
- Given a Group Managed Service Account with a service principal name, When the
  audit runs, Then it is not reported as Kerberoastable, because its password is
  domain-managed and not crackable offline.
- Given a domain controller trusted for unconstrained delegation, When the audit
  runs, Then it is reported as Informational, not Critical, so the member server
  that should not be unconstrained is not buried.
- Given a renamed or non-English privileged group, When tier-0 membership is
  resolved, Then it still resolves, because groups are found by well-known SID
  rather than by name.
- Given nested group membership, When tier-0 membership is expanded, Then indirect
  members are included, via the LDAP in-chain matching rule.
- Given a child domain, When the audit runs, Then forest-root-only groups
  (Enterprise Admins, Schema Admins, Enterprise Key Admins) are skipped rather than
  reported as unreadable.
- Given the audit runs, Then it makes no directory writes and needs no `-WhatIf`.

## Epic: Deprecation readiness

### Story: Find retired Microsoft APIs before their cutoff arrives

As an IT administrator, I want one pass over a script share that lists every call to
a Microsoft module or API with a published retirement date, ordered by how soon it
bites, so that I work the nearest cutoff first instead of finding out when an
overnight job stops authenticating.

Status: shipped 2026-08-14 (`scripts/utilities/Find-LegacyApiUsage.ps1`)

Acceptance criteria:

- Given a folder tree, When the scan runs, Then each finding carries the file, line
  number, matched text, deadline, why the deadline exists, and the replacement.
- Given a finding sits on a commented line, When it is reported, Then it is flagged
  as a comment rather than silently dropped or silently counted as live code.
- Given a modern replacement in the same file family (`Get-MessageTraceV2`,
  `Connect-ExchangeOnline -CertificateThumbprint`, `Get-AzVM`, `Connect-MgGraph`),
  When the scan runs, Then it produces no finding for that line.
- Given the scanner is inside the tree being scanned, When it runs, Then its own
  rule table is not reported as findings unless `-IncludeSelf` is passed.
- Given `-Path` is not supplied, When the script runs, Then it prints usage and exits
  with code 2 rather than prompting.

## Epic: Endpoint lifecycle and patch health

### Story: Know which machines fall off support and when

As an IT administrator, I want each machine reported against its vendor support end
date, so that an upgrade programme is planned against real dates instead of being
triggered by an outage.

Status: shipped 2026-08-14 (`scripts/it-operations/lifecycle/Export-WindowsLifecycleInventory.ps1`)

Acceptance criteria:

- Given a machine, When the inventory runs, Then it reports the support end date and
  days remaining, classified as Supported, EndingSoon, or OutOfSupport.
- Given support dates change, When they do, Then only
  `data/it-operations/lifecycle/windows-support-lifecycle.csv` needs editing, and the
  script warns when that file is older than `-DataMaxAgeDays`.
- Given a build with no matching row, When it is reported, Then its status is Unknown
  with a note naming what to add, never a guessed date.
- Given Windows 11 24H2 and Windows Server 2025 share build 26100, When either is
  matched, Then the product line decides the row, not the build number.

### Story: Split the estate into upgrade, remediate, and replace

As an IT administrator, I want Windows 11 hardware eligibility checked per machine
with the failing requirement named, so that budget goes to the machines that actually
need replacing.

Status: shipped 2026-08-14 (`scripts/it-operations/lifecycle/Test-Windows11UpgradeReadiness.ps1`)

Acceptance criteria:

- Given a machine, When the check runs, Then the verdict is Ready, Blocked, or
  Undetermined, with the failing checks named.
- Given a check could not be read, When the verdict is formed, Then it is
  Undetermined rather than Ready, because an unread TPM is not an absent TPM.
- Given TPM 2.0 is present but disabled, When it is reported, Then the note says it
  is a firmware setting rather than a hardware replacement.
- Given the CPU model, When it is reported, Then it is marked Review rather than
  pass or fail, because Microsoft publishes a supported list and not a rule.

### Story: Answer why a machine is not patching

As an IT administrator, I want the services, reboot state, deferral policy, and update
history collected in one pass, so that a stalled machine is diagnosed from evidence
rather than by clicking through Settings.

Status: shipped 2026-08-14 (`scripts/it-operations/lifecycle/Export-WindowsUpdateHealth.ps1`)

Acceptance criteria:

- Given a machine, When the collector runs, Then it reports service state, every
  pending-reboot signal, WSUS configuration, deferrals, pause state, last successful
  install, and recent failures, with a verdict of Healthy, Degraded, or Unhealthy.
- Given a pause expiry in the registry that has already passed, When it is reported,
  Then the machine is not described as paused. Verified against a machine carrying a
  four-month-old expiry value.
- Given update history timestamps arrive from COM as UTC, When ages are computed,
  Then they are converted to local time and never render as a negative age.

## Epic: Endpoint recoverability and privileged access

### Story: Separate "encrypted" from "recoverable"

As a security-conscious operator, I want BitLocker protection reported separately
from recovery key escrow, so that a machine that is encrypted with an unrecoverable
key is not counted as a success.

Status: shipped 2026-08-14 (`scripts/it-operations/windows-hardening/Export-BitLockerEscrowStatus.ps1`)

Acceptance criteria:

- Given a volume, When it is reported, Then its status distinguishes Unprotected,
  EncryptedNoRecoveryKey, EncryptedNotEscrowed, EncryptedEscrowUnknown, and
  Recoverable.
- Given the shell is not elevated, When volumes are assessed, Then they report
  Undetermined rather than a false pass.
- Given `-VerifyAdEscrow`, When it runs, Then escrow is confirmed by reading
  msFVE-RecoveryInformation rather than inferred from policy.
- Given any run, Then no recovery key value appears in any output file.

### Story: Know who holds local administrator and whether the password is managed

As a security-conscious operator, I want local administrator membership and LAPS state
reported per machine, so that shared and unmanaged local admin passwords are found
before an attacker finds them.

Status: shipped 2026-08-14 (`scripts/it-operations/windows-hardening/Export-LocalAdminAndLapsPosture.ps1`)

Acceptance criteria:

- Given the Administrators group has been renamed or localized, When membership is
  read, Then it still resolves, because the group is found by well-known SID.
- Given the group contains an orphaned SID from a deleted domain account, When
  `Get-LocalGroupMember` fails as it does in that case, Then an ADSI fallback still
  returns the membership and the orphan is reported.
- Given LAPS is configured but has never recorded a password update, When the verdict
  is formed, Then it is NeedsAttention rather than Managed.
- Given any run, Then no password value is read or written.

## Epic: Certificate lifecycle

### Story: Find expiring certificates wherever they hide

As an IT administrator, I want certificate expiry inventoried across machine stores,
IIS bindings, and live endpoints, so that a renewal that never reached the binding is
caught before the endpoint goes down.

Status: shipped 2026-08-14 (`scripts/certificates/Export-CertificateExpiryInventory.ps1`)

Acceptance criteria:

- Given a store, an IIS binding, and a remote endpoint, When the inventory runs, Then
  all three appear on one timeline with days to expiry.
- Given an endpoint serving an expired or untrusted certificate, When it is probed,
  Then the certificate is still read and reported. Verified against
  expired.badssl.com, which a validating client refuses outright.
- Given an IIS binding referencing a thumbprint absent from the store, When it is
  reported, Then its status is MissingCertificate, because it serves nothing.
- Given any run, Then no private key is read or exported.

## Epic: Directory hardening readiness

### Story: Find the clients that LDAP enforcement will break

As a security-conscious operator, I want the clients still binding without signing or
channel binding listed before enforcement is turned on, so that enforcement is a
planned change rather than an outage.

Status: shipped 2026-08-14 (`scripts/active-directory/Test-LdapSigningReadiness.ps1`)

Acceptance criteria:

- Given a domain controller, When the check runs, Then it reports the signing and
  channel binding configuration and every client seen doing an unsigned or unbound
  bind, with address, identity, and first and last seen.
- Given per-client logging is off, When no client events are found, Then the readiness
  is Unmeasured rather than a pass, and the note says how to switch logging on.
- Given no events exist in the window, When the log is queried, Then that is reported
  as a normal outcome, not as an inability to check.

### Story: Find who can make themselves privileged

As a security-conscious operator, I want AD permissions that permit object takeover or
directory replication reported against tier-0, so that escalation paths invisible in
group membership are found.

Status: shipped 2026-08-14 (`scripts/active-directory/Export-AdAclRiskReport.ps1`)

Acceptance criteria:

- Given a tier-0 object, When its descriptor is read, Then GenericAll, WriteDacl,
  WriteOwner, GenericWrite, ForceChangePassword, Self-Membership, and the replication
  extended rights are reported with a severity and an explanation.
- Given a Deny ACE, When it is evaluated, Then it is not reported as a grant.
- Given a principal holding both replication rights, or all extended rights on the
  domain root, When the rollup is written, Then it is flagged as granting DCSync.
- Given a principal that holds broad rights by design, such as Local System or a
  tier-0 group, When findings are collected, Then it is suppressed so real findings
  are not buried.
- Given an ACE whose identity no longer resolves to a name, When it is reported, Then
  it is marked orphaned rather than dropped.

## Epic: Identity readiness

### Story: Find the users a telephony cutoff will strand

As a security-conscious operator, I want users whose only registered method is SMS or
voice identified, so that the migration ahead of the February 2027 telephony cutoff
targets the users who actually have nothing else.

Status: shipped 2026-08-14 (`scripts/entra/Export-EntraAuthMethodReadiness.ps1`)

Acceptance criteria:

- Given a user with both Authenticator and a phone number, When readiness is
  classified, Then they are not reported as telephony-only.
- Given a user with no MFA method at all, When the report is sorted, Then they appear
  above telephony-only users, and administrators appear above everyone.
- Given any run, Then no phone number or method identifier is written to a report.

### Story: Know whether Conditional Access still matches what was agreed

As a security-conscious operator, I want policies exported, gap-analysed, and compared
against a saved baseline, so that both drift and never-configured gaps are visible.

Status: shipped 2026-08-14 (`scripts/entra/Export-EntraConditionalAccessBaseline.ps1`)

Acceptance criteria:

- Given a baseline, When policies are compared, Then added, removed, and modified
  policies are reported.
- Given a policy whose `modifiedDateTime` changed but whose enforced behaviour did
  not, When drift is computed, Then it is not reported as modified.
- Given a change to state, grant controls, or user exclusions, When drift is computed,
  Then it is reported as modified.
- Given a policy in report-only state, When gaps are analysed, Then it is reported as
  NotEnforcing, because it is visible in the portal and changes no sign-in outcome.
- Given `-UpdateBaseline`, When the baseline is overwritten, Then a warning states
  that it now records current state whatever that state is.

## Epic: Telemetry posture

### Story: Know whether anything would have recorded it

As a security-conscious operator, I want to know which security logging is switched on
across the estate and how many days of it actually survive, so that a hunt or an
investigation is not run against a channel that was never enabled or that rolled over
this morning.

Status: shipped 2026-08-17 (`scripts/logging/Export-EndpointTelemetryPosture.ps1`)

Acceptance criteria:

- Given a machine, When its telemetry posture is read, Then PowerShell script-block
  logging, command-line process auditing, the required audit subcategories, Sysmon,
  and event forwarding are each reported Enabled, Disabled, NotRequired, or
  Undetermined, with the reason the setting matters carried into the report.
- Given a setting that could not be read, such as audit policy in an unelevated
  session, When it is graded, Then it is Undetermined and never Enabled, and the
  machine verdict is Undetermined even where other settings were read cleanly.
- Given a channel, When its retention is reported, Then it is measured from the oldest
  record still present rather than from the configured maximum size, and a channel
  with no measurable history is Unmeasured rather than sufficient.
- Given a channel holding less than the required window, When it is graded, Then it is
  Insufficient only if it is full, and Building if it is simply younger than the
  window, so a newly built machine is not reported as misconfigured.
- Given Sysmon or event forwarding is absent, When the run is graded, Then their
  absence is not counted as a gap unless `-RequireSysmon` or `-RequireEventForwarding`
  was passed, because an estate that does not run them is not thereby non-compliant.

## Epic: Compliance evidence

### Story: Answer the questions insurers and assessors actually ask

As a security-conscious operator, I want one dated bundle that maps collector output
to the standard control questions, so that a questionnaire is answered from evidence
instead of from memory.

Status: shipped 2026-08-14 (`scripts/reporting/Export-SecurityControlEvidencePack.ps1`)

Acceptance criteria:

- Given a run, When the pack is assembled, Then every control is Met, Partial, NotMet,
  or NotAssessed, and the raw collector output is included in the pack.
- Given a collector did not run, failed, or timed out, When its controls are recorded,
  Then they are NotAssessed and never Met, and the summary counts NotAssessed
  separately from NotMet.
- Given a control this toolkit cannot evidence, such as backup restore testing or
  incident response exercises, When the pack is written, Then the control is listed
  as NotAssessed with what to attach, rather than omitted.
- Given one collector fails, When the run continues, Then the remaining collectors
  still run, because each runs isolated in its own process with a timeout.

## Epic: Repository quality

### Story: Run the validation ritual as one command

As an IT administrator maintaining this repo, I want the checks the README described
in prose to run as one command, so that they are actually run and cannot drift.

Status: shipped 2026-08-14 (`Invoke-RepoValidation.ps1`)

Acceptance criteria:

- Given the repo, When validation runs, Then it gates on parser, PSScriptAnalyzer,
  comment-based help, bash syntax, stale documentation references, and module
  manifests, and returns a per-gate result.
- Given a script whose comment-based help does not parse, When the help gate runs,
  Then it fails, because a non-standard keyword silently disables `Get-Help` and
  nothing else catches it.
- Given a documentation reference relative to its own folder rather than the repo
  root, When the stale-reference gate runs, Then it is not reported as stale.
- Given no working bash, When the shell gate runs, Then it is skipped with a note
  rather than failing every shell script.
- Given analyzer warnings but no errors, When the run completes, Then it does not fail
  unless `-Strict` is passed.

### Story: Write reports one way

As an IT administrator maintaining this repo, I want report writing to live in one
module, so that a fix to report handling lands everywhere at once.

Status: shipped 2026-08-14 (`modules/OpsToolkit.Reporting/`)

Acceptance criteria:

- Given a script needs to write a report, When it imports the module by relative path,
  Then it gets directory resolution, CSV plus JSON export, and run summaries without
  its own copy.
- Given an empty record set, When it is exported, Then both files are still written,
  because a report that exists and is empty proves the check ran while a missing file
  is ambiguous.
- Given a manifest declares a function the module does not export, When
  `Invoke-RepoValidation.ps1` runs, Then the module gate fails.

## Cross-references

- Per-script usage: comment-based help in each `.ps1` (`Get-Help <script> -Full`).
- Conventions and validation: [README.md](README.md) (Script Standards, Validation).
- Companion tools: `Invoke-WindowsFileCleanup.ps1`, `Invoke-DiskMaintenance.ps1`.
