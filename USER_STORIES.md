# ops-toolkit User Stories

User-value master for the ops-toolkit scripts. Sits above the per-script
comment-based help (the "how"). Stories follow the form "As a `<persona>`, I
want `<outcome>`, so that `<value>`" with Given/When/Then acceptance criteria.

This repo is script-based and unversioned, so shipped stories use a dated ship
marker (`shipped 2026-06-06`) instead of a semver string. This file was seeded
on 2026-06-06 covering the performance and disk-space tooling; the remaining
script families (Active Directory, Azure, IIS, Microsoft 365, Windows
hardening) are pending backfill.

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

## Cross-references

- Per-script usage: comment-based help in each `.ps1` (`Get-Help <script> -Full`).
- Conventions and validation: [README.md](README.md) (Script Standards, Validation).
- Companion tools: `Invoke-WindowsFileCleanup.ps1`, `Invoke-DiskMaintenance.ps1`.
