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

- Given the script is run with `-WhatIf`, When it executes, Then it writes a plan
  CSV/JSON and previews every target without deleting anything.
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

## Cross-references

- Per-script usage: comment-based help in each `.ps1` (`Get-Help <script> -Full`).
- Conventions and validation: [README.md](README.md) (Script Standards, Validation).
- Companion tools: `Invoke-WindowsFileCleanup.ps1`, `Invoke-DiskMaintenance.ps1`.
