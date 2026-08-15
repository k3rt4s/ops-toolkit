# ops-toolkit Future Features

Backlog for the ops-toolkit. Items flow from here onto the work board when picked up,
and off the board into the repository history when done. Shipped work and its
acceptance criteria live in [USER_STORIES.md](USER_STORIES.md), not here.

## Ready to pick up

Nothing.

The four items opened on 2026-08-15 were all completed the same day:

- Remote support for the last two collectors. `Export-CertificateExpiryInventory.ps1`
  and `Test-WindowsHardeningState.ps1` both take `-ComputerName`, and the evidence
  pack now fans out to all six collectors with none reported LocalMachineOnly.
- The four remaining scripts were retrofitted onto `OpsToolkit.Reporting`. No script
  in the repo defines its own report helpers any more.
- The analyzer findings were cleared. `Invoke-RepoValidation.ps1 -Strict` passes.
- `Page-File-Bleed.ps1` was kept rather than retired, and given a header. The help
  gate has no exemptions left.

## Considered and not queued

Recorded so the reasoning is not re-derived later.

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

## Known deviations

Things that look like gaps and are not.

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
