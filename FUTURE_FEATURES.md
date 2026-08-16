# ops-toolkit Future Features

Backlog for the ops-toolkit. Items flow from here onto the work board when picked up,
and off the board into the repository history when done. Shipped work and its
acceptance criteria live in [USER_STORIES.md](USER_STORIES.md), not here.

## Ready to pick up

One item: the hard-coded absolute paths, described in its own section below. There is
also one open question for the developer, further down.

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

## Queued item: hard-coded absolute paths

Nine of them across four scripts, in a repository whose standing rules say parameters
only. `Invoke-DiskSpaceReclaim`, `Set-WorkstationLockPosture`, and
`Set-WorkstationPerformance` default their report directory to `C:\Code_data`, and the
last also defaults a **Defender exclusion** to `C:\Code_data`, which is a security
setting pointed at one particular machine's layout. `Invoke-WindowsFileCleanup` carries
`C:\Temp`, `D:\Temp`, `E:\Temp`, `I:\Temp`, and `C:\Code` in its own lists.

Not done in the same pass that found them, because changing a default changes behaviour
for anyone already running these, and what the replacement should be is a product
decision rather than a cleanup: an environment variable, a required parameter, or a
per-install config file. The Defender one is the sharpest and could reasonably go first.

## Open question for the developer

**`windows-hardening` and `utilities` each exist at two levels of `scripts\`**, once at
the top and once under `it-operations\`, with no principle separating them:
`Test-WindowsHardeningState.ps1` is in one and `Export-BitLockerEscrowStatus.ps1` in the
other. It looks like a move that stopped halfway. Two leftover empty directories
(`scripts\printers\`, `scripts\windows-file-cleanup\`) were removed, as git tracked
nothing in them, but no script was moved: which way the split should resolve is a
structural call, and moving files would churn every documentation reference and any
scheduled task path for no functional gain. Raised here rather than decided.

## Residual risk, not a backlog item

39 of the 48 scripts have automated coverage, including all 22 that change something.
The nine without it are read-only or trivial utilities whose failure mode is an
unhelpful report rather than a change to a system.

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
