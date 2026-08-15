# ops-toolkit Future Features

Backlog for the ops-toolkit. Items flow from here onto the work board when picked up,
and off the board into CHANGELOG when done. Shipped work lives in
[USER_STORIES.md](USER_STORIES.md), not here.

Nothing in this file is blocking. As of 2026-08-15 the queue is empty and the only
work that changes the toolkit's value is running the six unverified scripts against a
real tenant and a real domain, which is an operator task rather than a build.

## Ready to pick up

### Remote support for the last two collectors

`Export-CertificateExpiryInventory.ps1` and `Test-WindowsHardeningState.ps1` have no
`-ComputerName` parameter, so they only ever cover the machine they run on.

The evidence pack already detects this by reading each collector's parameter block and
records those two as `LocalMachineOnly`, so nothing currently claims estate coverage
it does not have. That makes this an improvement rather than a correctness fix.

Adding `-ComputerName` to either one makes the evidence pack fan it out automatically,
with no change to the pack itself.

Done when: both accept `-ComputerName`, the pack reports them with a machine count
rather than `LocalMachineOnly`, and the certificate collector's TLS endpoint probe
still runs from the machine the script was started on rather than from each target,
because probing an endpoint is not a per-machine question.

### Retrofit the four remaining scripts onto OpsToolkit.Reporting

Still carrying their own copies of `Export-Report` and `Resolve-OutputDirectory`:

- `scripts\active-directory\Export-AdUserInventory.ps1`
- `scripts\azure\Export-AzNetworkInventory.ps1`
- `scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1`
- `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1`

These were left deliberately. None can be run on the build workstation, and swapping
tested duplication for untested shared code is a bad trade. The three scripts that
were retrofitted had unit tests or a real run behind them.

Take one at a time, when there is an opportunity to actually run it. The mechanical
transform is straightforward; the risk is entirely in not being able to prove it.

Note the behaviour change this introduces: the module writes both a CSV and a JSON
file even for an empty record set, where a bare `Export-Csv` writes nothing at all.
That is the intended behaviour, because a report that exists and is empty proves the
check ran while a missing file is ambiguous, but it will look like a difference.

Done when: the script uses the module, produces the same reports against a real run,
and `Invoke-RepoValidation.ps1` still passes.

### Close the analyzer findings in the three legacy files

29 warnings remain, and they are narrower than the count suggests: 27 are
`PSAvoidUsingWriteHost` and 2 are whitespace, spread across three files.

- `Invoke-DiskMaintenance.ps1` (21)
- `Page-File-Bleed.ps1` (7)
- `Set-WindowsLightMode.ps1` (1)

`Write-Host` in these is deliberate operator progress output on long-running disk
work, so this is not a blind sweep to `Write-Output`. The right change is
`Write-Information -InformationAction Continue`, which keeps the operator's live
feedback while making the stream redirectable, and each one needs a run to confirm the
output still reads correctly during a long operation.

Done when: `Invoke-RepoValidation.ps1 -Strict` passes.

### Give Page-File-Bleed.ps1 a header, or retire it

It is the single documented exemption in the validation help gate: no comment-based
help block at all, so `Get-Help` can say nothing about it.

Decide first whether it is still wanted. If it is kept, give it a header matching the
repo standard and remove the exemption from `Invoke-RepoValidation.ps1`. If it is not,
move it under `archive\` with a reason, per the repo's retirement convention.

Done when: the help gate reports zero exemptions.

## Considered and not queued

Recorded so the reasoning is not re-derived later.

- **Scheduling.** Every collector is run by hand. Scheduling them is what makes the
  change detection in `Compare-OpsToolkitRun.ps1` worth having, since comparing two
  runs needs two runs. Not queued because it should follow the live verification, not
  precede it: scheduling unproven collectors just produces unproven reports faster.
  When it happens, note that the task host runs Windows PowerShell 5.1, which is why
  the validation suite now fails any script with non-ASCII bytes and no BOM.
- **Backup verification.** The evidence pack reports BCK-01 as NotAssessed and says
  what to attach. A restore test is an operational exercise rather than a
  configuration read, and no amount of reading state can evidence it. Deliberately
  left unautomated rather than faked from configuration.
- **Third-party EDR detection.** The evidence pack reads Microsoft Defender only. A
  tenant running something else gets NotAssessed for EDR-01, which is correct but
  unhelpful. Worth adding if a specific product needs covering; not worth a generic
  abstraction first.
