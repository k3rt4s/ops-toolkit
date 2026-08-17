# ops-toolkit

Hardened operations and security administration scripts for Active Directory, Azure, IIS, Microsoft 365, Windows hardening, IT operations, and reporting. Every state-changing script supports `-WhatIf` and writes plan/state/rollback reports, parameters are validated explicitly, and no customer data, tenant IDs, subscription IDs, or storage keys are hard-coded.

**Author:** Jon Bowker
**Linting:** PSScriptAnalyzer (settings in `PSScriptAnalyzerSettings.psd1`)

## Contents

<!-- BEGIN CONTENTS (auto-generated, do not edit by hand) -->

- [archive/](archive/README.md): Retired scripts and supporting files kept for historical reference inside the ops-toolkit repo.
- [data/](data/README.md): Non-secret, version-controlled input files used by ops-toolkit scripts as reference data.
- [docs/](docs/README.md): Reference material, lab guides, diagrams, and review notes for the ops-toolkit.
- [modules/](modules/README.md): Shared PowerShell modules imported by ops-toolkit scripts by relative path.
- [scripts/](scripts/README.md): Runnable automation lives under this folder, grouped by platform or operational domain.
- [tests/](tests/README.md): Pester specs covering the ops-toolkit scripts, in two layers: unit specs over the decision logic, and integration specs that run whole scripts end to end against stubbed back ends.
- [CHANGELOG.md](CHANGELOG.md): Notable changes to the ops-toolkit.
- [FUTURE_FEATURES.md](FUTURE_FEATURES.md): Backlog for the ops-toolkit.
- [Invoke-RepoValidation.ps1](Invoke-RepoValidation.ps1): Run the ops-toolkit repository validation suite: parser, analyzer, help, shell syntax, and stale references.
- [PSScriptAnalyzerSettings.psd1](PSScriptAnalyzerSettings.psd1)
- [THEORY.md](THEORY.md): Constraints that look arbitrary until you know why, and traps a fresh thread will otherwise re-derive the hard way.
- [USER_STORIES.md](USER_STORIES.md): User-value master for the ops-toolkit scripts.

<!-- END CONTENTS -->

## What Changed

This repo was reviewed and reorganized in place. Files remain inside the ops-toolkit repo; retired material is kept under `archive\` with a documented reason instead of being deleted.

The review answers five maintenance questions:

1. What is no longer relevant and should be retired: see [docs/retirement-review.md](docs/retirement-review.md) and [docs/legacy-script-inventory.md](docs/legacy-script-inventory.md).
2. What we are keeping and how it is organized: see [Layout](#layout) and [Contents](#contents).
3. Which scripts needed updates: see [Updated Scripts](#updated-scripts).
4. What instructions belong at the top of kept scripts: see [Script Header Standard](#script-header-standard).
5. How future readers should work in this repo: see [Script Standards](#script-standards).

## Layout

```text
ops-toolkit\
├── archive\                 Retired legacy scripts and supporting files
├── data\                    Package lists and non-secret script input data
├── docs\                    Labs, diagrams, review notes, and reference material
├── modules\                 Shared PowerShell modules imported by relative path
├── reports\                 Generated script output, ignored by git
├── scripts\                 Runnable automation grouped by platform/domain
├── .editorconfig
├── .gitignore
├── Invoke-RepoValidation.ps1  Repository validation suite
├── PSScriptAnalyzerSettings.psd1
└── README.md
```

## Retired

The current retire-now items are:

| Path                                                 | Why retired                                                                                   |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `archive\windows-hardening\Bloat-Remove-Replace.ps1` | Historical bloat-removal script superseded by the active Windows hardening script.            |
| `archive\windows-hardening\Bloat-Server-Removal.ps1` | Historical bloat-removal script superseded by the active Windows hardening script.            |
| Deleted Cortana enable/disable archive scripts       | Cortana in Windows standalone app is deprecated/retired.                                      |
| Deleted old bloatware CSV archives                   | Superseded by `data\windows-hardening\` package lists.                                        |
| Old AzureRM-style NSG export snippets                | Replaced with `scripts\azure\Export-AzNetworkInventory.ps1` using the supported `Az` modules. |

See [docs/retirement-review.md](docs/retirement-review.md) for the full keep/retire rationale and sources.

## Script and Data Inventory

| Path                                          | Purpose                                                           |
| --------------------------------------------- | ----------------------------------------------------------------- |
| `scripts\active-directory\`                   | AD reports, exports, and password notification scripts            |
| `scripts\azure\`                              | Azure PowerShell and Azure CLI automation                         |
| `scripts\entra\`                              | Entra ID identity reporting through Microsoft Graph               |
| `scripts\iis\`                                | IIS setup and HTTP security header configuration                  |
| `scripts\it-operations\performance\`          | Workstation performance posture (power plan, exclusions)          |
| `scripts\it-operations\printers\`             | Windows printer connection helpers                                |
| `scripts\it-operations\utilities\`            | General endpoint and admin utilities                              |
| `scripts\it-operations\windows-file-cleanup\` | File, temp-folder, and cache reclaim helpers                      |
| `scripts\it-operations\lifecycle\`            | OS support lifecycle, upgrade readiness, and update health        |
| `scripts\it-operations\windows-hardening\`    | Workstation idle-lock, sleep, BitLocker, and local admin posture  |
| `scripts\certificates\`                       | Certificate expiry across stores, IIS bindings, and TLS endpoints |
| `scripts\logging\`                            | Security logging posture: what is being recorded and for how long |
| `scripts\email\thunderbird\`                  | Thunderbird MBOX extraction and Parquet export pipeline           |
| `scripts\microsoft-365\`                      | Exchange Online and Microsoft 365 administration                  |
| `scripts\pentesting\`                         | AutoRecon workstation/lab setup helper                            |
| `scripts\reporting\`                          | Evidence packs assembled from the read-only collectors            |
| `scripts\utilities\`                          | General utilities, CSV comparison, and folder diff tools          |
| `scripts\windows-hardening\`                  | Windows telemetry, bloatware, and cipher hardening                |
| `data\it-operations\printers\`                | Example non-secret printer input files                            |
| `data\windows-hardening\`                     | Bloatware allow/remove package lists                              |
| `docs\labs\`                                  | Azure and ELK lab materials                                       |
| `docs\iis\`                                   | IIS header notes                                                  |
| `modules\OpsToolkit.Reporting\`               | Shared report-writing helpers imported by scripts                 |
| `archive\`                                    | Retired material retained inside the ops-toolkit repo             |

## Examples

Preview disabling and moving stale AD computer accounts:

```powershell
pwsh -File .\scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1 -InactiveDays 90 -SearchBase "OU=Workstations,DC=example,DC=com" -TargetOu "OU=DisabledComputers,DC=example,DC=com" -WhatIf
```

Audit AD for privilege and delegation misconfigurations (read-only, no changes):

```powershell
pwsh -File .\scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1 -Server dc01.example.com
```

Report who can take over a privileged object or replicate the directory:

```powershell
pwsh -File .\scripts\active-directory\Export-AdAclRiskReport.ps1 -Server dc01.example.com
```

Find clients that still bind without LDAP signing before enforcement breaks them:

```powershell
pwsh -File .\scripts\active-directory\Test-LdapSigningReadiness.ps1 -ComputerName dc01,dc02 -LookbackDays 14
```

Generate an AD security report without sending email:

```powershell
pwsh -File .\scripts\active-directory\Send-AdSecurityEmailReport.ps1 -ReportType PrivilegedGroupMembership -GroupName "Domain Admins"
```

Export AD user inventory reports:

```powershell
pwsh -File .\scripts\active-directory\Export-AdUserInventory.ps1 -ReportType All -OutputDirectory .\reports\active-directory
```

Initialize an Az PowerShell session and write a session report:

```powershell
pwsh -File .\scripts\azure\Initialize-AzPowerShellSession.ps1 -TenantId "<tenant-id>" -SubscriptionId "<subscription-id>" -UseDeviceAuthentication
```

Export Azure network inventory reports:

```powershell
pwsh -File .\scripts\azure\Export-AzNetworkInventory.ps1 -SubscriptionId "<subscription-id>" -IncludeVirtualMachines
```

Preview creating or reusing a Key Vault service principal:

```powershell
pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -EnvironmentName prod -ApplicationShortName app -KeyVaultName kv-prod-app -WhatIf
```

Preview mapping an Azure Files share to a Windows drive:

```powershell
pwsh -File .\scripts\azure\New-AzFileShareMappedDrive.ps1 -DriveLetter Z -StorageAccountName examplestorage -ShareName data -StorageAccountKey "<key>" -WhatIf
```

Preview importing an Azure VPN Client XML profile on Windows 11:

```powershell
pwsh -File .\scripts\azure\Import-AzureVpnClientXmlProfile.ps1 -ProfileXmlPath .\azurevpnconfig.xml -WhatIf
```

Preview applying a hardened Application Gateway TLS policy:

```powershell
pwsh -File .\scripts\azure\Set-AzAppGatewayTlsPolicy.ps1 -ResourceGroupName rg-network -ApplicationGatewayName appgw-prod -PolicyMode CustomHardened -WhatIf
```

Assemble a dated evidence pack answering the control questions insurers and assessors ask:

```powershell
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -Organization "Example Ltd" -IncludeEntra -IncludeActiveDirectory
```

Find out whether the logging a hunt would need is switched on, and how many days of it
actually survive:

```powershell
pwsh -File .\scripts\logging\Export-EndpointTelemetryPosture.ps1
pwsh -File .\scripts\logging\Export-EndpointTelemetryPosture.ps1 -ComputerName srv01,srv02 -MinimumRetentionDays 90
```

Run it elevated. Audit policy and the Security log cannot be read without elevation,
and both are reported Undetermined rather than compliant when the read fails. Retention
is measured from the oldest record still in each channel rather than from the configured
maximum size, because a 4 GB Security log on a busy machine can hold hours.

Compare the two most recent runs of a collector and see what changed since last time:

```powershell
pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path .\reports\active-directory
pwsh -File .\scripts\reporting\Compare-OpsToolkitRun.ps1 -Path .\reports\entra -FailOnNewFinding
```

Run the same pack across an estate from a machine list:

```powershell
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -TargetListPath .\machines.txt
```

Find users who still depend on SMS or voice before Microsoft stops delivering them:

```powershell
pwsh -File .\scripts\entra\Export-EntraAuthMethodReadiness.ps1 -Connect
```

Export Conditional Access policies and compare them against a saved baseline:

```powershell
pwsh -File .\scripts\entra\Export-EntraConditionalAccessBaseline.ps1 -Connect -BaselinePath .\ca-baseline.json
```

Report Entra ID app registration secrets and certificates that have expired or expire soon:

```powershell
pwsh -File .\scripts\entra\Export-EntraAppCredentialExpiry.ps1 -Connect -ExpiringWithinDays 90
```

Include service principals and check which credentials are still authenticating:

```powershell
pwsh -File .\scripts\entra\Export-EntraAppCredentialExpiry.ps1 -Connect -IncludeServicePrincipals -IncludeSignInUsage -IncludeOwners
```

Report mailbox forwarding, legacy protocol exposure, and EWS use before the 2026 cutoffs:

```powershell
pwsh -File .\scripts\microsoft-365\Export-M365MailboxSecurityPosture.ps1 -Connect -IncludeInboxRules
```

Find Azure resources that are billing and attached to nothing:

```powershell
pwsh -File .\scripts\azure\Export-AzOrphanedResource.ps1 -MinimumAgeDays 30
```

Export Microsoft 365 distribution group usage from message traces:

```powershell
pwsh -File .\scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1 -Connect -Organization "<tenant-domain>"
```

Scan a script share for retired or soon-to-be-retired Microsoft APIs, nearest deadline first:

```powershell
pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts
```

Limit the scan to things that have already stopped working:

```powershell
pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts -Severity Broken
```

Join application inventory rows to endpoint site data:

```powershell
pwsh -File .\scripts\utilities\Join-ApplicationsWithEndpointSites.ps1 -ApplicationsPath .\applications.csv -EndpointsPath .\endpoints.csv -IncludeUnmatchedApplications
```

Preview installing AutoRecon dependencies on a lab workstation:

```bash
./scripts/pentesting/Install-AutoReconDependencies.sh --dry-run
```

Preview AD user UPN suffix updates:

```powershell
pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf
```

Add printer connections from a text file after previewing the action:

```powershell
pwsh -File .\scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1 -Action Add -PrinterListPath .\data\it-operations\printers\printers.example.txt -WhatIf
```

Preview recursive file cleanup:

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1 -Mode OlderThan -Path C:\Logs -OlderThanDays 30 -WhatIf
```

Preview adding a custom IIS response header:

```powershell
pwsh -File .\scripts\iis\Set-IisSiteCustomHeader.ps1 -SiteName "Default Web Site" -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf
```

Preview adding IIS site-default custom logging fields:

```powershell
pwsh -File .\scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1 -WhatIf
```

Preview replacing IIS custom headers with the recommended preset and write a before/after review CSV:

```powershell
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -RemoveExisting -WhatIf
```

Verify applied hardening is still in place, and prove the TLS client policy with real handshakes:

```powershell
pwsh -File .\scripts\windows-hardening\Test-WindowsHardeningState.ps1 -ProbeEndpoint 'www.example.com:443'
pwsh -File .\scripts\windows-hardening\Test-WindowsHardeningState.ps1 -ComputerName srv01,srv02 -FailOnDrift
```

Preview Windows Schannel/TLS hardening and write plan reports:

```powershell
pwsh -File .\scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1 -WhatIf
```

Preview Windows 11 privacy hardening and write plan reports:

```powershell
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -WhatIf
```

Preview rolling back Windows 11 privacy hardening:

```powershell
pwsh -File .\scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1 -Rollback -WhatIf
```

Preview Windows 11 AppX bloatware removal and write inventory/plan/state reports:

```powershell
pwsh -File .\scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1 -RemoveProvisionedPackages -InstalledPackageScope AllUsers -WhatIf
```

Preview reclaiming developer and Windows caches (pip cache, Docker build cache and dangling images, Recycle Bin, WinSxS):

```powershell
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
```

Preview setting the workstation performance posture, then roll it back:

```powershell
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -WhatIf
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1 -Rollback -WhatIf
```

Preview the workstation idle-lock and sleep posture (10-minute screensaver lock, never sleep on AC):

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -WhatIf
```

Apply the lock posture and roll it back:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -Rollback -WhatIf
```

The above (no elevation) sets AC sleep to Never, enables a 10-minute password-protected screensaver,
and records a rollback JSON. Two optional belt-and-suspenders controls require an elevated shell:

- `-EnableConsoleLock` sets the power-scheme "require password on wake" flag (AC + DC) via `powercfg`.
- `-EnableMachineWideLock` writes `InactivityTimeoutSecs` to `HKLM:\...\Policies\System`, enforcing
  the lock machine-wide via Group Policy registry regardless of per-user screensaver settings.

Apply both elevated controls and the Defender exclusion from an elevated shell:

```powershell
# Elevated shell — right-click > Run as Administrator
pwsh -File .\scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1 -EnableConsoleLock -EnableMachineWideLock
pwsh -File .\scripts\it-operations\performance\Set-WorkstationPerformance.ps1
```

> **Folder note:** this repo has two `windows-hardening` folders that cover different scopes.
> `scripts\windows-hardening\` contains system-level hardening (TLS cipher policy, Windows 11
> privacy/telemetry, AppX bloatware removal) and is typically run once at build or provisioning time.
> `scripts\it-operations\windows-hardening\` contains operator posture scripts (idle-lock, sleep)
> that are run and rolled back as workload needs change.

Report OS support lifecycle and how long each machine has left:

```powershell
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1 -WarnWithinDays 365
```

Check Windows 11 hardware eligibility and name the blocker on each machine:

```powershell
pwsh -File .\scripts\it-operations\lifecycle\Test-Windows11UpgradeReadiness.ps1
```

Find out why a machine is not patching (services, pending reboot, policy, history):

```powershell
pwsh -File .\scripts\it-operations\lifecycle\Export-WindowsUpdateHealth.ps1
```

Report BitLocker protection and whether the recovery key is escrowed anywhere:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1 -VerifyAdEscrow
```

Report local administrator membership and whether LAPS manages the password:

```powershell
pwsh -File .\scripts\it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1
```

Inventory certificate expiry across machine stores, IIS bindings, and live endpoints:

```powershell
pwsh -File .\scripts\certificates\Export-CertificateExpiryInventory.ps1 -IncludeIisBindings -Endpoint 'www.example.com:443'
pwsh -File .\scripts\certificates\Export-CertificateExpiryInventory.ps1 -ComputerName srv01,srv02 -IncludeIisBindings
```

Run all disk maintenance steps on drive D (chkdsk, cipher wipe, defrag, benchmark):

```powershell
pwsh -File .\scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1 -Drive D
```

Run disk maintenance skipping the cipher wipe (which can take hours on large drives):

```powershell
pwsh -File .\scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1 -Drive C -SkipCipherWipe
```

Compare two folder trees by BLAKE3 content hash with optional SHA-256 verification:

```powershell
python .\scripts\utilities\compare_folders.py --folder-a D:\Source --folder-b E:\Backup --label-a source --label-b backup --sha256
```

Split a single Thunderbird MBOX file into numbered .eml chunk folders:

```powershell
python .\scripts\email\thunderbird\extract_mbox_chunks.py --mbox "$env:APPDATA\Thunderbird\Profiles\<profile>\Mail\Local Folders\Inbox" --output-dir "C:\Code_data\ops-toolkit\thunderbird-extract\Inbox"
```

Batch-extract every MBOX in a Thunderbird profile directory:

```powershell
python .\scripts\email\thunderbird\extract_all_mboxes.py --source-dir "$env:APPDATA\Thunderbird\Profiles\<profile>\Mail\Local Folders" --output-root "C:\Code_data\ops-toolkit\thunderbird-extract"
```

Parse .eml files from a thunderbird-extract directory and write structured Parquet files:

```powershell
python .\scripts\email\thunderbird\export_emails_to_parquet.py --source-dir "C:\Code_data\ops-toolkit\thunderbird-extract" --output-dir "C:\Code_data\ops-toolkit\thunderbird-extract\parquet"
```

## Updated Scripts

| Script                                                                     | Update                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts\azure\Export-AzNetworkInventory.ps1`                              | Expanded reporting-only Azure network inventory for NSGs, rules, VNets, subnets, NICs, public IPs, optional VMs, CSV/JSON exports, and run summaries.                                                                                                                                                                                         |
| `scripts\azure\Initialize-AzPowerShellSession.ps1`                         | Hardened Az session bootstrap with explicit tenant/subscription/environment options, optional module install, context selection, and session reports.                                                                                                                                                                                         |
| `scripts\azure\Import-AzureVpnClientXmlProfile.ps1`                        | Hardened Windows 11 Azure VPN Client XML import with XML validation, optional profile backup, `-WhatIf`, and plan/state reports.                                                                                                                                                                                                              |
| `scripts\azure\New-AzFileShareMappedDrive.ps1`                             | Hardened Azure Files mapped-drive workflow with map/remove modes, credential cleanup, `-WhatIf`, plan/state reports, and no storage-key report writes.                                                                                                                                                                                        |
| `scripts\azure\New-AzKeyVaultServicePrincipal.ps1`                         | Rebuilt Key Vault service-principal creation with Az cmdlets, reuse mode, `-WhatIf`, plan/state reports, rollback guidance, and no secret writes to reports.                                                                                                                                                                                  |
| `scripts\azure\Set-AzAppGatewayTlsPolicy.ps1`                              | Combined hardened and predefined Application Gateway TLS policy updates with mode selection, `-WhatIf`, plan/state reports, and rollback guidance.                                                                                                                                                                                            |
| `scripts\active-directory\Disable-AdStaleComputerAccountsAndMoveToOu.ps1`  | Rebuilt stale-computer disable/move workflow with explicit action modes, plan/state/rollback reports, scoped AD filters, optional email, and `-WhatIf`.                                                                                                                                                                                       |
| `scripts\active-directory\Send-AdSecurityEmailReport.ps1`                  | Combined privileged-group and password-never-expires AD security reports with HTML/CSV/JSON output and optional email.                                                                                                                                                                                                                        |
| `scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1`         | Rebuilt password-expiry reminders with HTML/CSV/JSON output, email plan/state reports, `-WhatIf`, and explicit send switches.                                                                                                                                                                                                                 |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | Combined AD user attribute and distinguished-name exports into one report-driven inventory command.                                                                                                                                                                                                                                           |
| `scripts\active-directory\Set-AdUserUpnSuffix.ps1`                         | Combined mailbox-enabled and OU-scoped AD user UPN suffix updates with `-WhatIf`, plan/state reports, and explicit scope controls.                                                                                                                                                                                                            |
| `scripts\iis\Set-IisSiteCustomHeader.ps1`                                  | Renamed and hardened single-site IIS custom header updates with safer preview and summary output.                                                                                                                                                                                                                                             |
| `scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1`                       | Renamed and hardened all-site IIS custom header updates with safer preview and summary output.                                                                                                                                                                                                                                                |
| `scripts\iis\Set-IisSiteDefaultCustomLogFields.ps1`                        | Renamed and hardened IIS site-default custom log field updates with duplicate detection and summaries.                                                                                                                                                                                                                                        |
| `scripts\iis\Set-IisRecommendedSecurityHeaders.ps1`                        | Hardened the IIS security header preset with validation, replacement review reports, and summary output.                                                                                                                                                                                                                                      |
| `scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1`  | Hardened Exchange Online distribution group usage reporting with `Get-MessageTraceV2`, 10-day query windows, continuation keys, CSV/JSON outputs, and summaries.                                                                                                                                                                              |
| `scripts\utilities\Join-ApplicationsWithEndpointSites.ps1`                 | Rebuilt CSV join utility with configurable join columns, case handling, matched/unmatched reports, duplicate-key summaries, and output paths under reports.                                                                                                                                                                                   |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | Combined Windows printer add/remove helpers into one report-first command with data-file input and `-WhatIf`.                                                                                                                                                                                                                                 |
| `scripts\it-operations\utilities\Get-CurrentUserContext.ps1`               | Rebuilt current-user context reporting with optional group expansion and JSON/CSV outputs.                                                                                                                                                                                                                                                    |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | Combined temp cleanup and stale-file cleanup with guarded paths, plan/state reports, and `-WhatIf`.                                                                                                                                                                                                                                           |
| `scripts\pentesting\Install-AutoReconDependencies.sh`                      | Rebuilt AutoRecon lab installer with `--dry-run`, package-group switches, Debian-family guardrails, pipx install flow, and safer shell behavior.                                                                                                                                                                                              |
| `scripts\windows-hardening\Set-WindowsSchannelTlsHardening.ps1`            | Renamed and rebuilt Schannel TLS hardening with `-WhatIf`, plan reports, registry backups, and summaries.                                                                                                                                                                                                                                     |
| `scripts\windows-hardening\Set-Windows11PrivacyHardening.ps1`              | Renamed and rebuilt Windows 11 privacy/AI hardening with `-WhatIf`, rollback, plan/state reports, registry backups, and summaries.                                                                                                                                                                                                            |
| `scripts\windows-hardening\Remove-WindowsProvisionedBloatwareApps.ps1`     | Rebuilt Windows 11 AppX bloatware removal with clean data lists, `-WhatIf`, rollback guidance, inventory/plan/state reports, and protected package enforcement.                                                                                                                                                                               |
| `scripts\it-operations\utilities\Invoke-DiskMaintenance.ps1`               | New script consolidating chkdsk, cipher free-space wipe, defrag/optimize, and a 10 MB write/read benchmark into one parameterised command with individual skip switches.                                                                                                                                                                      |
| `scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1`   | New script reclaiming pip cache, Docker build cache and dangling images, Recycle Bin, WinSxS component store, and optional Windows Update cache, with `-WhatIf`, target selection, admin gating, and plan/state reports.                                                                                                                      |
| `scripts\it-operations\performance\Set-WorkstationPerformance.ps1`         | New script setting workstation performance posture (Ultimate/High Performance power plan plus opt-in Defender path/process exclusions) with `-WhatIf`, `-Rollback`, admin gating, and plan/state/rollback reports.                                                                                                                            |
| `scripts\it-operations\windows-hardening\Set-WorkstationLockPosture.ps1`   | New script setting workstation idle-lock and sleep posture (never sleep/hibernate on AC, screensaver lock) with `-WhatIf`, `-Rollback`, optional elevated ConsoleLock and machine-wide inactivity lock.                                                                                                                                       |
| `scripts\entra\Export-EntraAppCredentialExpiry.ps1`                        | New report-only Entra ID credential expiry export covering app registration and service principal secrets and certificates, with optional owner lookup and a sign-in match that says whether an expiring credential is still in use.                                                                                                          |
| `scripts\logging\Export-EndpointTelemetryPosture.ps1`                      | New read-only collector reporting whether PowerShell script-block logging, command-line process auditing, the required audit subcategories, Sysmon, and event forwarding are switched on, plus the measured retention of each security channel taken from its oldest surviving record. Feeds controls LOG-01 and LOG-02 in the evidence pack. |
| `scripts\reporting\Export-SecurityControlEvidencePack.ps1`                 | Added controls LOG-01 and LOG-02, covering whether security-relevant activity is logged and whether it is retained long enough to investigate an incident found late.                                                                                                                                                                         |
| `scripts\utilities\Find-LegacyApiUsage.ps1`                                | New read-only scanner for retired and soon-to-be-retired Microsoft APIs (MSOnline, AzureAD, AzureRM, ADAL, EWS, Exchange Online `-Credential`, Application Impersonation, Get-MessageTrace, Send-MailMessage), reporting deadline, replacement, and whether the hit is in a comment.                                                          |
| `scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1`              | New read-only AD audit covering AS-REP roastable and Kerberoastable accounts, all four delegation types, PASSWD_NOTREQD, reversible encryption, orphaned adminCount, krbtgt password age, and nested tier-0 membership resolved by well-known SID.                                                                                            |
| `scripts\utilities\compare_folders.py`                                     | New bidirectional BLAKE3 folder comparison with multiprocessing, four CSV/text output sets, and an optional SHA-256 verification pass.                                                                                                                                                                                                        |
| `scripts\email\thunderbird\extract_mbox_chunks.py`                         | New Stage 1 of the Thunderbird pipeline: splits a single MBOX into numbered .eml chunk folders with per-run progress and error logs.                                                                                                                                                                                                          |
| `scripts\email\thunderbird\extract_all_mboxes.py`                          | New Stage 2 of the Thunderbird pipeline: batch wrapper that walks a Thunderbird profile directory and calls the Stage 1 chunker on every MBOX found.                                                                                                                                                                                          |
| `scripts\email\thunderbird\export_emails_to_parquet.py`                    | New Stage 3 of the Thunderbird pipeline: parses .eml files with multiprocessing and streams structured data to batched Parquet files.                                                                                                                                                                                                         |

## Modernized Legacy Scripts

The remaining VBScript/CMD entry points were replaced with PowerShell equivalents and the originals were moved to `archive\legacy-scripts\retired-2026-05-04\`.

| Replacement                                                                | Replaces                                     |
| -------------------------------------------------------------------------- | -------------------------------------------- |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | `Export-AdUserAttributesToExcel.vbs`         |
| `scripts\active-directory\Export-AdUserInventory.ps1`                      | `Export-AdUserDistinguishedNamesToExcel.vbs` |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | `Add-LegacyPrinterConnections.vbs`           |
| `scripts\it-operations\printers\Set-WindowsPrinterConnections.ps1`         | `Remove-LegacyPrinterConnection.vbs`         |
| `scripts\it-operations\utilities\Get-CurrentUserContext.ps1`               | `Show-CurrentUser.vbs`                       |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | `Clear-UserAndDriveTempFolders.vbs`          |
| `scripts\it-operations\windows-file-cleanup\Invoke-WindowsFileCleanup.ps1` | `Remove-OldFilesRecursively.vbs`             |

## Script Header Standard

Every kept script should start with instructions in the native comment format for its language:

- PowerShell: comment-based help using only keywords PowerShell recognizes, so
  `Get-Help <script> -Full` works. Use `.SYNOPSIS`, then `.DESCRIPTION` carrying the
  `Instructions:`, `Purpose:`, and `Required syntax:` sections as plain labelled
  text, then `.OUTPUTS`, then `.NOTES` carrying `Status:`.
- Bash: shebang first, then an `# Instructions` block.
- Batch/CMD: `REM Instructions` block.
- VBScript: `' Instructions` block.

The header should tell the operator to read this README, review parameters or variables, run with admin rights only when needed, use `-WhatIf` when supported, and note whether the script is active, lab-only, or legacy keep.

Do not invent new dotted keywords. PowerShell accepts only a fixed set, and a single unrecognized keyword such as `.INSTRUCTIONS` silently invalidates the entire help block, leaving `Get-Help` with nothing but auto-generated syntax. Custom sections belong inside `.DESCRIPTION` or `.NOTES` as labelled text. Verify with:

```powershell
Get-ChildItem .\scripts -Filter *.ps1 -Recurse | ForEach-Object { (Get-Help $_.FullName).Synopsis }
```

Any script whose synopsis comes back as its own filename followed by a parameter list has a broken help block.

## Script Standards

- Prefer PowerShell 7.4+ and current modules for new work; keep Windows PowerShell 5.1 compatibility only where the target platform requires it.
- Use `Az` cmdlets for Azure PowerShell. Do not add new `AzureRM` automation.
- New or updated PowerShell scripts should use `[CmdletBinding()]`, named parameters, explicit output paths, and `Set-StrictMode -Version 3.0` where compatible.
- State-changing scripts should support `-WhatIf` and `-Confirm` through `SupportsShouldProcess`.
- Do not use interactive menus or mandatory prompts for automation. If required arguments are missing, print usage and exit with code `2`.
- Avoid hard-coded customer domains, email addresses, tenant IDs, subscription IDs, storage keys, and local output paths. Pass them as parameters.
- Use `PSScriptAnalyzerSettings.psd1` when linting PowerShell scripts.
- Treat VBScript/CMD as archived reference only. Active automation should be PowerShell unless a target system requires another shell.
- Put generated reports under `reports\`; do not commit generated output.
- Write reports through `modules\OpsToolkit.Reporting` rather than with a local copy
  of the same helpers. Every script writes to a timestamped run directory named
  `<prefix>-yyyyMMdd_HHmmss`, containing one CSV and one JSON per report plus a
  `summary.json`. That layout is what `Compare-OpsToolkitRun.ps1` needs in order to
  diff one run against the previous one; a script writing loose timestamped files
  cannot be compared at all.

## Validation

Run the suite before every commit that touches a script, and before any push:

```powershell
pwsh -File .\Invoke-RepoValidation.ps1
pwsh -File .\Invoke-RepoValidation.ps1 -Strict -OutputDirectory .\reports\validation
```

It runs seven gates:

- Parser check across every `.ps1` and `.psm1`.
- Full PSScriptAnalyzer rule pass against `PSScriptAnalyzerSettings.psd1`.
- Comment-based help check, because a non-standard keyword silently disables
  `Get-Help` and nothing else catches it.
- Bash syntax check for the lab and pentesting shell scripts.
- Stale-reference search: every script path named in a Markdown file must exist.
- Module manifest check: every manifest loads and exports what it declares.
- Pester tests under `tests\`, run in a child process so the Pester version cannot
  collide with whatever the caller already has loaded. Requires Pester 5 or later;
  the Pester 3.4 that ships with Windows cannot run these specs, and its absence is
  reported as a missing tool rather than as a pass. The suite has two layers: unit
  specs over the decision logic, and integration specs that run whole scripts end to
  end against stubbed back ends, including the Graph, Exchange and Active Directory
  scripts that cannot reach a live system from a build workstation. See
  [tests/README.md](tests/README.md).

Exit code 0 means the gates passed, 1 means a gate failed, 2 means a required tool
is missing. Analyzer warnings do not fail the run unless `-Strict` is used.
