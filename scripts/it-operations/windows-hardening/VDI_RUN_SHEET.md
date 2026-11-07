# Windows hardening: VDI test host run sheet

Checklist for the first real run of the windows-hardening scripts (`hard-elevated-run`) on a disposable Azure Virtual Desktop session host, listing every fact the scripts rely on that has only been tested against fakes.

## Before you start

- Use a session host you can delete and rebuild. Never a production host, never a physical laptop that matters. Take a snapshot or confirm the host pool can redeploy it.
- Run from an elevated PowerShell 7.4 or later on the host, from a copy of the repository with `scripts\` and `modules\` side by side (the scripts import `..\..\..\modules`).
- Record the build (`winver`), edition, join state (`dsregcmd /status`) and whether Intune manages the host at the top of your notes.
- Put the org settings file in place first if you are testing off-host forwarding and key backup: `%ProgramData%\OpsToolkit\settings.json` (schema in `modules\OpsToolkit.Hardening`, `Get-OpsOrgSettings`).
- For every script: run `-WhatIf` first, read the plan, then run it for real, then run `Test-WindowsHardeningState.ps1`, then `-Rollback`, then the checker again. Keep every run directory.
- Mark each fact below Confirmed, Wrong (write what you saw) or Not tested. A Wrong fact is a bug to file against the script named, not something to fix on the host.

## 1. Elevated test halves

1. On the host, from the repo root, run `Invoke-Pester -Path .\tests\Integration.StateChanging.Hardening*.Tests.ps1 -Output Detailed` elevated. These still use fakes; the point is that the elevated `It` blocks, skipped on every run so far, now run. Expect 0 failed.
2. Then `pwsh -NoProfile -Command "& .\Invoke-RepoValidation.ps1 -Gate Test,MachineState"`. MachineState must report no drift; drift means a test touched the real host.

## 2. Host detection (`modules\OpsToolkit.Hardening`, items 1 to 7 of its header)

| # | Fact | How to check | Result |
| - | ---- | ------------ | ------ |
| 2.1 | `dsregcmd /status` prints `AzureAdJoined : YES/NO`, `DomainJoined : YES/NO`, `WorkplaceJoined : YES/NO` with English key names on this build and display language. | Run it; also on a host with a non-English display language if the estate has one. | |
| 2.2 | AzureAdJoined YES and DomainJoined NO is Entra-only; YES and YES is hybrid; workplace-registered only reads as Workgroup. | Compare `Get-OpsHostContext` JoinType with the host's real join. | |
| 2.3 | `HKLM:\SOFTWARE\Microsoft\RDInfraAgent` exists on a session host (and on a Windows 365 Cloud PC), not on a physical machine. | `Test-Path` on the session host and on a physical machine. | |
| 2.4 | The `RDAgentBootLoader` service exists on a session host only. | `Get-Service RDAgentBootLoader` on both. | |
| 2.5 | An Intune-enrolled device has an `HKLM:\SOFTWARE\Microsoft\Enrollments` subkey with ProviderID `MS DM Server`; a stale enrollment keeps it. | Read the key; compare with the device in Intune. | |
| 2.6 | `Win32_ComputerSystem` Manufacturer/Model name the hypervisor (Azure reads `Microsoft Corporation` / `Virtual Machine`). | `Get-CimInstance Win32_ComputerSystem`. | |
| 2.7 | `dsregcmd /status` returns promptly and exits 0. | Time it; check `$LASTEXITCODE`. | |

## 3. Session host behaviour (B1)

| # | Fact | How to check | Result |
| - | ---- | ------------ | ------ |
| 3.1 | `Set-WindowsRemoteAccessPosture.ps1 -DisableRemoteDesktop` is skipped on the session host and RDP still works afterwards. | Run it with the switch; connect a user session after. | |
| 3.2 | `Set-WindowsLocalAccountPolicy.ps1` reports Administrator Protection as unwanted and writes nothing for it. | Read the plan; diff the UAC keys before and after. | |
| 3.3 | `Set-WindowsFirewallBaseline.ps1` profile defaults leave Remote Desktop and the AVD agent working; the skipped inbound controls are skipped. | Run it; reconnect a session; check the host is Available in the host pool. | |
| 3.4 | The NTLM audit values (`AuditReceivingNTLMTraffic = 2`, `RestrictSendingNTLMTraffic = 1`) produce events in `Microsoft-Windows-NTLM/Operational` in its default state. | Run `Set-WindowsNetworkProtocolHardening.ps1`; force an NTLM logon (for example a share by IP); read the log. | |
| 3.5 | `-RestrictOutgoingNtlm` is refused on the session host. Do not override it. | Read the plan. | |
| 3.6 | The policy override note appears on a joined or MDM-managed host, and a later Intune/GPO sync does or does not overwrite the local writes. | Run, force a sync (Settings, Accounts, Access work or school, Info, Sync; or `gpupdate /force` on a domain host), run the checker again. | |

## 4. LSA protection preflight (B3, `Set-WindowsCredentialProtection.ps1`)

| # | Fact | How to check | Result |
| - | ---- | ------------ | ------ |
| 4.1 | `Authentication Packages`, `Notification Packages`, `Security Packages` under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, and `Security Packages` under `Lsa\OSConfig`, are the lists lsass loads; a bare name means `System32\<name>.dll`. | Compare the preflight list with the modules loaded in lsass (Process Explorer or `tasklist /m /fi "imagename eq lsass.exe"`). | |
| 4.2 | The Winsock name-space catalog is `Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries64` (native) and `Catalog_Entries` (32-bit), DLL in `LibraryPath`, and lsass loads those providers. | Install a known third-party NSP (Bonjour) on the test host, enable RunAsPPL, restart, check events 3033/3063. | |
| 4.3 | A third-party signature is not enough; a Microsoft-cosigned (WHQL) module counts as Microsoft only when signer subject and issuer both name Microsoft Corporation, matching the loader's check. | Same event check with a WHQL-signed third-party module. | |
| 4.4 | `Get-AuthenticodeSignature` reports the Microsoft signer for in-box catalog-signed DLLs. | Run it on `msv1_0.dll`, `kerberos.dll`. | |
| 4.5 | Packages loaded another way (SSP added by API, smart card or credential provider DLLs) are not listed, so a short report is not proof nothing is blocked. | After enabling, read `Microsoft-Windows-CodeIntegrity/Operational` 3033/3063 for anything not in the preflight. | |
| 4.6 | The Winsock entry's `Enabled` value is not read; a disabled provider is still listed. | Note any listed provider that is disabled. | |

## 5. Defender, credentials, protocols, exploit and audit (FUTURE_FEATURES.md "Ingested 2026-10-29")

| # | Fact | Result |
| - | ---- | ------ |
| 5.1 | `Add-MpPreference` adds one ASR rule id and action without disturbing the other rules. | |
| 5.2 | Smart App Control `VerifiedAndReputablePolicyState` values read as reported. | |
| 5.3 | `Dnscache` `EnableMDNS` turns off the mDNS responder. | |
| 5.4 | The text a missing optional feature returns from `Get-WindowsOptionalFeature`. | |
| 5.5 | The nested HVCI key path for memory integrity. | |
| 5.6 | The object shapes `Get-ProcessMitigation -System` returns. | |
| 5.7 | Module Logging's `*` value name under `ModuleNames`. | |
| 5.8 | Office Click-to-Run detection through the 16.0 install roots. | |
| 5.9 | `auditpol` current-setting parsing, which matches English words only. | |
| 5.10 | `Get-WindowsOptionalFeature -Online -FeatureName` accepts wildcards the way the fake does. | |
| 5.11 | `Get-ProcessMitigation -Name <exe>` returns a NOTSET object for a process with no override, as the fake does. | |

## 6. Remote access, accounts and firewall

| # | Fact | Result |
| - | ---- | ------ |
| 6.1 | The WinRM listener registry path read for the report-only row. | |
| 6.2 | `AllowInboundRules False` on the local persistent store is accepted by the real NetSecurity cmdlets. | |
| 6.3 | Application filter binding when a program rule's path is missing. | |
| 6.4 | `netsh advfirewall export` fails unelevated (treated as a warning). | |

## 7. BitLocker and WDAC

| # | Fact | Result |
| - | ---- | ------ |
| 7.1 | The JSON shape `CiTool --list-policies --json` returns; whether `--update-policy` and `--remove-policy` also answer in JSON; which GUID form, braced or bare, each accepts. | |
| 7.2 | `Set-CIPolicyIdInfo -ResetPolicyID` gives the base and policy IDs the script expects. | |
| 7.3 | The Code Integrity event field names `Export-WdacAuditEvent.ps1` reads for 3076, 3077 and 3089. | |
| 7.4 | The ConfigCI module loads under PowerShell 7. | |
| 7.5 | `Add-BitLockerKeyProtector` works on a fully decrypted volume. | |
| 7.6 | The restart the BitLocker hardware test needs, and the volume state until then. | |
| 7.7 | Whether removing a WDAC policy with CiTool needs a restart. | |
| 7.8 | The `HvciOptions` value in the in-box example policies on current builds, and `Set-RuleOption -Option 6` taking on them. | |
| 7.9 | Whether `Get-BitLockerVolume` needs elevation (the script assumes it does). | |
| 7.10 | FVE startup-authentication value codes written by `-UseTpmAndPin` under `HKLM:\SOFTWARE\Policies\Microsoft\FVE` (`UseAdvancedStartup` 1, `EnableBDEWithNoTPM` 0, `UseTPM` 0, `UseTPMPIN` 1, `UseTPMKey` 0, `UseTPMKeyPIN` 0) mean "require TPM and PIN". On a VM the PIN path is refused; check the codes on a physical test machine only. | |
| 7.11 | WDAC enforce (`Set-WdacEnforcedPolicy.ps1`): `New-CIPolicy` builds rules from the audit events as expected; `CiTool --update-policy` of the supplemental then the enforced base leaves the host bootable and signed-in users working; `-Rollback` returns it to audit. Do this last, on a host you will delete. | |
| 7.12 | The Administrator Protection registry value behind CSP `LocalPoliciesSecurityOptions/UserAccountControl_TypeOfAdminApprovalMode` (undocumented). Read-only: note what the setting writes on a non-session-host test machine; never enable it on a session host. | |

## 8. Org settings and off-host (B2)

Put a test `settings.json` in place first (WEF to a test collector, or a Share, and a key backup type the host can use). Use a test collector and a test Entra or AD object, never production escrow you cannot clean up.

| # | Fact | How to check | Result |
| - | ---- | ------------ | ------ |
| 8.1 | The source-initiated WEF policy value is `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`, value name `1`, REG_SZ, holding the `Server=...` string. | Run `Set-WindowsAuditLogging.ps1` with a WEF setting; compare with what the GPO "Configure target Subscription Manager" writes; confirm the host appears on the collector. | |
| 8.2 | NETWORK SERVICE is `S-1-5-20` and Event Log Readers is `S-1-5-32-573`; `Add-LocalGroupMember`/`Remove-LocalGroupMember` accept the SID string for `-Member`; `Get-LocalGroupMember -SID S-1-5-32-573` lists members as the script reads them. | Run, then `Get-LocalGroupMember -SID S-1-5-32-573`; run `-Rollback` and check it is gone only if the run added it. | |
| 8.3 | WinRM running is enough for forwarded Security log events to arrive at the collector. | Generate a 4688 or logon event and look for it on the collector. | |
| 8.4 | The Azure Monitor Agent service name is `AzureMonitorAgent`. | `Get-Service` on a host with the agent installed. | |
| 8.5 | `BackupToAAD-BitLockerKeyProtector -MountPoint -KeyProtectorId` escrows to Entra ID on an Entra or hybrid joined host and throws on failure. | Physical or VM test machine with a test device object; check the key in the Entra device record. | |
| 8.6 | `Backup-BitLockerKeyProtector -MountPoint -KeyProtectorId` escrows to AD on a domain-joined host and throws on failure. | Domain test machine; read `msFVE-RecoveryInformation` under the computer object. | |
| 8.7 | A real Entra or domain join reads in `dsregcmd /status` the way the stand-in does (see 2.1, 2.2). | Compare `Get-OpsHostContext` with the real join. | |
| 8.8 | A failed escrow (for example no network) stops the run before `Enable-BitLocker` and removes the protector it added. | Block the network, run, check `Get-BitLockerVolume` shows no new protector and the volume still decrypted. | |
| 8.9 | The fakes assume an unknown group makes `Get-LocalGroupMember` throw and `-Member` filters by name, wildcard or SID. | Try both on the host. | |

## 9. Unelevated preview and confirmation (B4)

| # | Fact | How to check | Result |
| - | ---- | ------------ | ------ |
| 9.1 | A live elevated run without `-Confirm:$false` prompts once per change, and "Yes to All" applies the rest without further prompts. | Run one script (for example `Set-WindowsAuditLogging.ps1`) elevated without `-Confirm:$false`; answer No to the first prompt and check that item is not changed; rerun and answer Yes to All. | |
| 9.2 | An unelevated `-WhatIf` previews each item it could read ("What if:" line, result `Previewed`) and marks the rest `Skipped: requires elevation (not read)`; nothing changes. | Run each script unelevated with `-WhatIf`; compare the plan with an elevated `-WhatIf`; run `Test-WindowsHardeningState.ps1` and check MachineState shows no change. | |
| 9.3 | An unelevated live run changes nothing and marks each admin item `Skipped: requires elevation`. | Run one script unelevated without `-WhatIf`. | |
| 9.4 | Unelevated `Get-MpPreference` hides exclusions, so `Set-WorkstationPerformance.ps1` now shows the Defender exclusion rows as unread rather than absent. | Run it unelevated with `-WhatIf`; compare with `Get-MpPreference` elevated. | |
| 9.5 | Unelevated `Get-BitLockerVolume` fails, and the BitLocker plan marks those rows not read. | Run `Enable-BitLockerOsVolume.ps1 -WhatIf` unelevated. | |

## After the run

- File every Wrong result as a bug in the ops-toolkit repo with the run directory attached (no recovery keys).
- Delete or rebuild the session host.
