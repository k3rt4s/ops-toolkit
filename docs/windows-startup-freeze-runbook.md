# Windows startup-load and freeze evaluation runbook

Run prompt for an AI coding session that works out why a Windows 11 laptop freezes and crawls after startup, trims the startup load, and stages the elevated fixes and driver repairs for the administrator to run.

Paste everything below the line into a fresh session on the target machine, replacing `<MACHINE>` with its hostname. The first run was on 2026-11-16 and 11-17; the method, the decisions already taken and the pitfalls found there are baked in so a repeat does not rediscover them.

---

## Run prompt: startup-load and freeze evaluation on `<MACHINE>`

Mode: attended

You are working on the laptop named `<MACHINE>`. If a workspace framework playbook exists on this machine (for example `C:\Code\ai_development\PLAYBOOK.md` with its `profile.local.md`), read it and follow it. Otherwise work standalone with these rules: decisions go through the interactive question tool with a recommended option first, nothing is committed or pushed without being asked, generated files go under the data root (`C:\Code_data\workspace\startup_trim\` unless a profile names another), and the response style is short plain prose, no bold, no italics, commas instead of dashes.

### Task

The developer's words: "We have way too many items running after startup. Even the little things. Please check and evaluate why the computer halts to a stop regularly. In detail. Even the small items."

Deliver, in this order:

1. A written report `REPORT_<date>.md` in the data folder: freeze history with evidence, startup inventory, what changed, what is pending elevation, rollback.
2. A user-scope trim script, run in the session.
3. An elevated script `fix_admin.ps1` that the developer runs from an administrator PowerShell, with a per-change DONE, SKIP or FAIL line, a backup JSON of every prior value, a log, and the manual driver steps printed at the end.
4. Driver repair steps specific to this machine's hardware, with version numbers read from the machine and the vendor's support page URL for the exact model.
5. An ACTION FOR THE DEVELOPER message with numbered steps and the exact elevated command.

### Decisions already taken on the first run, apply them without re-asking

- Crash fix approach: drivers plus standby settings first. No hardware swaps proposed before that.
- Laptop-vendor bloat services (the maker's center, foundation, SCM and telemetry services, Macrium, Bonjour, Xbox GamingServices and GamingServicesNet, GameInput, audio-vendor services, peripheral updaters, Adobe ARM) go to Manual. Wi-Fi vendor "suite" services (Killer and the like) go to Disabled; the Wi-Fi driver itself stays.
- Cloud and media apps (Webex, Cloudflare WARP, Photoshop Express, OpenAI Codex, the OneDrive logon task, Discord, Signal, Steam, Docker Desktop, Teams, Spotify, game launchers) are disabled at startup.
- Updaters and Office logon tasks (Office Feature Updates Logon, Office Feature Updates C2R Client Logon, Office Startup Maintenance, Office Background Push Maintenance, Adobe, Google and Brave update tasks, MSI Afterburner) are disabled. Office Automatic Updates 2.0 and Office Actions Server stay.
- Apps the developer keeps at startup: iCloud and TeamViewer. Do not touch them.
- Fast Startup off (HiberbootEnabled 0), AlwaysKeepMemoryDump 1, Storage Sense temp-file cleanup off (it deletes minidumps), battery sleep 30 min, AC sleep Never, unattended sleep Never, USB selective suspend off on AC and battery, WinDbg installed.
- An external drive that hosts a sync client's root, a mail bridge cache, Docker, Ollama or backups stays where it is. The fix is the USB port behaviour (selective suspend off, the drive out of Windows Search indexing), not a move.

Ask the developer only about things that differ on this machine: a vendor or app not in the lists above, an external drive with a different role, any decision whose answer would change what you do.

### Method, in order

1. Freeze history, 60 days back. `Get-WinEvent` on System for Kernel-Power 41 (read BugcheckCode and LongPowerButtonPressDetected from the event XML), Kernel-Power 506 and 507 (Modern Standby entry and exit), disk 153 and 157 (surprise removal); Application for WER 1001 (BlueScreen codes such as 0x133 DPC_WATCHDOG and 0x116 VIDEO_TDR_FAILURE, and LiveKernelEvent codes such as 141 for GPU hangs), ESENT 533 (HUNGIO, an NVMe I/O stall), and Event 1000 crashes at boot. Build a table: when, evidence, reading. Check `C:\Windows\Minidump` and `C:\Windows\MEMORY.DMP`; a 1001 event naming a dump that no longer exists points at Storage Sense.
2. Startup surfaces, all of them: HKCU and HKLM Run and RunOnce; StartupApproved bytes (first byte 02 enabled, 03 disabled) under `Explorer\StartupApproved\Run` and `StartupFolder`; both Startup folders; Store app StartupTask State under `HKCU\...\CurrentVersion\Explorer\... SystemAppData\*\*` (State 2 enabled, 1 disabled); scheduled tasks with logon or boot triggers (`Get-ScheduledTask | Where-Object { $_.Triggers.CimClass.CimClassName -match 'Logon|Boot' }`); services set to Automatic and Automatic (Delayed Start); the live process list at 5 and 20 minutes after boot with private bytes, page faults per second, processor queue length and commit charge from `Get-Counter`. Write large outputs to files and read the files, the tool output truncates at 30k characters.
3. Power. `powercfg /a`; `powercfg /q` for standby timeouts, unattended sleep and USB selective suspend (subgroup `2a737441-1930-4402-8d77-b2bebba308a3`, setting `48e6b7a6-50f5-4782-a5d4-53bb8f07e226`); HiberbootEnabled under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power`; AlwaysKeepMemoryDump under `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`; Storage Sense value 04 under `HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy`.
4. Drivers. `Get-CimInstance Win32_PnPSignedDriver` for storage (RST, VMD, NVMe), Wi-Fi, Bluetooth, integrated and discrete graphics and chipset, with DriverVersion and DriverDate; `Win32_BIOS` for the BIOS version and date; `Win32_ComputerSystem` for maker and model. Anything older than two years on the crash path is a candidate. Name the vendor support page URL for the exact model and the Intel Driver and Support Assistant (`winget install Intel.IntelDriverAndSupportAssistant`) or the AMD equivalent. A storage driver on a machine that boots through VMD must come from the laptop vendor's package, not the generic Intel one. If the WebFetch hook blocks a vendor domain, say so and give the developer the escape line (`WebFetch(domain:<host>)` in `permissions.allow`); do not work around it.
5. External drives. `Get-Disk` and `Get-Volume` with bus type (UAS); what lives on each drive (sync roots, mail bridge cache, Docker, Ollama, backups, scratch); the Windows Search crawl scope under `HKLM\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager`; the Defender scan schedule. Never run a recursive file count over a USB drive; the first run froze the machine under exactly that load. Use `Get-Volume` sizes or the sync client's own counts.
6. Scheduled tasks the developer owns. For each with a non-zero LastTaskResult read its latest log, root-cause it, fix only tasks owned by a repo this session is assigned to, and record findings for other projects with the owning board named.

### Pitfalls from the first run

- Windows PowerShell 5.1 with `$ErrorActionPreference = "Stop"` turns a native command's redirected stderr (`2>$null` or `2>&1`) into a terminating RemoteException. Redirect inside cmd (`2>nul`) or test the exact pattern in `powershell.exe` before trusting a scheduled script.
- Protected services (GamingServices, GamingServicesNet) refuse `Set-Service`; set `Start` to 3 under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` and say "via registry" in the DONE line.
- Some logon tasks (MSI Afterburner on the first run) are access denied in user scope; move them to the admin script rather than failing.
- Storage Sense temp cleanup removes minidumps; turn it off before anything else so the next freeze leaves evidence.
- A canned "user declined" result from a tool is harness boilerplate, never a decision; redirect the output to a file and read it before diagnosing.
- The Store StartupTask registry wildcard needs two levels: `SystemAppData\*\*`.
- `-f` format strings inside a ForEach over `Get-Counter` samples fail; build strings with subexpressions.
- `Add-Content` to a log that another process holds open throws a sharing violation; a script under Stop dies on it. Retry briefly, then fall back to the console.
- A report file that a formatter hook touches must be re-read before every edit.

### Shape of the scripts

Two scripts in the data folder, `trim_user_scope.ps1` and `fix_admin.ps1`. Each change writes its prior value into a `$backup` hashtable saved as `backup_<scope>_<stamp>.json` and logs to `<scope>_<stamp>.log`. `fix_admin.ps1` checks for elevation first and exits with a message if not elevated, then prints the driver steps and ends with "Reboot now (Restart, not Shut down)". Parse-check both with `[System.Management.Automation.Language.Parser]::ParseFile` before offering them. Run the user-scope script yourself; never run the admin one, the developer runs it with:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Code_data\workspace\startup_trim\fix_admin.ps1
```

### Verification after the reboot and the driver updates

```powershell
powercfg /a
Get-WinEvent -LogName System -MaxEvents 200 | Where-Object { $_.Id -in 41,153,157,1000 }
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='ESENT'; Id=533} -MaxEvents 5
```

Empty output from the two event queries is the goal. After any later freeze, `C:\Windows\Minidump` holds the dump and WinDbg reads it.

### Close-out

Report done, pending and blocked with the ACTION FOR THE DEVELOPER steps on top, then put the close-out choice (continue, fresh thread, stop) through the interactive question tool. If the machine has a workspace repo and a framework board, log the work in its CHANGELOG and board any task findings as a Pending item; otherwise the report is the record.
