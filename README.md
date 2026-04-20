# SecOps

**Location:** `D:\Proton Drive\My files\Code\projects\SecOps\`
**Owner:** k3rt4s
**Purpose:** Security operations scripts for Azure, Active Directory, IIS
configuration, Windows hardening, and general IT administration.
**Last Updated:** 2026-04-19

---

## Contents

| Folder | Purpose |
| -------- | --------- |
| `Azure\` | Azure PowerShell — NSG export, VPN config, Key Vault, App Gateway |
| `IIS Configuration\` | IIS setup scripts |
| `IIS-Headers\` | HTTP security header configuration for IIS |
| `Labs\` | Azure cloud lab instructions, ELK stack lab materials |
| `Misc\` | General utilities — bginfo, dark mode toggle, ping tools |
| `Office365\` | O365 distribution group and UPN management |
| `PenTesting\` | AutoRecon wrapper script |
| `Printers\` | Printer add/remove VBS scripts |
| `Windows Active Directory\` | AD user management, expiring passwords, GPO scripts |
| `Windows File Cleanup\` | File and folder cleanup VBS scripts |
| `Windows Hardening\` | Bloat removal, telemetry disable, cipher suite hardening |

---

## Structure

```text
SecOps\
├── Azure\
├── IIS Configuration\
├── IIS-Headers\
├── Labs\
│   ├── Azure Cloud Labs\
│   └── Elk Lab\
├── Misc\
├── Office365\
├── PenTesting\
├── Printers\
├── Windows Active Directory\
├── Windows File Cleanup\
├── Windows Hardening\
│   └── Archive\
├── CherryTree.ctb
├── File Check.ps1
└── README.md
```

---

## Notes

- Primarily PowerShell and VBScript — no Python dependencies
- Does not use the shared venv
- `CherryTree.ctb` is a CherryTree notes database
- Scripts are generally standalone — check individual files for prerequisites
- `Labs\Elk Lab\` contains full lab documentation (PDF, PPTX, Visio diagrams)
