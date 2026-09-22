# External Security Findings Review Kit

Everything the team needs to check a client's external hosts, produce findings
with remediation steps, and build the evidence for arguing a scanner's rating
down where the evidence actually supports it.

## What is in this folder

- `Test-ExternalSecurityPosture.ps1` — the sweep. Give it a list of hosts and it
  checks all fifteen finding types (HTTP redirect, certificate hostname match,
  open SMTP/SSH, CSP, HSTS, server header, X-Frame-Options,
  X-Content-Type-Options, DMARC, DNSSEC, HSTS preload) and writes two reports: a
  wide per-host evidence table and a long-format findings table with remediation
  text.
- `New-SecurityFindingsRiskContext.ps1` — reads the sweep's output and adds, per
  finding, the concrete evidence for and against arguing a lower risk rating. It
  never changes a severity itself, it only surfaces the facts a human needs to
  make that call.
- `Invoke-SecurityFindingsReview.ps1` — the one script to run. It prompts for a
  host list, then runs the two scripts above in sequence.
- `Test-HstsAndHttpExposure.ps1` and `Test-ClickjackingProtection.ps1` — the two
  standalone checks the sweep script builds on. Use these instead of the sweep
  when you only need one specific check.
- `SecurityFindingsReviewPrompt.md` — a template prompt for an AI assistant that
  turns one scanner finding at a time into an accept/argue decision, an auditor
  reply, and paste-ready tracking-sheet rows. Copy it, fill in the placeholders
  for the client you are working, and keep your filled-in copy out of this
  repository (see Handling client data below).

## Setup

1. Clone or pull this repository.
2. Have PowerShell available (Windows PowerShell 5.1 or PowerShell 7+, both
   work).
3. No install step. The scripts import the shared
   `modules/OpsToolkit.Reporting` module from this repo automatically.

## Step 1: build your host list

Create a plain text file with one host per line, no `http://` or `https://`,
just the hostname (for example `www.example.com`). Blank lines and lines
starting with `#` are ignored, so you can leave yourself notes.

```text
# example.com fleet, from the scanner's asset list
www.example.com
staging.example.com
api.example.com
```

Save it somewhere outside this repository, for example a local working
folder, since a client's real host list is client data and should not be
committed here (see Handling client data below).

## Step 2: run the review

From the repository root in PowerShell:

```powershell
.\scripts\web\Invoke-SecurityFindingsReview.ps1
```

It will prompt for the path to the host list file you built in Step 1. To
skip the prompt, pass the path directly:

```powershell
.\scripts\web\Invoke-SecurityFindingsReview.ps1 -HostFile 'C:\path\to\your\hosts.txt'
```

This writes three reports under `reports\web\` in this repo: the raw evidence,
the findings with remediation, and the risk-context evidence. Read the
findings CSV first, it is the one that maps to a scanner's own report.

## Step 3: use the prompt for each scanner finding

Open `SecurityFindingsReviewPrompt.md`, copy it into a new file outside this
repository, and fill in the placeholders (client name, known facts, asset
groupings, tracking sheet link, and your own writing-style examples) for the
client you are working. Paste your filled-in prompt into your AI assistant
session once, then paste each scanner finding as the assistant asks for it,
along with the matching rows from the findings and risk-context CSVs from
Step 2.

## Handling client data

This repository is public. Never commit a client's real hostnames, IP
addresses, scan findings, tracking-sheet links, or a filled-in copy of
`SecurityFindingsReviewPrompt.md` here. Host list files, filled-in prompts,
and the `reports\web\` output from a real client run all belong in a private
location (a private repo, a private drive folder, or wherever your team
already keeps client-specific work), not in this repository or in a commit to
it.
