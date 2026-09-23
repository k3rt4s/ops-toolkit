# External Security Findings Review Kit

Everything the team needs to check a client's external hosts, produce findings
with remediation steps, and build the evidence for arguing a scanner's rating
down where the evidence actually supports it.

## What is in this folder

- `Invoke-SecurityFindingsReview.ps1`: the one script to run. It prompts for a
  host list, then runs the sweep and the risk-context pass in sequence.
- `Test-ExternalSecurityPosture.ps1`: the sweep. It checks fifteen finding types
  (HTTP redirect, certificate hostname match, open SMTP and SSH, CSP missing,
  unsafe CSP, CSP unsafe-eval, HSTS missing, HSTS includeSubDomains, HSTS
  preload, Server header, X-Frame-Options, X-Content-Type-Options, DMARC
  quarantine, and DNSSEC) and writes two reports: a per-host evidence table and a
  findings table with remediation text.
- `New-SecurityFindingsRiskContext.ps1`: reads the sweep's output and adds, per
  finding, a short Flags summary and the concrete evidence for and against
  arguing a lower rating. It never changes a severity itself.
- `Test-HstsAndHttpExposure.ps1` and `Test-ClickjackingProtection.ps1`:
  standalone checks for one question each. Use these instead of the sweep when
  you only need to re-check HSTS/port 80 or clickjacking on a few hosts.
- `OpsWebCommon.ps1`: shared helpers the other scripts dot-source (host-list
  parsing, TCP and HTTP probes, DNS lookups). Not run directly.
- `SecurityFindingsReviewPrompt.md`: a template prompt for an AI assistant that
  turns one scanner finding at a time into an accept-or-argue decision, an
  auditor reply, and paste-ready tracking-sheet rows.

## Which script answers which finding

| Scanner finding | Run | Key evidence columns |
| --- | --- | --- |
| HTTP does not redirect to HTTPS | sweep, or `Test-HstsAndHttpExposure.ps1` | `Port80`, `Http80Status`, `Http80Location` |
| HSTS not enforced / includeSubDomains / preload | sweep, or `Test-HstsAndHttpExposure.ps1` | `Hsts`, `HstsMaxAge`, `Port80`, `ApexPreloadStatus` |
| Hostname does not match SSL certificate | sweep | `CertHostnameMatch`, `CertSubjectAlternativeNames`, `CnameTarget`, `LikelyDead` |
| X-Frame-Options not deny or sameorigin | sweep, or `Test-ClickjackingProtection.ps1` | `XFrameOptions`, `FrameAncestors`, `HasPasswordField`, `AuthRequired` |
| CSP missing, unsafe, or unsafe-eval | sweep | `Csp`, `CspUnsafeSources`, `FinalContentType`, `AuthRequired` |
| X-Content-Type-Options not nosniff | sweep | `XContentTypeOptions`, `FinalContentType` |
| Server information header exposed | sweep | `ServerHeader`, `ServerHeaderHasVersion`, `XPoweredBy` |
| SSH or SMTP port open | sweep (from a cloud VM) | `Port22`, `Port22Banner`, `Port25`, `Port25Banner` |
| DMARC policy is p=quarantine | sweep with `-MailHostFile` | `DmarcRecord`, `DmarcEffectivePolicy`, `DmarcInherited`, `DmarcPct` |
| DNSSEC not enabled | sweep | `ApexDnssecEnabled` |

## Setup

1. Install PowerShell 7.4 or later (`winget install Microsoft.PowerShell` on
   Windows). These scripts do not run in Windows PowerShell 5.1: the shared
   reporting module requires 7.4, and the HTTPS checks rely on .NET features
   that 5.1 does not have. Run them with `pwsh`, not `powershell`.
2. Clone or pull this repository. If you downloaded it as a zip on Windows,
   unblock the files once:

   ```powershell
   Get-ChildItem -Recurse .\scripts\web, .\modules | Unblock-File
   ```

3. If script execution is disabled on your machine, allow it for the current
   session only:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

No install step beyond that. The scripts import the shared
`modules/OpsToolkit.Reporting` module from this repo automatically.

## Where to run it

Run from a cloud VM (any small Linux or Windows VM works), not from the office
network and ideally not from home:

- From inside the client's network, internal DNS and firewall paths can give
  answers the scanner never sees.
- Most residential ISPs block outbound TCP/25, so an SMTP check from home reports
  `Filtered` even when the port is open. The sweep warns when every host shows
  port 25 as filtered.

On Windows, DNS checks use `Resolve-DnsName`. On Linux or macOS, or with
`-UseDnsOverHttps`, they use Cloudflare's public DNS-over-HTTPS API, which sees
only the record names being looked up.

## Step 1: build your host lists

Create a plain text file with one host per line. You can paste the scanner's
asset list as-is: schemes (`https://`, `sftp://`), paths, and ports are stripped,
and duplicates are removed. Blank lines and lines starting with `#` are ignored.

```text
# example.com fleet, from the scanner's asset list
www.example.com
https://staging.example.com/
sftp://files.example.com
192.0.2.10
```

IP addresses are accepted. The certificate-name, DMARC, DNSSEC, and preload
checks are skipped for them, since none of those apply to a bare address.

Put mail-only names from the scanner's DMARC finding (for example
`em123.example.com`) in a second file and pass it as `-MailHostFile`. Those names
get a DMARC check without a web sweep. DMARC and DNSSEC are domain-level checks:
DNSSEC is checked once per apex domain, and DMARC is checked for each apex domain
and each mail host, not for every web host.

Save both files outside this repository. A client's real host list is client data
(see Handling client data below).

## Step 2: run the review

From the repository root:

```powershell
pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1
```

It prompts for the host file. To skip the prompt and add the optional inputs:

```powershell
pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1 `
  -HostFile 'C:\work\client\hosts.txt' `
  -MailHostFile 'C:\work\client\mail-hosts.txt' `
  -ExtraPath '/login','/account/login'
```

Useful options:

- `-ExtraPath`: every check reads the site root (`/`). Login pages often live
  elsewhere, so pass the login paths you know about and the sweep looks for a
  password field there too. A 401 or a `WWW-Authenticate` header at the root is
  flagged as `AuthRequired` either way. Treat those hosts as login pages.
- `-UserAgent`: the default user agent identifies the checker. If a host returns
  403 at the root, re-run with a browser user agent to tell a WAF block from a
  real access restriction.
- `-ApexDomain`: the apex domain is guessed from the last two labels, which is
  wrong for suffixes such as `.co.uk`. Pass the real apex (`-ApexDomain
  example.co.uk`) when that applies.

The run writes three timestamped report folders under `reports\web\`: the
evidence, the findings with remediation, and the risk context. Start with the
risk-context CSV. Its `Flags` column is the quickest way to spot dead hosts
(`Dead`, `NoDns`), login hosts (`AuthRequired`, `LoginFound`), APIs
(`NonHtml`), and third-party CNAMEs (`Cname`).

Two things to keep in mind when you read the results:

- **Severity is the script's typical value, not the scanner's.** Always use the
  scanner's own rating when you respond to the scanner.
- **A dead host that is a CNAME to a third-party service is a takeover risk,**
  not just clutter. If the vendor resource behind it is gone, someone else may be
  able to claim the name. Remove those records first.

## Step 3: use the prompt for each scanner finding

Open `SecurityFindingsReviewPrompt.md`, copy it into a new file outside this
repository, and fill in the placeholders for the client you are working. Paste
the filled-in prompt into your AI assistant session once, then paste each scanner
finding along with the matching rows from the risk-context CSV.

## Tracking sheet layout

The prompt produces paste blocks for a tracking sheet with these columns. If your
sheet differs, update the column list in your filled-in prompt to match.

| Column | Contents |
| --- | --- |
| A | URL |
| B | Reported Risk (the scanner's rating) |
| C | Actual Risk ("Same as reported" when the finding is accepted) |
| D | Remediate Now (X) |
| E | Remediate Later (X) |
| F | Finding |
| G | Research |
| H | Action |
| I | Message Sent to Prospect |
| J | Next Steps |
| K | Next Step Completed |
| L | Category |
| M | Summary |

## Fixing what the review finds

For IIS hosts, the repository's `scripts\iis\` folder has
`Set-IisRecommendedSecurityHeaders.ps1` and `Set-IisSiteCustomHeader.ps1`.
Preview with `-WhatIf` first, and check the defaults before applying them:
`Set-IisRecommendedSecurityHeaders.ps1` sets a strict
`Content-Security-Policy: default-src 'self'` (which can break pages that load
scripts from other origins), HSTS with `includeSubDomains` (unsafe until every
subdomain serves HTTPS), and `Cache-Control: no-cache, no-store`. Pass `-Headers`
with only the headers a finding calls for, for example:

```powershell
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" `
  -Headers @{ 'X-Content-Type-Options' = 'nosniff'; 'X-Frame-Options' = 'SAMEORIGIN' } -WhatIf
```

For hosts behind Cloudflare, one Transform Rule (Rules, Transform Rules, Modify
Response Header) can add a header to every proxied host at once.

## Known limits

- Only the paths you give it are checked: `/` plus any `-ExtraPath` values.
- `LikelyDead` is a heuristic (no HTTPS and nothing served on HTTP, or a 404/410
  at the root). Confirm before telling an auditor a host is dead.
- The apex-domain guess uses the last two labels unless you pass `-ApexDomain`.
- Port checks cover 22, 25, 80, and 443 only.
- A WAF can return 403 to the checker. See `-UserAgent` above.

## Handling client data

This repository is public. Never commit a client's real hostnames, IP
addresses, scan findings, tracking-sheet links, or a filled-in copy of
`SecurityFindingsReviewPrompt.md` here. The `reports\` folder is in
`.gitignore`, so a run's output will not be committed by accident, but copy any
report you need to share into a private location first (a private repo, a
private drive folder, or wherever your team keeps client-specific work) rather
than sharing it from your clone.
