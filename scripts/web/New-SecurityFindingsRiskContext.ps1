<#
.SYNOPSIS
Read a findings/evidence report pair from Test-ExternalSecurityPosture.ps1 and add
evidence-based context for and against treating each finding as lower risk, without
changing the severity itself.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads two CSV files already on disk (produced by
  Test-ExternalSecurityPosture.ps1) and makes no network calls of its own.
- Run Test-ExternalSecurityPosture.ps1 first; this script needs its
  *-findings.csv and *-evidence.csv output.
- No target data is hard-coded; both input paths are parameters.
- Works in Windows PowerShell 5.1 and PowerShell 7+.

Purpose:
A vendor risk questionnaire or a scan report assigns a severity from the finding
type alone, without the surrounding evidence a specific environment actually has.
Answering "why is this lower risk here" by hand means re-reading the raw evidence
for every finding on every host. This script does that re-read once, using only
facts Test-ExternalSecurityPosture.ps1 already collected (nothing new is guessed
or asserted), and writes two short bullet lists per finding: the concrete facts
that support arguing a lower practical risk, and the facts that cut against doing
so. It never re-scores or overrides the Severity column; a human still makes that
call, this just gathers the evidence they would otherwise have to go dig up.

Required syntax:
pwsh -File .\scripts\web\New-SecurityFindingsRiskContext.ps1 `
  -FindingsPath .\reports\web\external-posture-20260101_000000\external-posture-findings.csv `
  -EvidencePath .\reports\web\external-posture-20260101_000000\external-posture-evidence.csv

.OUTPUTS
Writes a findings-risk-context CSV and JSON report under reports\web by default,
one row per input finding with EvidenceForLowerRisk and EvidenceAgainstLowerRisk
columns added. Returns the record set.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$FindingsPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvidencePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'external-posture-risk-context'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

$findings = @(Import-Csv -LiteralPath $FindingsPath)
$evidenceByHost = @{}
foreach ($row in (Import-Csv -LiteralPath $EvidencePath)) {
    $evidenceByHost[$row.Host] = $row
}

if ($findings.Count -eq 0) {
    Write-Information 'No findings in the input file; nothing to add context to.' -InformationAction Continue
}

function Get-OpsRiskContext {
    <#
    .SYNOPSIS
    Build the for/against evidence lists for one finding row, using only facts
    already present in that host's evidence row.

    .PARAMETER Finding
    One row from the findings CSV (has Host, Finding, Category, Evidence).

    .PARAMETER Evidence
    The matching row from the evidence CSV for the same host, or $null if the
    host has no evidence row.

    .OUTPUTS
    Ordered hashtable with EvidenceForLowerRisk and EvidenceAgainstLowerRisk,
    each a semicolon-joined string (empty when nothing applicable was found).
    #>
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Finding,
        [Parameter()][pscustomobject]$Evidence
    )
    $for = [Collections.Generic.List[string]]::new()
    $against = [Collections.Generic.List[string]]::new()

    if (-not $Evidence) {
        $against.Add('No matching evidence row found for this host; context could not be derived.')
        return [ordered]@{ EvidenceForLowerRisk = ($for -join '; '); EvidenceAgainstLowerRisk = ($against -join '; ') }
    }

    switch -Wildcard ($Finding.Finding) {
        'HTTP does not redirect to HTTPS' {
            if ($Evidence.HttpsDirectOk -eq 'True' -and $Evidence.Hsts) {
                $for.Add('HTTPS itself works and returns an HSTS header, so a browser that has visited before will not repeat the plaintext request even without the redirect')
            }
            if ($Evidence.Port80 -ne 'Open') {
                $for.Add('Port 80 is not actually reachable, narrowing the exposure')
            }
            else {
                $against.Add('Port 80 is open and serving plaintext content, so a first-time visitor or a typed http:// link is exposed to interception')
            }
            if ($Evidence.HasPasswordField -eq 'True' -or $Evidence.HasForm -eq 'True') {
                $against.Add('The final page has a form or password field, so credentials or submitted data are at stake if a user lands on the plaintext page')
            }
        }
        'Hostname does not match SSL certificate' {
            if ($Evidence.CertSubjectAlternativeNames) {
                $against.Add("Certificate covers a different name set ($($Evidence.CertSubjectAlternativeNames)) than the hostname requested, so browsers will show a hard warning to every visitor, not an edge case")
            }
            if ($Evidence.HasPasswordField -eq 'True') {
                $against.Add('The page has a password field, so this is not a low-value target for a spoofing attempt riding on the browser warning')
            }
        }
        "'SMTP' port open" {
            if ($Evidence.Port25Banner -match '(?i)ESMTP') {
                $for.Add("Banner ('$($Evidence.Port25Banner)') indicates a standard mail daemon rather than an unexpected or unmanaged service")
            }
            $against.Add('An unauthenticated port scan can see the service is present and its banner, which is itself the finding regardless of whether it is later shown to require auth')
        }
        "'SSH' port open" {
            if ($Evidence.Port22Banner -match '(?i)OpenSSH') {
                $for.Add("Banner ('$($Evidence.Port22Banner)') indicates a maintained, standard SSH server rather than an unmanaged or outdated one")
            }
            $against.Add('The port is reachable from the public internet regardless of what authenticates against it, which is what an external scan is measuring')
        }
        'CSP implemented unsafely' {
            if ($Evidence.HasPasswordField -ne 'True' -and $Evidence.HasForm -ne 'True') {
                $for.Add('Page has no form or password field, so unsafe-inline widens the attack surface for injected script but there is less on this page for injected script to steal or submit')
            }
            else {
                $against.Add('Page has a form or password field, so a successful injection under an unsafe-inline CSP has something worth stealing')
            }
        }
        'CSP is not implemented' {
            if ($Evidence.FinalContentType -and $Evidence.FinalContentType -notmatch 'text/html') {
                $for.Add("Final response Content-Type is '$($Evidence.FinalContentType)', not HTML, so a missing CSP has no script-injection surface to defend on this endpoint")
            }
            if ($Evidence.HasPasswordField -eq 'True') {
                $against.Add('Page has a password field with no CSP as a defense-in-depth layer against injected script')
            }
        }
        'HTTP Strict Transport Security (HSTS) not enforced' {
            if ($Evidence.HttpsDirectOk -eq 'True' -and $Evidence.FinalUrl -match '^https://') {
                $for.Add('The site does resolve to HTTPS by default today, so the gap is specifically about protecting future visits and subdomains, not that HTTPS is unavailable now')
            }
            if ($Evidence.Port80 -eq 'Open' -and $Evidence.Http80Status -match '^3\d\d$') {
                $against.Add('Port 80 redirects to HTTPS, meaning the exact downgrade attack HSTS exists to close (an on-path attacker holding a visitor on http://) is still possible on every visit')
            }
        }
        'Server information header exposed' {
            $for.Add("Exposed value ('$($Evidence.ServerHeader)') is informational only; it does not by itself grant access, it narrows an attacker's guesswork for which other vulnerabilities to try")
        }
        'X-Frame-Options is not deny or sameorigin' {
            if ($Evidence.HasPasswordField -ne 'True' -and $Evidence.HasForm -ne 'True') {
                $for.Add('Page has no form or password field, so there is nothing on it a clickjacking overlay could trick a user into submitting')
            }
            else {
                $against.Add('Page has a form or password field, so an attacker can frame it and trick a logged-in user into submitting it unknowingly')
            }
        }
        'CSP contains unsafe-eval' {
            $for.Add('unsafe-eval only matters if an attacker can already get script content onto the page (via unsafe-inline, a missing CSP elsewhere, or a separate injection bug); on its own it does not open a new entry point')
        }
        'DMARC policy is p=quarantine' {
            $for.Add('Quarantine already routes spoofed mail claiming to be from this domain to spam rather than the inbox, which is most of the practical protection reject adds')
        }
        'DNSSEC not enabled' {
            $for.Add('DNSSEC protects against DNS response tampering specifically; it does not affect the confidentiality or integrity of the HTTPS session itself once a connection is made')
        }
        'Domain was not found on the HSTS preload list' {
            if ($Evidence.Hsts -and $Evidence.HstsIncludeSubDomains -eq 'True') {
                $for.Add("HSTS is already enforced with includeSubDomains; preload only closes the gap on a browser's very first visit to the domain, before it has ever seen the header")
            }
        }
        'HSTS header does not contain includeSubDomains' {
            if ($Evidence.Hsts) {
                $for.Add('The main host does enforce HSTS; the gap is specifically that subdomains are not covered by that same protection')
            }
        }
        'X-Content-Type-Options is not nosniff' {
            $for.Add('This header defends against a narrow MIME-sniffing scenario; it only matters in combination with a page that accepts and reflects user-controllable content as a non-HTML type')
        }
        default {
            $for.Add('No finding-specific context logic defined for this finding type yet.')
        }
    }

    return [ordered]@{ EvidenceForLowerRisk = ($for -join '; '); EvidenceAgainstLowerRisk = ($against -join '; ') }
}

$records = foreach ($finding in $findings) {
    $evidence = $evidenceByHost[$finding.Host]
    $context = Get-OpsRiskContext -Finding $finding -Evidence $evidence

    [pscustomobject]@{
        Host = $finding.Host
        Severity = $finding.Severity
        Finding = $finding.Finding
        Category = $finding.Category
        Evidence = $finding.Evidence
        Remediation = $finding.Remediation
        EvidenceForLowerRisk = $context.EvidenceForLowerRisk
        EvidenceAgainstLowerRisk = $context.EvidenceAgainstLowerRisk
    }
}

$records | Format-Table Host, Severity, Finding, EvidenceForLowerRisk -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Risk context written to $($report.CsvPath)" -InformationAction Continue

$records
