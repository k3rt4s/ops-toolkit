<#
.SYNOPSIS
Read a findings/evidence report pair from Test-ExternalSecurityPosture.ps1 and add
evidence-based context for and against treating each finding as lower risk, without
changing the severity itself.

.DESCRIPTION
Instructions:
- Read this folder's README.md before running this script.
- Requires PowerShell 7.4+.
- Read-only. It reads two CSV files already on disk (produced by
  Test-ExternalSecurityPosture.ps1) and makes no network calls of its own.
- Run Test-ExternalSecurityPosture.ps1 first; this script needs its
  *-findings.csv and *-evidence.csv output.
- No target data is hard-coded; both input paths are parameters.

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
one row per input finding with Flags, EvidenceForLowerRisk, and
EvidenceAgainstLowerRisk columns added. Flags is a short summary of the host facts
that most often decide an argument (Dead, NoDns, AuthRequired, LoginFound,
NonHtml, Cname, NoHttps). Returns the record set.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Version 7.4
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

function Get-OpsEvidenceValue {
    <#
    .SYNOPSIS
    Read one column from an evidence row, returning an empty string when the
    column is missing, so an evidence file from an older run cannot stop this
    script under StrictMode.
    #>
    param(
        [Parameter()][AllowNull()]$Evidence,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Evidence) { return '' }
    $property = $Evidence.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string]$property.Value
}

function Get-OpsRiskContext {
    <#
    .SYNOPSIS
    Build the flags and for/against evidence lists for one finding row, using only
    facts already present in that host's evidence row.

    .PARAMETER Finding
    One row from the findings CSV (has Host, Finding, Category, Evidence).

    .PARAMETER Evidence
    The matching row from the evidence CSV for the same host, or $null.

    .OUTPUTS
    Ordered hashtable with Flags, EvidenceForLowerRisk, and EvidenceAgainstLowerRisk,
    each a semicolon-joined string (empty when nothing applicable was found).
    #>
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Finding,
        [Parameter()][AllowNull()][pscustomobject]$Evidence
    )
    $for = [Collections.Generic.List[string]]::new()
    $against = [Collections.Generic.List[string]]::new()
    $flags = [Collections.Generic.List[string]]::new()

    if (-not $Evidence) {
        $against.Add('No matching evidence row found for this host; context could not be derived.')
        return [ordered]@{ Flags = ''; EvidenceForLowerRisk = ''; EvidenceAgainstLowerRisk = ($against -join '; ') }
    }

    $v = { param($name) Get-OpsEvidenceValue -Evidence $Evidence -Name $name }
    $isTrue = { param($name) (& $v $name) -eq 'True' }

    $finalStatus = & $v 'FinalStatus'
    $contentType = & $v 'FinalContentType'
    # A non-HTML Content-Type only says something about the endpoint when the
    # response is a success; a 403 or 404 in text/plain is just an error page.
    $nonHtml = [bool]($contentType -and $contentType -notmatch '(?i)text/html' -and $finalStatus -match '^[23]\d\d$')
    $dead = & $isTrue 'LikelyDead'
    $auth = & $isTrue 'AuthRequired'
    $login = (& $isTrue 'HasPasswordField')
    $form = (& $isTrue 'HasForm')
    $loginPath = & $v 'LoginPathFound'
    $cname = & $v 'CnameTarget'
    $httpsOk = & $isTrue 'HttpsOk'
    $port80 = & $v 'Port80'
    $http80Status = & $v 'Http80Status'
    $hsts = & $v 'Hsts'
    $isIp = & $isTrue 'IsIpAddress'
    $findingHost = $Finding.Host

    if ((& $v 'DnsResolved') -eq 'False') { $flags.Add('NoDns') }
    if ($dead) { $flags.Add('Dead') }
    if (-not $httpsOk -and (& $v 'DnsResolved') -eq 'True' -and (& $v 'Port443')) { $flags.Add('NoHttps') }
    if ($auth) { $flags.Add('AuthRequired') }
    if ($login) { $flags.Add('LoginFound') }
    if ($nonHtml) { $flags.Add('NonHtml') }
    if ($cname) { $flags.Add('Cname') }

    # Cross-cutting facts that apply whatever the finding is.
    if ((& $v 'DnsResolved') -eq 'False') {
        $for.Add('The host does not resolve in DNS today, so the finding is likely stale; confirm with the scanner and remove it from scope')
        return [ordered]@{ Flags = ($flags -join ' '); EvidenceForLowerRisk = ($for -join '; '); EvidenceAgainstLowerRisk = ($against -join '; ') }
    }
    if ($dead) {
        $cleanup = if ($isIp) { 'confirm, then shut the listener or remove the address from scope' } else { 'confirm, then remove the DNS record' }
        $for.Add("The root returns $(if ($finalStatus) { $finalStatus } else { 'no HTTPS response' }) with no application content, which usually means a dead page or service; $cleanup")
        if ($cname) {
            $against.Add("The name is a CNAME to $cname. If the third-party resource behind it no longer exists, someone else may be able to claim it (subdomain takeover), so removing the record is urgent rather than cleanup")
        }
    }
    if ($auth -and $Finding.Finding -notmatch 'DMARC|DNSSEC|preload|SMTP|SSH') {
        $against.Add('The root requires authentication (401 or a WWW-Authenticate header), so a login flow exists even though no password field was seen at /; treat it as a login page')
    }
    if ($finalStatus -eq '403') {
        $against.Add('The root returned 403, which can be an access restriction or a WAF blocking the checker; re-run with a browser -UserAgent before relying on "no content"')
    }

    switch -Wildcard ($Finding.Finding) {
        'HTTP does not redirect to HTTPS' {
            if ($hsts) {
                $for.Add('HTTPS returns an HSTS header, so a browser that has visited before will not repeat the plaintext request')
            }
            if ($http80Status -match '^[45]\d\d$') {
                $for.Add("Port 80 answers $http80Status with no content, so nothing is served over plain HTTP")
                $against.Add('The client request, including cookies and any tokens in the URL, is still sent in clear text before the error comes back')
            }
            elseif ($http80Status -match '^2\d\d$') {
                $against.Add('Port 80 serves content over plain HTTP, so a first-time visitor or an old http:// link is exposed to interception')
            }
            if ($login -or $form) {
                $against.Add('The site has a form or password field, so credentials or submitted data are at stake on a plaintext page')
            }
        }
        'Hostname does not match SSL certificate' {
            $sans = & $v 'CertSubjectAlternativeNames'
            $apex = & $v 'ApexDomain'
            if ($sans -and $apex -and $sans -notmatch [regex]::Escape($apex)) {
                $for.Add("The certificate belongs to another organization's domain ($sans), which usually means this name points at a third-party service rather than a site you run")
            }
            elseif ($sans) {
                $against.Add("The certificate covers a different name set ($sans) than the hostname requested, so every visitor gets a browser warning")
            }
            if ($login) {
                $against.Add('The page has a password field, so a certificate warning here trains users to click through on a login page')
            }
        }
        "'SMTP' port open" {
            $banner = & $v 'Port25Banner'
            if ($banner -match '(?i)ESMTP') {
                $for.Add("Banner ('$banner') indicates a standard mail daemon rather than an unexpected service")
            }
            if ($cname) { $for.Add("The name is a CNAME to $cname, so the listener belongs to that provider, not to infrastructure you control") }
            $against.Add('Any port scan can see the service and its banner, which is itself the finding regardless of whether it requires authentication')
        }
        "'SSH' port open" {
            $banner = & $v 'Port22Banner'
            if ($banner -match '(?i)OpenSSH') {
                $for.Add("Banner ('$banner') indicates a maintained, standard SSH server")
            }
            $against.Add('The port is reachable from the public internet regardless of what authenticates against it, which is what an external scan measures')
        }
        'CSP implemented unsafely' {
            if ($login -or $form -or $auth) {
                $against.Add('The site has a form, password field, or authentication, so a successful injection under this CSP has something worth stealing')
            }
            else {
                $for.Add('No form, password field, or authentication was seen, so there is less on the page for injected script to steal or submit')
            }
        }
        'CSP is not implemented' {
            if ($nonHtml) {
                $for.Add("The response Content-Type is '$contentType', not HTML, so a missing CSP has no script-injection surface to defend")
            }
            if ($login) {
                $against.Add('The page has a password field with no CSP as a defense-in-depth layer against injected script')
            }
            elseif (-not $auth -and -not $form -and -not $nonHtml -and -not $dead) {
                $for.Add('No form, password field, or authentication was seen at the root; a public information page has less for injected script to steal, though a CSP still limits defacement and redirects')
            }
        }
        'HTTP Strict Transport Security (HSTS) not enforced' {
            if ($port80 -like 'Closed*' -or $port80 -like 'Filtered*') {
                $for.Add("Port 80 is $port80, so no request can reach this server in clear text; the remaining exposure needs an on-path attacker to answer on port 80 themselves")
            }
            elseif ($http80Status -match '^3\d\d$') {
                $against.Add('Port 80 redirects to HTTPS, so the downgrade HSTS exists to close (an on-path attacker holding a visitor on http://) is possible on every first visit')
            }
            if ($nonHtml) {
                $for.Add("The endpoint returns '$contentType'; non-browser clients such as API integrations do not honor HSTS, so closing port 80 is the more effective control")
            }
            if ($login -or $auth) {
                $against.Add('The host has a login, so a downgraded first visit could expose credentials or session cookies')
            }
        }
        'Server information header exposed' {
            $server = & $v 'ServerHeader'
            $powered = & $v 'XPoweredBy'
            $genericHttpSys = [bool]($server -match '(?i)^Microsoft-HTTPAPI/2\.0$')
            if ((& $v 'ServerHeaderHasVersion') -eq 'True' -and -not $genericHttpSys) {
                $against.Add("The Server value ('$server') includes a version number, which narrows which known vulnerabilities to try")
            }
            elseif (-not $genericHttpSys) {
                $for.Add("The Server value ('$server') has no version number, so it does not point to specific known vulnerabilities")
            }
            if ($server -match '(?i)Microsoft-HTTPAPI') {
                $for.Add('Microsoft-HTTPAPI/2.0 is the default Windows HTTP.sys response when no site is bound to the name or IP requested; it is the same string across Windows versions')
            }
            if ($powered) {
                $against.Add("X-Powered-By is also sent ('$powered'); remove it with the Server header")
            }
        }
        'X-Frame-Options is not deny or sameorigin' {
            $fa = & $v 'FrameAncestors'
            if ($fa -match "(?i)'none'|'self'") {
                $for.Add("CSP frame-ancestors is set to $fa, which modern browsers enforce in place of X-Frame-Options")
            }
            elseif ($fa -eq '*') {
                $against.Add('CSP frame-ancestors * explicitly allows any site to frame the page; confirm that embedding is intentional (for example a status widget)')
            }
            if ($nonHtml) {
                $for.Add("The response is '$contentType', not a page a user can be tricked into clicking")
            }
            if ($login -or $form) {
                $against.Add("The site has a form or password field$(if ($loginPath) { " (found at $loginPath)" }), so an attacker can frame it and trick a user into submitting it")
            }
            elseif (-not $auth -and -not $nonHtml) {
                $for.Add('No form or password field was seen, so there is nothing on the page a clickjacking overlay could trick a user into submitting (only the paths checked; pass -ExtraPath to the sweep to check login pages)')
            }
        }
        'CSP contains unsafe-eval' {
            $for.Add('unsafe-eval only matters if an attacker can already get script onto the page; on its own it does not open a new entry point')
            if (-not $login -and -not $form -and -not $auth) {
                $for.Add('No form, password field, or authentication was seen, so there is no session or submitted data for injected script to target')
            }
        }
        'DMARC policy is p=quarantine' {
            $pct = & $v 'DmarcPct'
            if ($pct -eq '' -or $pct -eq '100') {
                $for.Add('Quarantine is enforced on 100% of failing mail, so spoofed messages go to spam instead of the inbox')
            }
            else {
                $against.Add("pct=$pct, so only part of failing mail is quarantined and the rest is delivered normally")
            }
            if ((& $v 'DmarcInherited') -eq 'True') {
                $for.Add("This name has no DMARC record of its own and is covered by the _dmarc.$(& $v 'DmarcQueriedDomain') policy; one change there fixes every inheriting name")
            }
        }
        'DNSSEC not enabled' {
            $for.Add('DNSSEC protects against forged DNS answers; it does not change the security of an HTTPS session to a correctly resolved host')
            $against.Add('Where HSTS is not enforced, a forged DNS answer can send a first-time http:// visitor to an attacker with no certificate check at all; mail delivery to your MX also relies on unsigned DNS')
        }
        'Domain was not found on the HSTS preload list' {
            if ($findingHost -ne (& $v 'ApexDomain')) {
                $for.Add('The preload list only accepts the apex domain; this subdomain cannot be submitted on its own, so the finding can only be closed by preloading the apex')
            }
            if ($hsts -and (& $v 'HstsIncludeSubDomains') -eq 'True') {
                $for.Add("HSTS is already enforced with includeSubDomains; preload only closes the gap on a browser's very first visit")
            }
        }
        'HSTS header does not contain includeSubDomains' {
            if ($hsts) {
                $for.Add('This host already enforces HSTS; on a subdomain, includeSubDomains only covers names below this host, not sibling hosts')
            }
            $against.Add('Confirm in the DNS zone that no names exist below this host before arguing the directive adds no protection')
        }
        'X-Content-Type-Options is not nosniff' {
            $for.Add('This header defends against a narrow MIME-sniffing scenario that needs user-controllable content served with a non-HTML type')
            if ($nonHtml) {
                $against.Add("The response is '$contentType'; nosniff also stops API responses from being sniffed and run as HTML, so it still applies to APIs")
            }
        }
        default {
            $for.Add('No finding-specific context logic defined for this finding type yet.')
        }
    }

    return [ordered]@{
        Flags = ($flags -join ' ')
        EvidenceForLowerRisk = ($for -join '; ')
        EvidenceAgainstLowerRisk = ($against -join '; ')
    }
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
        Flags = $context.Flags
        EvidenceForLowerRisk = $context.EvidenceForLowerRisk
        EvidenceAgainstLowerRisk = $context.EvidenceAgainstLowerRisk
    }
}

$records | Format-Table Host, Severity, Finding, Flags -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Risk context written to $($report.CsvPath)" -InformationAction Continue

$records
