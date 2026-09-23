<#
.SYNOPSIS
Run a fleet-wide external security posture sweep (redirect/HSTS/certificate
hostname/open ports/CSP/security headers/DMARC/DNSSEC/HSTS preload) against a
caller-supplied host list and map the results onto named findings with
plain-language remediation steps.

.DESCRIPTION
Instructions:
- Read this folder's README.md before running this script.
- Requires PowerShell 7.4+.
- Read-only. It opens TCP connections, sends GET requests, performs a TLS
  handshake that accepts any certificate so it can be inspected, and resolves DNS
  records. It changes nothing on the target or on this machine, and it never
  attempts authentication against SMTP or SSH, it only checks whether the port is
  reachable and reads the banner the service offers unprompted.
- Run it from a cloud VM outside the network whose hosts you are checking.
  Most residential ISPs block outbound TCP/25, so an SMTP check from a home
  connection reports "Filtered" even when the port is open.
- The host list is never hard-coded. Supply it with -HostName or -HostFile, or set
  the OPS_TOOLKIT_POSTURE_HOSTS environment variable to a comma-separated list.
  Entries may carry a scheme, path, or port (https://, sftp://, :8443); those are
  stripped. IP addresses are accepted; DNS-based checks and the certificate-name
  check are skipped for them.
- DMARC and DNSSEC are domain-level checks. DNSSEC is evaluated once per apex
  domain. DMARC is evaluated for each apex domain and for every -MailHostName
  entry, and not for every web host (a subdomain with no record of its own
  inherits the apex record's sp= policy, which is reported as inherited).
- DNS lookups use Resolve-DnsName where it exists (Windows) and fall back to
  Cloudflare's DNS-over-HTTPS API elsewhere, or always with -UseDnsOverHttps.
- The HSTS preload check calls the public hstspreload.org status API once per
  apex domain. Only the domain name is sent.
- Every check reads the site root (/). Login pages often live elsewhere; pass
  -ExtraPath '/login','/account/login' to look for a password field on those
  paths too. A 401 or a WWW-Authenticate header at the root is recorded as
  AuthRequired either way.

Purpose:
A vendor vulnerability report groups findings by name across a fleet of hosts
(HTTP not redirecting, HSTS missing, X-Frame-Options wrong, open SMTP/SSH, and so
on). Re-deriving that same shape by hand from raw header dumps is slow and
error-prone. This script runs the checks once per host and emits one row per
confirmed finding, with the report's Finding and Category wording, each row
carrying the evidence that justified it and a remediation step written for
whoever has to fix it. Severity here is this script's typical value for the
finding type; always use the scanner's own rating for the scanner's findings. It
also writes a wide per-host evidence table so New-SecurityFindingsRiskContext.ps1
can weigh mitigating context without re-probing the targets.

Required syntax:
pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1 -HostFile .\hosts.txt

pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1 -HostName example.com,www.example.com

pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1 -HostFile .\hosts.txt -MailHostName em123.example.com -ExtraPath '/login' -TimeoutMs 8000

.OUTPUTS
Writes two report pairs (CSV and JSON) in a timestamped folder under reports\web
by default: external-posture-findings (one row per confirmed finding) and
external-posture-evidence (one row per host, every raw fact the findings were
derived from, always with the same columns). Returns a hashtable with Findings,
Evidence, FindingsPath, and EvidencePath.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter()]
    [Alias('HostNames')]
    [string[]]$HostName,

    [Parameter()]
    [string]$HostFile,

    [Parameter()]
    [string[]]$MailHostName,

    [Parameter()]
    [string[]]$ApexDomain,

    [Parameter()]
    [string[]]$ExtraPath = @(),

    [Parameter()]
    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 8000,

    [Parameter()]
    [ValidateRange(0, 30000)]
    [int]$DelayMs = 250,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserAgent = 'ops-toolkit-posture-check',

    [Parameter()]
    [switch]$UseDnsOverHttps,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'external-posture'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force
. (Join-Path $PSScriptRoot 'OpsWebCommon.ps1')

$HostName = Resolve-OpsWebHostList -HostName $HostName -HostFile $HostFile -EnvironmentVariable 'OPS_TOOLKIT_POSTURE_HOSTS'
$mailHosts = @()
if ($MailHostName) { $mailHosts = @($MailHostName | ForEach-Object { ConvertTo-OpsWebHostName -Entry $_ } | Where-Object { $_ } | Select-Object -Unique) }

$script:HstsPreloadApiBase = 'https://hstspreload.org/api/v2/status'

# Every finding this script can emit, keyed the way the evaluation logic below
# references it. Finding and Category text matches the vendor report's wording
# (the same names used in the tracking sheet) so rows line up with it.
$script:FindingCatalog = @{
    HttpNoRedirect = @{
        Severity = 'High'; Category = 'SSL/TLS'; Finding = 'HTTP does not redirect to HTTPS'
        Remediation = "Configure the web server, load balancer, or CDN to send a 301 redirect from every http:// URL to its https:// equivalent (an Nginx 'return 301 https://`$host`$request_uri;' rule, an IIS URL Rewrite rule, or a redirect rule at the load balancer/CDN all work). Verify with 'curl -I http://<host>/' and confirm the Location header is an https:// URL."
    }
    CertHostnameMismatch = @{
        Severity = 'High'; Category = 'SSL/TLS'; Finding = 'Hostname does not match SSL certificate'
        Remediation = 'Reissue or replace the certificate served on this host so its Subject Alternative Name list includes every hostname clients actually use to reach it, or point this hostname at a server/certificate that already covers it. If a wildcard certificate is in play, confirm its depth actually matches (*.example.com does not cover a.b.example.com).'
    }
    SmtpPortOpen = @{
        Severity = 'Medium'; Category = 'Open Ports'; Finding = "'SMTP' port open"
        Remediation = 'If this host does not need to accept inbound mail, block inbound TCP/25 at the firewall or security group. If it does relay or receive mail, restrict which source IPs can reach port 25 and confirm the mail server requires authentication and TLS before accepting or relaying messages.'
    }
    SshPortOpen = @{
        Severity = 'Medium'; Category = 'Open Ports'; Finding = "'SSH' port open"
        Remediation = 'If remote administration from the public internet is not required, block inbound TCP/22 at the firewall or security group and require a VPN or bastion host instead. If it must stay open, restrict source IPs, disable password authentication in favor of keys, and keep the SSH daemon patched.'
    }
    CspUnsafe = @{
        Severity = 'Medium'; Category = 'Content Security Policy'; Finding = 'CSP implemented unsafely'
        Remediation = "Remove the unsafe source named in the evidence ('unsafe-inline', a bare '*', or data:/http: in script-src or default-src). Move inline <script>/<style> blocks and inline event handlers to external files, or use a per-request nonce or hash for inline scripts that must stay inline, and list specific HTTPS origins instead of wildcards."
    }
    CspMissing = @{
        Severity = 'Medium'; Category = 'Content Security Policy'; Finding = 'CSP is not implemented'
        Remediation = "Add a Content-Security-Policy response header, starting narrow (for example default-src 'self') and adding only the specific external sources the site actually needs. Ship it as Content-Security-Policy-Report-Only first to see what it would have blocked before enforcing it."
    }
    HstsNotEnforced = @{
        Severity = 'Medium'; Category = 'SSL/TLS'; Finding = 'HTTP Strict Transport Security (HSTS) not enforced'
        Remediation = "Add 'Strict-Transport-Security: max-age=31536000' to every HTTPS response at the web server, reverse proxy, or CDN. Start with a short max-age (for example 300) and raise it once HTTPS is confirmed working. Add includeSubDomains only after every subdomain is confirmed to serve HTTPS. For API hosts that browsers never visit, closing port 80 is the stronger control."
    }
    ServerHeaderExposed = @{
        Severity = 'Medium'; Category = 'Information Disclosure'; Finding = 'Server information header exposed'
        Remediation = "Remove or generalize the Server response header, and remove X-Powered-By (Apache: 'ServerTokens Prod'; Nginx: 'server_tokens off;'; IIS: removeServerHeader=true under requestFiltering and remove X-Powered-By under HTTP Response Headers; Windows HTTP.sys default responses (Microsoft-HTTPAPI/2.0): set DisableServerHeader=2 under HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters; or strip it at the CDN/reverse proxy in front of the origin)."
    }
    XfoNotDenyOrSameorigin = @{
        Severity = 'Medium'; Category = 'HTTP Security Headers'; Finding = 'X-Frame-Options is not deny or sameorigin'
        Remediation = "Add 'X-Frame-Options: SAMEORIGIN' (or DENY if the page should never be framed at all) and/or a Content-Security-Policy 'frame-ancestors' directive, at the web server or CDN."
    }
    CspUnsafeEval = @{
        Severity = 'Low'; Category = 'Content Security Policy'; Finding = 'CSP contains unsafe-eval'
        Remediation = "Remove 'unsafe-eval' from the CSP and refactor any code that relies on eval(), new Function(), or a string argument to setTimeout/setInterval so it no longer needs it."
    }
    DmarcQuarantine = @{
        Severity = 'Low'; Category = 'Email Security'; Finding = 'DMARC policy is p=quarantine'
        Remediation = "Once quarantine has run for a monitoring period with no legitimate mail affected (check DMARC aggregate reports), move the DMARC TXT record's policy to p=reject (and sp=reject for subdomains) to fully block spoofed mail instead of routing it to spam. A single change on the apex record covers every subdomain that has no record of its own."
    }
    DnssecMissing = @{
        Severity = 'Low'; Category = 'DNS'; Finding = 'DNSSEC not enabled'
        Remediation = 'Enable DNSSEC signing at the DNS host or registrar for this domain, then add the resulting DS record at the domain registrar so resolvers can actually validate the signed zone.'
    }
    HstsNotPreloaded = @{
        Severity = 'Low'; Category = 'SSL/TLS'; Finding = 'Domain was not found on the HSTS preload list'
        Remediation = "The preload list only accepts the registrable (apex) domain; subdomains cannot be submitted on their own. After every subdomain serves HTTPS and the apex sends Strict-Transport-Security with max-age of at least 31536000, includeSubDomains, and preload, submit the apex at hstspreload.org. Removal from the list takes months, so do this last."
    }
    HstsMissingIncludeSubDomains = @{
        Severity = 'Low'; Category = 'SSL/TLS'; Finding = 'HSTS header does not contain includeSubDomains'
        Remediation = "Add 'includeSubDomains' to the Strict-Transport-Security header, but only after confirming every name beneath this host actually supports HTTPS, since includeSubDomains applies HSTS to all of them at once. On a subdomain, it only covers names below that subdomain, not sibling hosts."
    }
    XctoMissing = @{
        Severity = 'Low'; Category = 'HTTP Security Headers'; Finding = 'X-Content-Type-Options is not nosniff'
        Remediation = "Add 'X-Content-Type-Options: nosniff' to HTTP responses at the web server or CDN config."
    }
}


$script:EvidenceColumns = @(
    'Host', 'IsIpAddress', 'ApexDomain', 'DnsResolved', 'CnameTarget'
    'Port80', 'Http80Status', 'Http80Location'
    'Port443', 'HttpsOk', 'HttpsError', 'HttpsDirectStatus', 'HttpsDirectLocation', 'HeaderSource'
    'CertHostnameMatch', 'CertChainValid', 'CertSubjectAlternativeNames', 'CertNote'
    'Hsts', 'HstsMaxAge', 'HstsIncludeSubDomains', 'HstsPreloadDirective', 'ApexPreloadStatus'
    'Csp', 'CspUnsafeInline', 'CspUnsafeEval', 'CspUnsafeSources', 'FrameAncestors'
    'XFrameOptions', 'XContentTypeOptions', 'ServerHeader', 'ServerHeaderHasVersion', 'XPoweredBy'
    'WwwAuthenticate', 'AuthRequired'
    'FinalUrl', 'FinalStatus', 'FinalContentType', 'FinalOnSameHost', 'HasForm', 'HasPasswordField', 'LoginPathFound', 'LikelyDead'
    'Port22', 'Port22Banner', 'Port25', 'Port25Banner'
    'IsMailHost', 'DmarcQueriedDomain', 'DmarcInherited', 'DmarcRecord', 'DmarcPolicy', 'DmarcSubdomainPolicy', 'DmarcEffectivePolicy', 'DmarcPct'
    'ApexDnssecEnabled', 'Note'
)

function New-OpsEvidenceRow {
    <#
    .SYNOPSIS
    Return an ordered hashtable with every evidence column present and blank.

    .DESCRIPTION
    Export-Csv takes its column list from the first record, so a short record for a
    host that failed DNS would otherwise drop every other column from the whole
    report, and the risk-context pass would then fail reading properties that are
    not there. Every row starts from this full shape.
    #>
    param([Parameter(Mandatory = $true)][string]$TargetHost)
    $row = [ordered]@{}
    foreach ($column in $script:EvidenceColumns) { $row[$column] = '' }
    $row.Host = $TargetHost
    return $row
}

function Get-OpsCertificateHostnameMatch {
    <#
    .SYNOPSIS
    TLS-handshake to host:443 accepting any certificate, then report whether the
    hostname matches the certificate and whether the chain is trusted.

    .OUTPUTS
    Ordered hashtable with HostnameMatch, ChainValid, SubjectAlternativeNames, and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $r = [ordered]@{ HostnameMatch = ''; ChainValid = ''; SubjectAlternativeNames = ''; Note = '' }
    $script:opsSslPolicyErrors = [Net.Security.SslPolicyErrors]::None
    $client = $null; $stream = $null
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $connect = $client.ConnectAsync($TargetHost, 443)
        if (-not $connect.Wait([timespan]::FromMilliseconds($Timeout))) {
            throw "Connection timed out after $Timeout ms."
        }
        # Accept any certificate but record the policy errors the runtime found, so a
        # name mismatch is captured even though the handshake is allowed to complete.
        $callback = { $script:opsSslPolicyErrors = $args[3]; return $true }
        $stream = [Net.Security.SslStream]::new($client.GetStream(), $false, $callback)
        $stream.ReadTimeout = $Timeout
        $stream.AuthenticateAsClient($TargetHost)
        $remote = [Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        $san = $remote.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($san) { $r.SubjectAlternativeNames = ($san.Format($false) -replace 'DNS Name=', '' -replace 'DNS:', '' -replace ',\s*', ';') }
        $r.HostnameMatch = -not [bool]($script:opsSslPolicyErrors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)
        $r.ChainValid = -not [bool]($script:opsSslPolicyErrors -band [Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors)
    }
    catch {
        $r.Note = "Certificate check: $($_.Exception.Message)"
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }
    return $r
}

function ConvertFrom-OpsDmarcRecord {
    <#
    .SYNOPSIS
    Parse a DMARC TXT value into its tags (p, sp, pct, rua, and so on).
    #>
    param([Parameter(Mandatory = $true)][string]$Record)
    $tags = @{}
    foreach ($part in ($Record -split ';')) {
        if ($part -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $tags[$Matches[1].ToLowerInvariant()] = $Matches[2] }
    }
    return $tags
}

function Get-OpsDmarcEvaluation {
    <#
    .SYNOPSIS
    Find the DMARC record that governs a name and work out the policy that
    actually applies to it.

    .DESCRIPTION
    A name with its own _dmarc record is governed by that record's p= tag. A
    subdomain with no record of its own inherits the apex (organizational domain)
    record, and for it the sp= tag applies when present, otherwise p=. pct= below
    100 means only part of failing mail gets the policy.

    .OUTPUTS
    Ordered hashtable with QueriedDomain, Inherited, Record, Policy,
    SubdomainPolicy, EffectivePolicy, Pct, and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Apex
    )
    $r = [ordered]@{ QueriedDomain = ''; Inherited = $false; Record = ''; Policy = ''; SubdomainPolicy = ''; EffectivePolicy = ''; Pct = ''; Note = '' }
    $candidates = @($Name)
    if ($Apex -and $Apex -ne $Name) { $candidates += $Apex }
    $notes = @()

    foreach ($candidate in $candidates) {
        $lookup = Resolve-OpsWebDnsRecord -Name "_dmarc.$candidate" -Type TXT -UseDnsOverHttps:$UseDnsOverHttps -TimeoutMs $TimeoutMs
        if ($lookup.Status -eq 'Error') { $notes += $lookup.Note; continue }
        $value = @($lookup.Answers | Where-Object { $_ -match '(?i)v\s*=\s*DMARC1' }) | Select-Object -First 1
        if (-not $value) { continue }

        $tags = ConvertFrom-OpsDmarcRecord -Record $value
        $r.QueriedDomain = $candidate
        $r.Inherited = ($candidate -ne $Name)
        $r.Record = $value
        $r.Policy = if ($tags.ContainsKey('p')) { $tags['p'].ToLowerInvariant() } else { '' }
        $r.SubdomainPolicy = if ($tags.ContainsKey('sp')) { $tags['sp'].ToLowerInvariant() } else { '' }
        $r.Pct = if ($tags.ContainsKey('pct')) { $tags['pct'] } else { '100' }
        $r.EffectivePolicy = if ($r.Inherited -and $r.SubdomainPolicy) { $r.SubdomainPolicy } else { $r.Policy }
        break
    }
    if (-not $r.Record -and $notes.Count -eq 0) { $notes += "No DMARC record at _dmarc.$Name or on the apex domain" }
    $r.Note = ($notes | Where-Object { $_ }) -join '; '
    return $r
}

function Get-OpsHstsPreloadStatus {
    <#
    .SYNOPSIS
    Query the public hstspreload.org status API for a domain.

    .OUTPUTS
    Ordered hashtable with Status and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $r = [ordered]@{ Status = ''; Note = '' }
    try {
        $uri = "$($script:HstsPreloadApiBase)?domain=$([uri]::EscapeDataString($Domain))"
        $response = Invoke-RestMethod -Uri $uri -TimeoutSec ([Math]::Max(1, [Math]::Ceiling($Timeout / 1000))) -ErrorAction Stop
        $r.Status = [string]$response.status
    }
    catch {
        $r.Note = "HSTS preload lookup failed: $($_.Exception.Message)"
    }
    return $r
}

function Get-OpsCspUnsafeSource {
    <#
    .SYNOPSIS
    List the unsafe sources in a CSP's script-src, or default-src when script-src
    is absent: 'unsafe-inline', a bare *, data:, or http:.
    #>
    param([Parameter()][AllowEmptyString()][string]$Csp)
    if (-not $Csp) { return @() }
    $directives = @{}
    foreach ($part in ($Csp -split ';')) {
        $tokens = @($part.Trim() -split '\s+' | Where-Object { $_ })
        if ($tokens.Count -gt 0) { $directives[$tokens[0].ToLowerInvariant()] = @($tokens | Select-Object -Skip 1) }
    }
    $sources = if ($directives.ContainsKey('script-src')) { $directives['script-src'] } elseif ($directives.ContainsKey('default-src')) { $directives['default-src'] } else { @() }
    $unsafe = @()
    foreach ($s in $sources) {
        $l = $s.ToLowerInvariant()
        if ($l -eq "'unsafe-inline'" -or $l -eq '*' -or $l -eq 'data:' -or $l -eq 'http:') { $unsafe += $s }
    }
    return @($unsafe | Select-Object -Unique)
}

function Add-OpsFinding {
    <#
    .SYNOPSIS
    Append one finding row, filled in from the finding catalog, to a list.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[object]]$FindingList,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Evidence
    )
    $meta = $script:FindingCatalog[$Key]
    $FindingList.Add([pscustomobject]@{
            Host = $TargetHost
            Severity = $meta.Severity
            Finding = $meta.Finding
            Category = $meta.Category
            Evidence = $Evidence
            Remediation = $meta.Remediation
        })
}

$findings = [Collections.Generic.List[object]]::new()
$evidenceRows = [Collections.Generic.List[object]]::new()
$evidenceByHost = @{}
$apexCache = @{}

function Get-OpsApexFacts {
    <#
    .SYNOPSIS
    DNSSEC and HSTS preload status for an apex domain, looked up once per run.
    #>
    param([Parameter(Mandatory = $true)][string]$Apex)
    if (-not $apexCache.ContainsKey($Apex)) {
        $dnskey = Resolve-OpsWebDnsRecord -Name $Apex -Type DNSKEY -UseDnsOverHttps:$UseDnsOverHttps -TimeoutMs $TimeoutMs
        $dnssec = switch ($dnskey.Status) { 'Ok' { $true } 'NoData' { $false } default { 'Unknown' } }
        $preload = Get-OpsHstsPreloadStatus -Domain $Apex -Timeout $TimeoutMs
        $apexCache[$Apex] = @{ Dnssec = $dnssec; DnssecNote = $dnskey.Note; Preload = $preload.Status; PreloadNote = $preload.Note }
    }
    return $apexCache[$Apex]
}

for ($i = 0; $i -lt $HostName.Count; $i++) {
    $h = $HostName[$i]
    Write-Verbose "Checking $h ..."
    $row = New-OpsEvidenceRow -TargetHost $h
    $notes = [Collections.Generic.List[string]]::new()
    $isIp = Test-OpsWebIpAddress -Value $h
    $apex = Get-OpsWebApexDomain -HostName $h -Override $ApexDomain
    $row.IsIpAddress = $isIp
    $row.ApexDomain = $apex
    $row.IsMailHost = ($mailHosts -contains $h)

    $dnsOk = $true
    if (-not $isIp) {
        try { [void][Net.Dns]::GetHostAddresses($h) } catch { $dnsOk = $false }
    }
    $row.DnsResolved = $dnsOk
    if (-not $dnsOk) {
        $row.Note = 'DNS lookup failed; host does not resolve'
        $evidenceRows.Add([pscustomobject]$row); $evidenceByHost[$h] = $row
        if ($DelayMs -gt 0 -and $i -lt $HostName.Count - 1) { Start-Sleep -Milliseconds $DelayMs }
        continue
    }

    if (-not $isIp) {
        $cname = Resolve-OpsWebDnsRecord -Name $h -Type CNAME -UseDnsOverHttps:$UseDnsOverHttps -TimeoutMs $TimeoutMs
        if ($cname.Status -eq 'Ok') { $row.CnameTarget = ($cname.Answers -join ';') }
    }

    $http80 = Get-OpsWebRawHttpResponse -TargetHost $h -Port 80 -Timeout $TimeoutMs -UserAgent $UserAgent
    $row.Port80 = $http80.PortStatus; $row.Http80Status = $http80.HttpStatus; $row.Http80Location = $http80.Location

    $row.Port443 = Test-OpsWebTcpPort -TargetHost $h -Port 443 -Timeout $TimeoutMs
    $direct = Get-OpsWebResponse -Url "https://$h/" -Timeout $TimeoutMs -UserAgent $UserAgent
    $final = Get-OpsWebResponse -Url "https://$h/" -Timeout $TimeoutMs -UserAgent $UserAgent -FollowRedirects
    $row.HttpsOk = $direct.Ok
    $row.HttpsError = $direct.Error
    $row.HttpsDirectStatus = $direct.Status
    $row.HttpsDirectLocation = Get-OpsWebHeaderValue -Headers $direct.Headers -Name 'Location'

    $cert = @{ HostnameMatch = ''; ChainValid = ''; SubjectAlternativeNames = ''; Note = '' }
    if ($row.Port443 -eq 'Open') { $cert = Get-OpsCertificateHostnameMatch -TargetHost $h -Timeout $TimeoutMs }
    $row.CertHostnameMatch = $cert.HostnameMatch; $row.CertChainValid = $cert.ChainValid
    $row.CertSubjectAlternativeNames = $cert.SubjectAlternativeNames; $row.CertNote = $cert.Note
    if ($isIp) { $notes.Add('IP address: certificate-name, DMARC, DNSSEC, and preload checks do not apply') }

    $row.Port22 = Test-OpsWebTcpPort -TargetHost $h -Port 22 -Timeout $TimeoutMs
    $row.Port25 = Test-OpsWebTcpPort -TargetHost $h -Port 25 -Timeout $TimeoutMs
    if ($row.Port22 -eq 'Open') { $row.Port22Banner = Get-OpsWebTcpBanner -TargetHost $h -Port 22 -Timeout $TimeoutMs }
    if ($row.Port25 -eq 'Open') { $row.Port25Banner = Get-OpsWebTcpBanner -TargetHost $h -Port 25 -Timeout $TimeoutMs }

    # Headers users actually see: when the root redirects within the same host
    # (for example / to /home), read page headers from the final page; otherwise
    # from the direct response. HSTS is always read from the direct response.
    $finalOnSameHost = $false
    if ($final.Ok -and $final.FinalUrl) {
        try { $finalOnSameHost = ([uri]$final.FinalUrl).Host -eq $h } catch { $finalOnSameHost = $false }
    }
    $row.FinalOnSameHost = $finalOnSameHost
    $directIsRedirect = ($direct.Ok -and $direct.Status -ge 300 -and $direct.Status -lt 400)
    $page = if ($directIsRedirect -and $finalOnSameHost) { $final } else { $direct }
    $row.HeaderSource = if (-not $direct.Ok) { 'none (HTTPS request failed)' } elseif ($directIsRedirect -and $finalOnSameHost) { 'final page (same-host redirect)' } else { 'direct response' }

    if ($direct.Ok) {
        $hsts = Get-OpsWebHeaderValue -Headers $direct.Headers -Name 'Strict-Transport-Security'
        $row.Hsts = $hsts
        if ($hsts -match 'max-age\s*=\s*"?(\d+)') { $row.HstsMaxAge = [long]$Matches[1] }
        $row.HstsIncludeSubDomains = [bool]($hsts -match '(?i)includeSubDomains')
        $row.HstsPreloadDirective = [bool]($hsts -match '(?i)\bpreload\b')
        if ($hsts -and $row.HstsMaxAge -ne '' -and $row.HstsMaxAge -lt 31536000) { $notes.Add("HSTS max-age $($row.HstsMaxAge) is under one year") }

        $csp = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'Content-Security-Policy'
        $row.Csp = $csp
        $row.CspUnsafeInline = [bool]($csp -match "'unsafe-inline'")
        $row.CspUnsafeEval = [bool]($csp -match "'unsafe-eval'")
        $row.CspUnsafeSources = (Get-OpsCspUnsafeSource -Csp $csp) -join ' '
        if ($csp -match 'frame-ancestors\s+([^;]+)') { $row.FrameAncestors = $Matches[1].Trim() }
        $row.XFrameOptions = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'X-Frame-Options'
        $row.XContentTypeOptions = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'X-Content-Type-Options'
        $server = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'Server'
        if (-not $server) { $server = Get-OpsWebHeaderValue -Headers $direct.Headers -Name 'Server' }
        $row.ServerHeader = $server
        $row.ServerHeaderHasVersion = [bool]($server -match '\d')
        $row.XPoweredBy = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'X-Powered-By'
        $row.WwwAuthenticate = Get-OpsWebHeaderValue -Headers $final.Headers -Name 'WWW-Authenticate'
    }
    else {
        $notes.Add("HTTPS request failed ($($direct.Error)); header checks skipped")
    }

    if ($final.Ok) {
        $row.FinalUrl = $final.FinalUrl
        $row.FinalStatus = $final.Status
        $row.FinalContentType = Get-OpsWebHeaderValue -Headers $final.Headers -Name 'Content-Type'
        $row.HasForm = [bool]($final.Body -match '(?i)<form\b')
        $row.HasPasswordField = [bool]($final.Body -match '(?i)<input[^>]+type\s*=\s*["'']?password')
    }
    $row.AuthRequired = ($row.FinalStatus -eq 401 -or [bool]$row.WwwAuthenticate)
    if ($row.FinalStatus -eq 403) { $notes.Add('Root returns 403: access restricted or blocked by a WAF; re-run with a browser -UserAgent to tell them apart') }

    foreach ($path in @($ExtraPath | Where-Object { $_ })) {
        $p = if ($path.StartsWith('/')) { $path } else { "/$path" }
        $extra = Get-OpsWebResponse -Url "https://$h$p" -Timeout $TimeoutMs -UserAgent $UserAgent -FollowRedirects
        if ($extra.Ok -and $extra.Body -match '(?i)<input[^>]+type\s*=\s*["'']?password') {
            $row.HasPasswordField = $true; $row.HasForm = $true
            $row.LoginPathFound = if ($row.LoginPathFound) { "$($row.LoginPathFound);$p" } else { $p }
        }
    }

    $httpServes = ($http80.HttpStatus -is [int] -and $http80.HttpStatus -lt 400)
    $row.LikelyDead = ((-not $direct.Ok -and -not $httpServes) -or ($final.Ok -and $final.Status -in 404, 410))

    if (-not $isIp -and $apex) {
        $facts = Get-OpsApexFacts -Apex $apex
        $row.ApexDnssecEnabled = $facts.Dnssec
        $row.ApexPreloadStatus = $facts.Preload
        if ($facts.DnssecNote) { $notes.Add($facts.DnssecNote) }
        if ($facts.PreloadNote) { $notes.Add($facts.PreloadNote) }
    }

    if ($cert.Note) { $notes.Add($cert.Note) }
    $row.Note = ($notes | Where-Object { $_ }) -join '; '
    $evidenceRows.Add([pscustomobject]$row); $evidenceByHost[$h] = $row

    # ---- Findings for this host ----
    if ($http80.PortStatus -eq 'Open') {
        $redirectsToHttps = ($http80.HttpStatus -is [int] -and $http80.HttpStatus -ge 300 -and $http80.HttpStatus -lt 400 -and $http80.Location -match '^https://')
        if (-not $redirectsToHttps) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HttpNoRedirect' -Evidence "Port 80 open; status=$($http80.HttpStatus), Location='$($http80.Location)'. The request was sent in clear text before any response."
        }
    }

    if (-not $isIp -and $cert.HostnameMatch -eq $false) {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CertHostnameMismatch' -Evidence "Requested host '$h'; certificate SANs: $($cert.SubjectAlternativeNames); CNAME: '$($row.CnameTarget)'"
    }

    if ($row.Port25 -eq 'Open') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'SmtpPortOpen' -Evidence "TCP/25 open; banner: '$($row.Port25Banner)'"
    }
    if ($row.Port22 -eq 'Open') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'SshPortOpen' -Evidence "TCP/22 open; banner: '$($row.Port22Banner)'"
    }

    if ($direct.Ok) {
        if ($row.Csp) {
            if ($row.CspUnsafeSources) {
                Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspUnsafe' -Evidence "Unsafe script sources: $($row.CspUnsafeSources). CSP: $($row.Csp)"
            }
            if ($row.CspUnsafeEval) {
                Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspUnsafeEval' -Evidence "CSP: $($row.Csp)"
            }
        }
        else {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspMissing' -Evidence "No Content-Security-Policy header ($($row.HeaderSource), status $($page.Status))"
        }

        if (-not $row.Hsts -or $row.HstsMaxAge -eq 0) {
            $why = if ($row.Hsts) { "HSTS header present but max-age=0 disables it: $($row.Hsts)" } else { "No Strict-Transport-Security header on the HTTPS response (status $($direct.Status))" }
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsNotEnforced' -Evidence "$why. Port 80: $($http80.PortStatus)"
        }
        elseif (-not $row.HstsIncludeSubDomains) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsMissingIncludeSubDomains' -Evidence "HSTS header: $($row.Hsts)"
        }

        if ($row.ServerHeader) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'ServerHeaderExposed' -Evidence "Server: $($row.ServerHeader); version number present: $($row.ServerHeaderHasVersion); X-Powered-By: '$($row.XPoweredBy)'"
        }

        if ($row.XFrameOptions -notmatch '(?i)^\s*(deny|sameorigin)\s*$') {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'XfoNotDenyOrSameorigin' -Evidence "X-Frame-Options: '$($row.XFrameOptions)'; CSP frame-ancestors: '$($row.FrameAncestors)'"
        }

        if ($row.XContentTypeOptions -notmatch '(?i)nosniff') {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'XctoMissing' -Evidence "X-Content-Type-Options: '$($row.XContentTypeOptions)'"
        }

        if (-not $isIp -and $row.ApexPreloadStatus -and $row.ApexPreloadStatus -ne 'preloaded') {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsNotPreloaded' -Evidence "Apex $apex hstspreload.org status: $($row.ApexPreloadStatus). Subdomains cannot be submitted to the preload list on their own."
        }
    }

    if ($DelayMs -gt 0 -and $i -lt $HostName.Count - 1) { Start-Sleep -Milliseconds $DelayMs }
}

# ---- Domain-level checks: DNSSEC per apex, DMARC per apex and per mail host ----
$apexList = @($HostName + $mailHosts | Where-Object { -not (Test-OpsWebIpAddress -Value $_) } |
        ForEach-Object { Get-OpsWebApexDomain -HostName $_ -Override $ApexDomain } | Where-Object { $_ } | Select-Object -Unique)

foreach ($apex in $apexList) {
    $facts = Get-OpsApexFacts -Apex $apex
    if (-not $evidenceByHost.ContainsKey($apex)) {
        $row = New-OpsEvidenceRow -TargetHost $apex
        $row.ApexDomain = $apex; $row.IsIpAddress = $false; $row.ApexDnssecEnabled = $facts.Dnssec; $row.ApexPreloadStatus = $facts.Preload
        $row.Note = 'Domain-level row (DNSSEC/DMARC only); apex was not in the web host list'
        $evidenceRows.Add([pscustomobject]$row); $evidenceByHost[$apex] = $row
    }
    if ($facts.Dnssec -eq $false) {
        Add-OpsFinding -FindingList $findings -TargetHost $apex -Key 'DnssecMissing' -Evidence "No DNSKEY record at the zone apex $apex"
    }
}

$dmarcTargets = @($apexList + $mailHosts | Select-Object -Unique)
foreach ($name in $dmarcTargets) {
    $apex = Get-OpsWebApexDomain -HostName $name -Override $ApexDomain
    $dmarc = Get-OpsDmarcEvaluation -Name $name -Apex $apex
    if (-not $evidenceByHost.ContainsKey($name)) {
        $row = New-OpsEvidenceRow -TargetHost $name
        $row.ApexDomain = $apex; $row.IsIpAddress = $false; $row.IsMailHost = $true
        $row.Note = 'Domain-level row (DMARC only); mail host was not in the web host list'
        $evidenceRows.Add([pscustomobject]$row); $evidenceByHost[$name] = $row
    }
    $row = $evidenceByHost[$name]
    $row.DmarcQueriedDomain = $dmarc.QueriedDomain; $row.DmarcInherited = $dmarc.Inherited; $row.DmarcRecord = $dmarc.Record
    $row.DmarcPolicy = $dmarc.Policy; $row.DmarcSubdomainPolicy = $dmarc.SubdomainPolicy; $row.DmarcEffectivePolicy = $dmarc.EffectivePolicy; $row.DmarcPct = $dmarc.Pct
    if ($dmarc.Note) { $row.Note = (@($row.Note, $dmarc.Note) | Where-Object { $_ }) -join '; ' }

    if ($dmarc.EffectivePolicy -eq 'quarantine') {
        $source = if ($dmarc.Inherited) { "inherited from _dmarc.$($dmarc.QueriedDomain) (sp=$(if ($dmarc.SubdomainPolicy) { $dmarc.SubdomainPolicy } else { 'not set, p applies' }))" } else { "_dmarc.$($dmarc.QueriedDomain)" }
        Add-OpsFinding -FindingList $findings -TargetHost $name -Key 'DmarcQuarantine' -Evidence "Effective policy quarantine at pct=$($dmarc.Pct), $source. Record: $($dmarc.Record)"
    }
}

# Evidence rows were built from hashtables that the domain-level pass may have
# updated after conversion; rebuild so every row reflects the final values.
$evidence = [Collections.Generic.List[object]]::new()
foreach ($row in $evidenceRows) {
    $key = $row.Host
    $evidence.Add([pscustomobject]$evidenceByHost[$key])
}

$webRows = @($evidence | Where-Object { $_.Port25 })
if ($webRows.Count -gt 1 -and @($webRows | Where-Object { $_.Port25 -notlike 'Filtered*' }).Count -eq 0) {
    Write-Warning 'TCP/25 showed Filtered on every host. Many ISPs block outbound port 25, so re-run from a cloud VM before trusting the SMTP results.'
}

$findings = @($findings | Sort-Object @{ Expression = { Get-OpsSeverityRank -Severity $_.Severity } }, Host, Finding)
$findings | Format-Table Host, Severity, Finding, Category -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$findingsReport = Export-OpsReport -Name "$OutputPrefix-findings" -Record $findings -Directory $runDirectory
$evidenceReport = Export-OpsReport -Name "$OutputPrefix-evidence" -Record $evidence -Directory $runDirectory
Write-Information "Findings written to $($findingsReport.CsvPath)" -InformationAction Continue
Write-Information "Evidence written to $($evidenceReport.CsvPath)" -InformationAction Continue

@{ Findings = $findings; Evidence = $evidence; FindingsPath = $findingsReport.CsvPath; EvidencePath = $evidenceReport.CsvPath }
