<#
.SYNOPSIS
Run a fleet-wide external security posture sweep (redirect/HSTS/certificate
hostname/open ports/CSP/security headers/DMARC/DNSSEC/HSTS preload) against a
caller-supplied host list and map the results onto named findings with
plain-language remediation steps.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It opens TCP connections, sends GET requests, performs a TLS
  handshake that accepts any certificate so it can be inspected, and resolves DNS
  records. It changes nothing on the target or on this machine, and it never
  attempts authentication against SMTP or SSH, it only checks whether the port is
  reachable and reads the banner the service offers unprompted.
- Run it from outside the network whose hosts you are checking (a home connection or
  a cloud VM), so results reflect what an external scanner and the public see rather
  than what an internal path sees.
- The host list is never hard-coded. Supply it with -HostName, or set it once in the
  OPS_TOOLKIT_POSTURE_HOSTS environment variable as a comma-separated list and omit
  -HostName on each run. The script refuses to run with no hosts from either source.
- DMARC and DNSSEC lookups need the Resolve-DnsName cmdlet (built into Windows). If
  it is not present, those two checks are skipped with a note rather than failing
  the whole run.
- The HSTS preload check calls the public hstspreload.org status API, the same data
  Chromium's own preload list tooling uses. No target data leaves this machine for
  that call, only the domain name already being checked.
- Works in Windows PowerShell 5.1 and PowerShell 7+.

Purpose:
A vendor vulnerability report groups findings by name across a fleet of hosts
(HTTP not redirecting, HSTS missing, X-Frame-Options wrong, open SMTP/SSH, and so
on). Re-deriving that same shape by hand from raw header dumps is slow and
error-prone. This script runs the checks once per host and emits one row per
confirmed finding, in the same Severity/Finding/Category shape as the report, each
row carrying the evidence that justified it and a remediation step written for
whoever has to fix it, not just whoever has to read the report. It also writes a
wide per-host evidence table so a later, separate pass (see
New-SecurityFindingsRiskContext.ps1) can weigh mitigating context without
re-probing the targets.

Required syntax:
$env:OPS_TOOLKIT_POSTURE_HOSTS = 'example.com,www.example.com'
pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1

pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1 -HostName example.com,www.example.com

pwsh -File .\scripts\web\Test-ExternalSecurityPosture.ps1 -HostName example.com -TimeoutMs 8000 -OutputDirectory .\reports\web

.OUTPUTS
Writes two report pairs (CSV and JSON) under reports\web by default:
external-posture-findings (one row per confirmed finding, matching a vendor
report's Severity/Finding/Category shape, plus Evidence and Remediation) and
external-posture-evidence (one row per host, every raw fact the findings were
derived from). Returns a hashtable with Findings and Evidence record sets.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Alias('HostNames')]
    [string[]]$HostName,

    [Parameter()]
    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 8000,

    [Parameter()]
    [ValidateRange(0, 30000)]
    [int]$DelayMs = 250,

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

if (-not $HostName -or $HostName.Count -eq 0) {
    if ($env:OPS_TOOLKIT_POSTURE_HOSTS) {
        $HostName = $env:OPS_TOOLKIT_POSTURE_HOSTS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
}

if (-not $HostName -or $HostName.Count -eq 0) {
    throw "No hosts to check. Pass -HostName, or set `$env:OPS_TOOLKIT_POSTURE_HOSTS` to a comma-separated list before running this script."
}

# Windows PowerShell 5.1 may not enable TLS 1.2 by default
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

$script:HstsPreloadApiBase = 'https://hstspreload.org/api/v2/status'

# Every finding this script can emit, keyed the way the evaluation logic below
# references it. Severity/Finding/Category text matches a vendor report's own
# wording so rows from this script line up with one, row for row.
$script:FindingCatalog = @{
    HttpNoRedirect = @{
        Severity = 'high'; Category = 'Encryption'; Finding = 'HTTP does not redirect to HTTPS'
        Remediation = "Configure the web server, load balancer, or CDN to send a 301 redirect from every http:// URL to its https:// equivalent (an Nginx 'return 301 https://`$host`$request_uri;' rule, an IIS URL Rewrite rule, or a redirect rule at the load balancer/CDN all work). Verify with 'curl -I http://<host>/' and confirm the Location header is an https:// URL."
    }
    CertHostnameMismatch = @{
        Severity = 'high'; Category = 'Encryption'; Finding = 'Hostname does not match SSL certificate'
        Remediation = 'Reissue or replace the certificate served on this host so its Subject Alternative Name list includes every hostname clients actually use to reach it, or point this hostname at a server/certificate that already covers it. If a wildcard certificate is in play, confirm its depth actually matches (*.example.com does not cover a.b.example.com).'
    }
    SmtpPortOpen = @{
        Severity = 'medium'; Category = 'Network'; Finding = "'SMTP' port open"
        Remediation = 'If this host does not need to accept inbound mail, block inbound TCP/25 at the firewall or security group. If it does relay or receive mail, restrict which source IPs can reach port 25 and confirm the mail server requires authentication and TLS before accepting or relaying messages.'
    }
    SshPortOpen = @{
        Severity = 'medium'; Category = 'Network'; Finding = "'SSH' port open"
        Remediation = 'If remote administration from the public internet is not required, block inbound TCP/22 at the firewall or security group and require a VPN or bastion host instead. If it must stay open, restrict source IPs, disable password authentication in favor of keys, and keep the SSH daemon patched.'
    }
    CspUnsafe = @{
        Severity = 'medium'; Category = 'Website'; Finding = 'CSP implemented unsafely'
        Remediation = "Remove 'unsafe-inline' from the Content-Security-Policy and move inline <script>/<style> blocks and inline event handlers to external files, or use a per-request nonce or hash for the specific inline scripts that must stay inline."
    }
    CspMissing = @{
        Severity = 'medium'; Category = 'Website'; Finding = 'CSP is not implemented'
        Remediation = "Add a Content-Security-Policy response header, starting narrow (for example default-src 'self') and adding only the specific external sources the site actually needs. Ship it as Content-Security-Policy-Report-Only first to see what it would have blocked before enforcing it."
    }
    HstsNotEnforced = @{
        Severity = 'medium'; Category = 'Encryption'; Finding = 'HTTP Strict Transport Security (HSTS) not enforced'
        Remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to every HTTPS response, at the web server, reverse proxy, or CDN, once HTTPS is confirmed working correctly across the whole site and its subdomains."
    }
    ServerHeaderExposed = @{
        Severity = 'medium'; Category = 'Website'; Finding = 'Server information header exposed'
        Remediation = "Remove or generalize the Server response header (Apache: 'ServerTokens Prod'; Nginx: 'server_tokens off;'; IIS: strip the Server header at the site or via URL Rewrite outbound rules; or strip it at the CDN/reverse proxy in front of the origin)."
    }
    XfoNotDenyOrSameorigin = @{
        Severity = 'medium'; Category = 'Website'; Finding = 'X-Frame-Options is not deny or sameorigin'
        Remediation = "Add 'X-Frame-Options: SAMEORIGIN' (or DENY if the page should never be framed at all) and/or a Content-Security-Policy 'frame-ancestors' directive, at the web server or CDN."
    }
    CspUnsafeEval = @{
        Severity = 'low'; Category = 'Website'; Finding = 'CSP contains unsafe-eval'
        Remediation = "Remove 'unsafe-eval' from the CSP and refactor any code that relies on eval(), new Function(), or a string argument to setTimeout/setInterval so it no longer needs it."
    }
    DmarcQuarantine = @{
        Severity = 'low'; Category = 'Email'; Finding = 'DMARC policy is p=quarantine'
        Remediation = "Once quarantine has run for a monitoring period with no legitimate mail affected (check DMARC aggregate reports), move the DMARC TXT record's policy to p=reject to fully block spoofed mail instead of routing it to spam."
    }
    DnssecMissing = @{
        Severity = 'low'; Category = 'DNS'; Finding = 'DNSSEC not enabled'
        Remediation = 'Enable DNSSEC signing at the DNS host or registrar for this domain, then add the resulting DS record at the domain registrar so resolvers can actually validate the signed zone.'
    }
    HstsNotPreloaded = @{
        Severity = 'low'; Category = 'Encryption'; Finding = 'Domain was not found on the HSTS preload list'
        Remediation = "After the Strict-Transport-Security header has been enforced fleet-wide with includeSubDomains, a max-age of at least one year, and the preload directive for a sustained period, submit the domain at the HSTS preload list's own submission site."
    }
    HstsMissingIncludeSubDomains = @{
        Severity = 'low'; Category = 'Encryption'; Finding = 'HSTS header does not contain includeSubDomains'
        Remediation = "Add 'includeSubDomains' to the Strict-Transport-Security header, but only after confirming every subdomain of this domain actually supports HTTPS, since includeSubDomains applies HSTS to all of them at once."
    }
    XctoMissing = @{
        Severity = 'low'; Category = 'Website'; Finding = 'X-Content-Type-Options is not nosniff'
        Remediation = "Add 'X-Content-Type-Options: nosniff' to HTTP responses at the web server or CDN config."
    }
}

function Test-OpsTcpPort {
    <#
    .SYNOPSIS
    Open (or fail to open) a TCP connection to a host:port and report which.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Port
    TCP port to connect to.

    .PARAMETER Timeout
    Connect timeout, in milliseconds.

    .OUTPUTS
    String: 'Open', 'Closed (refused)', 'Filtered (timeout)', or an error message.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { return 'Filtered (timeout)' }
        try {
            $client.EndConnect($ar)
        }
        catch {
            $se = $_.Exception.InnerException
            if ($se -is [Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'ConnectionRefused') { return 'Closed (refused)' }
            return "Error: $($se.Message)"
        }
        return 'Open'
    }
    finally {
        $client.Close()
    }
}

function Get-OpsTcpBanner {
    <#
    .SYNOPSIS
    Read whatever a service sends unprompted right after connect (SSH/SMTP both
    greet first), without sending any data of our own.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Port
    TCP port to connect to.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .OUTPUTS
    String. Empty if the port was not open or no banner arrived in time.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { return '' }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $Timeout
        $reader = New-Object IO.StreamReader($stream)
        return [string]$reader.ReadLine()
    }
    catch {
        return ''
    }
    finally {
        $client.Close()
    }
}

function Get-OpsRawHttpResponse {
    <#
    .SYNOPSIS
    Send a raw HTTP/1.1 GET on the given port and read the status line and
    headers without following a redirect.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Port
    TCP port to connect to.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .OUTPUTS
    Ordered hashtable with PortStatus, HttpStatus, and Location.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $r = [ordered]@{ PortStatus = ''; HttpStatus = ''; Location = '' }
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { $r.PortStatus = 'Filtered (timeout)'; return $r }
        try {
            $client.EndConnect($ar)
        }
        catch {
            $se = $_.Exception.InnerException
            if ($se -is [Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'ConnectionRefused') { $r.PortStatus = 'Closed (refused)' }
            else { $r.PortStatus = "Error: $($se.Message)" }
            return $r
        }
        $r.PortStatus = 'Open'

        $stream = $client.GetStream()
        $stream.ReadTimeout = $Timeout; $stream.WriteTimeout = $Timeout
        $req = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: ops-toolkit-posture-check`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $reader = New-Object IO.StreamReader($stream)
        $statusLine = $reader.ReadLine()
        if ($statusLine -match '^HTTP/\S+\s+(\d{3})') { $r.HttpStatus = [int]$Matches[1] } else { $r.HttpStatus = 'No HTTP response' }
        while ($null -ne ($line = $reader.ReadLine()) -and $line -ne '') {
            if ($line -match '^Location:\s*(.+)$') { $r.Location = $Matches[1].Trim() }
        }
    }
    catch {
        if (-not $r.HttpStatus) { $r.HttpStatus = "Read error: $($_.Exception.Message)" }
    }
    finally {
        $client.Close()
    }
    return $r
}

function Get-OpsHttpsResponse {
    <#
    .SYNOPSIS
    Request a URL over HTTPS and return status, headers, and (optionally) body.

    .PARAMETER Url
    URL to request.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .PARAMETER FollowRedirects
    Follow redirects and read the response body of the final page. When false,
    the direct response (redirect or not) is returned with no body, which is what
    header-based checks (HSTS, CSP, Server, X-Content-Type-Options) want to see.

    .OUTPUTS
    Hashtable with Ok, Status, FinalUrl, Headers, Body, and Error.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$Timeout,
        [Parameter()][switch]$FollowRedirects
    )
    $out = @{ Ok = $false; Status = ''; FinalUrl = ''; Headers = $null; Body = ''; Error = '' }
    $resp = $null
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.AllowAutoRedirect = [bool]$FollowRedirects
        if ($FollowRedirects) { $req.MaximumAutomaticRedirections = 5 }
        $req.Timeout = $Timeout; $req.ReadWriteTimeout = $Timeout
        $req.UserAgent = 'ops-toolkit-posture-check'
        $resp = $req.GetResponse()
    }
    catch {
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [Net.WebException])) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) { $resp = $ex.Response }
        else { $out.Error = if ($ex) { $ex.Message } else { $_.Exception.Message } }
    }
    if ($resp) {
        $out.Ok = $true
        $out.Status = [int]$resp.StatusCode
        $out.FinalUrl = [string]$resp.ResponseUri
        $out.Headers = $resp.Headers
        if ($FollowRedirects) {
            try {
                $reader = New-Object IO.StreamReader($resp.GetResponseStream())
                $out.Body = $reader.ReadToEnd()
                $reader.Close()
            }
            catch {
                Write-Verbose "Body read failed for $Url`: $($_.Exception.Message)"
            }
        }
        $resp.Close()
    }
    return $out
}

function Get-OpsCertificateHostnameMatch {
    <#
    .SYNOPSIS
    TLS-handshake to host:443 accepting any certificate, then report whether the
    hostname actually matches what the certificate covers, independent of any
    other trust-chain problem.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Timeout
    Connect timeout, in milliseconds.

    .OUTPUTS
    Ordered hashtable with HostnameMatch, SubjectAlternativeNames, and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $r = [ordered]@{ HostnameMatch = ''; SubjectAlternativeNames = ''; Note = '' }
    $script:opsSslPolicyErrors = [Net.Security.SslPolicyErrors]::None
    $client = $null; $stream = $null
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $connect = $client.ConnectAsync($TargetHost, 443)
        if (-not $connect.Wait([timespan]::FromMilliseconds($Timeout))) {
            throw "Connection timed out after $Timeout ms."
        }
        # Accept any certificate but record the policy errors the runtime found,
        # so a name mismatch is captured even though the handshake is allowed to
        # complete: refusing it here would leave us unable to read the certificate
        # that caused the mismatch in the first place.
        $callback = { $script:opsSslPolicyErrors = $args[3]; return $true }
        $stream = [Net.Security.SslStream]::new($client.GetStream(), $false, $callback)
        $stream.AuthenticateAsClient($TargetHost)
        $remote = [Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        $san = $remote.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($san) { $r.SubjectAlternativeNames = ($san.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ';') }
        $mismatch = [bool]($script:opsSslPolicyErrors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)
        $r.HostnameMatch = -not $mismatch
    }
    catch {
        $r.Note = $_.Exception.Message
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }
    return $r
}

function Get-OpsDmarcRecord {
    <#
    .SYNOPSIS
    Look up the DMARC TXT record at _dmarc.<host>, falling back to the apex
    domain (last two labels) if the host itself has none.

    .PARAMETER Domain
    Host or domain to check.

    .OUTPUTS
    Ordered hashtable with Record, Policy, QueriedDomain, and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain
    )
    $r = [ordered]@{ Record = ''; Policy = ''; QueriedDomain = ''; Note = '' }
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $r.Note = 'Resolve-DnsName not available on this host; DMARC check skipped.'
        return $r
    }
    $candidates = [Collections.Generic.List[string]]::new()
    $candidates.Add($Domain)
    $labels = $Domain -split '\.'
    # A naive apex fallback (last two labels): correct for most .com/.net/.org
    # style domains, not for multi-part public suffixes like .co.uk.
    if ($labels.Count -gt 2) { $candidates.Add(($labels[-2..-1] -join '.')) }

    foreach ($candidate in $candidates) {
        try {
            $txt = Resolve-DnsName -Name "_dmarc.$candidate" -Type TXT -ErrorAction Stop
            $value = (@($txt | Where-Object { $_.Strings }) | Select-Object -First 1 -ExpandProperty Strings) -join ''
            if ($value -match 'v=DMARC1') {
                $r.Record = $value
                $r.QueriedDomain = $candidate
                if ($value -match 'p\s*=\s*([A-Za-z]+)') { $r.Policy = $Matches[1].ToLowerInvariant() }
                return $r
            }
        }
        catch {
            $r.Note = $_.Exception.Message
        }
    }
    return $r
}

function Get-OpsDnssecStatus {
    <#
    .SYNOPSIS
    Check whether a domain publishes DNSKEY records, as a proxy for DNSSEC
    being enabled.

    .PARAMETER Domain
    Domain to check.

    .OUTPUTS
    Ordered hashtable with Enabled and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain
    )
    $r = [ordered]@{ Enabled = ''; Note = '' }
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $r.Note = 'Resolve-DnsName not available on this host; DNSSEC check skipped.'
        return $r
    }
    try {
        $answer = Resolve-DnsName -Name $Domain -Type DNSKEY -DnssecOk -ErrorAction Stop
        $r.Enabled = [bool](@($answer | Where-Object { $_.Type -eq 'DNSKEY' }).Count -gt 0)
    }
    catch {
        $r.Enabled = $false
        $r.Note = $_.Exception.Message
    }
    return $r
}

function Get-OpsHstsPreloadStatus {
    <#
    .SYNOPSIS
    Query the public hstspreload.org status API for a domain.

    .PARAMETER Domain
    Domain to check.

    .PARAMETER Timeout
    Timeout, in milliseconds.

    .OUTPUTS
    Ordered hashtable with Status and Note.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $r = [ordered]@{ Status = ''; Note = '' }
    try {
        $uri = "$($script:HstsPreloadApiBase)?domain=$Domain"
        $response = Invoke-RestMethod -Uri $uri -TimeoutSec ([Math]::Max(1, [Math]::Ceiling($Timeout / 1000))) -ErrorAction Stop
        $r.Status = [string]$response.status
    }
    catch {
        $r.Note = "HSTS preload lookup failed: $($_.Exception.Message)"
    }
    return $r
}

function Add-OpsFinding {
    <#
    .SYNOPSIS
    Append one finding row, filled in from the finding catalog, to a list.

    .PARAMETER FindingList
    The list being built up for the whole run.

    .PARAMETER TargetHost
    Host the finding applies to.

    .PARAMETER Key
    Key into $script:FindingCatalog.

    .PARAMETER Evidence
    The specific fact from this host that triggered the finding.
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
$evidence = [Collections.Generic.List[object]]::new()

for ($i = 0; $i -lt $HostName.Count; $i++) {
    $h = $HostName[$i]
    Write-Verbose "Checking $h ..."

    $dnsOk = $true
    try { [void][Net.Dns]::GetHostAddresses($h) } catch { $dnsOk = $false }

    if (-not $dnsOk) {
        $evidence.Add([pscustomobject]@{ Host = $h; Note = 'DNS lookup failed'; DnsResolved = $false })
        if ($DelayMs -gt 0 -and $i -lt $HostName.Count - 1) { Start-Sleep -Milliseconds $DelayMs }
        continue
    }

    $http80 = Get-OpsRawHttpResponse -TargetHost $h -Port 80 -Timeout $TimeoutMs
    $httpsDirect = Get-OpsHttpsResponse -Url "https://$h/" -Timeout $TimeoutMs
    $httpsFinal = Get-OpsHttpsResponse -Url "https://$h/" -Timeout $TimeoutMs -FollowRedirects
    $port443 = Test-OpsTcpPort -TargetHost $h -Port 443 -Timeout $TimeoutMs
    $port22 = Test-OpsTcpPort -TargetHost $h -Port 22 -Timeout $TimeoutMs
    $port25 = Test-OpsTcpPort -TargetHost $h -Port 25 -Timeout $TimeoutMs
    $banner22 = if ($port22 -eq 'Open') { Get-OpsTcpBanner -TargetHost $h -Port 22 -Timeout $TimeoutMs } else { '' }
    $banner25 = if ($port25 -eq 'Open') { Get-OpsTcpBanner -TargetHost $h -Port 25 -Timeout $TimeoutMs } else { '' }
    $cert = Get-OpsCertificateHostnameMatch -TargetHost $h -Timeout $TimeoutMs
    $dmarc = Get-OpsDmarcRecord -Domain $h
    $dnssec = Get-OpsDnssecStatus -Domain $h
    $preload = Get-OpsHstsPreloadStatus -Domain $h -Timeout $TimeoutMs

    $hsts = if ($httpsDirect.Ok) { [string]$httpsDirect.Headers['Strict-Transport-Security'] } else { '' }
    $hstsMaxAge = ''
    if ($hsts -match 'max-age\s*=\s*"?(\d+)') { $hstsMaxAge = [long]$Matches[1] }
    $hstsIncludeSubDomains = [bool]($hsts -match '(?i)includeSubDomains')

    $csp = if ($httpsDirect.Ok) { [string]$httpsDirect.Headers['Content-Security-Policy'] } else { '' }
    $cspUnsafeInline = [bool]($csp -match "'unsafe-inline'")
    $cspUnsafeEval = [bool]($csp -match "'unsafe-eval'")

    $serverHeader = if ($httpsDirect.Ok) { [string]$httpsDirect.Headers['Server'] } else { '' }
    $xcto = if ($httpsDirect.Ok) { [string]$httpsDirect.Headers['X-Content-Type-Options'] } else { '' }
    $xfo = if ($httpsDirect.Ok) { [string]$httpsDirect.Headers['X-Frame-Options'] } else { '' }
    $frameAncestors = ''
    if ($csp -match 'frame-ancestors\s+([^;]+)') { $frameAncestors = $Matches[1].Trim() }

    $finalContentType = if ($httpsFinal.Ok) { [string]$httpsFinal.Headers['Content-Type'] } else { '' }
    $hasForm = [bool]($httpsFinal.Body -match '(?i)<form\b')
    $hasPassword = [bool]($httpsFinal.Body -match '(?i)<input[^>]+type\s*=\s*["'']?password')

    $evidence.Add([pscustomobject]@{
            Host = $h
            DnsResolved = $true
            Port80 = $http80.PortStatus
            Http80Status = $http80.HttpStatus
            Http80Location = $http80.Location
            HttpsDirectOk = $httpsDirect.Ok
            HttpsDirectStatus = $httpsDirect.Status
            Port443 = $port443
            Port22 = $port22
            Port22Banner = $banner22
            Port25 = $port25
            Port25Banner = $banner25
            CertHostnameMatch = $cert.HostnameMatch
            CertSubjectAlternativeNames = $cert.SubjectAlternativeNames
            CertNote = $cert.Note
            Hsts = $hsts
            HstsMaxAge = $hstsMaxAge
            HstsIncludeSubDomains = $hstsIncludeSubDomains
            HstsPreloadStatus = $preload.Status
            Csp = $csp
            CspUnsafeInline = $cspUnsafeInline
            CspUnsafeEval = $cspUnsafeEval
            ServerHeader = $serverHeader
            XContentTypeOptions = $xcto
            XFrameOptions = $xfo
            FrameAncestors = $frameAncestors
            FinalUrl = $httpsFinal.FinalUrl
            FinalStatus = $httpsFinal.Status
            FinalContentType = $finalContentType
            HasForm = $hasForm
            HasPasswordField = $hasPassword
            DmarcQueriedDomain = $dmarc.QueriedDomain
            DmarcRecord = $dmarc.Record
            DmarcPolicy = $dmarc.Policy
            DnssecEnabled = $dnssec.Enabled
            Note = (@($cert.Note, $dmarc.Note, $dnssec.Note, $preload.Note) | Where-Object { $_ }) -join '; '
        })

    if ($http80.PortStatus -eq 'Open') {
        $redirectsToHttps = ($http80.HttpStatus -is [int] -and $http80.HttpStatus -ge 300 -and $http80.HttpStatus -lt 400 -and $http80.Location -match '^https://')
        if (-not $redirectsToHttps) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HttpNoRedirect' -Evidence "Port 80 status=$($http80.HttpStatus), Location='$($http80.Location)'"
        }
    }

    if ($cert.HostnameMatch -eq $false) {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CertHostnameMismatch' -Evidence "Requested host '$h'; certificate SANs: $($cert.SubjectAlternativeNames)"
    }

    if ($port25 -eq 'Open') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'SmtpPortOpen' -Evidence "TCP/25 open; banner: '$banner25'"
    }

    if ($port22 -eq 'Open') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'SshPortOpen' -Evidence "TCP/22 open; banner: '$banner22'"
    }

    if ($csp) {
        if ($cspUnsafeInline) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspUnsafe' -Evidence "CSP: $csp"
        }
        if ($cspUnsafeEval) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspUnsafeEval' -Evidence "CSP: $csp"
        }
    }
    else {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'CspMissing' -Evidence 'No Content-Security-Policy header on the HTTPS response'
    }

    if (-not $hsts) {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsNotEnforced' -Evidence 'No Strict-Transport-Security header on the HTTPS response'
    }
    else {
        if (-not $hstsIncludeSubDomains) {
            Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsMissingIncludeSubDomains' -Evidence "HSTS header: $hsts"
        }
    }

    if ($serverHeader) {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'ServerHeaderExposed' -Evidence "Server: $serverHeader"
    }

    if ($xfo -notmatch '(?i)^\s*(deny|sameorigin)\s*$') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'XfoNotDenyOrSameorigin' -Evidence "X-Frame-Options: '$xfo'; CSP frame-ancestors: '$frameAncestors'"
    }

    if ($xcto -notmatch '(?i)nosniff') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'XctoMissing' -Evidence "X-Content-Type-Options: '$xcto'"
    }

    if ($dmarc.Policy -eq 'quarantine') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'DmarcQuarantine' -Evidence "_dmarc.$($dmarc.QueriedDomain) = $($dmarc.Record)"
    }

    if ($dnssec.Enabled -eq $false) {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'DnssecMissing' -Evidence $(if ($dnssec.Note) { $dnssec.Note } else { 'No DNSKEY record found' })
    }

    if ($preload.Status -and $preload.Status -ne 'preloaded') {
        Add-OpsFinding -FindingList $findings -TargetHost $h -Key 'HstsNotPreloaded' -Evidence "hstspreload.org status: $($preload.Status)"
    }

    if ($DelayMs -gt 0 -and $i -lt $HostName.Count - 1) { Start-Sleep -Milliseconds $DelayMs }
}

$findings | Sort-Object Host, Severity | Format-Table Host, Severity, Finding, Category -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$findingsReport = Export-OpsReport -Name "$OutputPrefix-findings" -Record $findings -Directory $runDirectory
$evidenceReport = Export-OpsReport -Name "$OutputPrefix-evidence" -Record $evidence -Directory $runDirectory
Write-Information "Findings written to $($findingsReport.CsvPath)" -InformationAction Continue
Write-Information "Evidence written to $($evidenceReport.CsvPath)" -InformationAction Continue

@{ Findings = $findings; Evidence = $evidence; FindingsPath = $findingsReport.CsvPath; EvidencePath = $evidenceReport.CsvPath }
