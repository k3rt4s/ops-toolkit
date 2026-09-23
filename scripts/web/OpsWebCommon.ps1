<#
.SYNOPSIS
Shared helpers for the scripts in scripts/web. Dot-source this file; it is not
meant to be run on its own.

.DESCRIPTION
Instructions:
- Dot-source from a script in this folder: . (Join-Path $PSScriptRoot 'OpsWebCommon.ps1')
- Read-only. Nothing here changes a target or this machine.
- Requires PowerShell 7.4+. HTTPS requests skip certificate validation on purpose,
  so headers are read the same way an external scanner reads them, even from
  hosts with an invalid or mismatched certificate.

Purpose:
The sweep and the two standalone checks used to carry their own copies of the
host-list parsing, TCP probe, raw HTTP probe, and HTTPS request code, and the copies
had drifted apart (different environment variables, timeouts, user agents, and
certificate handling). One copy here keeps every script reading hosts and headers
the same way.

.NOTES
Status:
Active helper kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

$script:OpsWebDefaultUserAgent = 'ops-toolkit-posture-check'
$script:OpsWebDohEndpoint = 'https://cloudflare-dns.com/dns-query'

function ConvertTo-OpsWebHostName {
    <#
    .SYNOPSIS
    Normalize one host-list entry to a bare host name or IP address.

    .DESCRIPTION
    Scanner asset lists often carry a scheme (https://, sftp://), a path, a port, or
    a trailing dot. All of those are stripped so every check targets the same bare
    name. Returns an empty string for blank lines and # comments.

    .PARAMETER Entry
    One line from a host file or one -HostName value.

    .OUTPUTS
    String. Lower-case host name or IP address, or empty.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Entry
    )

    $value = $Entry.Trim()
    if (-not $value -or $value.StartsWith('#')) { return '' }

    # Inline comment after the host, for example "www.example.com  # marketing site"
    $value = ($value -split '\s+#', 2)[0].Trim()
    # Scheme, for example https:// or sftp://
    $value = $value -replace '^[A-Za-z][A-Za-z0-9+.-]*://', ''
    # user@ prefix, path, query, fragment
    $value = $value -replace '^[^@/]+@', ''
    $value = ($value -split '[/?#]', 2)[0]
    # :port, but leave bracketed IPv6 alone
    if ($value -notmatch '^\[') { $value = $value -replace ':\d+$', '' }
    $value = $value.TrimEnd('.').ToLowerInvariant()
    return $value
}

function Resolve-OpsWebHostList {
    <#
    .SYNOPSIS
    Build the de-duplicated host list for a run from -HostName, -HostFile, or an
    environment variable, in that order of preference.

    .PARAMETER HostName
    Host names passed directly.

    .PARAMETER HostFile
    Path to a text file, one host per line. Blank lines and lines starting with #
    are ignored.

    .PARAMETER EnvironmentVariable
    Name of an environment variable holding a comma-separated list, used only when
    neither -HostName nor -HostFile supplies anything.

    .OUTPUTS
    String array. Throws when no usable host is found.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()][string[]]$HostName,
        [Parameter()][string]$HostFile,
        [Parameter()][string]$EnvironmentVariable
    )

    $raw = [Collections.Generic.List[string]]::new()
    if ($HostName) { foreach ($h in $HostName) { $raw.Add([string]$h) } }

    if ($HostFile) {
        if (-not (Test-Path -LiteralPath $HostFile -PathType Leaf)) {
            throw "Host file not found: '$HostFile'"
        }
        foreach ($line in (Get-Content -LiteralPath $HostFile)) { $raw.Add([string]$line) }
    }

    if ($raw.Count -eq 0 -and $EnvironmentVariable) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
        if ($envValue) { foreach ($item in ($envValue -split ',')) { $raw.Add($item) } }
    }

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $list = [Collections.Generic.List[string]]::new()
    foreach ($entry in $raw) {
        $name = ConvertTo-OpsWebHostName -Entry $entry
        if ($name -and $seen.Add($name)) { $list.Add($name) }
    }

    if ($list.Count -eq 0) {
        $sources = @('-HostName', '-HostFile')
        if ($EnvironmentVariable) { $sources += "`$env:$EnvironmentVariable" }
        throw "No hosts to check. Supply at least one host through $($sources -join ', or ')."
    }

    return , $list.ToArray()
}

function Test-OpsWebIpAddress {
    <#
    .SYNOPSIS
    True when the value is an IPv4 or IPv6 address rather than a host name.

    .PARAMETER Value
    Host-list entry, already normalized.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Value)

    $parsed = $null
    return [Net.IPAddress]::TryParse($Value.Trim('[', ']'), [ref]$parsed)
}

function Get-OpsWebApexDomain {
    <#
    .SYNOPSIS
    Return the registrable (apex) domain for a host name.

    .DESCRIPTION
    Uses the last two labels, which is right for .com/.net/.org style domains and
    wrong for multi-part public suffixes such as .co.uk or .com.au. Pass -ApexDomain
    to the sweep to override it for those.

    .PARAMETER HostName
    Host name to reduce.

    .PARAMETER Override
    Explicit apex domains. When the host equals or ends with one of these, that
    value wins over the two-label guess.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter()][string[]]$Override
    )

    if (Test-OpsWebIpAddress -Value $HostName) { return '' }
    foreach ($apex in @($Override | Where-Object { $_ })) {
        $a = $apex.Trim().TrimEnd('.').ToLowerInvariant()
        if ($HostName -eq $a -or $HostName.EndsWith(".$a")) { return $a }
    }
    $labels = $HostName -split '\.'
    if ($labels.Count -le 2) { return $HostName }
    return ($labels[-2..-1] -join '.')
}

function Resolve-OpsWebDnsRecord {
    <#
    .SYNOPSIS
    Look up TXT, DNSKEY, or CNAME records, separating "no such record" from "the
    lookup itself failed."

    .DESCRIPTION
    Uses Resolve-DnsName when it exists (Windows). Otherwise, or when
    -UseDnsOverHttps is set, queries Cloudflare's public DNS-over-HTTPS JSON API.
    The DoH path sends only the record name being looked up.

    .PARAMETER Name
    DNS name to query.

    .PARAMETER Type
    TXT, DNSKEY, or CNAME.

    .PARAMETER UseDnsOverHttps
    Force the DNS-over-HTTPS path even when Resolve-DnsName exists.

    .PARAMETER TimeoutMs
    Timeout for the DoH request, in milliseconds.

    .OUTPUTS
    Hashtable with Status ('Ok', 'NoData', or 'Error'), Answers (string array),
    Source, and Note.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('TXT', 'DNSKEY', 'CNAME')][string]$Type,
        [Parameter()][switch]$UseDnsOverHttps,
        [Parameter()][int]$TimeoutMs = 8000
    )

    $result = @{ Status = 'Error'; Answers = @(); Source = ''; Note = '' }
    $haveResolver = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)

    if ($haveResolver -and -not $UseDnsOverHttps) {
        $result.Source = 'Resolve-DnsName'
        try {
            $params = @{ Name = $Name; Type = $Type; ErrorAction = 'Stop' }
            if ($Type -eq 'DNSKEY') { $params.DnssecOk = $true }
            $answer = @(Resolve-DnsName @params)
            $matched = @($answer | Where-Object { [string]$_.Type -eq $Type })
            $values = foreach ($record in $matched) {
                switch ($Type) {
                    'TXT' { ($record.Strings -join '') }
                    'CNAME' { [string]$record.NameHost }
                    'DNSKEY' { 'DNSKEY' }
                }
            }
            $result.Answers = @($values | Where-Object { $_ })
            $result.Status = if ($result.Answers.Count -gt 0) { 'Ok' } else { 'NoData' }
        }
        catch {
            $message = $_.Exception.Message
            if ($message -match '(?i)does not exist|no records|9003|9501') {
                $result.Status = 'NoData'
            }
            else {
                $result.Status = 'Error'
                $result.Note = "DNS $Type lookup for $Name failed: $message"
            }
        }
        return $result
    }

    $result.Source = 'DNS-over-HTTPS'
    try {
        $uri = "$($script:OpsWebDohEndpoint)?name=$([uri]::EscapeDataString($Name))&type=$Type&do=1"
        $response = Invoke-RestMethod -Uri $uri -Headers @{ Accept = 'application/dns-json' } `
            -TimeoutSec ([Math]::Max(1, [Math]::Ceiling($TimeoutMs / 1000))) -ErrorAction Stop
        $typeCode = @{ TXT = 16; DNSKEY = 48; CNAME = 5 }[$Type]
        $answers = @()
        if ($response.PSObject.Properties['Answer'] -and $response.Answer) {
            $answers = @($response.Answer | Where-Object { [int]$_.type -eq $typeCode } | ForEach-Object {
                    $data = [string]$_.data
                    if ($Type -eq 'TXT') { ($data -replace '"\s*"', '' -replace '^"|"$', '') }
                    elseif ($Type -eq 'CNAME') { $data.TrimEnd('.') }
                    else { 'DNSKEY' }
                })
        }
        $result.Answers = @($answers | Where-Object { $_ })
        # DoH status 0 = NOERROR, 3 = NXDOMAIN; anything else is a resolver failure.
        if ($result.Answers.Count -gt 0) { $result.Status = 'Ok' }
        elseif ([int]$response.Status -in 0, 3) { $result.Status = 'NoData' }
        else { $result.Status = 'Error'; $result.Note = "DoH $Type lookup for $Name returned DNS status $($response.Status)" }
    }
    catch {
        $result.Status = 'Error'
        $result.Note = "DoH $Type lookup for $Name failed: $($_.Exception.Message)"
    }
    return $result
}

function Test-OpsWebTcpPort {
    <#
    .SYNOPSIS
    Open (or fail to open) a TCP connection and report which.

    .OUTPUTS
    String: 'Open', 'Closed (refused)', 'Filtered (timeout)', or 'Error: ...'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { return 'Filtered (timeout)' }
        try { $client.EndConnect($ar) }
        catch {
            $se = $_.Exception.InnerException
            if ($se -is [Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'ConnectionRefused') { return 'Closed (refused)' }
            return "Error: $(if ($se) { $se.Message } else { $_.Exception.Message })"
        }
        return 'Open'
    }
    finally { $client.Close() }
}

function Get-OpsWebTcpBanner {
    <#
    .SYNOPSIS
    Read whatever a service sends unprompted right after connect (SSH and SMTP both
    greet first), without sending any data.

    .OUTPUTS
    String. Empty when the port is not open or no banner arrives in time.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Timeout
    )
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { return '' }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $Timeout
        $reader = [IO.StreamReader]::new($stream)
        return [string]$reader.ReadLine()
    }
    catch { return '' }
    finally { $client.Close() }
}

function Get-OpsWebRawHttpResponse {
    <#
    .SYNOPSIS
    Send a raw HTTP/1.1 GET on a plain-text port and read the status line and
    headers without following a redirect.

    .DESCRIPTION
    A raw socket is used so a redirect is never followed and an error status never
    throws. PortStatus distinguishes a closed port (nothing sent) from an open port
    that answers with an error (the request was still sent in clear text).

    .OUTPUTS
    Ordered hashtable with PortStatus, HttpStatus, Location, and Server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter()][int]$Port = 80,
        [Parameter(Mandatory = $true)][int]$Timeout,
        [Parameter()][string]$UserAgent = $script:OpsWebDefaultUserAgent
    )
    $r = [ordered]@{ PortStatus = ''; HttpStatus = ''; Location = ''; Server = '' }
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { $r.PortStatus = 'Filtered (timeout)'; return $r }
        try { $client.EndConnect($ar) }
        catch {
            $se = $_.Exception.InnerException
            if ($se -is [Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'ConnectionRefused') { $r.PortStatus = 'Closed (refused)' }
            else { $r.PortStatus = "Error: $(if ($se) { $se.Message } else { $_.Exception.Message })" }
            return $r
        }
        $r.PortStatus = 'Open'

        $stream = $client.GetStream()
        $stream.ReadTimeout = $Timeout; $stream.WriteTimeout = $Timeout
        $req = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: $UserAgent`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $reader = [IO.StreamReader]::new($stream)
        $statusLine = $reader.ReadLine()
        if ($statusLine -match '^HTTP/\S+\s+(\d{3})') { $r.HttpStatus = [int]$Matches[1] } else { $r.HttpStatus = 'No HTTP response' }
        while ($null -ne ($line = $reader.ReadLine()) -and $line -ne '') {
            if ($line -match '^Location:\s*(.+)$') { $r.Location = $Matches[1].Trim() }
            elseif ($line -match '^Server:\s*(.+)$') { $r.Server = $Matches[1].Trim() }
        }
    }
    catch { if (-not $r.HttpStatus) { $r.HttpStatus = "Read error: $($_.Exception.Message)" } }
    finally { $client.Close() }
    return $r
}

function Get-OpsWebHeaderValue {
    <#
    .SYNOPSIS
    Read one response header as a single string from an Invoke-WebRequest header
    dictionary, where values may be string arrays.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()]$Headers,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Headers) { return '' }
    foreach ($key in @($Headers.Keys)) {
        if ([string]::Equals([string]$key, $Name, [StringComparison]::OrdinalIgnoreCase)) {
            return ((@($Headers[$key]) | ForEach-Object { [string]$_ }) -join ', ')
        }
    }
    return ''
}

function Get-OpsWebResponse {
    <#
    .SYNOPSIS
    Request a URL and return status, headers, final URL, and (optionally) body,
    without failing on error statuses or certificate problems.

    .DESCRIPTION
    Certificate validation is skipped on purpose: an external scanner still reads
    headers from a host with a mismatched or expired certificate, so this does too.
    Certificate validity is reported separately by the sweep's certificate check.
    HttpClient is used directly (rather than Invoke-WebRequest) because
    Invoke-WebRequest -MaximumRedirection 0 fails on some PowerShell 7 builds
    instead of returning the redirect response.

    .PARAMETER Url
    URL to request.

    .PARAMETER Timeout
    Timeout, in milliseconds.

    .PARAMETER FollowRedirects
    Follow up to five redirects and read the final page's body. Without it, the
    direct response (redirect or not) is returned with no body.

    .PARAMETER UserAgent
    User-Agent header to send. Some WAFs block unfamiliar agents with a 403; pass a
    browser-like string to rule that out.

    .OUTPUTS
    Hashtable with Ok, Status, FinalUrl, Headers (case-insensitive hashtable of
    header name to value), Body, and Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$Timeout,
        [Parameter()][switch]$FollowRedirects,
        [Parameter()][string]$UserAgent = $script:OpsWebDefaultUserAgent
    )
    $out = @{ Ok = $false; Status = ''; FinalUrl = ''; Headers = @{}; Body = ''; Error = '' }
    $handler = $null; $client = $null; $response = $null
    try {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = [bool]$FollowRedirects
        $handler.MaxAutomaticRedirections = 5
        $handler.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromMilliseconds($Timeout)
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Url)
        [void]$request.Headers.TryAddWithoutValidation('User-Agent', $UserAgent)
        $response = $client.SendAsync($request).GetAwaiter().GetResult()

        $out.Ok = $true
        $out.Status = [int]$response.StatusCode
        $out.FinalUrl = [string]$response.RequestMessage.RequestUri
        foreach ($h in $response.Headers) { $out.Headers[$h.Key] = ($h.Value -join ', ') }
        if ($response.Content) {
            foreach ($h in $response.Content.Headers) { $out.Headers[$h.Key] = ($h.Value -join ', ') }
            if ($FollowRedirects) {
                $contentType = [string]$out.Headers['Content-Type']
                if (-not $contentType -or $contentType -match '(?i)text|html|xml|json|javascript') {
                    try { $out.Body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
                    catch { Write-Verbose "Body read failed for $Url`: $($_.Exception.Message)" }
                }
            }
        }
    }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $out.Error = $ex.Message
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
        elseif ($handler) { $handler.Dispose() }
    }
    return $out
}
