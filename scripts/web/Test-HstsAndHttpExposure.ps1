<#
.SYNOPSIS
Check a set of hosts for a reachable plain-HTTP port 80 and for a missing or weak
Strict-Transport-Security (HSTS) header on HTTPS.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It opens TCP connections and sends GET requests; it changes nothing on
  the target or on this machine.
- Run it from outside the network whose hosts you are checking (a home connection or
  a cloud VM), so results reflect what an external scanner and the public see rather
  than what an internal path sees.
- The host list is never hard-coded. Supply it with -HostName, or set it once in the
  OPS_TOOLKIT_HSTS_HOSTS environment variable as a comma-separated list and omit
  -HostName on each run. The script refuses to run with no hosts from either source.
- Works in Windows PowerShell 5.1 and PowerShell 7+.

Purpose:
A redirect from HTTP to HTTPS is not the same guarantee as HSTS: the first plaintext
request in that redirect is still interceptable, and a host that answers on port 80
at all is one an attacker can downgrade to. This reports both facts per host, plus
the HSTS header's max-age, includeSubDomains, and preload flags, so a fleet-wide
gap shows up as one CSV instead of N manual browser checks.

Required syntax:
$env:OPS_TOOLKIT_HSTS_HOSTS = 'example.com,www.example.com'
pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1

pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1 -HostName example.com,www.example.com

pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1 -HostName example.com -TimeoutMs 8000 -OutputDirectory .\reports\web

.OUTPUTS
Writes a per-host CSV and JSON report under reports\web by default. Returns the
record set.

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
    [int]$TimeoutMs = 5000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'hsts-http-exposure'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

if (-not $HostName -or $HostName.Count -eq 0) {
    if ($env:OPS_TOOLKIT_HSTS_HOSTS) {
        $HostName = $env:OPS_TOOLKIT_HSTS_HOSTS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
}

if (-not $HostName -or $HostName.Count -eq 0) {
    throw "No hosts to check. Pass -HostName, or set `$env:OPS_TOOLKIT_HSTS_HOSTS` to a comma-separated list before running this script."
}

# Windows PowerShell 5.1 may not enable TLS 1.2 by default
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

function Test-OpsHttpPort {
    <#
    .SYNOPSIS
    Probe TCP port 80 and, if open, read the raw HTTP response line and headers.

    .DESCRIPTION
    Sends a raw HTTP request over the socket instead of using a web client, so a
    redirect is never followed and a non-2xx status never throws.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .OUTPUTS
    Ordered hashtable with Port80, HttpStatus, and HttpLocation.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$Timeout
    )
    $r = [ordered]@{ Port80 = ''; HttpStatus = ''; HttpLocation = '' }
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($TargetHost, 80, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout)) { $r.Port80 = 'Filtered (timeout)'; return $r }
        try { $client.EndConnect($ar) }
        catch {
            $se = $_.Exception.InnerException
            if ($se -is [Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'ConnectionRefused') { $r.Port80 = 'Closed (refused)' }
            else { $r.Port80 = "Error: $($se.Message)" }
            return $r
        }
        $r.Port80 = 'Open'

        $stream = $client.GetStream()
        $stream.ReadTimeout = $Timeout; $stream.WriteTimeout = $Timeout
        $req = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: ops-toolkit-hsts-check`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $reader = New-Object IO.StreamReader($stream)
        $statusLine = $reader.ReadLine()
        if ($statusLine -match '^HTTP/\S+\s+(\d{3})') { $r.HttpStatus = [int]$Matches[1] } else { $r.HttpStatus = 'No HTTP response' }
        while ($null -ne ($line = $reader.ReadLine()) -and $line -ne '') {
            if ($line -match '^Location:\s*(.+)$') { $r.HttpLocation = $Matches[1].Trim() }
        }
    }
    catch { if (-not $r.HttpStatus) { $r.HttpStatus = "Read error: $($_.Exception.Message)" } }
    finally { $client.Close() }
    return $r
}

function Get-OpsHstsHeader {
    <#
    .SYNOPSIS
    Request the target over HTTPS without following redirects and read the
    Strict-Transport-Security header from whatever status comes back.

    .PARAMETER TargetHost
    Host name to connect to.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .OUTPUTS
    Ordered hashtable with HttpsStatus, HSTS, and HttpsError.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$Timeout
    )
    $r = [ordered]@{ HttpsStatus = ''; HSTS = ''; HttpsError = '' }
    $resp = $null
    try {
        $req = [Net.HttpWebRequest]::Create("https://$TargetHost/")
        $req.Method = 'GET'; $req.AllowAutoRedirect = $false
        $req.Timeout = $Timeout; $req.ReadWriteTimeout = $Timeout
        $req.UserAgent = 'ops-toolkit-hsts-check'
        $resp = $req.GetResponse()
    }
    catch {
        # Unwrap to the WebException; 4xx/5xx responses still carry headers
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [Net.WebException])) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) { $resp = $ex.Response }
        else { $r.HttpsError = if ($ex) { $ex.Message } else { $_.Exception.Message } }
    }
    if ($resp) {
        $r.HttpsStatus = [int]$resp.StatusCode
        $r.HSTS = $resp.Headers['Strict-Transport-Security']
        $resp.Close()
    }
    return $r
}

$records = foreach ($h in $HostName) {
    Write-Verbose "Checking $h ..."
    try { [void][Net.Dns]::GetHostAddresses($h) }
    catch {
        [pscustomobject]@{ Host = $h; HttpVerdict = 'DNS lookup failed'; Port80 = ''; HttpStatus = ''; HttpLocation = '';
            HttpsStatus = ''; HSTS = ''; MaxAge = ''; IncludeSubDomains = ''; Preload = ''; Notes = '' }
        continue
    }

    $http = Test-OpsHttpPort -TargetHost $h -Timeout $TimeoutMs
    $https = Get-OpsHstsHeader -TargetHost $h -Timeout $TimeoutMs

    if ($http.Port80 -like 'Closed*' -or $http.Port80 -like 'Filtered*') {
        $verdict = 'HTTP not reachable'
    }
    elseif ($http.Port80 -ne 'Open') {
        $verdict = 'Port 80 check error'
    }
    elseif ($http.HttpStatus -is [int] -and $http.HttpStatus -ge 300 -and $http.HttpStatus -lt 400) {
        $verdict = if ($http.HttpLocation -match '^https://') { 'Redirects to HTTPS' } else { 'Redirects, NOT to HTTPS' }
    }
    elseif ($http.HttpStatus -is [int] -and $http.HttpStatus -lt 300) {
        $verdict = 'Serves content over HTTP'
    }
    elseif ($http.HttpStatus -is [int]) {
        $verdict = 'Listening, returns error (request still sent in cleartext)'
    }
    else {
        $verdict = 'Open, no valid HTTP response'
    }

    $maxAge = ''; $isd = ''; $pre = ''; $notes = @()
    if ($https.HSTS) {
        if ($https.HSTS -match 'max-age\s*=\s*"?(\d+)') { $maxAge = [long]$Matches[1] }
        $isd = [bool]($https.HSTS -match 'includeSubDomains')
        $pre = [bool]($https.HSTS -match 'preload')
        if ($maxAge -ne '' -and $maxAge -lt 31536000) { $notes += 'max-age under 1 year (preload requires >= 31536000)' }
        if ($maxAge -eq 0) { $notes += 'max-age=0 disables HSTS' }
    }
    elseif (-not $https.HttpsError) { $notes += 'No HSTS header on HTTPS response' }
    if ($https.HttpsError) { $notes += "HTTPS error: $($https.HttpsError)" }

    [pscustomobject]@{
        Host = $h; HttpVerdict = $verdict; Port80 = $http.Port80; HttpStatus = $http.HttpStatus; HttpLocation = $http.HttpLocation
        HttpsStatus = $https.HttpsStatus; HSTS = $https.HSTS; MaxAge = $maxAge; IncludeSubDomains = $isd; Preload = $pre
        Notes = ($notes -join '; ')
    }
}

$records | Format-Table Host, HttpVerdict, HttpStatus, HttpsStatus, HSTS -AutoSize -Wrap

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Full results written to $($report.CsvPath)" -InformationAction Continue

$records
