<#
.SYNOPSIS
Check a set of hosts for clickjacking protection (X-Frame-Options or CSP
frame-ancestors) and flag which of them are an actual clickjacking risk.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It sends GET requests over HTTP/HTTPS; it changes nothing on the
  target or on this machine.
- Run it from outside the network whose hosts you are checking (a home connection or
  a cloud VM), so results reflect what an external scanner and the public see rather
  than what an internal path sees.
- The host list is never hard-coded. Supply it with -HostName, or set it once in the
  OPS_TOOLKIT_XFO_HOSTS environment variable as a comma-separated list and omit
  -HostName on each run. The script refuses to run with no hosts from either source.
- Works in Windows PowerShell 5.1 and PowerShell 7+.

Purpose:
A missing X-Frame-Options/frame-ancestors header is not automatically an exploitable
finding: a JSON API, a 404 page, and a static marketing page with no form on it
cannot be meaningfully clickjacked, but a login page with the header missing can be.
This checks both the header and, for pages it can protect, whether the page actually
has a password field or a form, so the CSV separates "missing header" from "missing
header on something worth framing" instead of flagging every host at the same
severity.

Required syntax:
$env:OPS_TOOLKIT_XFO_HOSTS = 'example.com,www.example.com'
pwsh -File .\scripts\web\Test-ClickjackingProtection.ps1

pwsh -File .\scripts\web\Test-ClickjackingProtection.ps1 -HostName example.com,www.example.com

pwsh -File .\scripts\web\Test-ClickjackingProtection.ps1 -HostName example.com -TimeoutMs 8000 -OutputDirectory .\reports\web

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
    [int]$TimeoutMs = 10000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'clickjacking-protection'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

if (-not $HostName -or $HostName.Count -eq 0) {
    if ($env:OPS_TOOLKIT_XFO_HOSTS) {
        $HostName = $env:OPS_TOOLKIT_XFO_HOSTS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
}

if (-not $HostName -or $HostName.Count -eq 0) {
    throw "No hosts to check. Pass -HostName, or set `$env:OPS_TOOLKIT_XFO_HOSTS` to a comma-separated list before running this script."
}

# Windows PowerShell 5.1 may not enable TLS 1.2 by default
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

function Get-OpsPage {
    <#
    .SYNOPSIS
    Fetch a URL, following redirects, and return status, final URL, headers, and body.

    .DESCRIPTION
    A non-2xx status is still returned rather than thrown, so a 403 or 500 page's
    headers and body are inspected the same as a 200.

    .PARAMETER Url
    URL to request.

    .PARAMETER Timeout
    Connect and read timeout, in milliseconds.

    .OUTPUTS
    Hashtable with Ok, Status, FinalUrl, Headers, Body, and Error.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [int]$Timeout
    )
    $out = @{ Ok = $false; Status = ''; FinalUrl = ''; Headers = $null; Body = ''; Error = '' }
    $resp = $null
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 5
        $req.Timeout = $Timeout; $req.ReadWriteTimeout = $Timeout
        $req.UserAgent = 'ops-toolkit-xfo-check'
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
        try {
            $reader = New-Object IO.StreamReader($resp.GetResponseStream())
            $out.Body = $reader.ReadToEnd()
            $reader.Close()
        }
        catch {
            # Body is best-effort context for the verdict; a read failure here still
            # leaves the headers already captured above usable.
            Write-Verbose "Body read failed for $Url`: $($_.Exception.Message)"
        }
        $resp.Close()
    }
    return $out
}

$records = foreach ($h in $HostName) {
    Write-Verbose "Checking $h ..."

    $page = Get-OpsPage -Url "https://$h/" -Timeout $TimeoutMs
    $scheme = 'https'
    if (-not $page.Ok) {
        $httpsError = $page.Error
        $page = Get-OpsPage -Url "http://$h/" -Timeout $TimeoutMs
        $scheme = 'http (HTTPS failed)'
        if (-not $page.Ok) { $page.Error = "HTTPS: $httpsError | HTTP: $($page.Error)" }
    }

    $xfo = ''; $frameAncestors = ''; $contentType = ''; $hasPassword = $false; $hasForm = $false
    if ($page.Ok) {
        $xfo = [string]$page.Headers['X-Frame-Options']
        $csp = [string]$page.Headers['Content-Security-Policy']
        $contentType = [string]$page.Headers['Content-Type']
        if ($csp -match 'frame-ancestors\s+([^;]+)') { $frameAncestors = $Matches[1].Trim() }
        $hasPassword = [bool]($page.Body -match '(?i)<input[^>]+type\s*=\s*["'']?password')
        $hasForm = [bool]($page.Body -match '(?i)<form\b')
    }

    $isHtml = $contentType -match 'text/html'

    if (-not $page.Ok) {
        $verdict = 'Not reachable'
    }
    elseif ($xfo -match '(?i)^\s*(deny|sameorigin)\s*$') {
        $verdict = 'Protected by X-Frame-Options'
    }
    elseif ($frameAncestors -match "(?i)'none'|'self'") {
        $verdict = 'Protected by CSP frame-ancestors'
    }
    elseif ($frameAncestors) {
        $verdict = 'CSP frame-ancestors set, review value'
    }
    elseif ($contentType -and -not $isHtml) {
        $verdict = 'Non-HTML response (API or data), clickjacking not applicable'
    }
    elseif ($page.Status -ge 400) {
        $verdict = 'Error page, no content to frame'
    }
    elseif ($hasPassword) {
        $verdict = 'Login page, no framing protection (finding valid)'
    }
    elseif ($hasForm) {
        $verdict = 'HTML with forms, no framing protection (review)'
    }
    else {
        $verdict = 'HTML, no forms or logins (low risk)'
    }

    [pscustomobject]@{
        Host = $h; Verdict = $verdict; Scheme = $scheme; Status = $page.Status; FinalUrl = $page.FinalUrl
        ContentType = $contentType; XFrameOptions = $xfo; FrameAncestors = $frameAncestors
        PasswordField = $hasPassword; Form = $hasForm; Error = $page.Error
    }
}

$records | Format-Table Host, Verdict, Status, ContentType, XFrameOptions, FrameAncestors -AutoSize -Wrap

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Full results written to $($report.CsvPath)" -InformationAction Continue

$records
