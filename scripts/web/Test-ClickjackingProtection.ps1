<#
.SYNOPSIS
Check a set of hosts for clickjacking protection (X-Frame-Options or CSP
frame-ancestors) and flag which of them are an actual clickjacking risk.

.DESCRIPTION
Instructions:
- Read this folder's README.md before running this script.
- Requires PowerShell 7.4+.
- Read-only. It sends GET requests over HTTP/HTTPS; it changes nothing on the
  target or on this machine.
- Run it from outside the network whose hosts you are checking (a cloud VM is
  best), so results reflect what an external scanner and the public see.
- The host list is never hard-coded. Supply it with -HostName or -HostFile, or set
  the OPS_TOOLKIT_XFO_HOSTS environment variable to a comma-separated list.
  Schemes, paths, and ports in entries are stripped.
- The root (/) is always checked. Login pages often live elsewhere; pass
  -ExtraPath '/login' (or several paths) to look for a password field there too.

Purpose:
A missing X-Frame-Options/frame-ancestors header is not automatically an exploitable
finding: a JSON API, a 404 page, and a static page with no form on it cannot be
meaningfully clickjacked, but a login page with the header missing can be. This
checks the header and whether the page actually has a password field or a form. A
401 or a WWW-Authenticate header at the root is reported as "Authentication
required" rather than as an error page, because it means a login flow exists even
when no password field is visible at /.

Required syntax:
pwsh -File .\scripts\web\Test-ClickjackingProtection.ps1 -HostFile .\hosts.txt

pwsh -File .\scripts\web\Test-ClickjackingProtection.ps1 -HostName example.com,www.example.com -ExtraPath '/login'

.OUTPUTS
Writes a per-host CSV and JSON report in a timestamped folder under reports\web by
default. Returns the record set.

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
    [string[]]$ExtraPath = @(),

    [Parameter()]
    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 8000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserAgent = 'ops-toolkit-posture-check',

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
. (Join-Path $PSScriptRoot 'OpsWebCommon.ps1')

$HostName = Resolve-OpsWebHostList -HostName $HostName -HostFile $HostFile -EnvironmentVariable 'OPS_TOOLKIT_XFO_HOSTS'
$passwordPattern = '(?i)<input[^>]+type\s*=\s*["'']?password'

$records = foreach ($h in $HostName) {
    Write-Verbose "Checking $h ..."

    $page = Get-OpsWebResponse -Url "https://$h/" -Timeout $TimeoutMs -UserAgent $UserAgent -FollowRedirects
    $scheme = 'https'
    if (-not $page.Ok) {
        $httpsError = $page.Error
        $page = Get-OpsWebResponse -Url "http://$h/" -Timeout $TimeoutMs -UserAgent $UserAgent -FollowRedirects
        $scheme = 'http (HTTPS failed)'
        if (-not $page.Ok) { $page.Error = "HTTPS: $httpsError | HTTP: $($page.Error)" }
    }

    $xfo = ''; $frameAncestors = ''; $contentType = ''; $hasPassword = $false; $hasForm = $false; $wwwAuth = ''; $loginPath = ''
    if ($page.Ok) {
        $xfo = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'X-Frame-Options'
        $csp = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'Content-Security-Policy'
        $contentType = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'Content-Type'
        $wwwAuth = Get-OpsWebHeaderValue -Headers $page.Headers -Name 'WWW-Authenticate'
        if ($csp -match 'frame-ancestors\s+([^;]+)') { $frameAncestors = $Matches[1].Trim() }
        $hasPassword = [bool]($page.Body -match $passwordPattern)
        $hasForm = [bool]($page.Body -match '(?i)<form\b')
    }

    foreach ($path in @($ExtraPath | Where-Object { $_ })) {
        $p = if ($path.StartsWith('/')) { $path } else { "/$path" }
        $extra = Get-OpsWebResponse -Url "https://$h$p" -Timeout $TimeoutMs -UserAgent $UserAgent -FollowRedirects
        if ($extra.Ok -and $extra.Body -match $passwordPattern) {
            $hasPassword = $true; $hasForm = $true
            $loginPath = if ($loginPath) { "$loginPath;$p" } else { $p }
        }
    }

    $isHtml = $contentType -match '(?i)text/html'
    $authRequired = ($page.Ok -and ($page.Status -eq 401 -or [bool]$wwwAuth))

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
    elseif ($hasPassword) {
        $verdict = 'LOGIN PAGE, no framing protection (finding valid)'
    }
    elseif ($authRequired) {
        $verdict = 'Authentication required at root, no framing protection (treat as login page)'
    }
    elseif ($page.Status -eq 403) {
        $verdict = '403 at root (access restricted or WAF; re-run with a browser -UserAgent)'
    }
    elseif ($page.Status -ge 400) {
        $verdict = 'Error page, no content to frame'
    }
    elseif ($contentType -and -not $isHtml) {
        $verdict = 'Non-HTML response (API or data), clickjacking not applicable'
    }
    elseif ($hasForm) {
        $verdict = 'HTML with forms, no framing protection (review)'
    }
    else {
        $verdict = 'HTML, no forms or logins seen (low risk)'
    }

    [pscustomobject]@{
        Host = $h; Verdict = $verdict; Scheme = $scheme; Status = $page.Status; FinalUrl = $page.FinalUrl
        ContentType = $contentType; XFrameOptions = $xfo; FrameAncestors = $frameAncestors
        AuthRequired = $authRequired; PasswordField = $hasPassword; LoginPathFound = $loginPath; Form = $hasForm; Error = $page.Error
    }
}

$records | Format-Table Host, Verdict, Status, ContentType, XFrameOptions, FrameAncestors -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Full results written to $($report.CsvPath)" -InformationAction Continue

$records
