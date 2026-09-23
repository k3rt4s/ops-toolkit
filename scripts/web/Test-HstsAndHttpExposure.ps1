<#
.SYNOPSIS
Check a set of hosts for a reachable plain-HTTP port 80 and for a missing or weak
Strict-Transport-Security (HSTS) header on HTTPS.

.DESCRIPTION
Instructions:
- Read this folder's README.md before running this script.
- Requires PowerShell 7.4+.
- Read-only. It opens TCP connections and sends GET requests; it changes nothing on
  the target or on this machine.
- Run it from outside the network whose hosts you are checking (a cloud VM is
  best), so results reflect what an external scanner and the public see.
- The host list is never hard-coded. Supply it with -HostName or -HostFile, or set
  the OPS_TOOLKIT_HSTS_HOSTS environment variable to a comma-separated list.
  Schemes, paths, and ports in entries are stripped.
- HTTPS is requested with certificate validation skipped, the same way a scanner
  reads headers, so a host with a mismatched certificate still reports its HSTS
  header instead of an HTTPS error.

Purpose:
A redirect from HTTP to HTTPS is not the same guarantee as HSTS: the first plaintext
request in that redirect is still interceptable, and a host that answers on port 80
at all is one an attacker can downgrade to. This reports both facts per host, plus
the HSTS header's max-age, includeSubDomains, and preload flags. The HttpVerdict
column separates a closed port 80 (nothing is ever sent in clear text) from an open
port that answers with an error (the request was still sent in clear text).

Required syntax:
pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1 -HostFile .\hosts.txt

pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1 -HostName example.com,www.example.com

pwsh -File .\scripts\web\Test-HstsAndHttpExposure.ps1 -HostFile .\hosts.txt -TimeoutMs 8000 -OutputDirectory .\reports\web

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
    [string]$OutputPrefix = 'hsts-http-exposure'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force
. (Join-Path $PSScriptRoot 'OpsWebCommon.ps1')

$HostName = Resolve-OpsWebHostList -HostName $HostName -HostFile $HostFile -EnvironmentVariable 'OPS_TOOLKIT_HSTS_HOSTS'

$records = foreach ($h in $HostName) {
    Write-Verbose "Checking $h ..."
    if (-not (Test-OpsWebIpAddress -Value $h)) {
        try { [void][Net.Dns]::GetHostAddresses($h) }
        catch {
            [pscustomobject]@{ Host = $h; HttpVerdict = 'DNS lookup failed'; Port80 = ''; HttpStatus = ''; HttpLocation = ''
                HttpsStatus = ''; HSTS = ''; MaxAge = ''; IncludeSubDomains = ''; Preload = ''; Notes = 'Host does not resolve' }
            continue
        }
    }

    $http = Get-OpsWebRawHttpResponse -TargetHost $h -Port 80 -Timeout $TimeoutMs -UserAgent $UserAgent
    $https = Get-OpsWebResponse -Url "https://$h/" -Timeout $TimeoutMs -UserAgent $UserAgent

    if ($http.PortStatus -like 'Closed*' -or $http.PortStatus -like 'Filtered*') {
        $verdict = 'HTTP not reachable'
    }
    elseif ($http.PortStatus -ne 'Open') {
        $verdict = 'Port 80 check error'
    }
    elseif ($http.HttpStatus -is [int] -and $http.HttpStatus -ge 300 -and $http.HttpStatus -lt 400) {
        $verdict = if ($http.Location -match '^https://') { 'Redirects to HTTPS' } else { 'Redirects, NOT to HTTPS' }
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

    $hsts = if ($https.Ok) { Get-OpsWebHeaderValue -Headers $https.Headers -Name 'Strict-Transport-Security' } else { '' }
    $maxAge = ''; $isd = ''; $pre = ''; $notes = @()
    if ($hsts) {
        if ($hsts -match 'max-age\s*=\s*"?(\d+)') { $maxAge = [long]$Matches[1] }
        $isd = [bool]($hsts -match '(?i)includeSubDomains')
        $pre = [bool]($hsts -match '(?i)\bpreload\b')
        if ($maxAge -ne '' -and $maxAge -lt 31536000) { $notes += 'max-age under 1 year (preload requires >= 31536000)' }
        if ($maxAge -eq 0) { $notes += 'max-age=0 disables HSTS' }
    }
    elseif ($https.Ok) { $notes += 'No HSTS header on HTTPS response' }
    if (-not $https.Ok) { $notes += "HTTPS error: $($https.Error)" }

    [pscustomobject]@{
        Host = $h; HttpVerdict = $verdict; Port80 = $http.PortStatus; HttpStatus = $http.HttpStatus; HttpLocation = $http.Location
        HttpsStatus = $https.Status; HSTS = $hsts; MaxAge = $maxAge; IncludeSubDomains = $isd; Preload = $pre
        Notes = ($notes -join '; ')
    }
}

$records | Format-Table Host, HttpVerdict, HttpStatus, HttpsStatus, HSTS -AutoSize -Wrap | Out-Host

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$report = Export-OpsReport -Name $OutputPrefix -Record $records -Directory $runDirectory
Write-Information "Full results written to $($report.CsvPath)" -InformationAction Continue

$records
