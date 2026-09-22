<#
.SYNOPSIS
Prompt for a text file of hosts, then run the external security posture sweep and
the risk-context pass over it in one step.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only against every target; it delegates to Test-ExternalSecurityPosture.ps1
  and New-SecurityFindingsRiskContext.ps1, which are themselves read-only.
- The host list lives only in the text file the caller points at (one host per
  line; blank lines and lines starting with # are ignored). No host is ever
  hard-coded in any of these three scripts.
- Interactive by default: with no -HostFile, it prompts for the path. Pass
  -HostFile to run unattended (for example from a scheduled task or another
  script).
- Works in Windows PowerShell 5.1 and PowerShell 7+.

Purpose:
This is the single entry point for "check this list of sites and tell me what a
vendor scan would find, with remediation steps and the evidence for arguing a
finding down." It reads the host file once, runs
Test-ExternalSecurityPosture.ps1 against every host in it, then feeds that run's
own output straight into New-SecurityFindingsRiskContext.ps1, so the two pieces
never go out of sync with each other.

Required syntax:
pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1
  (prompts for the host file path)

pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1 -HostFile .\hosts.txt

pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1 -HostFile .\hosts.txt -TimeoutMs 8000 -OutputDirectory .\reports\web

.OUTPUTS
Runs Test-ExternalSecurityPosture.ps1 and New-SecurityFindingsRiskContext.ps1 in
sequence, each writing its own CSV/JSON report under reports\web by default.
Returns a hashtable with Findings, Evidence, and RiskContext record sets.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$HostFile,

    [Parameter()]
    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 8000,

    [Parameter()]
    [ValidateRange(0, 30000)]
    [int]$DelayMs = 250,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

if (-not $HostFile) {
    $HostFile = Read-Host -Prompt 'Path to a text file listing the hosts to check (one per line)'
}

if (-not $HostFile -or -not (Test-Path -LiteralPath $HostFile -PathType Leaf)) {
    throw "Host file not found: '$HostFile'"
}

$rawLines = Get-Content -LiteralPath $HostFile
$hostList = @($rawLines | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })

if ($hostList.Count -eq 0) {
    throw "Host file '$HostFile' contained no usable host entries (blank lines and lines starting with # are ignored)."
}

Write-Information "Loaded $($hostList.Count) host(s) from $HostFile" -InformationAction Continue

$sweepScript = Join-Path $PSScriptRoot 'Test-ExternalSecurityPosture.ps1'
$riskContextScript = Join-Path $PSScriptRoot 'New-SecurityFindingsRiskContext.ps1'

$sweep = & $sweepScript -HostName $hostList -TimeoutMs $TimeoutMs -DelayMs $DelayMs -OutputDirectory $OutputDirectory

if ($sweep.Findings.Count -eq 0) {
    Write-Information 'No findings from the sweep; skipping the risk-context pass.' -InformationAction Continue
    return @{ Findings = $sweep.Findings; Evidence = $sweep.Evidence; RiskContext = @() }
}

$riskContext = & $riskContextScript -FindingsPath $sweep.FindingsPath -EvidencePath $sweep.EvidencePath -OutputDirectory $OutputDirectory

@{ Findings = $sweep.Findings; Evidence = $sweep.Evidence; RiskContext = $riskContext }
