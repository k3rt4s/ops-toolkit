<#
.SYNOPSIS
Prompt for a text file of hosts, then run the external security posture sweep and
the risk-context pass over it in one step.

.DESCRIPTION
Instructions:
- Read this folder's README.md before running this script.
- Requires PowerShell 7.4+.
- Read-only against every target; it delegates to Test-ExternalSecurityPosture.ps1
  and New-SecurityFindingsRiskContext.ps1, which are themselves read-only.
- The host list lives only in the text file the caller points at (one host per
  line; blank lines and lines starting with # are ignored; schemes such as
  https:// or sftp://, paths, and ports are stripped). No host is ever hard-coded
  in any of these scripts.
- Mail-only names from the scanner's DMARC finding (for example em123.example.com)
  go in -MailHostFile, not the web host file, so they get a DMARC check without a
  web sweep.
- Interactive by default: with no -HostFile, it prompts for the path. Pass
  -HostFile to run unattended.

Purpose:
This is the single entry point for "check this list of sites and tell me what a
vendor scan would find, with remediation steps and the evidence for arguing a
finding down." It runs Test-ExternalSecurityPosture.ps1 against every host, then
feeds that run's own output straight into New-SecurityFindingsRiskContext.ps1, so
the two pieces never go out of sync.

Required syntax:
pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1
  (prompts for the host file path)

pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1 -HostFile .\hosts.txt

pwsh -File .\scripts\web\Invoke-SecurityFindingsReview.ps1 -HostFile .\hosts.txt -MailHostFile .\mail-hosts.txt -ExtraPath '/login' -TimeoutMs 8000

.OUTPUTS
Runs Test-ExternalSecurityPosture.ps1 and New-SecurityFindingsRiskContext.ps1 in
sequence, each writing its own CSV/JSON report under reports\web by default.
Returns a hashtable with Findings, Evidence, and RiskContext record sets.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter()]
    [string]$HostFile,

    [Parameter()]
    [string]$MailHostFile,

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
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\web')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force
. (Join-Path $PSScriptRoot 'OpsWebCommon.ps1')

if (-not $HostFile) {
    $HostFile = Read-Host -Prompt 'Path to a text file listing the hosts to check (one per line)'
}
$HostFile = $HostFile.Trim('"', "'", ' ')

$hostList = Resolve-OpsWebHostList -HostFile $HostFile
Write-Information "Loaded $($hostList.Count) host(s) from $HostFile" -InformationAction Continue

$sweepParams = @{
    HostName = $hostList
    TimeoutMs = $TimeoutMs
    DelayMs = $DelayMs
    UserAgent = $UserAgent
    OutputDirectory = $OutputDirectory
    ExtraPath = $ExtraPath
    UseDnsOverHttps = $UseDnsOverHttps
}
if ($ApexDomain) { $sweepParams.ApexDomain = $ApexDomain }
if ($MailHostFile) {
    $mailHosts = Resolve-OpsWebHostList -HostFile $MailHostFile
    Write-Information "Loaded $($mailHosts.Count) mail host(s) from $MailHostFile" -InformationAction Continue
    $sweepParams.MailHostName = $mailHosts
}

$sweepScript = Join-Path $PSScriptRoot 'Test-ExternalSecurityPosture.ps1'
$riskContextScript = Join-Path $PSScriptRoot 'New-SecurityFindingsRiskContext.ps1'

$sweep = & $sweepScript @sweepParams

if (@($sweep.Findings).Count -eq 0) {
    Write-Information 'No findings from the sweep; skipping the risk-context pass.' -InformationAction Continue
    return @{ Findings = $sweep.Findings; Evidence = $sweep.Evidence; RiskContext = @() }
}

$riskContext = & $riskContextScript -FindingsPath $sweep.FindingsPath -EvidencePath $sweep.EvidencePath -OutputDirectory $OutputDirectory

@{ Findings = $sweep.Findings; Evidence = $sweep.Evidence; RiskContext = $riskContext }
