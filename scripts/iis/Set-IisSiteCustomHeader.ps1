<#
.SYNOPSIS
Set one custom HTTP response header on one IIS site.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\ops-toolkit\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Confirm the target IIS site name before running.
- Run from an elevated shell on the IIS server.
- Run with -WhatIf first before making live changes.
- Review the summary output before rerunning without -WhatIf.

.PURPOSE
Use this when one response header should be added or updated for one IIS site.
For every IIS site on the local server, use Set-IisSiteCustomHeaderForAllSites.ps1.

.REQUIRED SYNTAX
pwsh -File .\scripts\iis\Set-IisSiteCustomHeader.ps1 -SiteName "Default Web Site" -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf

.OUTPUTS
Returns one summary object containing the site name, requested header, old value,
new value, action, changed state, and reason.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SiteName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[A-Za-z0-9!#$%&'*+\-.^_``|~]+$")]
    [string]$HeaderName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderValue
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\iis\Set-IisSiteCustomHeader.ps1 -SiteName "Default Web Site" -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf

Options:
  -SiteName     IIS site name.
  -HeaderName   HTTP response header name.
  -HeaderValue  HTTP response header value.
  -WhatIf       Preview IIS changes and summary output without applying them.
'@
}

if (-not $SiteName -or -not $HeaderName -or -not $HeaderValue) {
    Show-Usage
    exit 2
}

Import-Module WebAdministration -ErrorAction Stop

$sitePath = "IIS:\Sites\$SiteName"
if (-not (Test-Path -LiteralPath $sitePath)) {
    throw "IIS site '$SiteName' was not found."
}

$filter = 'system.webServer/httpProtocol/customHeaders'
$existing = Get-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection |
    Where-Object { $_.name -eq $HeaderName }

$oldValue = if ($existing) { [string]$existing.value } else { $null }
$action = if ($existing) { 'Update' } else { 'Add' }
$changed = $false

if ($existing -and $oldValue -eq $HeaderValue) {
    [pscustomobject]@{
        SiteName = $SiteName
        HeaderName = $HeaderName
        OldHeaderValue = $oldValue
        NewHeaderValue = $HeaderValue
        Action = 'None'
        Changed = $false
        Reason = 'Already set'
    }
    return
}

if ($existing) {
    if ($PSCmdlet.ShouldProcess($SiteName, "Update HTTP response header $HeaderName")) {
        Set-WebConfigurationProperty -PSPath $sitePath -Filter "$filter/add[@name='$HeaderName']" -Name value -Value $HeaderValue
        $changed = $true
    }
} elseif ($PSCmdlet.ShouldProcess($SiteName, "Add HTTP response header $HeaderName")) {
    Add-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection -Value @{
        name = $HeaderName
        value = $HeaderValue
    }
    $changed = $true
}

[pscustomobject]@{
    SiteName = $SiteName
    HeaderName = $HeaderName
    OldHeaderValue = $oldValue
    NewHeaderValue = $HeaderValue
    Action = $action
    Changed = $changed
    Reason = if ($changed) { 'Updated' } else { 'Previewed' }
}
