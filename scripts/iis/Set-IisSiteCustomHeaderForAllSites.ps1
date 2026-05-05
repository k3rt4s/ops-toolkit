<#
.SYNOPSIS
Set one custom HTTP response header on all IIS sites.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review the target server first; this script applies one header value to every IIS site returned by IIS:\Sites.
- Run from an elevated shell on the IIS server.
- Run with -WhatIf first before making live changes.
- Review the summary output before rerunning without -WhatIf.

.PURPOSE
Use this only when one response header should be added or updated for every IIS
site on the local server. For one site, use Set-IisSiteCustomHeader.ps1.

.REQUIRED SYNTAX
pwsh -File .\scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1 -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf

.OUTPUTS
Returns one summary object containing the requested header, changed/skipped
counts, and per-site results with old value, new value, action, and reason.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
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
  pwsh -File .\scripts\iis\Set-IisSiteCustomHeaderForAllSites.ps1 -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff" -WhatIf

Options:
  -HeaderName   HTTP response header name.
  -HeaderValue  HTTP response header value.
  -WhatIf       Preview IIS changes and summary output without applying them.
'@
}

if (-not $HeaderName -or -not $HeaderValue) {
    Show-Usage
    exit 2
}

Import-Module WebAdministration -ErrorAction Stop

$filter = 'system.webServer/httpProtocol/customHeaders'

$changedCount = 0
$skippedCount = 0

$results = Get-ChildItem -Path IIS:\Sites |
    Sort-Object Name |
    ForEach-Object {
        $site = $_
        $sitePath = "IIS:\Sites\$($site.Name)"
        $existing = Get-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection |
            Where-Object { $_.name -eq $HeaderName }

            $oldValue = if ($existing) { [string]$existing.value } else { $null }
            $action = if ($existing) { 'Update' } else { 'Add' }
            $changed = $false

            if ($existing -and $oldValue -eq $HeaderValue) {
                $skippedCount++
                [pscustomobject]@{
                    SiteName = $site.Name
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
                if ($PSCmdlet.ShouldProcess($site.Name, "Update HTTP response header $HeaderName")) {
                    Set-WebConfigurationProperty -PSPath $sitePath -Filter "$filter/add[@name='$HeaderName']" -Name value -Value $HeaderValue
                    $changed = $true
                    $changedCount++
                }
            } elseif ($PSCmdlet.ShouldProcess($site.Name, "Add HTTP response header $HeaderName")) {
                Add-WebConfigurationProperty -PSPath $sitePath -Filter $filter -Name collection -Value @{
                    name = $HeaderName
                    value = $HeaderValue
                }
                $changed = $true
                $changedCount++
            }

            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = $HeaderName
                OldHeaderValue = $oldValue
                NewHeaderValue = $HeaderValue
                Action = $action
                Changed = $changed
                Reason = if ($changed) { 'Updated' } else { 'Previewed' }
            }
        }

[pscustomobject]@{
    HeaderName = $HeaderName
    HeaderValue = $HeaderValue
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    Results = @($results)
}
