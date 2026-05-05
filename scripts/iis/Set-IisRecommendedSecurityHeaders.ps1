<#
.SYNOPSIS
Apply a recommended HTTP security header preset to IIS sites.

.NOTES
AI REVIEWER - READ BEFORE EDITING
Before changing this file, read:
  C:\Code\README.md
  C:\Code\projects\SecOps\README.md

Those files define the repo workflow, script standards, archive rules, and
validation expectations. Do not guess path conventions or safety behavior.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review the preset headers before applying them to a production application.
- Run from an elevated shell on the IIS server.
- Run with -WhatIf first before making live changes.
- Use -RemoveExisting only when replacing all existing custom headers is intended.
- Review the summary output before rerunning without -WhatIf.

.PURPOSE
Use this as a curated preset for common IIS HTTP security headers. For one
custom header, use Set-IisSiteCustomHeader.ps1 or
Set-IisSiteCustomHeaderForAllSites.ps1 instead.

.REQUIRED SYNTAX
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -WhatIf
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName * -WhatIf

Custom preset example:
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -Headers @{ "X-Content-Type-Options" = "nosniff" } -WhatIf

.OUTPUTS
Returns one summary object containing target scope, changed/skipped/removed
counts, restart state, and per-site header results with old value, new value,
action, and reason.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SiteName = '*',

    [Parameter()]
    [switch]$RemoveExisting,

    [Parameter()]
    [switch]$RestartIis,

    [Parameter()]
    [hashtable]$Headers = @{
        'Content-Security-Policy' = "default-src 'self'; frame-ancestors 'self'"
        'X-Content-Type-Options' = 'nosniff'
        'Referrer-Policy' = 'strict-origin-when-cross-origin'
        'Strict-Transport-Security' = 'max-age=31536000; includeSubDomains'
        'Cache-Control' = 'no-cache, no-store'
        'Pragma' = 'no-cache'
        'Permissions-Policy' = 'geolocation=(), microphone=(), camera=()'
    }
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Invalid IIS security header input.

Usage:
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -WhatIf
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName * -WhatIf

Options:
  -SiteName        IIS site name, or * for all sites. Defaults to *.
  -Headers         Header hashtable. Defaults to the recommended preset.
  -RemoveExisting  Clear existing custom HTTP headers before applying the preset.
  -RestartIis      Restart IIS after changes are applied.
  -WhatIf          Preview IIS changes and summary output without applying them.
'@
}

function ConvertTo-ValidatedHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        Show-Usage
        throw 'Header names cannot be blank.'
    }

    if ($Name -notmatch "^[A-Za-z0-9!#$%&'*+\-.^_``|~]+$") {
        throw "Header name '$Name' contains unsupported characters."
    }

    [pscustomobject]@{
        Name = $Name
        Value = $Value
    }
}

if (-not $Headers -or $Headers.Count -eq 0) {
    Show-Usage
    throw 'Headers cannot be empty.'
}

$headerList = @(
    foreach ($headerName in $Headers.Keys) {
        ConvertTo-ValidatedHeader -Name ([string]$headerName) -Value ([string]$Headers[$headerName])
    }
) | Sort-Object Name

Import-Module WebAdministration -ErrorAction Stop

$filter = 'system.webServer/httpProtocol/customHeaders'
$sites = if ($SiteName -eq '*') {
    Get-ChildItem IIS:\Sites | Sort-Object Name
} else {
    Get-Item -Path "IIS:\Sites\$SiteName" -ErrorAction Stop
}

$changedCount = 0
$skippedCount = 0
$removedCount = 0

$results = foreach ($site in $sites) {
    $psPath = "IIS:\Sites\$($site.Name)"

    if ($RemoveExisting) {
        $existingHeaders = @(Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection)
        foreach ($existingHeader in $existingHeaders) {
            $removed = $false
            if ($PSCmdlet.ShouldProcess($site.Name, "Remove existing HTTP header $($existingHeader.name)")) {
                Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -AtElement @{ name = $existingHeader.name }
                $removedCount++
                $removed = $true
            }

            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = [string]$existingHeader.name
                OldHeaderValue = [string]$existingHeader.value
                NewHeaderValue = $null
                Action = 'Remove'
                Changed = $removed
                Reason = if ($removed) { 'Removed before preset' } elseif ($WhatIfPreference) { 'Previewed' } else { 'Skipped' }
            }
        }
    }

    foreach ($header in $headerList) {
        $existing = Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection |
            Where-Object { $_.name -eq $header.Name } |
            Select-Object -First 1

        $oldValue = if ($existing) { [string]$existing.value } else { $null }
        $action = if ($existing) { 'Update' } else { 'Add' }
        $changed = $false

        if ($existing -and $oldValue -eq $header.Value) {
            $skippedCount++
            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = $header.Name
                OldHeaderValue = $oldValue
                NewHeaderValue = $header.Value
                Action = 'None'
                Changed = $false
                Reason = 'Already set'
            }
            continue
        }

        if ($existing) {
            if ($PSCmdlet.ShouldProcess($site.Name, "Update HTTP header $($header.Name)")) {
                Set-WebConfigurationProperty -PSPath $psPath -Filter "$filter/add[@name='$($header.Name)']" -Name value -Value $header.Value
                $changed = $true
                $changedCount++
            }
        } elseif ($PSCmdlet.ShouldProcess($site.Name, "Add HTTP header $($header.Name)")) {
            Add-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -Value @{
                name = $header.Name
                value = $header.Value
            }
            $changed = $true
            $changedCount++
        }

        [pscustomobject]@{
            SiteName = $site.Name
            HeaderName = $header.Name
            OldHeaderValue = $oldValue
            NewHeaderValue = $header.Value
            Action = $action
            Changed = $changed
            Reason = if ($changed) { 'Updated' } else { 'Previewed' }
        }
    }

    $poweredBy = Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection |
        Where-Object { $_.name -eq 'X-Powered-By' } |
        Select-Object -First 1

    if ($poweredBy) {
        $removed = $false
        if ($PSCmdlet.ShouldProcess($site.Name, 'Remove X-Powered-By header')) {
            Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -AtElement @{ name = 'X-Powered-By' }
            $removedCount++
            $removed = $true
        }

        [pscustomobject]@{
            SiteName = $site.Name
            HeaderName = 'X-Powered-By'
            OldHeaderValue = [string]$poweredBy.value
            NewHeaderValue = $null
            Action = 'Remove'
            Changed = $removed
            Reason = if ($removed) { 'Removed disclosure header' } elseif ($WhatIfPreference) { 'Previewed' } else { 'Skipped' }
        }
    }
}

$restarted = $false
if ($RestartIis) {
    if ($PSCmdlet.ShouldProcess('IIS', 'Restart IIS')) {
        iisreset.exe /restart
        $restarted = $true
    }
}

[pscustomobject]@{
    SiteName = $SiteName
    RemoveExisting = [bool]$RemoveExisting
    RestartRequested = [bool]$RestartIis
    Restarted = $restarted
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    RemovedCount = $removedCount
    Results = @($results)
}
