<#
.SYNOPSIS
Apply a recommended HTTP security header preset to IIS sites.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Review the preset headers before applying them to a production application.
- Run from an elevated shell on the IIS server.
- Run with -WhatIf first before making live changes.
- Start with -CspReportOnly on an existing application, review the violation reports, then rerun without it.
- Use -RemoveExisting only when replacing all existing custom headers is intended.
- When using -RemoveExisting, review the generated backup report before applying changes.
- Review the summary output before rerunning without -WhatIf.

Purpose:
Use this as a curated preset for common IIS HTTP security headers. For one
custom header, use Set-IisSiteCustomHeader.ps1 or
Set-IisSiteCustomHeaderForAllSites.ps1 instead.

The default preset sets Content-Security-Policy (default-src 'self'; object-src
'none'; base-uri 'self'; frame-ancestors 'self'), X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy,
Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies, and
Strict-Transport-Security (max-age only). It also removes the X-Powered-By custom
header and turns on the Server header removal (requestFiltering
removeServerHeader, which needs IIS 10 version 1607 or later; a site that does not
support it is reported as NotRun, not as a failure). Cache-Control is not set by
default because no-store on every response breaks caching of static content; use
-IncludeNoStore for sites that serve only sensitive pages. Pragma is not set.

Required syntax:
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -WhatIf
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName * -WhatIf
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -RemoveExisting -WhatIf

Report-only CSP example:
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -CspReportOnly -WhatIf

Native HSTS example (IIS 10 version 1709 or later):
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -UseNativeHsts -HstsIncludeSubDomains -WhatIf

Custom preset example:
pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -Headers @{ "X-Content-Type-Options" = "nosniff" } -WhatIf

.PARAMETER SiteName
IIS site name, or * for all sites. Defaults to *.

.PARAMETER RemoveExisting
Clear existing custom HTTP headers before applying the preset. A backup report is written first.

.PARAMETER RestartIis
Restart IIS after changes are applied.

.PARAMETER BackupReportPath
CSV report path for -RemoveExisting review. Defaults under reports\iis.

.PARAMETER Headers
Custom header hashtable that replaces the preset entirely. Cannot be combined with
-CspReportOnly or -IncludeNoStore. A Strict-Transport-Security entry cannot be
combined with -UseNativeHsts, -HstsIncludeSubDomains, or -HstsMaxAgeSeconds.

.PARAMETER CspReportOnly
Send the preset policy as Content-Security-Policy-Report-Only instead of
Content-Security-Policy, so violations are reported without blocking anything.

.PARAMETER HstsIncludeSubDomains
Add includeSubDomains to Strict-Transport-Security. Use only after every subdomain
serves HTTPS, because it applies to all of them at once.

.PARAMETER HstsMaxAgeSeconds
HSTS max-age in seconds, 0 to 63072000. Defaults to 31536000 (one year).

.PARAMETER UseNativeHsts
Configure the IIS native HSTS feature (system.applicationHost hsts element, IIS 10
version 1709 or later) instead of sending a custom Strict-Transport-Security header,
and remove any custom Strict-Transport-Security header so it is not sent twice. The
run stops before any change if a target site does not support it. The
redirectHttpToHttps attribute is never changed.

.PARAMETER IncludeNoStore
Add Cache-Control: no-store to the preset.

.PARAMETER KeepServerHeader
Leave the Server response header alone instead of turning on removeServerHeader.

.OUTPUTS
Returns one summary object containing target scope, changed/skipped/removed/not-run
counts, restart state, optional backup report path, and per-site header results
with old value, new value, action, and reason.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
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
    [ValidateNotNullOrEmpty()]
    [string]$BackupReportPath,

    [Parameter()]
    [hashtable]$Headers,

    [Parameter()]
    [switch]$CspReportOnly,

    [Parameter()]
    [switch]$HstsIncludeSubDomains,

    [Parameter()]
    [ValidateRange(0, 63072000)]
    [int]$HstsMaxAgeSeconds = 31536000,

    [Parameter()]
    [switch]$UseNativeHsts,

    [Parameter()]
    [switch]$IncludeNoStore,

    [Parameter()]
    [switch]$KeepServerHeader
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Invalid IIS security header input.

Usage:
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -WhatIf
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName * -WhatIf
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -CspReportOnly -WhatIf
  pwsh -File .\scripts\iis\Set-IisRecommendedSecurityHeaders.ps1 -SiteName "Default Web Site" -UseNativeHsts -WhatIf

Options:
  -SiteName        IIS site name, or * for all sites. Defaults to *.
  -Headers         Header hashtable. Replaces the recommended preset. Cannot be combined
                   with -CspReportOnly or -IncludeNoStore, or (with a
                   Strict-Transport-Security entry) with the -Hsts* and -UseNativeHsts options.
  -CspReportOnly   Send the CSP as Content-Security-Policy-Report-Only.
  -HstsIncludeSubDomains
                   Add includeSubDomains to HSTS.
  -HstsMaxAgeSeconds
                   HSTS max-age, 0 to 63072000. Defaults to 31536000.
  -UseNativeHsts   Configure native IIS HSTS (IIS 10 version 1709 or later) instead of a custom header.
  -IncludeNoStore  Add Cache-Control: no-store.
  -KeepServerHeader
                   Do not turn on removeServerHeader (IIS 10 version 1607 or later).
  -RemoveExisting  Clear existing custom HTTP headers before applying the preset.
  -RestartIis      Restart IIS after changes are applied.
  -BackupReportPath
                   CSV report path for -RemoveExisting review. Defaults under reports\iis.
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

    # The single quote is a valid token character but the name is interpolated into
    # an XPath filter add[@name='...'], so it is rejected.
    if ($Name -notmatch "^[A-Za-z0-9!#$%&*+\-.^_``|~]+$") {
        throw "Header name '$Name' contains unsupported characters."
    }

    # Horizontal tab is allowed in a header value; every other control character
    # (CR and LF in particular) is rejected.
    if ($Value -match '[\x00-\x08\x0A-\x1F\x7F]') {
        throw "Header '$Name' has a value containing control characters, which are not allowed."
    }

    [pscustomobject]@{
        Name = $Name
        Value = $Value
    }
}

function Get-ConfigAttributeValue {
    <#
    .SYNOPSIS
    Read one IIS configuration attribute, or return $null when it cannot be read.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$PSPath,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    # An attribute the installed IIS does not know either comes back null or throws.
    # Both mean unsupported, and the caller decides what that costs.
    try {
        $raw = Get-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name
    } catch {
        return $null
    }

    if ($null -eq $raw) { return $null }
    if ($raw -is [bool] -or $raw -is [string] -or $raw -is [ValueType]) { return $raw }

    # The real cmdlet returns a ConfigurationAttribute whose Value is the setting.
    $valueProperty = $raw.PSObject.Properties['Value']
    if ($valueProperty) { return $valueProperty.Value }

    $raw
}

function New-HeaderReplacementReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Sites,

        [Parameter(Mandatory = $true)]
        [object[]]$HeaderList,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Filter
    )

    $directory = Split-Path -Parent $Path
    if ($directory) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $presetByName = @{}
    foreach ($header in $HeaderList) {
        $presetByName[$header.Name] = $header.Value
    }

    $rows = foreach ($site in $Sites) {
        $psPath = "IIS:\Sites\$($site.Name)"
        $existingHeaders = @(Get-WebConfigurationProperty -PSPath $psPath -Filter $Filter -Name collection)
        $existingByName = @{}

        foreach ($existingHeader in $existingHeaders) {
            $existingByName[[string]$existingHeader.name] = [string]$existingHeader.value
        }

        $allNames = @($existingByName.Keys + $presetByName.Keys) |
            Sort-Object -Unique

        foreach ($headerName in $allNames) {
            $oldValue = if ($existingByName.ContainsKey($headerName)) { $existingByName[$headerName] } else { $null }
            $newValue = if ($presetByName.ContainsKey($headerName)) { $presetByName[$headerName] } else { $null }
            $inPreset = $presetByName.ContainsKey($headerName)
            $existsNow = $existingByName.ContainsKey($headerName)

            $plannedAction = if ($inPreset -and $existsNow) {
                if ($oldValue -eq $newValue) { 'ReplaceWithSameValue' } else { 'ReplaceWithPresetValue' }
            } elseif ($inPreset) {
                'AddPresetHeader'
            } else {
                'RemoveExistingHeader'
            }

            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = $headerName
                ExistingHeaderValue = $oldValue
                PresetHeaderValue = $newValue
                PlannedAction = $plannedAction
                ExistingHeader = $existsNow
                PresetHeader = $inPreset
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($Path, 'Write IIS security header replacement review report')) {
        @($rows) | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
    }

    (Resolve-Path -LiteralPath $Path).Path
}

# Conflicting switches are rejected before anything is read or written.
$headersBound = $PSBoundParameters.ContainsKey('Headers')
$maxAgeBound = $PSBoundParameters.ContainsKey('HstsMaxAgeSeconds')

if ($headersBound) {
    if (-not $Headers -or $Headers.Count -eq 0) {
        Show-Usage
        throw 'Headers cannot be empty.'
    }

    if ($CspReportOnly -or $IncludeNoStore) {
        Show-Usage
        throw '-Headers replaces the preset, so it cannot be combined with -CspReportOnly or -IncludeNoStore.'
    }

    $customHasSts = @($Headers.Keys | Where-Object { [string]$_ -ieq 'Strict-Transport-Security' }).Count -gt 0
    if ($customHasSts -and ($UseNativeHsts -or $HstsIncludeSubDomains -or $maxAgeBound)) {
        Show-Usage
        throw '-Headers already contains Strict-Transport-Security, so it cannot be combined with -UseNativeHsts, -HstsIncludeSubDomains, or -HstsMaxAgeSeconds.'
    }

    if (-not $customHasSts -and -not $UseNativeHsts -and ($HstsIncludeSubDomains -or $maxAgeBound)) {
        Show-Usage
        throw '-HstsIncludeSubDomains and -HstsMaxAgeSeconds do nothing here: -Headers has no Strict-Transport-Security entry and -UseNativeHsts is not set.'
    }
} else {
    $cspName = if ($CspReportOnly) { 'Content-Security-Policy-Report-Only' } else { 'Content-Security-Policy' }
    $Headers = @{
        $cspName = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
        'X-Content-Type-Options' = 'nosniff'
        'X-Frame-Options' = 'SAMEORIGIN'
        'Referrer-Policy' = 'strict-origin-when-cross-origin'
        'Permissions-Policy' = 'geolocation=(), microphone=(), camera=()'
        'Cross-Origin-Opener-Policy' = 'same-origin'
        'Cross-Origin-Resource-Policy' = 'same-site'
        'X-Permitted-Cross-Domain-Policies' = 'none'
    }

    if (-not $UseNativeHsts) {
        $stsValue = "max-age=$HstsMaxAgeSeconds"
        if ($HstsIncludeSubDomains) { $stsValue += '; includeSubDomains' }
        $Headers['Strict-Transport-Security'] = $stsValue
    }

    if ($IncludeNoStore) {
        $Headers['Cache-Control'] = 'no-store'
    }
}

$headerList = @(
    foreach ($headerName in $Headers.Keys) {
        ConvertTo-ValidatedHeader -Name ([string]$headerName) -Value ([string]$Headers[$headerName])
    }
) | Sort-Object Name

Import-Module WebAdministration -ErrorAction Stop

$filter = 'system.webServer/httpProtocol/customHeaders'
$requestFilteringFilter = 'system.webServer/security/requestFiltering'
$apphostPath = 'MACHINE/WEBROOT/APPHOST'
$sites = if ($SiteName -eq '*') {
    Get-ChildItem IIS:\Sites | Sort-Object Name
} else {
    Get-Item -Path "IIS:\Sites\$SiteName" -ErrorAction Stop
}

if ($UseNativeHsts) {
    # Preflight every target site before any write, so a server that lacks native HSTS
    # is not left half configured.
    foreach ($site in @($sites)) {
        if ([string]$site.Name -match "'") {
            throw "Site name '$($site.Name)' contains a single quote and cannot be used in a native HSTS configuration filter."
        }
    }

    foreach ($site in @($sites)) {
        $hstsFilter = "system.applicationHost/sites/site[@name='$($site.Name)']/hsts"
        $probe = Get-ConfigAttributeValue -PSPath $apphostPath -Filter $hstsFilter -Name 'enabled'
        if ($null -eq $probe) {
            throw 'Native HSTS needs IIS 10 version 1709 or later; rerun without -UseNativeHsts to send HSTS as a custom header.'
        }
    }
}

$changedCount = 0
$skippedCount = 0
$removedCount = 0
$notRunCount = 0
$resolvedBackupReportPath = $null

if ($RemoveExisting) {
    if (-not $BackupReportPath) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $BackupReportPath = Join-Path $PSScriptRoot "..\..\reports\iis\security-header-replacement-$timestamp.csv"
    }

    $resolvedBackupReportPath = New-HeaderReplacementReport -Sites @($sites) -HeaderList @($headerList) -Path $BackupReportPath -Filter $filter -WhatIf:$false
    Write-Information "IIS security header replacement report written to $resolvedBackupReportPath" -InformationAction Continue
}

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

    if (-not $KeepServerHeader) {
        $serverState = Get-ConfigAttributeValue -PSPath $psPath -Filter $requestFilteringFilter -Name 'removeServerHeader'

        if ($null -eq $serverState) {
            $notRunCount++
            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = 'Server'
                OldHeaderValue = $null
                NewHeaderValue = $null
                Action = 'NotRun'
                Changed = $false
                Reason = 'removeServerHeader not supported (needs IIS 10 version 1607 or later)'
            }
        } elseif ([bool]$serverState) {
            $skippedCount++
            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = 'Server'
                OldHeaderValue = $null
                NewHeaderValue = $null
                Action = 'None'
                Changed = $false
                Reason = 'Already set'
            }
        } else {
            $changed = $false
            if ($PSCmdlet.ShouldProcess($site.Name, 'Turn on removeServerHeader')) {
                Set-WebConfigurationProperty -PSPath $psPath -Filter $requestFilteringFilter -Name removeServerHeader -Value $true
                $changed = $true
                $changedCount++
            }

            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = 'Server'
                OldHeaderValue = $null
                NewHeaderValue = $null
                Action = 'Update'
                Changed = $changed
                Reason = if ($changed) { 'Updated' } else { 'Previewed' }
            }
        }
    }

    if ($UseNativeHsts) {
        $hstsFilter = "system.applicationHost/sites/site[@name='$($site.Name)']/hsts"
        $wanted = [ordered]@{
            'enabled' = $true
            'max-age' = [int64]$HstsMaxAgeSeconds
            'includeSubDomains' = [bool]$HstsIncludeSubDomains
        }

        foreach ($attribute in $wanted.Keys) {
            $current = Get-ConfigAttributeValue -PSPath $apphostPath -Filter $hstsFilter -Name $attribute
            $label = "Strict-Transport-Security (native $attribute)"

            if ($null -ne $current -and [string]$current -eq [string]$wanted[$attribute]) {
                $skippedCount++
                [pscustomobject]@{
                    SiteName = $site.Name
                    HeaderName = $label
                    OldHeaderValue = [string]$current
                    NewHeaderValue = [string]$wanted[$attribute]
                    Action = 'None'
                    Changed = $false
                    Reason = 'Already set'
                }
                continue
            }

            $changed = $false
            if ($PSCmdlet.ShouldProcess($site.Name, "Set native HSTS $attribute to $($wanted[$attribute])")) {
                Set-WebConfigurationProperty -PSPath $apphostPath -Filter $hstsFilter -Name $attribute -Value $wanted[$attribute]
                $changed = $true
                $changedCount++
            }

            [pscustomobject]@{
                SiteName = $site.Name
                HeaderName = $label
                OldHeaderValue = if ($null -ne $current) { [string]$current } else { $null }
                NewHeaderValue = [string]$wanted[$attribute]
                Action = 'Update'
                Changed = $changed
                Reason = if ($changed) { 'Updated' } else { 'Previewed' }
            }
        }

        # A custom Strict-Transport-Security header left in place would be sent
        # alongside the native one. With -RemoveExisting it is already gone.
        if (-not $RemoveExisting) {
            $customSts = Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection |
                Where-Object { $_.name -ieq 'Strict-Transport-Security' } |
                Select-Object -First 1

            if ($customSts) {
                $removed = $false
                if ($PSCmdlet.ShouldProcess($site.Name, 'Remove custom Strict-Transport-Security header')) {
                    Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -AtElement @{ name = [string]$customSts.name }
                    $removedCount++
                    $removed = $true
                }

                [pscustomobject]@{
                    SiteName = $site.Name
                    HeaderName = [string]$customSts.name
                    OldHeaderValue = [string]$customSts.value
                    NewHeaderValue = $null
                    Action = 'Remove'
                    Changed = $removed
                    Reason = if ($removed) { 'Replaced by native HSTS' } elseif ($WhatIfPreference) { 'Previewed' } else { 'Skipped' }
                }
            }
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
    BackupReportPath = $resolvedBackupReportPath
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    RemovedCount = $removedCount
    NotRunCount = $notRunCount
    CspReportOnly = [bool]$CspReportOnly
    UseNativeHsts = [bool]$UseNativeHsts
    ServerHeaderRemoval = (-not $KeepServerHeader)
    Results = @($results)
}
