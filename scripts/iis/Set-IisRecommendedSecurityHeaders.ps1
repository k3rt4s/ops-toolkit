<#
.SYNOPSIS
Apply recommended HTTP security headers to IIS sites.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-IisRecommendedSecurityHeaders.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules WebAdministration
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
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
Import-Module WebAdministration -ErrorAction Stop

$sites = if ($SiteName -eq '*') {
    Get-ChildItem IIS:\Sites
} else {
    Get-Item -Path "IIS:\Sites\$SiteName" -ErrorAction Stop
}

foreach ($site in $sites) {
    $filter = 'system.webServer/httpProtocol/customHeaders'
    $psPath = "IIS:\Sites\$($site.Name)"

    if ($RemoveExisting -and $PSCmdlet.ShouldProcess($site.Name, 'Clear existing custom HTTP headers')) {
        Clear-WebConfiguration -PSPath $psPath -Filter "$filter/add"
    }

    foreach ($headerName in $Headers.Keys) {
        $value = [string]$Headers[$headerName]
        $existing = Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection |
            Where-Object { $_.name -eq $headerName }

        if ($existing) {
            if ($PSCmdlet.ShouldProcess($site.Name, "Update HTTP header $headerName")) {
                Set-WebConfigurationProperty -PSPath $psPath -Filter "$filter/add[@name='$headerName']" -Name value -Value $value
            }
        } elseif ($PSCmdlet.ShouldProcess($site.Name, "Add HTTP header $headerName")) {
            Add-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -Value @{ name = $headerName; value = $value }
        }
    }

    $poweredBy = Get-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection |
        Where-Object { $_.name -eq 'X-Powered-By' }
    if ($poweredBy -and $PSCmdlet.ShouldProcess($site.Name, 'Remove X-Powered-By header')) {
        Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name collection -AtElement @{ name = 'X-Powered-By' }
    }
}

if ($RestartIis -and $PSCmdlet.ShouldProcess('IIS', 'Restart IIS')) {
    iisreset.exe /restart
}


