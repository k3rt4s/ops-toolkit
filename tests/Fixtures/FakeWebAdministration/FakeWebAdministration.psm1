<#
.SYNOPSIS
Stand-in for the WebAdministration module so the IIS scripts can be run end to end without IIS.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeWebAdministration` in TestHelpers.psm1 stages
  it on PSModulePath under the name WebAdministration and hands back the path.
- Set OPSTOOLKIT_TEST_IIS_SITES to a semicolon-separated list of site names before
  running a script under test. Set OPSTOOLKIT_TEST_IIS_HEADERS to a JSON object
  keyed by site name holding the headers that site already has.
- Set OPSTOOLKIT_TEST_IIS_REMOVESERVERHEADER to a JSON object keyed by site name
  holding the requestFiltering removeServerHeader value (true or false). A site
  that is absent reads false. The value "unsupported", for one site or as the whole
  variable, makes the read return $null the way an IIS without the attribute does.
- Set OPSTOOLKIT_TEST_IIS_HSTS to a JSON object keyed by site name holding the native
  hsts attributes (enabled, max-age, includeSubDomains, redirectHttpToHttps). Absent attributes read
  false or 0. "unsupported" works as for removeServerHeader (IIS before 10 version 1709).
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted configuration writes. Writes
  at MACHINE/WEBROOT/APPHOST record the site named in the filter's [@name='...'].
- Add a cmdlet here only when a script under test actually calls it, and make it
  behave the way the real one does in the cases that matter.

Purpose:
The IIS scripts call `Import-Module WebAdministration -ErrorAction Stop` and then walk
the IIS: drive, so on a machine with no IIS they stop at the import and none of their
logic can be exercised. This module satisfies the import, creates an IIS: drive over a
temporary directory so `Get-ChildItem IIS:\Sites` returns one item per site, and
supplies the configuration cmdlets.

The drive is a real PSDrive over the file system rather than a stub of Get-ChildItem,
because shadowing Get-ChildItem would change the behaviour of every other command in
the script as well.

What this proves and what it does not: it proves the scripts' own logic, including
which sites they would touch and what they would write. It cannot prove that a real
IIS configuration store accepts those calls.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

# The drive root lives inside the staged module directory, so the caller removing that
# directory removes this too. A separate temp directory would survive every run and
# accumulate, since a module has no reliable teardown hook.
$script:DriveRoot = Join-Path $PSScriptRoot 'iis-drive'

function Write-FakeIisMutation {
    <#
    .SYNOPSIS
    Append one attempted configuration change to the mutation log a test is watching.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter()][string]$PSPath,
        [Parameter()][string]$Filter,
        [Parameter()][string]$Name,
        [Parameter()]$Value
    )

    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }

    # APPHOST-level writes carry no site in the path, only in the filter.
    $siteName = ($PSPath -replace '^IIS:\\Sites\\', '')
    if ($PSPath -like 'MACHINE/WEBROOT/APPHOST*' -and $Filter -match "\[@name='([^']*)'\]") {
        $siteName = $Matches[1]
    }

    $rendered = if ($Value -is [System.Collections.IDictionary]) {
        (($Value.Keys | Sort-Object | ForEach-Object { "$_=$($Value[$_])" }) -join ',')
    } else {
        [string]$Value
    }

    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command
            Site    = $siteName
            Filter  = $Filter
            Name    = $Name
            Value   = $rendered
        } | ConvertTo-Json -Compress)
}

function Get-FakeIisSiteHeader {
    <#
    .SYNOPSIS
    Read the headers a site already has, from the fixture environment.
    #>
    param([string]$Site)

    if (-not $env:OPSTOOLKIT_TEST_IIS_HEADERS) { return @() }
    $bySite = $env:OPSTOOLKIT_TEST_IIS_HEADERS | ConvertFrom-Json
    $match = $bySite.PSObject.Properties | Where-Object { $_.Name -eq $Site }
    if (-not $match) { return @() }

    @($match.Value | ForEach-Object {
            # The real cmdlet returns objects carrying lowercase name and value
            # properties, which is what the scripts filter on.
            [pscustomobject]@{ name = $_.name; value = $_.value }
        })
}

function Get-FakeIisSiteSetting {
    <#
    .SYNOPSIS
    Read one site's entry from a JSON fixture variable, or flag it unsupported.

    .DESCRIPTION
    Returns a result object with Supported and Value. Supported is false when the whole
    variable, or the site's entry, is the string "unsupported". Value is $null when the
    variable is unset or has no entry for the site.
    #>
    param([string]$EnvName, [string]$Site)

    $raw = [Environment]::GetEnvironmentVariable($EnvName)
    if ($raw -eq 'unsupported') { return [pscustomobject]@{ Supported = $false; Value = $null } }
    if (-not $raw) { return [pscustomobject]@{ Supported = $true; Value = $null } }

    $match = ($raw | ConvertFrom-Json).PSObject.Properties | Where-Object { $_.Name -eq $Site }
    if (-not $match) { return [pscustomobject]@{ Supported = $true; Value = $null } }
    if ($match.Value -is [string] -and $match.Value -eq 'unsupported') {
        return [pscustomobject]@{ Supported = $false; Value = $null }
    }

    [pscustomobject]@{ Supported = $true; Value = $match.Value }
}

function Get-WebConfigurationProperty {
    [CmdletBinding()]
    param(
        [Parameter()]$PSPath, [Parameter()]$Filter, [Parameter()]$Name, [Parameter()]$Location
    )

    if ([string]$Filter -match 'customFields') {
        if (-not $env:OPSTOOLKIT_TEST_IIS_LOGFIELDS) { return @() }
        return @($env:OPSTOOLKIT_TEST_IIS_LOGFIELDS | ConvertFrom-Json | ForEach-Object {
                [pscustomobject]@{ logFieldName = $_.logFieldName; sourceName = $_.sourceName; sourceType = $_.sourceType }
            })
    }

    if ([string]$Filter -match 'requestFiltering') {
        # The real cmdlet returns a ConfigurationAttribute whose Value holds the
        # setting, and nothing at all for an attribute the installed IIS lacks.
        $setting = Get-FakeIisSiteSetting -EnvName 'OPSTOOLKIT_TEST_IIS_REMOVESERVERHEADER' -Site ([string]$PSPath -replace '^IIS:\\Sites\\', '')
        if (-not $setting.Supported) { return $null }
        return [pscustomobject]@{ Value = [bool]$setting.Value }
    }

    if ([string]$Filter -match '/hsts$') {
        if ([string]$Filter -notmatch "\[@name='([^']*)'\]") { return $null }
        $setting = Get-FakeIisSiteSetting -EnvName 'OPSTOOLKIT_TEST_IIS_HSTS' -Site $Matches[1]
        if (-not $setting.Supported) { return $null }

        $attribute = [string]$Name
        $current = if ($setting.Value) { $setting.Value.PSObject.Properties | Where-Object { $_.Name -eq $attribute } } else { $null }
        $default = if ($attribute -eq 'max-age') { 0 } else { $false }
        return [pscustomobject]@{ Value = if ($current) { $current.Value } else { $default } }
    }

    # Only the header collection is answered with headers. Any other filter reads
    # nothing, so a new read cannot be mistaken for the header list.
    if ([string]$Filter -match 'customHeaders') {
        return Get-FakeIisSiteHeader -Site ([string]$PSPath -replace '^IIS:\\Sites\\', '')
    }

    $null
}

function Set-WebConfigurationProperty {
    [CmdletBinding()]
    param(
        [Parameter()]$PSPath, [Parameter()]$Filter, [Parameter()]$Name,
        [Parameter()]$Value, [Parameter()]$Location, [Parameter()]$AtElement
    )
    Write-FakeIisMutation -Command 'Set-WebConfigurationProperty' -PSPath $PSPath -Filter $Filter -Name $Name -Value $Value
}

function Add-WebConfigurationProperty {
    [CmdletBinding()]
    param(
        [Parameter()]$PSPath, [Parameter()]$Filter, [Parameter()]$Name,
        [Parameter()]$Value, [Parameter()]$Location, [Parameter()]$AtElement
    )
    Write-FakeIisMutation -Command 'Add-WebConfigurationProperty' -PSPath $PSPath -Filter $Filter -Name $Name -Value $Value
}

function Remove-WebConfigurationProperty {
    [CmdletBinding()]
    param(
        [Parameter()]$PSPath, [Parameter()]$Filter, [Parameter()]$Name,
        [Parameter()]$Location, [Parameter()]$AtElement
    )
    $rendered = if ($AtElement -is [System.Collections.IDictionary]) {
        (($AtElement.Keys | Sort-Object | ForEach-Object { "$_=$($AtElement[$_])" }) -join ',')
    } else {
        [string]$AtElement
    }
    Write-FakeIisMutation -Command 'Remove-WebConfigurationProperty' -PSPath $PSPath -Filter $Filter -Name $Name -Value $rendered
}

function Restart-WebAppPool {
    [CmdletBinding()]
    param([Parameter()]$Name)
    Write-FakeIisMutation -Command 'Restart-WebAppPool' -Name ([string]$Name)
}

# Build the IIS: drive at import time. Every site named in the fixture becomes a
# directory, so Get-ChildItem IIS:\Sites returns one item per site with a Name
# property, and Get-Item IIS:\Sites\<name> resolves or throws exactly as the real
# provider would for a site that does not exist.
$sitesDirectory = Join-Path $script:DriveRoot 'Sites'
New-Item -ItemType Directory -Path $sitesDirectory -Force | Out-Null
foreach ($site in @(($env:OPSTOOLKIT_TEST_IIS_SITES -split ';') | Where-Object { $_ })) {
    New-Item -ItemType Directory -Path (Join-Path $sitesDirectory $site) -Force | Out-Null
}

if (-not (Get-PSDrive -Name 'IIS' -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name 'IIS' -PSProvider FileSystem -Root $script:DriveRoot -Scope Global | Out-Null
}

Export-ModuleMember -Function 'Get-WebConfigurationProperty', 'Set-WebConfigurationProperty',
'Add-WebConfigurationProperty', 'Remove-WebConfigurationProperty', 'Restart-WebAppPool'
