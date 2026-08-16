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
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted configuration writes.
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

$script:DriveRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-fakeiis-$([guid]::NewGuid().ToString('N'))"

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

    $rendered = if ($Value -is [System.Collections.IDictionary]) {
        (($Value.Keys | Sort-Object | ForEach-Object { "$_=$($Value[$_])" }) -join ',')
    } else {
        [string]$Value
    }

    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command
            Site    = ($PSPath -replace '^IIS:\\Sites\\', '')
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

    Get-FakeIisSiteHeader -Site ([string]$PSPath -replace '^IIS:\\Sites\\', '')
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
