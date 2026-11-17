<#
.SYNOPSIS
Stand-in for the Dism module so scripts that enable or disable Windows optional features never change the real machine.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_OPTFEATURES to a semicolon-separated list of Name=State pairs
  describing the features this pretend build has, for example
  'SMB1Protocol=Enabled;MicrosoftWindowsPowerShellV2Root=Disabled'. A feature that is not
  listed does not exist on the pretend build and Get-WindowsOptionalFeature throws the
  "unknown feature" error for it.
- Set OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE to 'true' to make every read throw the
  elevation error an unelevated session gets on a real machine.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.
- Write-FakeDismExecutable writes a stand-in dism.exe (a .cmd that runs a .ps1) for the scripts
  that call dism.exe themselves, because under PowerShell 7 the DISM cmdlets fail with 'Class not
  registered'. Pass the returned path as -DismPath. It prints real dism output shapes for
  /Get-FeatureInfo (from OPSTOOLKIT_TEST_OPTFEATURES, an unlisted feature gives error 0x800f080c
  and exit code -2146498548) and /Get-ProvisionedAppxPackages (from OPSTOOLKIT_TEST_APPX, entries
  'DisplayName|PackageName|Version' separated by semicolons). Further variables:
  OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE (error 740), OPSTOOLKIT_TEST_DISM_GARBAGE=true (feature
  query exits 0 with no State line), OPSTOOLKIT_TEST_DISM_HANG=<feature name> (that feature query
  sleeps 120 seconds; the value Get-ProvisionedAppxPackages makes the package inventory sleep), OPSTOOLKIT_TEST_DISM_FAIL=<name> (a change of that feature or package exits
  1), OPSTOOLKIT_TEST_DISM_LOG (every call, one JSON line with the arguments and the PID).
  Changes (/Disable-Feature, /Enable-Feature, /Remove-ProvisionedAppxPackage) append a
  Dism.exe record to OPSTOOLKIT_TEST_MUTATION_LOG with the feature or package as Target.

Purpose:
Scripts under test call Get-WindowsOptionalFeature, Enable-WindowsOptionalFeature and
Disable-WindowsOptionalFeature. A same-named function does not reliably shadow commands
exported by a system module, so this module is found first on PSModulePath and the real
Dism module is never loaded. Every mutating function only records a JSON line.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeDismMutation {
    param([string]$Command, [string]$Target, [string]$Detail)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-FakeFeatureTable {
    $table = [ordered]@{}
    foreach ($pair in @(([string][Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_OPTFEATURES')) -split ';')) {
        if (-not $pair) { continue }
        $parts = $pair -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0]) { $table[$parts[0]] = $parts[1] }
    }
    $table
}

function Get-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param(
        [Parameter()][switch]$Online,
        [Parameter()][string]$FeatureName
    )

    if (([string][Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE')) -eq 'true') {
        throw 'The requested operation requires elevation.'
    }
    $table = Get-FakeFeatureTable
    if ($FeatureName) {
        if (-not $table.Contains($FeatureName)) { throw "Feature name $FeatureName is unknown." }
        return [pscustomobject]@{ FeatureName = $FeatureName; State = $table[$FeatureName] }
    }
    foreach ($key in $table.Keys) { [pscustomobject]@{ FeatureName = $key; State = $table[$key] } }
}

function Disable-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    # The real cmdlet declares no SupportsShouldProcess (checked with Get-Command, 2026-11-06), so neither does
    # this one: a -WhatIf passed to it fails to bind, as it does against the real module.
    [CmdletBinding()]
    param(
        [Parameter()][switch]$Online,
        [Parameter(Mandatory = $true)][string[]]$FeatureName,
        [Parameter()][switch]$NoRestart,
        [Parameter()][switch]$Remove
    )

    foreach ($name in $FeatureName) {
        Write-FakeDismMutation -Command 'Disable-WindowsOptionalFeature' -Target $name -Detail 'RestartNeeded=False'
    }
    [pscustomobject]@{ RestartNeeded = $false }
}

function Enable-WindowsOptionalFeature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    # The real cmdlet declares no SupportsShouldProcess (checked with Get-Command, 2026-11-06), so neither does
    # this one: a -WhatIf passed to it fails to bind, as it does against the real module.
    [CmdletBinding()]
    param(
        [Parameter()][switch]$Online,
        [Parameter(Mandatory = $true)][string[]]$FeatureName,
        [Parameter()][switch]$NoRestart,
        [Parameter()][switch]$All
    )

    foreach ($name in $FeatureName) {
        Write-FakeDismMutation -Command 'Enable-WindowsOptionalFeature' -Target $name -Detail 'RestartNeeded=False'
    }
    [pscustomobject]@{ RestartNeeded = $false }
}

$script:FakeDismScript = @'
$ErrorActionPreference = 'Stop'
$verb = ''
$featureName = ''
$packageName = ''
foreach ($a in $args) {
    if ($a -match '^/FeatureName:(.+)$') { $featureName = $Matches[1] }
    elseif ($a -match '^/PackageName:(.+)$') { $packageName = $Matches[1] }
    elseif ($a -match '^/(Get-FeatureInfo|Disable-Feature|Enable-Feature|Get-ProvisionedAppxPackages|Remove-ProvisionedAppxPackage)$') { $verb = $Matches[1] }
}
if ($env:OPSTOOLKIT_TEST_DISM_LOG) {
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_DISM_LOG -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
            Verb = $verb; Feature = $featureName; Package = $packageName; ProcessId = $PID; Arguments = ($args -join ' ') } | ConvertTo-Json -Compress)
}
function Write-Mutation([string]$Target) {
    if ($env:OPSTOOLKIT_TEST_MUTATION_LOG) {
        Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
                Command = 'Dism.exe'; Target = $Target; Detail = "/$verb" } | ConvertTo-Json -Compress)
    }
}
function Write-Header {
    'Deployment Image Servicing and Management tool'
    'Version: 10.0.26100.1'
    ''
    'Image Version: 10.0.26100.1'
    ''
}
if ($env:OPSTOOLKIT_TEST_OPTFEATURES_UNREADABLE -eq 'true' -and $verb -ne '') {
    Write-Header
    'Error: 740'
    ''
    'Elevated permissions are required to run DISM.'
    'Use an elevated command prompt to complete these tasks.'
    exit 740
}
$features = @{}
foreach ($pair in @(([string]$env:OPSTOOLKIT_TEST_OPTFEATURES) -split ';')) {
    if (-not $pair) { continue }
    $parts = $pair -split '=', 2
    if ($parts.Count -eq 2 -and $parts[0]) { $features[$parts[0]] = $parts[1] }
}
function Convert-State([string]$State) {
    switch ($State) {
        'EnablePending' { 'Enable Pending' }
        'DisablePending' { 'Disable Pending' }
        'DisabledWithPayloadRemoved' { 'Disabled with Payload Removed' }
        'PartiallyInstalled' { 'Partially Installed' }
        default { $State }
    }
}
switch ($verb) {
    'Get-FeatureInfo' {
        if ($env:OPSTOOLKIT_TEST_DISM_HANG -and $env:OPSTOOLKIT_TEST_DISM_HANG -eq $featureName) { Start-Sleep -Seconds 120 }
        Write-Header
        if ($env:OPSTOOLKIT_TEST_DISM_GARBAGE -eq 'true') {
            'Feature Information:'
            ''
            "Feature Name : $featureName"
            'The operation completed successfully.'
            exit 0
        }
        if (-not $features.ContainsKey($featureName)) {
            'Error: 0x800f080c'
            ''
            "Feature name $featureName is unknown."
            'The DISM log file can be found at C:\Windows\Logs\DISM\dism.log'
            exit -2146498548
        }
        'Feature Information:'
        ''
        "Feature Name : $featureName"
        "Display Name : $featureName"
        'Description : Stand-in feature.'
        'Restart Required : Possible'
        'State : ' + (Convert-State $features[$featureName])
        ''
        'Custom Properties:'
        ''
        '(No custom properties found)'
        ''
        'The operation completed successfully.'
        exit 0
    }
    { $_ -in 'Disable-Feature', 'Enable-Feature' } {
        Write-Header
        if ($env:OPSTOOLKIT_TEST_DISM_FAIL -eq $featureName) {
            'Error: 1'
            ''
            'Stand-in failure.'
            exit 1
        }
        Write-Mutation $featureName
        'Enabling or disabling feature(s)'
        '[==========================100.0%==========================]'
        'The operation completed successfully.'
        exit 0
    }
    'Get-ProvisionedAppxPackages' {
        if ($env:OPSTOOLKIT_TEST_DISM_HANG -eq 'Get-ProvisionedAppxPackages') { Start-Sleep -Seconds 120 }
        Write-Header
        $entries = @(([string]$env:OPSTOOLKIT_TEST_APPX) -split ';' | Where-Object { $_ })
        'Getting list of provisioned packages...'
        ''
        "Found $($entries.Count) provisioned packages."
        ''
        $n = 0
        foreach ($entry in $entries) {
            $n++
            $f = $entry -split '\|'
            "Package $n :"
            "DisplayName : $($f[0])"
            "Version : $($f[2])"
            'Architecture : neutral'
            'ResourceId : ~'
            "PackageName : $($f[1])"
            'Regions : None'
            ''
        }
        'The operation completed successfully.'
        exit 0
    }
    'Remove-ProvisionedAppxPackage' {
        Write-Header
        if ($env:OPSTOOLKIT_TEST_DISM_FAIL -and $packageName -like "*$($env:OPSTOOLKIT_TEST_DISM_FAIL)*") {
            'Error: 87'
            ''
            'Stand-in failure.'
            exit 87
        }
        Write-Mutation $packageName
        'Removing package'
        'The operation completed successfully.'
        exit 0
    }
    default {
        Write-Header
        'Error: 87'
        ''
        'The stand-in dism.exe does not know this option.'
        exit 87
    }
}
'@

function Write-FakeDismExecutable {
    <#
    .SYNOPSIS
    Write a stand-in dism.exe into a directory and return the path of the launcher to pass as -DismPath.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Directory)

    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $scriptPath = Join-Path $Directory 'fake-dism.ps1'
    $launcher = Join-Path $Directory 'fake-dism.cmd'
    Set-Content -LiteralPath $scriptPath -Value $script:FakeDismScript -Encoding utf8 -WhatIf:$false
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $pwsh)) { $pwsh = Join-Path $PSHOME 'powershell.exe' }
    Set-Content -LiteralPath $launcher -Encoding ascii -WhatIf:$false -Value @(
        '@echo off'
        "`"$pwsh`" -NoProfile -NonInteractive -File `"%~dp0fake-dism.ps1`" %*"
        'exit /b %ERRORLEVEL%'
    )
    $launcher
}

Export-ModuleMember -Function 'Get-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Enable-WindowsOptionalFeature', 'Write-FakeDismExecutable'
