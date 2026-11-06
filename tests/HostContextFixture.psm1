#Requires -Version 7.4
Set-StrictMode -Version 3.0

# Stages a pretend host for tests of scripts that call Get-OpsHostContext: a stand-in for dsregcmd.exe
# and a JSON fact table that replaces the registry, service and CIM probes. No test that runs a
# hardening script may reach the real dsregcmd.exe or read the real machine, so every such test file
# calls Use-FakeHostContext once and then names a host kind only where the kind matters.

# Facts for every probe the module can replace. A kind overrides only what differs from Physical.
$script:Kinds = @{
    Physical = @{ Join = 'Workgroup'; Fact = @{} }
    Avd = @{ Join = 'Entra'; Fact = @{ RdInfraAgentKey = 'present'; RdAgentService = 'present'; Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' } }
    AvdMarkerKeyOnly = @{ Join = 'Entra'; Fact = @{ RdInfraAgentKey = 'present'; Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' } }
    AvdUnread = @{ Join = 'Entra'; Fact = @{ RdInfraAgentKey = 'error'; RdAgentService = 'absent' } }
    Domain = @{ Join = 'Domain'; Fact = @{} }
    HybridMdm = @{ Join = 'Hybrid'; Fact = @{ Enrollments = @('MS DM Server') } }
    JoinUnread = @{ Join = 'Missing'; Fact = @{} }
    EntraJoined = @{ Join = 'Entra'; Fact = @{} }
}

function Get-FakeHostFactText {
    <#
    .SYNOPSIS
    Return the JSON text of the host fact table for one host kind.

    .PARAMETER Kind
    Physical, Avd, AvdMarkerKeyOnly, AvdUnread, Domain, HybridMdm, JoinUnread or EntraJoined (Entra-joined physical host).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Physical', 'Avd', 'AvdMarkerKeyOnly', 'AvdUnread', 'Domain', 'HybridMdm', 'JoinUnread', 'EntraJoined')][string]$Kind)
    $facts = [ordered]@{ RdInfraAgentKey = 'absent'; RdAgentService = 'absent'; Enrollments = 'absent'; Manufacturer = 'Dell Inc.'; Model = 'Latitude 5540' }
    foreach ($key in $script:Kinds[$Kind].Fact.Keys) { $facts[$key] = $script:Kinds[$Kind].Fact[$key] }
    $facts | ConvertTo-Json -Compress
}

function Use-FakeHostContext {
    <#
    .SYNOPSIS
    Write stand-in dsregcmd programs under a directory and return what a test needs to select one.

    .DESCRIPTION
    Returns an object with Path (join name to stand-in .cmd file) and Directory. The caller sets the
    two OPSTOOLKIT_TEST_* variables from Get-FakeHostSetupText, in the child process, or in its own
    process through Set-FakeHostEnvironment so every child inherits them.

    .PARAMETER Directory
    Existing directory that receives the .cmd and .txt files.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Directory)

    $output = @{
        Workgroup = @('AzureAdJoined : NO', 'DomainJoined : NO', 'WorkplaceJoined : NO')
        Entra = @('AzureAdJoined : YES', 'DomainJoined : NO', 'WorkplaceJoined : NO')
        Domain = @('AzureAdJoined : NO', 'DomainJoined : YES', 'WorkplaceJoined : NO')
        Hybrid = @('AzureAdJoined : YES', 'DomainJoined : YES', 'WorkplaceJoined : NO')
        Missing = @('no join information here')
    }
    $paths = @{}
    foreach ($name in $output.Keys) {
        $text = Join-Path $Directory "dsreg-$name.txt"
        Set-Content -LiteralPath $text -Value $output[$name] -Encoding ascii
        $cmd = Join-Path $Directory "dsreg-$name.cmd"
        Set-Content -LiteralPath $cmd -Encoding ascii -Value @('@echo off', "type `"$text`"", 'exit /b 0')
        $paths[$name] = $cmd
    }
    [pscustomobject]@{ Directory = $Directory; Path = $paths }
}

function Get-FakeHostSetupText {
    <#
    .SYNOPSIS
    Return child-process setup text that selects one pretend host kind.

    .PARAMETER Fixture
    The object from Use-FakeHostContext.

    .PARAMETER Kind
    Physical, Avd, AvdMarkerKeyOnly, AvdUnread, Domain, HybridMdm, JoinUnread or EntraJoined (Entra-joined physical host).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][ValidateSet('Physical', 'Avd', 'AvdMarkerKeyOnly', 'AvdUnread', 'Domain', 'HybridMdm', 'JoinUnread', 'EntraJoined')][string]$Kind
    )
    $join = $script:Kinds[$Kind].Join
    "`n`$env:OPSTOOLKIT_TEST_DSREGCMD_PATH = '$($Fixture.Path[$join])'`n`$env:OPSTOOLKIT_TEST_HOSTFACTS = '$(Get-FakeHostFactText -Kind $Kind)'`n"
}

function Set-FakeHostEnvironment {
    <#
    .SYNOPSIS
    Set the two host hooks in this process to a host kind and return the values they replaced.

    .DESCRIPTION
    Child processes started afterwards inherit the hooks. Pass the returned object to
    Restore-FakeHostEnvironment in AfterAll.

    .PARAMETER Fixture
    The object from Use-FakeHostContext.

    .PARAMETER Kind
    Host kind, Physical by default.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [ValidateSet('Physical', 'Avd', 'AvdMarkerKeyOnly', 'AvdUnread', 'Domain', 'HybridMdm', 'JoinUnread', 'EntraJoined')][string]$Kind = 'Physical'
    )
    $saved = [pscustomobject]@{
        Dsregcmd = $env:OPSTOOLKIT_TEST_DSREGCMD_PATH
        Facts = $env:OPSTOOLKIT_TEST_HOSTFACTS
    }
    if ($PSCmdlet.ShouldProcess('process environment', "select the $Kind fake host")) {
        $env:OPSTOOLKIT_TEST_DSREGCMD_PATH = $Fixture.Path[$script:Kinds[$Kind].Join]
        $env:OPSTOOLKIT_TEST_HOSTFACTS = Get-FakeHostFactText -Kind $Kind
    }
    $saved
}

function Restore-FakeHostEnvironment {
    <#
    .SYNOPSIS
    Put the two host hooks back to the values Set-FakeHostEnvironment returned.

    .PARAMETER Saved
    The object from Set-FakeHostEnvironment.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Saved)
    if (-not $PSCmdlet.ShouldProcess('process environment', 'restore the host hooks')) { return }
    [Environment]::SetEnvironmentVariable('OPSTOOLKIT_TEST_DSREGCMD_PATH', $Saved.Dsregcmd)
    [Environment]::SetEnvironmentVariable('OPSTOOLKIT_TEST_HOSTFACTS', $Saved.Facts)
}

Export-ModuleMember -Function Use-FakeHostContext, Get-FakeHostSetupText, Set-FakeHostEnvironment, Restore-FakeHostEnvironment
