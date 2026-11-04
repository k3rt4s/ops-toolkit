<#
.SYNOPSIS
Shared host-context detection (join state, VDI session host, MDM management) for the windows-hardening scripts.

.DESCRIPTION
Instructions:
- Import with a path relative to the calling script, not by module name, because this module is
  not installed to a PSModulePath:
  Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Hardening') -Force
- Every probe here is read-only. A probe that fails leaves its field at $null (or 'Unknown') and
  adds a reason to Notes and the field to Unread. An undetermined fact is never folded into a
  guess: a script that gates on a fact must treat $null as "cannot prove it is safe".
- Test hooks, read only when the matching parameter is not bound, and named OPSTOOLKIT_TEST_* so
  they are never set in production:
  OPSTOOLKIT_TEST_DSREGCMD_PATH  path of a stand-in for dsregcmd.exe (the way -DismPath works in
                                 Set-WindowsNetworkProtocolHardening.ps1).
  OPSTOOLKIT_TEST_HOSTFACTS      JSON text that replaces the registry, service and CIM probes. A
                                 stub function defined in a test runner is not visible from inside
                                 a module, so a child-process integration test cannot shadow those
                                 cmdlets; this hook is the substitute. Properties, each optional:
                                 RdInfraAgentKey, RdAgentService ('present', 'absent' or 'error'),
                                 Enrollments (array of ProviderID strings, 'absent' or 'error'),
                                 Manufacturer and Model (strings) or ComputerSystem ('error').
                                 A property left out falls through to the real probe.

Purpose:
Twenty scripts need the same answers to the same questions: how is this host joined, is it a
VDI session host, is it MDM managed. Separate copies drift, so the detection lives here once and
each script imports it.

Detection facts NOT verified on a real host (the module is tested only with stand-ins; copy this
list into the VDI run sheet and tick each one on a real session host):
1. dsregcmd.exe /status prints the lines 'AzureAdJoined : YES|NO', 'DomainJoined : YES|NO' and
   'WorkplaceJoined : YES|NO' with those English key names on every supported build and language.
2. AzureAdJoined YES with DomainJoined NO is an Entra-only device, YES with YES is hybrid; a
   device that is only workplace-registered reads as Workgroup here.
3. HKLM:\SOFTWARE\Microsoft\RDInfraAgent exists on an Azure Virtual Desktop session host and does
   not exist on a physical or non-AVD machine. It is also expected on Windows 365 Cloud PCs,
   which are reported as session hosts too.
4. The RDAgentBootLoader service exists on an Azure Virtual Desktop session host and nowhere else.
5. A device enrolled in Intune has a subkey of HKLM:\SOFTWARE\Microsoft\Enrollments whose
   ProviderID is 'MS DM Server', and a stale enrollment left behind after unenrolling keeps the
   subkey, so IsMdmManaged can read $true for a device that is no longer managed.
6. Win32_ComputerSystem Manufacturer and Model name the common hypervisors with the strings
   matched in Get-OpsVmProbe ('Virtual Machine', VMware, VirtualBox, KVM, QEMU, HVM domU,
   Parallels); an unlisted hypervisor reads as not a virtual machine.
7. dsregcmd.exe /status returns promptly and exits 0 on a healthy host; no timeout guards it.

.NOTES
Status:
Active module. Not yet exercised on a real machine (hard-elevated-run).
#>

Set-StrictMode -Version 3.0

# Reads the OPSTOOLKIT_TEST_HOSTFACTS fixture, or $null when the hook is not set. A fixture that
# is not valid JSON is a test mistake and throws rather than silently falling through to real probes.
function Get-OpsHostFactFixture {
    $text = [string][System.Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_HOSTFACTS')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text | ConvertFrom-Json -ErrorAction Stop
}

function Get-OpsFixtureValue {
    param($Fixture, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -ne $Fixture -and $Fixture.PSObject.Properties[$Name]) { return , $Fixture.PSObject.Properties[$Name].Value }
    return $null
}

# Returns @{ State = 'present'|'absent'|'error'; Reason = <text> } for one registry key.
function Get-OpsRegistryKeyProbe {
    param([Parameter(Mandatory = $true)][string]$Path, [string]$FixtureName, $Fixture)
    $fixed = if ($FixtureName) { Get-OpsFixtureValue -Fixture $Fixture -Name $FixtureName } else { $null }
    if ($null -ne $fixed) {
        $state = [string]@($fixed)[0]
        return @{ State = $state; Reason = "fixture value '$state'" }
    }
    try {
        $null = Get-Item -LiteralPath $Path -ErrorAction Stop
        @{ State = 'present'; Reason = '' }
    } catch [System.Management.Automation.ItemNotFoundException] {
        @{ State = 'absent'; Reason = '' }
    } catch {
        @{ State = 'error'; Reason = "could not read ${Path}: $($_.Exception.Message)" }
    }
}

# Returns @{ State = 'present'|'absent'|'error'; Reason = <text> } for one service name.
function Get-OpsServiceProbe {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$FixtureName, $Fixture)
    $fixed = if ($FixtureName) { Get-OpsFixtureValue -Fixture $Fixture -Name $FixtureName } else { $null }
    if ($null -ne $fixed) {
        $state = [string]@($fixed)[0]
        return @{ State = $state; Reason = "fixture value '$state'" }
    }
    try {
        $hit = @(Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq $Name })
        if ($hit.Count -gt 0) { @{ State = 'present'; Reason = '' } } else { @{ State = 'absent'; Reason = '' } }
    } catch {
        @{ State = 'error'; Reason = "could not list services: $($_.Exception.Message)" }
    }
}

# Returns @{ State = 'present'|'absent'|'error'; Reason; Providers = string[] } for the MDM
# enrollment subkeys. 'present' means at least one subkey names a ProviderID; Providers lists them.
function Get-OpsEnrollmentProbe {
    param($Fixture)
    $fixed = Get-OpsFixtureValue -Fixture $Fixture -Name 'Enrollments'
    if ($null -ne $fixed) {
        $values = @($fixed)
        if ($values.Count -eq 1 -and "$($values[0])" -in @('absent', 'error')) {
            return @{ State = "$($values[0])"; Reason = "fixture value '$($values[0])'"; Providers = @() }
        }
        return @{ State = 'present'; Reason = ''; Providers = @($values | ForEach-Object { "$_" }) }
    }
    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    try {
        $keys = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
    } catch [System.Management.Automation.ItemNotFoundException] {
        return @{ State = 'absent'; Reason = ''; Providers = @() }
    } catch {
        return @{ State = 'error'; Reason = "could not list ${root}: $($_.Exception.Message)"; Providers = @() }
    }
    $providers = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $keys) {
        try {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($null -ne $props -and $props.PSObject.Properties['ProviderID']) {
                $providers.Add("$($props.PSObject.Properties['ProviderID'].Value)")
            }
        } catch {
            $failed.Add("$($key.PSChildName): $($_.Exception.Message)")
        }
    }
    # A subkey that could not be read might have been the MDM one, so any failure makes the state
    # 'error'; the caller still reports $true when a readable subkey already named the MDM provider.
    $state = if ($failed.Count -gt 0) { 'error' } elseif ($providers.Count -gt 0) { 'present' } else { 'absent' }
    $reason = if ($failed.Count -gt 0) { "could not read enrollment subkey(s): $($failed -join '; ')" } else { '' }
    @{ State = $state; Reason = $reason; Providers = @($providers) }
}

# Returns @{ State = 'present'|'error'; Reason; Text = '<manufacturer> <model>' } from Win32_ComputerSystem.
function Get-OpsComputerSystemProbe {
    param($Fixture)
    $fixedState = Get-OpsFixtureValue -Fixture $Fixture -Name 'ComputerSystem'
    if ($null -ne $fixedState -and "$(@($fixedState)[0])" -eq 'error') {
        return @{ State = 'error'; Reason = "fixture value 'error'"; Text = '' }
    }
    $maker = Get-OpsFixtureValue -Fixture $Fixture -Name 'Manufacturer'
    $model = Get-OpsFixtureValue -Fixture $Fixture -Name 'Model'
    if ($null -ne $maker -or $null -ne $model) {
        return @{ State = 'present'; Reason = ''; Text = "$(@($maker)[0]) $(@($model)[0])".Trim() }
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $text = ''
        if ($null -ne $cs) {
            $parts = foreach ($field in 'Manufacturer', 'Model') {
                if ($cs.PSObject.Properties[$field]) { "$($cs.PSObject.Properties[$field].Value)" }
            }
            $text = ($parts -join ' ').Trim()
        }
        if ([string]::IsNullOrWhiteSpace($text)) { return @{ State = 'error'; Reason = 'Win32_ComputerSystem returned no Manufacturer or Model'; Text = '' } }
        @{ State = 'present'; Reason = ''; Text = $text }
    } catch {
        @{ State = 'error'; Reason = "could not read Win32_ComputerSystem: $($_.Exception.Message)"; Text = '' }
    }
}

# True when the Manufacturer/Model text names a common hypervisor. Pure.
function Get-OpsVmProbe {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $Text -match 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|HVM domU|Parallels'
}

# Runs dsregcmd /status and returns @{ Ran = bool; Text = string; Reason = string }. Never throws.
function Invoke-OpsDsregcmd {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $global:LASTEXITCODE = 0
        $lines = @(& $Path /status 2>&1 | ForEach-Object { "$_" })
        $code = $global:LASTEXITCODE
        if ($code -ne 0) { return @{ Ran = $false; Text = ''; Reason = "dsregcmd exited with code $code" } }
        @{ Ran = $true; Text = ($lines -join "`n"); Reason = '' }
    } catch {
        @{ Ran = $false; Text = ''; Reason = "dsregcmd could not be run: $($_.Exception.Message)" }
    }
}

# Returns $true for YES, $false for NO, $null when the line is missing or says anything else. Pure.
function ConvertFrom-OpsDsregFlag {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [Parameter(Mandatory = $true)][string]$Name)
    $m = [regex]::Match($Text, "(?im)^\s*$([regex]::Escape($Name))\s*:\s*(?<v>YES|NO)\s*$")
    if (-not $m.Success) { return $null }
    $m.Groups['v'].Value.ToUpperInvariant() -eq 'YES'
}

function Get-OpsHostContext {
    <#
    .SYNOPSIS
    Return one object describing how this host is joined, whether it is a VDI session host, and whether MDM manages it.

    .DESCRIPTION
    Reads dsregcmd /status, the RDInfraAgent registry key, the RDAgentBootLoader service, the MDM
    enrollment keys and Win32_ComputerSystem, read-only. Any probe that cannot answer leaves its
    field $null (JoinType and Platform say 'Unknown'), adds a reason to Notes and the field name to
    Unread. Nothing is guessed: a caller that gates on IsAvdSessionHost must treat $null as
    "could not prove this is not a session host".

    IsAvdSessionHost is $true when the RDInfraAgent key or the RDAgentBootLoader service exists,
    even if the other probe failed; $false only when both probes ran and found nothing; otherwise
    $null.

    Platform is 'VDI' for an AVD session host, 'Physical' for a host that is not one and is not a
    virtual machine, 'VirtualMachine' for a virtual machine that is not one, and 'Unknown' when
    either answer is missing.

    .PARAMETER DsregcmdPath
    Path of dsregcmd.exe. Defaults to dsregcmd.exe on the PATH, or the
    OPSTOOLKIT_TEST_DSREGCMD_PATH environment variable when set. Tests pass a stand-in; the real
    one is never needed to test this function.

    .OUTPUTS
    PSCustomObject with JoinType (EntraJoined, HybridJoined, DomainJoined, Workgroup, Unknown),
    AzureAdJoined, DomainJoined, WorkplaceJoined, IsAvdSessionHost, IsMdmManaged, IsVirtualMachine
    (each $true, $false or $null), Platform (Physical, VirtualMachine, VDI, Unknown), Notes
    (string[], one reason per failed probe) and Unread (string[], the fields left undetermined).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DsregcmdPath
    )

    $notes = [System.Collections.Generic.List[string]]::new()
    $unread = [System.Collections.Generic.List[string]]::new()
    $fixture = Get-OpsHostFactFixture

    if (-not $PSBoundParameters.ContainsKey('DsregcmdPath')) {
        $fromEnv = [string][System.Environment]::GetEnvironmentVariable('OPSTOOLKIT_TEST_DSREGCMD_PATH')
        $DsregcmdPath = if ($fromEnv) { $fromEnv } else { 'dsregcmd.exe' }
    }

    # Join state.
    $dsreg = Invoke-OpsDsregcmd -Path $DsregcmdPath
    $flags = @{ AzureAdJoined = $null; DomainJoined = $null; WorkplaceJoined = $null }
    if ($dsreg.Ran) {
        foreach ($name in @($flags.Keys)) {
            $flags[$name] = ConvertFrom-OpsDsregFlag -Text $dsreg.Text -Name $name
            if ($null -eq $flags[$name]) {
                $notes.Add("${name}: no 'YES' or 'NO' line in dsregcmd /status output")
                $unread.Add($name)
            }
        }
    } else {
        foreach ($name in @($flags.Keys)) {
            $notes.Add("${name}: $($dsreg.Reason)")
            $unread.Add($name)
        }
    }
    $joinType = 'Unknown'
    if ($null -ne $flags.AzureAdJoined -and $null -ne $flags.DomainJoined) {
        $joinType = if ($flags.AzureAdJoined -and $flags.DomainJoined) { 'HybridJoined' }
        elseif ($flags.AzureAdJoined) { 'EntraJoined' }
        elseif ($flags.DomainJoined) { 'DomainJoined' }
        else { 'Workgroup' }
    } else {
        $unread.Add('JoinType')
    }

    # AVD session host: either marker proves it; both absent proves it is not; anything else is unknown.
    $key = Get-OpsRegistryKeyProbe -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent' -FixtureName 'RdInfraAgentKey' -Fixture $fixture
    $svc = Get-OpsServiceProbe -Name 'RDAgentBootLoader' -FixtureName 'RdAgentService' -Fixture $fixture
    $isAvd = $null
    if ($key.State -eq 'present' -or $svc.State -eq 'present') {
        $isAvd = $true
    } elseif ($key.State -eq 'absent' -and $svc.State -eq 'absent') {
        $isAvd = $false
    } else {
        foreach ($probe in @($key, $svc)) {
            if ($probe.State -eq 'error') { $notes.Add("IsAvdSessionHost: $($probe.Reason)") }
        }
        $unread.Add('IsAvdSessionHost')
    }

    # MDM management.
    $enroll = Get-OpsEnrollmentProbe -Fixture $fixture
    $isMdm = $null
    if (@($enroll.Providers | Where-Object { $_ -eq 'MS DM Server' }).Count -gt 0) {
        $isMdm = $true
    } elseif ($enroll.State -in @('absent', 'present')) {
        $isMdm = $false
    } else {
        $notes.Add("IsMdmManaged: $($enroll.Reason)")
        $unread.Add('IsMdmManaged')
    }
    # An unreadable subkey does not change a $true answer, but it is still recorded.
    if ($null -ne $isMdm -and $enroll.Reason) { $notes.Add("IsMdmManaged: $($enroll.Reason)") }

    # Virtual machine.
    $cs = Get-OpsComputerSystemProbe -Fixture $fixture
    $isVm = $null
    if ($cs.State -eq 'present') {
        $isVm = [bool](Get-OpsVmProbe -Text $cs.Text)
    } else {
        $notes.Add("IsVirtualMachine: $($cs.Reason)")
        $unread.Add('IsVirtualMachine')
    }

    $platform = if ($isAvd -eq $true) { 'VDI' }
    elseif ($null -eq $isAvd -or $null -eq $isVm) { 'Unknown' }
    elseif ($isVm) { 'VirtualMachine' }
    else { 'Physical' }
    if ($platform -eq 'Unknown') { $unread.Add('Platform') }

    [pscustomobject]@{
        JoinType = $joinType
        AzureAdJoined = $flags.AzureAdJoined
        DomainJoined = $flags.DomainJoined
        WorkplaceJoined = $flags.WorkplaceJoined
        IsAvdSessionHost = $isAvd
        IsMdmManaged = $isMdm
        IsVirtualMachine = $isVm
        Platform = $platform
        Notes = @($notes)
        Unread = @($unread | Select-Object -Unique)
    }
}

function Get-OpsPolicyOverrideNote {
    <#
    .SYNOPSIS
    Return the one-sentence warning that policy may override local writes, or $null when no policy source applies.

    .DESCRIPTION
    A domain or hybrid joined host may take Group Policy, and an MDM managed host takes Intune
    policy; either can overwrite a value a local script wrote, now or at the next refresh. When the
    join type or MDM state could not be read, the note says so instead of implying that no policy
    applies. An Entra-joined or standalone host that was read cleanly and is not MDM managed has no
    policy source and gets $null. The note does not detect which settings conflict.

    .PARAMETER HostContext
    The object returned by Get-OpsHostContext.

    .OUTPUTS
    String, or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscustomobject]$HostContext
    )

    $joinType = [string]$HostContext.JoinType
    $mdm = $HostContext.IsMdmManaged
    $sources = [System.Collections.Generic.List[string]]::new()
    if ($joinType -in @('DomainJoined', 'HybridJoined')) { $sources.Add("Group Policy ($joinType)") }
    if ($mdm -eq $true) { $sources.Add('MDM policy (enrolled)') }
    if ($sources.Count -gt 0) {
        return "This host is managed by $($sources -join ' and '): policy may override the local values this script writes, and a later policy refresh can revert them. Conflicting settings are not detected; check the policy owner."
    }
    if ($joinType -eq 'Unknown' -or $null -eq $mdm) {
        return 'Could not determine whether Group Policy or MDM manages this host (see HostContext Unread); if one does, it may override the local values this script writes.'
    }
    $null
}

Export-ModuleMember -Function @(
    'Get-OpsHostContext'
    'Get-OpsPolicyOverrideNote'
)
