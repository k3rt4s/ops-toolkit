<#
.SYNOPSIS
Stand-in for the NetSecurity module so scripts that read or change Windows Firewall never touch the real firewall.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_FW_RULES (or OPSTOOLKIT_TEST_FW_RULES_FILE, a path to a JSON file) to a
  JSON list of rules. Each rule may carry Name, DisplayName, Group, DisplayGroup, Direction,
  Action, Enabled, Profile, Program, LocalPort, RemotePort, Protocol, LocalAddress and
  RemoteAddress. Unset or empty means no rules.
- Set OPSTOOLKIT_TEST_FW_PROFILES (or OPSTOOLKIT_TEST_FW_PROFILES_FILE) to a JSON list of
  profiles with Name and any of Enabled, DefaultInboundAction, DefaultOutboundAction,
  NotifyOnListen, LogBlocked, LogMaxSizeKilobytes, AllowInboundRules, AllowLocalFirewallRules.
  Unset means the three profiles at Windows defaults (inbound and outbound NotConfigured).
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
A firewall rule or profile setting is a security control, so a test must never be able to
change one. The real NetSecurity module is never loaded because this one is found first. State
does not change between calls in one process: mutating functions only record what they were
asked to do.

Commands implemented, which covers every NetSecurity command the repository's scripts call:
Get-NetFirewallProfile, Set-NetFirewallProfile, Get-NetFirewallRule, Set-NetFirewallRule,
Enable-NetFirewallRule, Disable-NetFirewallRule, Get-NetFirewallApplicationFilter,
Get-NetFirewallAddressFilter, Get-NetFirewallPortFilter.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeFirewallMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Read-FakeFirewallJson {
    param([string]$InlineVariable, [string]$FileVariable)
    $text = [Environment]::GetEnvironmentVariable($InlineVariable)
    $file = [Environment]::GetEnvironmentVariable($FileVariable)
    if ($file -and (Test-Path -LiteralPath $file)) { $text = Get-Content -LiteralPath $file -Raw }
    if (-not $text -or -not $text.Trim()) { return @() }
    @($text | ConvertFrom-Json)
}

function Get-FakeFirewallField {
    param($Object, [string]$Name, $Default)
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) {
        $value = $Object.PSObject.Properties[$Name].Value
        if ($null -ne $value) { return $value }
    }
    $Default
}

function Get-FakeFirewallRuleSource {
    $index = 0
    foreach ($r in @(Read-FakeFirewallJson 'OPSTOOLKIT_TEST_FW_RULES' 'OPSTOOLKIT_TEST_FW_RULES_FILE')) {
        $index++
        $name = [string](Get-FakeFirewallField $r 'Name' "FakeRule$index")
        [pscustomobject]@{
            Name          = $name
            DisplayName   = [string](Get-FakeFirewallField $r 'DisplayName' $name)
            Group         = [string](Get-FakeFirewallField $r 'Group' '')
            DisplayGroup  = [string](Get-FakeFirewallField $r 'DisplayGroup' '')
            Direction     = [string](Get-FakeFirewallField $r 'Direction' 'Inbound')
            Action        = [string](Get-FakeFirewallField $r 'Action' 'Allow')
            Enabled       = [string](Get-FakeFirewallField $r 'Enabled' 'True')
            Profile       = [string](Get-FakeFirewallField $r 'Profile' 'Any')
            Program       = [string](Get-FakeFirewallField $r 'Program' 'Any')
            LocalPort     = @(Get-FakeFirewallField $r 'LocalPort' 'Any')
            RemotePort    = @(Get-FakeFirewallField $r 'RemotePort' 'Any')
            Protocol      = [string](Get-FakeFirewallField $r 'Protocol' 'Any')
            LocalAddress  = @(Get-FakeFirewallField $r 'LocalAddress' 'Any')
            RemoteAddress = @(Get-FakeFirewallField $r 'RemoteAddress' 'Any')
        }
    }
}

function ConvertTo-FakeFirewallRuleObject {
    param($Source)
    # The real objects carry no Program or address columns; those live on the filter objects.
    [pscustomobject]@{
        Name = $Source.Name; DisplayName = $Source.DisplayName; Group = $Source.Group
        DisplayGroup = $Source.DisplayGroup; Direction = $Source.Direction; Action = $Source.Action
        Enabled = $Source.Enabled; Profile = $Source.Profile
    }
}

function Get-NetFirewallProfile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Name,
        [string[]]$Profile,
        [switch]$All,
        [string]$PolicyStore
    )

    $defaults = foreach ($n in 'Domain', 'Private', 'Public') {
        [pscustomobject]@{ Name = $n }
    }
    $configured = @(Read-FakeFirewallJson 'OPSTOOLKIT_TEST_FW_PROFILES' 'OPSTOOLKIT_TEST_FW_PROFILES_FILE')
    $source = if ($configured.Count) { $configured } else { @($defaults) }

    $wanted = @(@($Name) + @($Profile) | Where-Object { $_ })
    foreach ($p in $source) {
        $n = [string](Get-FakeFirewallField $p 'Name' '')
        if ($wanted.Count -and $n -notin $wanted) { continue }
        [pscustomobject]@{
            Name                    = $n
            Enabled                 = [string](Get-FakeFirewallField $p 'Enabled' 'True')
            DefaultInboundAction    = [string](Get-FakeFirewallField $p 'DefaultInboundAction' 'NotConfigured')
            DefaultOutboundAction   = [string](Get-FakeFirewallField $p 'DefaultOutboundAction' 'NotConfigured')
            AllowInboundRules       = [string](Get-FakeFirewallField $p 'AllowInboundRules' 'NotConfigured')
            AllowLocalFirewallRules = [string](Get-FakeFirewallField $p 'AllowLocalFirewallRules' 'NotConfigured')
            NotifyOnListen          = [string](Get-FakeFirewallField $p 'NotifyOnListen' 'True')
            LogBlocked              = [string](Get-FakeFirewallField $p 'LogBlocked' 'False')
            LogMaxSizeKilobytes     = [string](Get-FakeFirewallField $p 'LogMaxSizeKilobytes' '4096')
        }
    }
}

function Set-NetFirewallProfile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Name,
        [string[]]$Profile,
        [string]$Enabled,
        [string]$DefaultInboundAction,
        [string]$DefaultOutboundAction,
        [string]$AllowInboundRules,
        [string]$AllowLocalFirewallRules,
        [string]$AllowLocalIPsecRules,
        [string]$NotifyOnListen,
        [string]$LogBlocked,
        [string]$LogAllowed,
        [string]$LogFileName,
        [uint64]$LogMaxSizeKilobytes,
        [string]$PolicyStore
    )

    $skip = 'Name', 'Profile', 'PolicyStore', 'ErrorAction', 'WhatIf', 'Confirm', 'Verbose', 'Debug'
    $detail = (@($PSBoundParameters.Keys | Where-Object { $_ -notin $skip } | Sort-Object |
                ForEach-Object { "$_=$($PSBoundParameters[$_])" })) -join ';'
    Write-FakeFirewallMutation -Command 'Set-NetFirewallProfile' `
        -Target ((@($Name) + @($Profile) | Where-Object { $_ }) -join ',') -Detail $detail
}

function Get-NetFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][string[]]$Name,
        [string[]]$DisplayName,
        [string[]]$Group,
        [string[]]$DisplayGroup,
        [string]$Direction,
        [string]$Action,
        [string]$Enabled,
        [string]$PolicyStore,
        [switch]$All
    )

    process {
        foreach ($s in @(Get-FakeFirewallRuleSource)) {
            if ($Name -and -not (@($Name) | Where-Object { $s.Name -like $_ })) { continue }
            if ($DisplayName -and -not (@($DisplayName) | Where-Object { $s.DisplayName -like $_ })) { continue }
            if ($Group -and -not (@($Group) | Where-Object { $s.Group -like $_ })) { continue }
            if ($DisplayGroup -and -not (@($DisplayGroup) | Where-Object { $s.DisplayGroup -like $_ })) { continue }
            if ($Direction -and $s.Direction -ne $Direction) { continue }
            if ($Action -and $s.Action -ne $Action) { continue }
            if ($Enabled -and $s.Enabled -ne $Enabled) { continue }
            ConvertTo-FakeFirewallRuleObject -Source $s
        }
    }
}

function Get-FakeFilterTarget {
    param($Rule, [switch]$All)
    $sources = @(Get-FakeFirewallRuleSource)
    if ($Rule) {
        $names = @($Rule | ForEach-Object { $_.Name })
        return @($sources | Where-Object { $_.Name -in $names })
    }
    $sources
}

function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$AssociatedNetFirewallRule,
        [string]$PolicyStore,
        [switch]$All
    )
    process {
        foreach ($s in @(Get-FakeFilterTarget -Rule $AssociatedNetFirewallRule)) {
            [pscustomobject]@{ InstanceID = $s.Name; Program = $s.Program; Package = $null; Service = 'Any' }
        }
    }
}

function Get-NetFirewallAddressFilter {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$AssociatedNetFirewallRule,
        [string]$PolicyStore,
        [switch]$All
    )
    process {
        foreach ($s in @(Get-FakeFilterTarget -Rule $AssociatedNetFirewallRule)) {
            [pscustomobject]@{ InstanceID = $s.Name; LocalAddress = $s.LocalAddress; RemoteAddress = $s.RemoteAddress }
        }
    }
}

function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$AssociatedNetFirewallRule,
        [string]$PolicyStore,
        [switch]$All
    )
    process {
        foreach ($s in @(Get-FakeFilterTarget -Rule $AssociatedNetFirewallRule)) {
            [pscustomobject]@{ InstanceID = $s.Name; Protocol = $s.Protocol; LocalPort = $s.LocalPort; RemotePort = $s.RemotePort }
        }
    }
}

function Set-NetFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][string[]]$Name,
        [string[]]$DisplayName,
        [string[]]$Profile,
        [string[]]$RemoteAddress,
        [string[]]$LocalAddress,
        [string]$Enabled,
        [string]$Action,
        [string]$PolicyStore
    )
    process {
        $detail = @(
            if ($PSBoundParameters.ContainsKey('Profile')) { "Profile=$(@($Profile) -join ',')" }
            if ($PSBoundParameters.ContainsKey('RemoteAddress')) { "RemoteAddress=$(@($RemoteAddress) -join ',')" }
            if ($PSBoundParameters.ContainsKey('LocalAddress')) { "LocalAddress=$(@($LocalAddress) -join ',')" }
            if ($PSBoundParameters.ContainsKey('Enabled')) { "Enabled=$Enabled" }
            if ($PSBoundParameters.ContainsKey('Action')) { "Action=$Action" }
        ) -join ';'
        foreach ($n in @(@($Name) + @($DisplayName) | Where-Object { $_ })) {
            Write-FakeFirewallMutation -Command 'Set-NetFirewallRule' -Target $n -Detail $detail
        }
    }
}

function Enable-NetFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][string[]]$Name,
        [string[]]$DisplayName,
        [string[]]$Group,
        [string]$PolicyStore
    )
    process {
        foreach ($n in @(@($Name) + @($DisplayName) + @($Group) | Where-Object { $_ })) {
            Write-FakeFirewallMutation -Command 'Enable-NetFirewallRule' -Target $n
        }
    }
}

function Disable-NetFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][string[]]$Name,
        [string[]]$DisplayName,
        [string[]]$Group,
        [string]$PolicyStore
    )
    process {
        foreach ($n in @(@($Name) + @($DisplayName) + @($Group) | Where-Object { $_ })) {
            Write-FakeFirewallMutation -Command 'Disable-NetFirewallRule' -Target $n
        }
    }
}

Export-ModuleMember -Function 'Get-NetFirewallProfile', 'Set-NetFirewallProfile', 'Get-NetFirewallRule',
'Set-NetFirewallRule', 'Enable-NetFirewallRule', 'Disable-NetFirewallRule',
'Get-NetFirewallApplicationFilter', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallPortFilter'
