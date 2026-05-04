<#
.SYNOPSIS
Export Azure NSG rules, NSG assignments, and optional VM inventory to CSV reports.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Export-AzNetworkInventory.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Requires -Modules Az.Accounts, Az.Network
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string[]]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\reports\azure'),

    [Parameter()]
    [switch]$IncludeVirtualMachines
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Join-RuleValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return ($Value -join ',')
    }

    return [string]$Value
}

function Get-NsgRuleRecord {
    param(
        [Parameter(Mandatory)]
        [object]$NetworkSecurityGroup,

        [Parameter(Mandatory)]
        [object]$Rule,

        [Parameter(Mandatory)]
        [string]$SubscriptionName
    )

    [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        ResourceGroupName = $NetworkSecurityGroup.ResourceGroupName
        NetworkSecurityGroupName = $NetworkSecurityGroup.Name
        Location = $NetworkSecurityGroup.Location
        RuleName = $Rule.Name
        Description = $Rule.Description
        Priority = $Rule.Priority
        Protocol = $Rule.Protocol
        Access = $Rule.Access
        Direction = $Rule.Direction
        SourceAddressPrefix = Join-RuleValue $Rule.SourceAddressPrefix
        SourceAddressPrefixes = Join-RuleValue $Rule.SourceAddressPrefixes
        SourcePortRange = Join-RuleValue $Rule.SourcePortRange
        SourcePortRanges = Join-RuleValue $Rule.SourcePortRanges
        DestinationAddressPrefix = Join-RuleValue $Rule.DestinationAddressPrefix
        DestinationAddressPrefixes = Join-RuleValue $Rule.DestinationAddressPrefixes
        DestinationPortRange = Join-RuleValue $Rule.DestinationPortRange
        DestinationPortRanges = Join-RuleValue $Rule.DestinationPortRanges
    }
}

function Get-NsgAssignmentRecord {
    param(
        [Parameter(Mandatory)]
        [object]$NetworkSecurityGroup,

        [Parameter(Mandatory)]
        [string]$SubscriptionName
    )

    $subnets = @($NetworkSecurityGroup.Subnets | ForEach-Object { ($_.Id -split '/')[-3] + '/' + ($_.Id -split '/')[-1] })
    $networkInterfaces = @($NetworkSecurityGroup.NetworkInterfaces | ForEach-Object { ($_.Id -split '/')[-1] })

    [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        ResourceGroupName = $NetworkSecurityGroup.ResourceGroupName
        NetworkSecurityGroupName = $NetworkSecurityGroup.Name
        Location = $NetworkSecurityGroup.Location
        AssignedSubnets = $subnets -join ';'
        AssignedNetworkInterfaces = $networkInterfaces -join ';'
    }
}

if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$subscriptions = if ($SubscriptionId) {
    foreach ($id in $SubscriptionId) { Get-AzSubscription -SubscriptionId $id }
} else {
    Get-AzSubscription
}

$nsgRules = foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null
    foreach ($nsg in Get-AzNetworkSecurityGroup) {
        foreach ($rule in @($nsg.SecurityRules) + @($nsg.DefaultSecurityRules)) {
            Get-NsgRuleRecord -NetworkSecurityGroup $nsg -Rule $rule -SubscriptionName $subscription.Name
        }
    }
}

$nsgAssignments = foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null
    foreach ($nsg in Get-AzNetworkSecurityGroup) {
        Get-NsgAssignmentRecord -NetworkSecurityGroup $nsg -SubscriptionName $subscription.Name
    }
}

$rulePath = Join-Path $OutputPath 'nsg-rules.csv'
$assignmentPath = Join-Path $OutputPath 'nsg-assignments.csv'

if ($PSCmdlet.ShouldProcess($rulePath, 'Export NSG rule inventory')) {
    $nsgRules | Export-Csv -Path $rulePath -NoTypeInformation -Encoding utf8
}

if ($PSCmdlet.ShouldProcess($assignmentPath, 'Export NSG assignment inventory')) {
    $nsgAssignments | Export-Csv -Path $assignmentPath -NoTypeInformation -Encoding utf8
}

if ($IncludeVirtualMachines) {
    Import-Module Az.Compute -ErrorAction Stop
    $vmPath = Join-Path $OutputPath 'virtual-machines.csv'
    $vms = foreach ($subscription in $subscriptions) {
        Set-AzContext -SubscriptionId $subscription.Id | Out-Null
        foreach ($vm in Get-AzVM) {
            [pscustomobject]@{
                SubscriptionName = $subscription.Name
                ResourceGroupName = $vm.ResourceGroupName
                Name = $vm.Name
                Location = $vm.Location
                Size = $vm.HardwareProfile.VmSize
                NetworkInterfaces = (@($vm.NetworkProfile.NetworkInterfaces.Id) | ForEach-Object { ($_ -split '/')[-1] }) -join ';'
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($vmPath, 'Export VM inventory')) {
        $vms | Export-Csv -Path $vmPath -NoTypeInformation -Encoding utf8
    }
}

Write-Information "Reports written to $OutputPath" -InformationAction Continue


