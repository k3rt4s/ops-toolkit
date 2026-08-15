<#
.SYNOPSIS
Export Azure network inventory reports for NSGs, VNets, subnets, NICs, public IPs, and optional VMs.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Requires Az.Accounts and Az.Network. VM inventory additionally requires Az.Compute.
- Connect first with Initialize-AzPowerShellSession.ps1 when working in a known tenant.
- Use -SubscriptionId and -ResourceGroupName to keep exports scoped when possible.
- Generated reports are written under reports\azure by default.

Purpose:
Use this script to collect network review data without changing Azure. It
exports separate CSV and JSON files for network security rules, NSG
assignments, virtual networks, subnets, network interfaces, public IPs, and
optional virtual machines.

Required syntax:
pwsh -File .\scripts\azure\Export-AzNetworkInventory.ps1
pwsh -File .\scripts\azure\Export-AzNetworkInventory.ps1 -SubscriptionId "<subscription-id>" -ResourceGroupName rg-network
pwsh -File .\scripts\azure\Export-AzNetworkInventory.ps1 -IncludeVirtualMachines -OutputDirectory .\reports\azure

.OUTPUTS
Writes CSV and JSON inventory files under reports\azure by default. Returns a
summary object with output paths and record counts.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules Az.Accounts, Az.Network
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure'),

    [Parameter()]
    [switch]$IncludeVirtualMachines
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Get-ResourceNameFromId {
    param(
        [Parameter()]
        [string]$Id
    )

    if (-not $Id) {
        return ''
    }

    ($Id -split '/')[-1]
}

function Get-ResourceGroupFromId {
    param(
        [Parameter()]
        [string]$Id
    )

    if (-not $Id) {
        return ''
    }

    $parts = $Id -split '/'
    $index = [array]::IndexOf($parts, 'resourceGroups')
    if ($index -ge 0 -and $parts.Count -gt ($index + 1)) {
        return $parts[$index + 1]
    }

    ''
}

function Get-NsgRuleRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$NetworkSecurityGroup,

        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $NetworkSecurityGroup.ResourceGroupName
        NetworkSecurityGroupName = $NetworkSecurityGroup.Name
        Location = $NetworkSecurityGroup.Location
        RuleName = $Rule.Name
        Description = $Rule.Description
        Priority = $Rule.Priority
        Protocol = $Rule.Protocol
        Access = $Rule.Access
        Direction = $Rule.Direction
        SourceAddressPrefix = Join-OpsValue $Rule.SourceAddressPrefix
        SourceAddressPrefixes = Join-OpsValue $Rule.SourceAddressPrefixes
        SourcePortRange = Join-OpsValue $Rule.SourcePortRange
        SourcePortRanges = Join-OpsValue $Rule.SourcePortRanges
        DestinationAddressPrefix = Join-OpsValue $Rule.DestinationAddressPrefix
        DestinationAddressPrefixes = Join-OpsValue $Rule.DestinationAddressPrefixes
        DestinationPortRange = Join-OpsValue $Rule.DestinationPortRange
        DestinationPortRanges = Join-OpsValue $Rule.DestinationPortRanges
        IsDefaultRule = [bool]($Rule.Name -in @('AllowVnetInBound', 'AllowAzureLoadBalancerInBound', 'DenyAllInBound', 'AllowVnetOutBound', 'AllowInternetOutBound', 'DenyAllOutBound'))
    }
}

function Get-NsgAssignmentRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$NetworkSecurityGroup,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $NetworkSecurityGroup.ResourceGroupName
        NetworkSecurityGroupName = $NetworkSecurityGroup.Name
        Location = $NetworkSecurityGroup.Location
        AssignedSubnets = Join-OpsValue (@($NetworkSecurityGroup.Subnets.Id) | ForEach-Object { Get-ResourceNameFromId -Id $_ })
        AssignedNetworkInterfaces = Join-OpsValue (@($NetworkSecurityGroup.NetworkInterfaces.Id) | ForEach-Object { Get-ResourceNameFromId -Id $_ })
    }
}

function Get-VNetRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$VirtualNetwork,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $VirtualNetwork.ResourceGroupName
        VirtualNetworkName = $VirtualNetwork.Name
        Location = $VirtualNetwork.Location
        AddressPrefixes = Join-OpsValue $VirtualNetwork.AddressSpace.AddressPrefixes
        DnsServers = Join-OpsValue $VirtualNetwork.DhcpOptions.DnsServers
        SubnetCount = @($VirtualNetwork.Subnets).Count
    }
}

function Get-SubnetRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$VirtualNetwork,

        [Parameter(Mandatory = $true)]
        [object]$Subnet,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $VirtualNetwork.ResourceGroupName
        VirtualNetworkName = $VirtualNetwork.Name
        SubnetName = $Subnet.Name
        AddressPrefix = Join-OpsValue $Subnet.AddressPrefix
        AddressPrefixes = Join-OpsValue $Subnet.AddressPrefixes
        NetworkSecurityGroup = Get-ResourceNameFromId -Id $Subnet.NetworkSecurityGroup.Id
        RouteTable = Get-ResourceNameFromId -Id $Subnet.RouteTable.Id
        ServiceEndpoints = Join-OpsValue (@($Subnet.ServiceEndpoints) | ForEach-Object { $_.Service })
        Delegations = Join-OpsValue (@($Subnet.Delegations) | ForEach-Object { $_.ServiceName })
        PrivateEndpointNetworkPolicies = $Subnet.PrivateEndpointNetworkPolicies
        PrivateLinkServiceNetworkPolicies = $Subnet.PrivateLinkServiceNetworkPolicies
    }
}

function Get-NicRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$NetworkInterface,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $NetworkInterface.ResourceGroupName
        NetworkInterfaceName = $NetworkInterface.Name
        Location = $NetworkInterface.Location
        NetworkSecurityGroup = Get-ResourceNameFromId -Id $NetworkInterface.NetworkSecurityGroup.Id
        VirtualMachine = Get-ResourceNameFromId -Id $NetworkInterface.VirtualMachine.Id
        PrivateIpAddresses = Join-OpsValue (@($NetworkInterface.IpConfigurations) | ForEach-Object { $_.PrivateIpAddress })
        PrivateIpAllocationMethods = Join-OpsValue (@($NetworkInterface.IpConfigurations) | ForEach-Object { $_.PrivateIpAllocationMethod })
        PublicIpAddresses = Join-OpsValue (@($NetworkInterface.IpConfigurations) | ForEach-Object { Get-ResourceNameFromId -Id $_.PublicIpAddress.Id })
        Subnets = Join-OpsValue (@($NetworkInterface.IpConfigurations) | ForEach-Object { Get-ResourceNameFromId -Id $_.Subnet.Id })
        EnableAcceleratedNetworking = $NetworkInterface.EnableAcceleratedNetworking
        EnableIPForwarding = $NetworkInterface.EnableIPForwarding
    }
}

function Get-PublicIpRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PublicIpAddress,

        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    [pscustomobject]@{
        SubscriptionName = $Subscription.Name
        SubscriptionId = $Subscription.Id
        ResourceGroupName = $PublicIpAddress.ResourceGroupName
        PublicIpName = $PublicIpAddress.Name
        Location = $PublicIpAddress.Location
        IpAddress = $PublicIpAddress.IpAddress
        AllocationMethod = $PublicIpAddress.PublicIpAllocationMethod
        SkuName = $PublicIpAddress.Sku.Name
        DnsFqdn = $PublicIpAddress.DnsSettings.Fqdn
        AttachedResource = Get-ResourceNameFromId -Id $PublicIpAddress.IpConfiguration.Id
        AttachedResourceGroup = Get-ResourceGroupFromId -Id $PublicIpAddress.IpConfiguration.Id
    }
}

if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

if ($IncludeVirtualMachines) {
    Import-Module Az.Compute -ErrorAction Stop
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix 'network-inventory'

$subscriptions = if ($SubscriptionId) {
    foreach ($id in $SubscriptionId) {
        Get-AzSubscription -SubscriptionId $id
    }
} else {
    Get-AzSubscription
}

$nsgRules = [System.Collections.Generic.List[object]]::new()
$nsgAssignments = [System.Collections.Generic.List[object]]::new()
$virtualNetworks = [System.Collections.Generic.List[object]]::new()
$subnets = [System.Collections.Generic.List[object]]::new()
$networkInterfaces = [System.Collections.Generic.List[object]]::new()
$publicIpAddresses = [System.Collections.Generic.List[object]]::new()
$virtualMachines = [System.Collections.Generic.List[object]]::new()

foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null
    $resourceGroupFilter = if ($ResourceGroupName) { $ResourceGroupName } else { @($null) }

    foreach ($resourceGroup in $resourceGroupFilter) {
        $groupParameter = if ($resourceGroup) { @{ ResourceGroupName = $resourceGroup } } else { @{} }

        foreach ($nsg in Get-AzNetworkSecurityGroup @groupParameter) {
            $nsgAssignments.Add((Get-NsgAssignmentRecord -NetworkSecurityGroup $nsg -Subscription $subscription))
            foreach ($rule in @($nsg.SecurityRules) + @($nsg.DefaultSecurityRules)) {
                $nsgRules.Add((Get-NsgRuleRecord -NetworkSecurityGroup $nsg -Rule $rule -Subscription $subscription))
            }
        }

        foreach ($vnet in Get-AzVirtualNetwork @groupParameter) {
            $virtualNetworks.Add((Get-VNetRecord -VirtualNetwork $vnet -Subscription $subscription))
            foreach ($subnet in @($vnet.Subnets)) {
                $subnets.Add((Get-SubnetRecord -VirtualNetwork $vnet -Subnet $subnet -Subscription $subscription))
            }
        }

        foreach ($nic in Get-AzNetworkInterface @groupParameter) {
            $networkInterfaces.Add((Get-NicRecord -NetworkInterface $nic -Subscription $subscription))
        }

        foreach ($publicIp in Get-AzPublicIpAddress @groupParameter) {
            $publicIpAddresses.Add((Get-PublicIpRecord -PublicIpAddress $publicIp -Subscription $subscription))
        }

        if ($IncludeVirtualMachines) {
            foreach ($vm in Get-AzVM @groupParameter) {
                $virtualMachines.Add([pscustomobject]@{
                        SubscriptionName = $subscription.Name
                        SubscriptionId = $subscription.Id
                        ResourceGroupName = $vm.ResourceGroupName
                        Name = $vm.Name
                        Location = $vm.Location
                        Size = $vm.HardwareProfile.VmSize
                        OsType = $vm.StorageProfile.OsDisk.OsType
                        NetworkInterfaces = Join-OpsValue (@($vm.NetworkProfile.NetworkInterfaces.Id) | ForEach-Object { Get-ResourceNameFromId -Id $_ })
                    })
            }
        }
    }
}

$exports = @(
    Export-OpsReport -Name 'nsg-rules' -Record $nsgRules -Directory $runDirectory
    Export-OpsReport -Name 'nsg-assignments' -Record $nsgAssignments -Directory $runDirectory
    Export-OpsReport -Name 'virtual-networks' -Record $virtualNetworks -Directory $runDirectory
    Export-OpsReport -Name 'subnets' -Record $subnets -Directory $runDirectory
    Export-OpsReport -Name 'network-interfaces' -Record $networkInterfaces -Directory $runDirectory
    Export-OpsReport -Name 'public-ip-addresses' -Record $publicIpAddresses -Directory $runDirectory
)

if ($IncludeVirtualMachines) {
    $exports += Export-OpsReport -Name 'virtual-machines' -Record $virtualMachines -Directory $runDirectory
}

$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    OutputDirectory = $runDirectory
    SubscriptionIds = @($subscriptions | ForEach-Object { $_.Id })
    ResourceGroupNames = @($ResourceGroupName)
    IncludeVirtualMachines = [bool]$IncludeVirtualMachines
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
