Connect-AzureRmAccount
Select-AzureRmSubscription "Subscription name"
$nsg = Get-AzureRmNetworkSecurityGroup
$exportPath = 'C:\'
Foreach ($nsg in $nsgs){
New-Item -ItemType file -Path "$exportPath\$($nsg.Name).csv" -Force
$nsgRules = $nsg.SecurityRules
    foreach ($nsgRule in $nsgRules){
    $nsgRule | Select-Object Name,Description,Priority,Protocol,Access,Direction,@{Name=’SourceAddressPrefix’;Expression={[string]::join(“,”, ($_.SourceAddressPrefix))}},@{Name=’SourcePortRange’;Expression={[string]::join(“,”, ($_.SourcePortRange))}},@{Name=’DestinationAddressPrefix’;Expression={[string]::join(“,”, ($_.DestinationAddressPrefix))}},@{Name=’DestinationPortRange’;Expression={[string]::join(“,”, ($_.DestinationPortRange))}} `
    | Export-Csv "$exportPath\$($nsg.Name).csv" -NoTypeInformation -Encoding ASCII -Append}
}



  
$subs = Get-AzureRmSubscription

$allResources = @()

foreach ($sub in $subs) 
{
    Select-AzureRmSubscription -SubscriptionId $sub.Id
    $resources = Get-AzureRmNetworkSecurityGroup
    foreach ($resource in $resources)
    {
        $customPsObject = New-Object -TypeName PsObject
        $subscription = Get-AzureRmSubscription -SubscriptionId $resource.SubscriptionId
        $tags = $resource.Tags.Keys + $resource.Tags.Values -join ':'
        $nics = $resource.NetworkInterfaces
        $subnets = $resource.Subnets

        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceName -Value $resource.Name
        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $resource.ResourceGroupName
        $customPsObject | Add-Member -MemberType NoteProperty -Name Location -Value $resource.Location

        #get subnets
        $i = 0
        foreach ($subnet in $subnets)
        {
            $subnetString = ($subnet.Id -split '/')[-3] + "\" + ($subnet.Id -split '/')[-1]
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("AssignedSubnet-" + $i) -Value $subnetString
            $i++
        }

        #get nics
        $i = 0
        foreach ($nic in $nics)
        {
            $nicString = ($nic.Id -split '/')[-1]
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("AssignedNic-" + $i) -Value $subnetString
            $i++
        }


        $customPsObject | Add-Member -MemberType NoteProperty -Name Subscription -Value $subscription.Name
        $allResources += $customPsObject

    }
       
}


$allResources | Export-Csv c:\temp\nsg-audit.csv -NoTypeInformation


$nsgs = Get-AzureRmNetworkSecurityGroup
$exportPath = 'C:\temp'

Foreach ($nsg in $nsgs) {
    $nsgRules = $nsg.SecurityRules
    foreach ($nsgRule in $nsgRules) {
        $nsgRule | Select-Object Name,Description,Priority,@{Name=’SourceAddressPrefix’;Expression={[string]::join(“,”, ($_.SourceAddressPrefix))}},@{Name=’SourcePortRange’;Expression={[string]::join(“,”, ($_.SourcePortRange))}},@{Name=’DestinationAddressPrefix’;Expression={[string]::join(“,”, ($_.DestinationAddressPrefix))}},@{Name=’DestinationPortRange’;Expression={[string]::join(“,”, ($_.DestinationPortRange))}},Protocol,Access,Direction `
        | Export-Csv "$exportPath\$nsg.Name.csv" -NoTypeInformation -Encoding ASCII
    }
}


$subs = Get-AzureRmSubscription

$allResources = @()

foreach ($sub in $subs) 
{
    Select-AzureRmSubscription -SubscriptionId $sub.Id
    $resources = Get-AzureRmVM
    foreach ($vm in $resources)
    {
        $customPsObject = New-Object -TypeName PsObject
        
        If ($vm.StorageProfile.OsDisk.ManagedDisk.Id -ne $null)
        {
            $osDiskStorageAccount = 'Managed Disk'
        }
        
        else
        {
            $osDiskStorageAccount = ([uri]$vm.StorageProfile.OsDisk.Vhd.Uri).Host
        }
        
        $nics = $vm.NetworkProfile.NetworkInterfaces
        $dataDiskS = $vm.StorageProfile.DataDisks
        $subscription = Get-AzureRmSubscription -SubscriptionId ($vm.Id -split '/')[2]
        
        $customPsObject | Add-Member -MemberType NoteProperty -Name VmName -Value $vm.Name
        $customPsObject | Add-Member -MemberType NoteProperty -Name RG -Value $vm.ResourceGroupName
        $customPsObject | Add-Member -MemberType NoteProperty -Name Location -Value $vm.Location
        $customPsObject | Add-Member -MemberType NoteProperty -Name Size -Value $vm.HardwareProfile.VmSize

        $i = 0
        foreach ($adapter in $nics)
        {
            $nic = Get-AzureRmResource -ResourceId $adapter.Id
            $vnet = ($nic.Properties.ipConfigurations.properties.subnet -split '/')[-3]
            $subnet = ($nic.Properties.ipConfigurations.properties.subnet -split '/')[-1]
            $privateIpAddress = $nic.Properties.ipConfigurations.properties.privateIPAddress
            $publicIpId = $nic.Properties.ipConfigurations.properties.publicIPAddress.id
            
            if ($publicIpId -eq $null)
            {
                $publicIpAddress = $null
            }
            Else
            {
                $publicIpResource = Get-AzureRmResource -ResourceId $publicIpId -ErrorAction SilentlyContinue
                $publicIpAddress = $publicIpResource.Properties.ipAddress
            }
            
            $availabilitySet = ($vm.AvailabilitySetReference.Id -split '/')[-1]        
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("nic-" + $i + "-Vnet") -Value $vnet
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("nic-" + $i + "-Subnet")  -Value $subnet
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("nic-" + $i + "-PrivateIpAddress") -Value $privateIpAddress
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("nic-" + $i + "-PublicIpAddress") -Value $publicIpAddress
            $i++
        }

        $customPsObject | Add-Member -MemberType NoteProperty -Name AvailabilitySet -Value $availabilitySet
        $customPsObject | Add-Member -MemberType NoteProperty -Name osDisk -Value $osDiskStorageAccount

        $i = 0
        foreach ($dataDisk in $dataDiskS)
        {
            if ($DataDisk.ManagedDisk.Id -ne $null)
            {
                $dataDiskHost = 'Managed Disk'
            }
            Else
            {
                $dataDiskHost = ([uri]($dataDisk.Vhd.Uri)).Host
            }
            $customPsObject | Add-Member -MemberType NoteProperty -Name ("dataDisk-" + $i) -Value $dataDiskHost
            $i++
        }
        
        $customPsObject | Add-Member -MemberType NoteProperty -Name Subscription -Value $subscription.Name
        $allResources += $customPsObject
    }
}

$allResources | Export-Csv c:\temp\vm-audit.csv -NoTypeInformation

