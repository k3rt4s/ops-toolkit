#Requires -Modules Pester

# The four scripts whose output layout was changed when they were moved onto
# OpsToolkit.Reporting. Three of them have never executed on this machine, which made
# them the least proven code in the repository: changed, and unverified.
#
# What matters here is not just that they run, but that they produce the run-directory
# layout Compare-OpsToolkitRun.ps1 needs, since that layout was the whole reason for
# the change.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    $script:adModulePath = Use-FakeActiveDirectory
    $script:azModulePath = Use-FakePlaceholderModule -Name @('Az.Accounts', 'Az.Network', 'Az.Compute')

    function Test-RunDirectoryLayout {
        <#
        .SYNOPSIS
        Assert a summary points at a run directory holding the expected reports.
        #>
        param($Summary, [string[]]$ReportName, [string]$Prefix)

        $directory = $Summary.OutputDirectory
        (Split-Path $directory -Leaf) | Should -Match "^$Prefix-\d{8}_\d{6}$"
        foreach ($name in $ReportName) {
            Test-Path (Join-Path $directory "$name.csv") | Should -BeTrue -Because "$name.csv should exist"
            Test-Path (Join-Path $directory "$name.json") | Should -BeTrue -Because "$name.json should exist"
        }
        Test-Path (Join-Path $directory 'summary.json') | Should -BeTrue
    }
}

AfterAll {
    foreach ($p in $script:adModulePath, $script:azModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Export-AdUserInventory end to end' {
    BeforeAll {
        $setup = @'
$global:FakeAdData = @{
    Users = @(
        [pscustomobject]@{ Name = 'Alice'; SamAccountName = 'alice'; UserPrincipalName = 'alice@test.local'
            DistinguishedName = 'CN=Alice,OU=Staff,DC=test,DC=local'; Enabled = $true
            EmailAddress = 'alice@test.local'; Department = 'IT'; Title = 'Engineer'
            Description = ''; whenCreated = (Get-Date).AddDays(-500); LastLogonDate = (Get-Date).AddDays(-1)
            PasswordLastSet = (Get-Date).AddDays(-30); PasswordNeverExpires = $false; Manager = $null }
        [pscustomobject]@{ Name = 'Bob'; SamAccountName = 'bob'; UserPrincipalName = 'bob@test.local'
            DistinguishedName = 'CN=Bob,OU=Staff,DC=test,DC=local'; Enabled = $false
            EmailAddress = 'bob@test.local'; Department = 'Sales'; Title = 'Rep'
            Description = ''; whenCreated = (Get-Date).AddDays(-900); LastLogonDate = (Get-Date).AddDays(-400)
            PasswordLastSet = (Get-Date).AddDays(-800); PasswordNeverExpires = $true; Manager = $null }
    )
}
'@

        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\active-directory\Export-AdUserInventory.ps1' `
            -Setup $setup -ModulePath $script:adModulePath `
            -Argument @{
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "adinv-$([guid]::NewGuid().ToString('N'))")
            ReportType = 'All'
        }
        $script:summary = $script:run.Summary
    }

    It 'runs to completion after the module retrofit' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'writes the run-directory layout the comparison tool needs' {
        Test-RunDirectoryLayout -Summary $script:summary -Prefix 'ad-user-inventory' `
            -ReportName @('attributes', 'distinguished-names')
    }

    It 'reports both users in both reports' {
        $script:summary.UserCount | Should -Be 2
        @(Import-Csv (Join-Path $script:summary.OutputDirectory 'attributes.csv')).Count | Should -Be 2
        @(Import-Csv (Join-Path $script:summary.OutputDirectory 'distinguished-names.csv')).Count | Should -Be 2
    }

    It 'honours the report type selection' {
        # Attributes is also the default, so this is what an unqualified run writes.
        $single = Invoke-ScriptUnderTest -RelativePath 'scripts\active-directory\Export-AdUserInventory.ps1' `
            -Setup $setup -ModulePath $script:adModulePath `
            -Argument @{
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "adinv2-$([guid]::NewGuid().ToString('N'))")
            ReportType = 'Attributes'
        }
        $single.ExitCode | Should -Be 0
        @($single.Summary.Exports).Count | Should -Be 1
        $single.Summary.Exports[0].Name | Should -Be 'attributes'
        Test-Path (Join-Path $single.Summary.OutputDirectory 'distinguished-names.csv') | Should -BeFalse
    }
}

Describe 'Export-AzNetworkInventory end to end' {
    BeforeAll {
        # Az.Network and Az.Compute are not installed, so placeholder modules satisfy
        # #Requires and every cmdlet is stubbed as a global function.
        $setup = @'
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' } } }
function Set-AzContext { param($SubscriptionId) }
function Connect-AzAccount { }
function Get-AzSubscription {
    param($SubscriptionId)
    @([pscustomobject]@{ Name = 'Contoso Prod'; Id = 'sub-1' })
}
function Get-AzNetworkSecurityGroup {
    param($ResourceGroupName)
    @([pscustomobject]@{
        Name = 'nsg-web'; ResourceGroupName = 'rg-net'; Location = 'uksouth'
        Subnets = @([pscustomobject]@{ Id = '/subscriptions/s/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/web' })
        NetworkInterfaces = @()
        SecurityRules = @([pscustomobject]@{ Name = 'AllowHttps'; Description = ''; Priority = 100; Protocol = 'Tcp'
            Access = 'Allow'; Direction = 'Inbound'; SourceAddressPrefix = 'Internet'; SourceAddressPrefixes = @()
            SourcePortRange = '*'; SourcePortRanges = @(); DestinationAddressPrefix = '*'; DestinationAddressPrefixes = @()
            DestinationPortRange = '443'; DestinationPortRanges = @() })
        DefaultSecurityRules = @()
    })
}
function Get-AzVirtualNetwork {
    param($ResourceGroupName)
    @([pscustomobject]@{
        Name = 'vnet1'; ResourceGroupName = 'rg-net'; Location = 'uksouth'
        AddressSpace = [pscustomobject]@{ AddressPrefixes = @('10.0.0.0/16') }
        DhcpOptions = [pscustomobject]@{ DnsServers = @('10.0.0.4') }
        Subnets = @([pscustomobject]@{ Name = 'web'; AddressPrefix = '10.0.1.0/24'; AddressPrefixes = @()
            NetworkSecurityGroup = [pscustomobject]@{ Id = '/x/nsg-web' }; RouteTable = $null
            ServiceEndpoints = @(); Delegations = @()
            PrivateEndpointNetworkPolicies = 'Disabled'; PrivateLinkServiceNetworkPolicies = 'Enabled' })
    })
}
function Get-AzNetworkInterface {
    param($ResourceGroupName)
    @([pscustomobject]@{
        Name = 'nic1'; ResourceGroupName = 'rg-net'; Location = 'uksouth'
        NetworkSecurityGroup = $null; VirtualMachine = [pscustomobject]@{ Id = '/x/vm1' }
        IpConfigurations = @([pscustomobject]@{ PrivateIpAddress = '10.0.1.4'; PrivateIpAllocationMethod = 'Dynamic'
            PublicIpAddress = $null; Subnet = [pscustomobject]@{ Id = '/x/web' } })
        EnableAcceleratedNetworking = $false; EnableIPForwarding = $false
    })
}
function Get-AzPublicIpAddress {
    param($ResourceGroupName)
    @([pscustomobject]@{
        Name = 'pip1'; ResourceGroupName = 'rg-net'; Location = 'uksouth'; IpAddress = '20.1.2.3'
        PublicIpAllocationMethod = 'Static'; Sku = [pscustomobject]@{ Name = 'Standard' }
        DnsSettings = $null; IpConfiguration = $null
    })
}
'@

        $script:azRun = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Export-AzNetworkInventory.ps1' `
            -Setup $setup -ModulePath $script:azModulePath `
            -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "aznet-$([guid]::NewGuid().ToString('N'))") }
        $script:azSummary = $script:azRun.Summary
    }

    It 'runs to completion after the module retrofit' {
        $script:azRun.ExitCode | Should -Be 0 -Because "the script failed: $($script:azRun.Output)"
        $script:azSummary | Should -Not -BeNullOrEmpty
    }

    It 'writes the run-directory layout the comparison tool needs' {
        Test-RunDirectoryLayout -Summary $script:azSummary -Prefix 'network-inventory' `
            -ReportName @('nsg-rules', 'nsg-assignments', 'virtual-networks', 'subnets', 'network-interfaces', 'public-ip-addresses')
    }

    It 'reports the subscription it read' {
        $script:azSummary.SubscriptionIds | Should -Contain 'sub-1'
    }

    It 'does not write a null entry for an unsupplied resource group filter' {
        # @($null) has Count 1, which used to put a null row in this list.
        @($script:azSummary.ResourceGroupNames).Count | Should -Be 0
    }

    It 'still scans everything when no resource group filter is supplied' {
        # The regression this guards is silent and reads as good news. The filter was
        # built as `if ($ResourceGroupName) { ... } else { @($null) }`, and an
        # if-statement unrolls its one-element result to a bare $null, over which
        # foreach iterates zero times. Every collection below it was skipped, so the
        # script exited 0 having written six empty reports, and an unscanned
        # subscription was indistinguishable from an empty one. Assert on the row
        # counts rather than on the files, because the files existed either way.
        #
        # Count the reports first. A bare foreach over the Exports list passes
        # vacuously when the run failed and the summary is null, which is the same
        # iterate-over-nothing trap this test exists to catch.
        $reports = @($script:azSummary.Exports)
        $reports.Count | Should -Be 6
        foreach ($report in $reports) {
            $report.Count | Should -BeGreaterThan 0 -Because "$($report.Name) should have been collected"
        }
    }

    It 'flattens the nested rule and subnet shapes' {
        $rules = @(Import-Csv (Join-Path $script:azSummary.OutputDirectory 'nsg-rules.csv'))
        $rules.Count | Should -Be 1
        $rules[0].DestinationPortRange | Should -Be '443'

        $subnets = @(Import-Csv (Join-Path $script:azSummary.OutputDirectory 'subnets.csv'))
        $subnets[0].NetworkSecurityGroup | Should -Be 'nsg-web'
    }
}

Describe 'Export-AzOrphanedResource end to end' {
    # Not a retrofitted script, but it shared the resource-group filter defect with
    # Export-AzNetworkInventory and had no end-to-end coverage, so the failure mode it
    # was in (reporting no orphans because it scanned nothing) was invisible. Every
    # resource type below is planted twice: once as a genuine orphan, once as a
    # resource that must not be reported.
    BeforeAll {
        $setup = @'
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' } } }
function Set-AzContext { param($SubscriptionId) }
function Get-AzSubscription {
    param($SubscriptionId)
    @([pscustomobject]@{ Name = 'Contoso Prod'; Id = 'sub-1' })
}
function Get-AzDisk {
    param($ResourceGroupName)
    @(
        [pscustomobject]@{ Name = 'disk-orphan'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-orphan'
            ManagedBy = $null; DiskSizeGB = 128; Sku = [pscustomobject]@{ Name = 'Premium_LRS' }
            TimeCreated = (Get-Date).AddDays(-200); Tags = @{} }
        [pscustomobject]@{ Name = 'disk-attached'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-attached'
            ManagedBy = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm1'
            DiskSizeGB = 256; Sku = [pscustomobject]@{ Name = 'Premium_LRS' }
            TimeCreated = (Get-Date).AddDays(-200); Tags = @{} }
    )
}
function Get-AzNetworkInterface {
    param($ResourceGroupName)
    @(
        [pscustomobject]@{ Name = 'nic-orphan'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-orphan'
            VirtualMachine = $null; PrivateEndpoint = $null; PrivateLinkService = $null; Tags = @{} }
        [pscustomobject]@{ Name = 'nic-on-vm'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-on-vm'
            VirtualMachine = [pscustomobject]@{ Id = '/x/vm1' }; PrivateEndpoint = $null
            PrivateLinkService = $null; Tags = @{} }
        # Held by a private endpoint, so it has no VM and is still in use.
        [pscustomobject]@{ Name = 'nic-private-endpoint'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-pe'
            VirtualMachine = $null; PrivateEndpoint = [pscustomobject]@{ Id = '/x/pe1' }
            PrivateLinkService = $null; Tags = @{} }
    )
}
function Get-AzPublicIpAddress {
    param($ResourceGroupName)
    @(
        [pscustomobject]@{ Name = 'pip-orphan-static'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/publicIPAddresses/pip-orphan'
            IpConfiguration = $null; PublicIpAllocationMethod = 'Static'
            Sku = [pscustomobject]@{ Name = 'Standard' }; Tags = @{} }
        [pscustomobject]@{ Name = 'pip-attached'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/publicIPAddresses/pip-attached'
            IpConfiguration = [pscustomobject]@{ Id = '/x/ipconfig1' }; PublicIpAllocationMethod = 'Static'
            Sku = [pscustomobject]@{ Name = 'Standard' }; Tags = @{} }
    )
}
function Get-AzSnapshot {
    param($ResourceGroupName)
    @(
        [pscustomobject]@{ Name = 'snap-old'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Compute/snapshots/snap-old'
            DiskSizeGB = 64; Sku = [pscustomobject]@{ Name = 'Standard_LRS' }
            TimeCreated = (Get-Date).AddDays(-400); Tags = @{} }
        [pscustomobject]@{ Name = 'snap-new'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Compute/snapshots/snap-new'
            DiskSizeGB = 32; Sku = [pscustomobject]@{ Name = 'Standard_LRS' }
            TimeCreated = (Get-Date).AddDays(-2); Tags = @{} }
    )
}
function Get-AzNetworkSecurityGroup {
    param($ResourceGroupName)
    @(
        [pscustomobject]@{ Name = 'nsg-unused'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkSecurityGroups/nsg-unused'
            Subnets = @(); NetworkInterfaces = @(); Tags = @{} }
        [pscustomobject]@{ Name = 'nsg-on-subnet'; ResourceGroupName = 'rg-a'; Location = 'uksouth'
            Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkSecurityGroups/nsg-on-subnet'
            Subnets = @([pscustomobject]@{ Id = '/x/subnet1' }); NetworkInterfaces = @(); Tags = @{} }
    )
}
'@

        $script:orphanRun = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Export-AzOrphanedResource.ps1' `
            -Setup $setup -ModulePath $script:azModulePath `
            -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "azorph-$([guid]::NewGuid().ToString('N'))") }
        $script:orphanSummary = $script:orphanRun.Summary
    }

    It 'runs to completion' {
        $script:orphanRun.ExitCode | Should -Be 0 -Because "the script failed: $($script:orphanRun.Output)"
        $script:orphanSummary | Should -Not -BeNullOrEmpty
    }

    It 'writes the run-directory layout the comparison tool needs' {
        Test-RunDirectoryLayout -Summary $script:orphanSummary -Prefix 'azure-orphaned-resources' `
            -ReportName @('orphaned-resources', 'type-rollup', 'subscription-rollup', 'tag-actions')
    }

    It 'still scans when no resource group filter is supplied' {
        # The defect this guards reported a clean estate for an estate it never looked
        # at, which is the one wrong answer nobody questions.
        $script:orphanSummary.SubscriptionsScanned | Should -Be 1
        $script:orphanSummary.OrphanCount | Should -BeGreaterThan 0
    }

    It 'finds the planted orphan of each type' {
        $script:orphanSummary.ManagedDiskCount | Should -Be 1
        $script:orphanSummary.NetworkInterfaceCount | Should -Be 1
        $script:orphanSummary.PublicIpCount | Should -Be 1
        $script:orphanSummary.UnattachedNsgCount | Should -Be 1
    }

    It 'leaves the in-use resources out of the report' {
        $rows = @(Import-Csv (Join-Path $script:orphanSummary.OutputDirectory 'orphaned-resources.csv'))
        # Prove the column exists before asserting absence from it. A misnamed column
        # yields null for every row, and every -Not -Contain below then passes without
        # testing anything.
        $rows[0].PSObject.Properties.Name | Should -Contain 'Name'
        $names = $rows | ForEach-Object { $_.Name }
        $names | Should -Not -Contain 'disk-attached'
        $names | Should -Not -Contain 'nic-on-vm'
        $names | Should -Not -Contain 'pip-attached'
        $names | Should -Not -Contain 'nsg-on-subnet'
        # A NIC with no VM but a private endpoint is in use. Reporting it would send
        # someone to delete a live private endpoint's interface.
        $names | Should -Not -Contain 'nic-private-endpoint'
    }

    It 'reports a static unassociated address with the cost-bearing reason' {
        $rows = @(Import-Csv (Join-Path $script:orphanSummary.OutputDirectory 'orphaned-resources.csv'))
        $pip = $rows | Where-Object { $_.Name -eq 'pip-orphan-static' }
        $pip.Reason | Should -Match 'bills continuously'
    }

    It 'prices nothing when no price table was supplied' {
        # An unpriced row is honest. An invented rate in a savings report is not.
        $script:orphanSummary.PriceTableSupplied | Should -BeFalse
        $script:orphanSummary.EstimatedMonthlyCost | Should -BeNullOrEmpty
        $script:orphanSummary.UnpricedCount | Should -Be $script:orphanSummary.OrphanCount
    }

    It 'applies the minimum age filter to snapshots' {
        $aged = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Export-AzOrphanedResource.ps1' `
            -Setup $setup -ModulePath $script:azModulePath `
            -Argument @{
            OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "azorph2-$([guid]::NewGuid().ToString('N'))")
            ResourceType = 'Snapshot'
            MinimumAgeDays = 30
        }
        $aged.ExitCode | Should -Be 0 -Because "the script failed: $($aged.Output)"
        $aged.Summary.SnapshotCount | Should -Be 1
        $kept = @(Import-Csv (Join-Path $aged.Summary.OutputDirectory 'orphaned-resources.csv'))
        $kept.Count | Should -Be 1
        $kept[0].Name | Should -Be 'snap-old'
    }
}

Describe 'Export-M365DistributionGroupMessageTraceUsage end to end' {
    BeforeAll {
        $setup = @'
Import-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue

function Connect-ExchangeOnline { param($ShowBanner, $Organization) }
function Disconnect-ExchangeOnline { param($Confirm) }
function Get-DistributionGroup {
    param($ResultSize)
    @(
        [pscustomobject]@{ DisplayName = 'Active List'; PrimarySmtpAddress = 'active@contoso.com'
            Alias = 'active'; RecipientTypeDetails = 'MailUniversalDistributionGroup'
            GroupType = 'Universal'; ManagedBy = @(); WhenCreated = (Get-Date).AddDays(-500) }
        [pscustomobject]@{ DisplayName = 'Dormant List'; PrimarySmtpAddress = 'dormant@contoso.com'
            Alias = 'dormant'; RecipientTypeDetails = 'MailUniversalDistributionGroup'
            GroupType = 'Universal'; ManagedBy = @(); WhenCreated = (Get-Date).AddDays(-900) }
    )
}
# Only the active list appears in the trace, so the other must report as inactive.
function Get-MessageTraceV2 {
    param($StartDate, $EndDate, $Status, $ResultSize, $StartingRecipientAddress)
    @(
        [pscustomobject]@{ RecipientAddress = 'active@contoso.com'; Received = (Get-Date).AddDays(-1); Status = 'Expanded' }
        [pscustomobject]@{ RecipientAddress = 'active@contoso.com'; Received = (Get-Date).AddDays(-2); Status = 'Expanded' }
    )
}
'@

        $script:m365Run = Invoke-ScriptUnderTest -RelativePath 'scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1' `
            -Setup $setup `
            -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "m365dg-$([guid]::NewGuid().ToString('N'))") }
        $script:m365Summary = $script:m365Run.Summary
    }

    It 'runs to completion after the module retrofit' {
        $script:m365Run.ExitCode | Should -Be 0 -Because "the script failed: $($script:m365Run.Output)"
        $script:m365Summary | Should -Not -BeNullOrEmpty
    }

    It 'writes the run-directory layout the comparison tool needs' {
        Test-RunDirectoryLayout -Summary $script:m365Summary -Prefix 'distribution-group-message-trace-usage' `
            -ReportName @('distribution-group-usage')
    }

    It 'separates the active list from the dormant one' {
        $script:m365Summary.GroupCount | Should -Be 2
        $script:m365Summary.ActiveGroupCount | Should -Be 1
        $script:m365Summary.InactiveGroupCount | Should -Be 1
    }
}

Describe 'Join-ApplicationsWithEndpointSites end to end' {
    BeforeAll {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) "join-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:work -Force | Out-Null

        @(
            [pscustomobject]@{ 'Agent Name' = 'PC001'; 'Name' = 'App1'; 'Machine Type' = 'Laptop' }
            [pscustomobject]@{ 'Agent Name' = 'PC999'; 'Name' = 'App2'; 'Machine Type' = 'Desktop' }
        ) | Export-Csv (Join-Path $script:work 'apps.csv') -NoTypeInformation -Encoding utf8

        @([pscustomobject]@{ 'Endpoint Name' = 'PC001'; 'Site' = 'London' }) |
            Export-Csv (Join-Path $script:work 'endpoints.csv') -NoTypeInformation -Encoding utf8

        $script:joinSummary = & (Get-RepositoryScriptPath -RelativePath 'scripts\utilities\Join-ApplicationsWithEndpointSites.ps1') `
            -ApplicationsPath (Join-Path $script:work 'apps.csv') `
            -EndpointsPath (Join-Path $script:work 'endpoints.csv') `
            -IncludeUnmatchedApplications `
            -OutputDirectory (Join-Path $script:work 'out')
    }

    AfterAll {
        if (Test-Path $script:work) { Remove-Item $script:work -Recurse -Force }
    }

    It 'writes the run-directory layout the comparison tool needs' {
        Test-RunDirectoryLayout -Summary $script:joinSummary -Prefix 'applications-endpoint-sites' `
            -ReportName @('matched', 'unmatched')
    }

    It 'matches and reports the leftover separately' {
        $script:joinSummary.MatchedCount | Should -Be 1
        $script:joinSummary.UnmatchedCount | Should -Be 1
    }

    It 'writes the unmatched report even when unmatched output was not requested' {
        # An empty report proves the join ran and found nothing left over. A missing
        # file cannot be told apart from a run that never happened.
        $summary = & (Get-RepositoryScriptPath -RelativePath 'scripts\utilities\Join-ApplicationsWithEndpointSites.ps1') `
            -ApplicationsPath (Join-Path $script:work 'apps.csv') `
            -EndpointsPath (Join-Path $script:work 'endpoints.csv') `
            -OutputDirectory (Join-Path $script:work 'out2')

        Test-Path (Join-Path $summary.OutputDirectory 'unmatched.csv') | Should -BeTrue
        @(Import-Csv (Join-Path $summary.OutputDirectory 'unmatched.csv')).Count | Should -Be 0
    }
}
