<#
.SYNOPSIS
Report Azure resources that are paid for and attached to nothing: unattached disks, idle NICs, unassociated public IPs, and old snapshots.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only by default. It deletes nothing. -TagForReview adds a tag and is the only
  action it can take, and it supports -WhatIf.
- Requires Az.Accounts, Az.Compute, and Az.Network. Connect first, or with
  Initialize-AzPowerShellSession.ps1 for a known tenant and subscription.
- Nothing here is priced. Azure rates vary by region, SKU, and agreement, and an
  invented number in a savings report is worse than no number. Supply your own rates
  with -PriceTablePath to get an estimate, or read the SKU and size columns and price
  them yourself.
- Age is measured from the resource's own timestamps where Azure exposes them. A
  resource with no usable timestamp is reported with an empty age rather than a
  guessed one.
- Confirm before deleting anything. An unattached disk can be a deliberate backup,
  and a reserved public IP can be a DNS dependency someone forgot to document.
- Generated reports are written under reports\azure by default.

Purpose:
Deleting a virtual machine does not delete its disk, its network interface, or its
public IP, and nothing in the portal groups the leftovers together. They accumulate
quietly and bill monthly. This finds them in one pass across every subscription in
scope and reports what each one is, how large it is, and how long it has been
detached, so the review has something to work from.

This is the one report in this toolkit that returns money rather than reducing risk,
which also makes it the one where a wrong deletion is expensive. Hence report-first,
tag-second, and never delete.

Required syntax:
pwsh -File .\scripts\azure\Export-AzOrphanedResource.ps1
pwsh -File .\scripts\azure\Export-AzOrphanedResource.ps1 -SubscriptionId "<subscription-id>" -MinimumAgeDays 30
pwsh -File .\scripts\azure\Export-AzOrphanedResource.ps1 -TagForReview -WhatIf

.OUTPUTS
Writes orphaned resources, a per-type rollup, a per-subscription rollup, and a run
summary as CSV and JSON under reports\azure by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules Az.Accounts, Az.Compute, Az.Network
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ResourceGroupName,

    [Parameter()]
    [ValidateSet('ManagedDisk', 'NetworkInterface', 'PublicIpAddress', 'Snapshot', 'NetworkSecurityGroup')]
    [string[]]$ResourceType = @('ManagedDisk', 'NetworkInterface', 'PublicIpAddress', 'Snapshot', 'NetworkSecurityGroup'),

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$MinimumAgeDays = 0,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PriceTablePath,

    [Parameter()]
    [switch]$TagForReview,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReviewTagName = 'ops-toolkit-review',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'azure-orphaned-resources'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

function Get-ResourceAgeDay {
    <#
    .SYNOPSIS
    Return the age in days from whichever timestamp a resource actually exposes.

    .DESCRIPTION
    Azure resource types disagree about which timestamp they publish. Rather than
    guessing, this tries the known property names in order and returns null when none
    is present, so the report shows an empty age instead of a fabricated one.

    .PARAMETER Resource
    The Azure resource object.

    .PARAMETER AsOf
    Reference point.

    .OUTPUTS
    Int32 days, or null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Resource,

        [Parameter(Mandatory = $true)]
        [datetime]$AsOf
    )

    foreach ($property in @('TimeCreated', 'DiskState', 'CreatedTime', 'ProvisioningTime')) {
        $value = Get-OpsPropertyValue -InputObject $Resource -Name $property
        if ($value -is [datetime]) {
            return Get-OpsAge -Timestamp $value -AsOf $AsOf
        }
    }

    $null
}

function Get-PriceEstimate {
    <#
    .SYNOPSIS
    Look up a monthly rate from the operator-supplied price table.

    .DESCRIPTION
    Returns null when no table was supplied or no row matches. Never invents a rate:
    an unpriced row in a savings report is honest, a wrong one is not.

    .PARAMETER PriceTable
    Rows with ResourceType, Sku, and MonthlyRate columns.

    .PARAMETER ResourceType
    The resource type to match.

    .PARAMETER Sku
    The SKU or size to match. A row with an empty Sku matches any.

    .PARAMETER Quantity
    Multiplier, for example the disk size in GB when the rate is per GB.

    .OUTPUTS
    Double, or null.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$PriceTable,

        [Parameter(Mandatory = $true)]
        [string]$ResourceType,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Sku = '',

        [Parameter()]
        [double]$Quantity = 1
    )

    if (-not $PriceTable) {
        return $null
    }

    $row = @($PriceTable | Where-Object {
            $_.ResourceType -eq $ResourceType -and ($_.Sku -eq $Sku -or -not $_.Sku)
        } | Sort-Object { if ($_.Sku) { 0 } else { 1 } } | Select-Object -First 1)

    if ($row.Count -eq 0) {
        return $null
    }

    $rate = 0.0
    if (-not [double]::TryParse([string]$row[0].MonthlyRate, [ref]$rate)) {
        return $null
    }

    [math]::Round($rate * $Quantity, 2)
}

$priceTable = $null
if ($PriceTablePath) {
    if (-not (Test-Path -LiteralPath $PriceTablePath)) {
        throw "Price table not found: $PriceTablePath. It needs ResourceType, Sku, and MonthlyRate columns."
    }

    $priceTable = @(Import-Csv -LiteralPath $PriceTablePath)
    Write-Verbose "Loaded $($priceTable.Count) price row(s)."
}

if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

$asOf = Get-Date
$subscriptions = if ($SubscriptionId) {
    foreach ($id in $SubscriptionId) { Get-AzSubscription -SubscriptionId $id }
} else {
    Get-AzSubscription
}

$orphans = [System.Collections.Generic.List[object]]::new()
$tagActions = [System.Collections.Generic.List[object]]::new()

function Add-Orphan {
    param($Subscription, $Type, $Resource, $Reason, $Sku = '', $SizeGb = $null, $AgeDays = $null, $Estimate = $null)

    $orphans.Add([pscustomobject]@{
            SubscriptionName = $Subscription.Name
            SubscriptionId = $Subscription.Id
            ResourceType = $Type
            Name = Join-OpsValue (Get-OpsPropertyValue -InputObject $Resource -Name 'Name')
            ResourceGroupName = Join-OpsValue (Get-OpsPropertyValue -InputObject $Resource -Name 'ResourceGroupName')
            Location = Join-OpsValue (Get-OpsPropertyValue -InputObject $Resource -Name 'Location')
            Sku = $Sku
            SizeGb = $SizeGb
            AgeDays = $AgeDays
            Reason = $Reason
            EstimatedMonthlyCost = $Estimate
            ResourceId = Join-OpsValue (Get-OpsPropertyValue -InputObject $Resource -Name 'Id')
            Tags = Join-OpsValue (Get-OpsPropertyValue -InputObject $Resource -Name 'Tags')
        })
}

foreach ($subscription in $subscriptions) {
    Write-Verbose "Scanning subscription $($subscription.Name)."
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null
    $groupFilter = if ($ResourceGroupName) { $ResourceGroupName } else { @($null) }

    foreach ($group in $groupFilter) {
        $groupParameter = if ($group) { @{ ResourceGroupName = $group } } else { @{} }

        if ($ResourceType -contains 'ManagedDisk') {
            foreach ($disk in (Get-AzDisk @groupParameter)) {
                # ManagedBy holds the owning VM id. Empty means nothing is using it.
                if (Get-OpsPropertyValue -InputObject $disk -Name 'ManagedBy') {
                    continue
                }

                $sizeGb = [double](Get-OpsPropertyValue -InputObject $disk -Name 'DiskSizeGB')
                $sku = Join-OpsValue ((Get-OpsPropertyValue -InputObject $disk -Name 'Sku') | ForEach-Object { Get-OpsPropertyValue -InputObject $_ -Name 'Name' })
                $age = Get-ResourceAgeDay -Resource $disk -AsOf $asOf
                Add-Orphan -Subscription $subscription -Type 'ManagedDisk' -Resource $disk `
                    -Reason 'Managed disk is not attached to any virtual machine.' `
                    -Sku $sku -SizeGb $sizeGb -AgeDays $age `
                    -Estimate (Get-PriceEstimate -PriceTable $priceTable -ResourceType 'ManagedDisk' -Sku $sku -Quantity $sizeGb)
            }
        }

        if ($ResourceType -contains 'NetworkInterface') {
            foreach ($nic in (Get-AzNetworkInterface @groupParameter)) {
                if (Get-OpsPropertyValue -InputObject $nic -Name 'VirtualMachine') {
                    continue
                }

                # A NIC can also be held by a private endpoint or a load balancer,
                # neither of which is a VM. Those are in use and must not be reported.
                if ((Get-OpsPropertyValue -InputObject $nic -Name 'PrivateEndpoint') -or (Get-OpsPropertyValue -InputObject $nic -Name 'PrivateLinkService')) {
                    continue
                }

                Add-Orphan -Subscription $subscription -Type 'NetworkInterface' -Resource $nic `
                    -Reason 'Network interface is not attached to a virtual machine, private endpoint, or private link service.' `
                    -AgeDays (Get-ResourceAgeDay -Resource $nic -AsOf $asOf) `
                    -Estimate (Get-PriceEstimate -PriceTable $priceTable -ResourceType 'NetworkInterface')
            }
        }

        if ($ResourceType -contains 'PublicIpAddress') {
            foreach ($publicIp in (Get-AzPublicIpAddress @groupParameter)) {
                if (Get-OpsPropertyValue -InputObject $publicIp -Name 'IpConfiguration') {
                    continue
                }

                $sku = Join-OpsValue ((Get-OpsPropertyValue -InputObject $publicIp -Name 'Sku') | ForEach-Object { Get-OpsPropertyValue -InputObject $_ -Name 'Name' })
                $allocation = Join-OpsValue (Get-OpsPropertyValue -InputObject $publicIp -Name 'PublicIpAllocationMethod')

                # A static address that is unassociated still bills and may still be
                # in DNS. That combination is the one worth flagging loudly.
                $reason = if ($allocation -ieq 'Static') {
                    'Public IP is static and associated with nothing. It bills continuously and may still be referenced in DNS.'
                } else {
                    'Public IP is associated with nothing.'
                }

                Add-Orphan -Subscription $subscription -Type 'PublicIpAddress' -Resource $publicIp `
                    -Reason $reason -Sku "$sku/$allocation" `
                    -AgeDays (Get-ResourceAgeDay -Resource $publicIp -AsOf $asOf) `
                    -Estimate (Get-PriceEstimate -PriceTable $priceTable -ResourceType 'PublicIpAddress' -Sku $sku)
            }
        }

        if ($ResourceType -contains 'Snapshot') {
            foreach ($snapshot in (Get-AzSnapshot @groupParameter)) {
                $age = Get-ResourceAgeDay -Resource $snapshot -AsOf $asOf
                if ($null -ne $age -and $age -lt $MinimumAgeDays) {
                    continue
                }

                $sizeGb = [double](Get-OpsPropertyValue -InputObject $snapshot -Name 'DiskSizeGB')
                $sku = Join-OpsValue ((Get-OpsPropertyValue -InputObject $snapshot -Name 'Sku') | ForEach-Object { Get-OpsPropertyValue -InputObject $_ -Name 'Name' })
                Add-Orphan -Subscription $subscription -Type 'Snapshot' -Resource $snapshot `
                    -Reason 'Snapshot retained. Snapshots bill for as long as they exist and are rarely reviewed.' `
                    -Sku $sku -SizeGb $sizeGb -AgeDays $age `
                    -Estimate (Get-PriceEstimate -PriceTable $priceTable -ResourceType 'Snapshot' -Sku $sku -Quantity $sizeGb)
            }
        }

        if ($ResourceType -contains 'NetworkSecurityGroup') {
            foreach ($nsg in (Get-AzNetworkSecurityGroup @groupParameter)) {
                $subnets = @(Get-OpsPropertyValue -InputObject $nsg -Name 'Subnets')
                $nics = @(Get-OpsPropertyValue -InputObject $nsg -Name 'NetworkInterfaces')
                if ($subnets.Count -gt 0 -or $nics.Count -gt 0) {
                    continue
                }

                # An NSG costs nothing, so this is hygiene rather than savings: an
                # unattached NSG is usually a rule set someone believes is protecting
                # something.
                Add-Orphan -Subscription $subscription -Type 'NetworkSecurityGroup' -Resource $nsg `
                    -Reason 'Network security group is attached to no subnet and no network interface, so its rules are enforcing nothing. No direct cost.' `
                    -AgeDays (Get-ResourceAgeDay -Resource $nsg -AsOf $asOf)
            }
        }
    }
}

$filtered = @($orphans | Where-Object { $null -eq $_.AgeDays -or $_.AgeDays -ge $MinimumAgeDays })

if ($TagForReview) {
    foreach ($orphan in $filtered) {
        if (-not $PSCmdlet.ShouldProcess($orphan.ResourceId, "Add tag $ReviewTagName")) {
            $tagActions.Add([pscustomobject]@{ ResourceId = $orphan.ResourceId; Action = 'WouldTag'; Result = 'WhatIf' })
            continue
        }

        try {
            Update-AzTag -ResourceId $orphan.ResourceId -Tag @{ $ReviewTagName = "orphaned-$($asOf.ToString('yyyy-MM-dd'))" } -Operation Merge | Out-Null
            $tagActions.Add([pscustomobject]@{ ResourceId = $orphan.ResourceId; Action = 'Tagged'; Result = 'Success' })
        } catch {
            $tagActions.Add([pscustomobject]@{ ResourceId = $orphan.ResourceId; Action = 'Tag'; Result = "Failed: $($_.Exception.Message)" })
        }
    }
}

$typeRollup = foreach ($group in (@($filtered) | Group-Object -Property ResourceType)) {
    $rows = @($group.Group)
    $priced = @($rows | Where-Object { $null -ne $_.EstimatedMonthlyCost })
    [pscustomobject]@{
        ResourceType = $group.Name
        Count = $rows.Count
        TotalSizeGb = [math]::Round((@($rows | ForEach-Object { [double]($_.SizeGb ?? 0) }) | Measure-Object -Sum).Sum, 2)
        PricedCount = $priced.Count
        EstimatedMonthlyCost = if ($priced.Count -gt 0) { [math]::Round((@($priced | ForEach-Object { [double]$_.EstimatedMonthlyCost }) | Measure-Object -Sum).Sum, 2) } else { $null }
        OldestAgeDays = (@($rows | Where-Object { $null -ne $_.AgeDays } | ForEach-Object { [int]$_.AgeDays } | Sort-Object -Descending) | Select-Object -First 1)
    }
}

$subscriptionRollup = foreach ($group in (@($filtered) | Group-Object -Property SubscriptionName)) {
    [pscustomobject]@{
        SubscriptionName = $group.Name
        OrphanCount = $group.Count
        Types = (@($group.Group | ForEach-Object { $_.ResourceType } | Select-Object -Unique) | Sort-Object) -join ';'
    }
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'orphaned-resources' -Record $filtered -Directory $runDirectory
    Export-OpsReport -Name 'type-rollup' -Record @($typeRollup) -Directory $runDirectory
    Export-OpsReport -Name 'subscription-rollup' -Record @($subscriptionRollup) -Directory $runDirectory
    Export-OpsReport -Name 'tag-actions' -Record @($tagActions) -Directory $runDirectory
)

$pricedTotal = @($filtered | Where-Object { $null -ne $_.EstimatedMonthlyCost })
$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    SubscriptionsScanned = @($subscriptions).Count
    ResourceTypesScanned = @($ResourceType)
    MinimumAgeDays = $MinimumAgeDays
    PriceTableSupplied = [bool]$priceTable
    OrphanCount = $filtered.Count
    ManagedDiskCount = @($filtered | Where-Object { $_.ResourceType -eq 'ManagedDisk' }).Count
    NetworkInterfaceCount = @($filtered | Where-Object { $_.ResourceType -eq 'NetworkInterface' }).Count
    PublicIpCount = @($filtered | Where-Object { $_.ResourceType -eq 'PublicIpAddress' }).Count
    SnapshotCount = @($filtered | Where-Object { $_.ResourceType -eq 'Snapshot' }).Count
    UnattachedNsgCount = @($filtered | Where-Object { $_.ResourceType -eq 'NetworkSecurityGroup' }).Count
    TotalOrphanedDiskGb = [math]::Round((@($filtered | Where-Object { $_.ResourceType -in @('ManagedDisk', 'Snapshot') } | ForEach-Object { [double]($_.SizeGb ?? 0) }) | Measure-Object -Sum).Sum, 2)
    EstimatedMonthlyCost = if ($pricedTotal.Count -gt 0) { [math]::Round((@($pricedTotal | ForEach-Object { [double]$_.EstimatedMonthlyCost }) | Measure-Object -Sum).Sum, 2) } else { $null }
    UnpricedCount = @($filtered | Where-Object { $null -eq $_.EstimatedMonthlyCost }).Count
    TaggedForReview = @($tagActions | Where-Object { $_.Result -eq 'Success' }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
