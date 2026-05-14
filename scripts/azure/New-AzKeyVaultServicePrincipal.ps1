<#
.SYNOPSIS
Create or reuse a Microsoft Entra service principal and optionally grant Key Vault access-policy permissions.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Requires Az.Accounts, Az.Resources, and Az.KeyVault.
- Always run with -WhatIf first and review the generated plan/state reports.
- Prefer managed identities when the workload can use them; use service principals only when required.
- Do not store generated client secrets in reports or source control.
- Generated reports are written under reports\azure by default.

.PURPOSE
Use this script when an automation workload needs a service principal with
explicit Key Vault access-policy permissions. It creates or reuses the service
principal, optionally grants certificate/secret/key permissions, and writes plan
and state artifacts for review. The rollback report describes the commands to
remove the access policy and service principal if the change needs to be undone.

.REQUIRED SYNTAX
pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -SubscriptionId "<subscription-id>" -EnvironmentName prod -ApplicationShortName app -KeyVaultName kv-prod-app -WhatIf
pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -DisplayName prod-app-serviceprincipal -KeyVaultName kv-prod-app -CertificatePermissions Get,List -SecretPermissions Get -WhatIf
pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -DisplayName prod-app-serviceprincipal -KeyVaultName kv-prod-app -ReuseExisting -SkipKeyVaultPolicy

.OUTPUTS
Writes plan, state, rollback guidance, and summary files under reports\azure by
default. Returns a summary object with service principal identifiers and report
paths. Client secrets are not written to report files.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules Az.Accounts, Az.Resources, Az.KeyVault
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$EnvironmentName,

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$ApplicationShortName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultResourceGroupName,

    [Parameter()]
    [ValidateSet('All', 'Get', 'List', 'Delete', 'Create', 'Import', 'Update', 'ManageContacts', 'GetIssuers', 'ListIssuers', 'SetIssuers', 'DeleteIssuers', 'ManageIssuers', 'Recover', 'Backup', 'Restore', 'Purge')]
    [string[]]$CertificatePermissions = @('Get', 'List', 'Create', 'Update', 'Backup'),

    [Parameter()]
    [ValidateSet('All', 'Get', 'List', 'Set', 'Delete', 'Backup', 'Restore', 'Recover', 'Purge')]
    [string[]]$SecretPermissions = @(),

    [Parameter()]
    [ValidateSet('All', 'Decrypt', 'Encrypt', 'UnwrapKey', 'WrapKey', 'Verify', 'Sign', 'Get', 'List', 'Update', 'Create', 'Import', 'Delete', 'Backup', 'Restore', 'Recover', 'Purge', 'Rotate')]
    [string[]]$KeyPermissions = @(),

    [Parameter()]
    [ValidateRange(1, 5)]
    [int]$CredentialYears = 1,

    [Parameter()]
    [switch]$ReuseExisting,

    [Parameter()]
    [switch]$SkipKeyVaultPolicy,

    [Parameter()]
    [switch]$ShowGeneratedSecret,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\..\reports\azure')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -SubscriptionId "<subscription-id>" -EnvironmentName prod -ApplicationShortName app -KeyVaultName kv-prod-app -WhatIf
  pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -DisplayName prod-app-serviceprincipal -KeyVaultName kv-prod-app -CertificatePermissions Get,List -SecretPermissions Get -WhatIf
  pwsh -File .\scripts\azure\New-AzKeyVaultServicePrincipal.ps1 -DisplayName prod-app-serviceprincipal -KeyVaultName kv-prod-app -ReuseExisting -SkipKeyVaultPolicy

Options:
  -SubscriptionId              Optional Azure subscription ID to select before changes.
  -TenantId                    Optional tenant ID used when connecting.
  -EnvironmentName             Environment slug used to build the display name.
  -ApplicationShortName        Application slug used to build the display name.
  -DisplayName                 Explicit service principal display name.
  -KeyVaultName                Target Key Vault name. Required unless -SkipKeyVaultPolicy is used.
  -KeyVaultResourceGroupName   Optional Key Vault resource group for policy updates.
  -CertificatePermissions      Certificate permissions to grant. Defaults to Get,List,Create,Update,Backup.
  -SecretPermissions           Optional secret permissions to grant.
  -KeyPermissions              Optional key permissions to grant.
  -CredentialYears             Generated credential lifetime. Defaults to 1 year.
  -ReuseExisting               Reuse an existing service principal with the same display name.
  -SkipKeyVaultPolicy          Create/reuse the SP but do not grant Key Vault policy permissions.
  -ShowGeneratedSecret         Print the generated client secret to the host; never writes it to reports.
  -ReportDirectory             Plan/state output directory.
  -WhatIf                      Preview creation and Key Vault policy changes.
'@
}

function Resolve-ReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function ConvertFrom-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [securestring]$SecureString
    )

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    foreach ($propertyName in $Name) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($property) {
            return $property.Value
        }
    }

    $null
}

function Get-ResolvedDisplayName {
    param(
        [Parameter()]
        [string]$ExplicitDisplayName,

        [Parameter()]
        [string]$EnvironmentSlug,

        [Parameter()]
        [string]$ApplicationSlug
    )

    if ($ExplicitDisplayName) {
        return $ExplicitDisplayName
    }

    if ($EnvironmentSlug -and $ApplicationSlug) {
        return "$EnvironmentSlug-$ApplicationSlug-serviceprincipal"
    }

    $null
}

function Get-ServicePrincipalPlan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedDisplayName,

        [Parameter(Mandatory = $true)]
        [bool]$ReuseExistingPrincipal,

        [Parameter(Mandatory = $true)]
        [int]$CredentialLifetimeYears
    )

    [pscustomobject]@{
        GeneratedAt = Get-Date
        Action = if ($ReuseExistingPrincipal) { 'ReuseOrCreateServicePrincipal' } else { 'CreateServicePrincipal' }
        DisplayName = $ResolvedDisplayName
        SubscriptionId = $SubscriptionId
        TenantId = $TenantId
        KeyVaultName = $KeyVaultName
        KeyVaultResourceGroupName = $KeyVaultResourceGroupName
        SkipKeyVaultPolicy = [bool]$SkipKeyVaultPolicy
        CredentialYears = $CredentialLifetimeYears
        CertificatePermissions = $CertificatePermissions -join ';'
        SecretPermissions = $SecretPermissions -join ';'
        KeyPermissions = $KeyPermissions -join ';'
        ClientSecretStorage = if ($ShowGeneratedSecret) { 'PrintedToHostOnly' } else { 'NotDisplayedOrStored' }
    }
}

function Get-ServicePrincipalByDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedDisplayName
    )

    @(Get-AzADServicePrincipal -DisplayName $ResolvedDisplayName -ErrorAction SilentlyContinue) |
        Sort-Object DisplayName |
        Select-Object -First 1
}

function New-OrReuseServicePrincipal {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedDisplayName,

        [Parameter(Mandatory = $true)]
        [bool]$ReuseExistingPrincipal,

        [Parameter(Mandatory = $true)]
        [int]$CredentialLifetimeYears
    )

    $existing = Get-ServicePrincipalByDisplayName -ResolvedDisplayName $ResolvedDisplayName
    if ($existing -and $ReuseExistingPrincipal) {
        return [pscustomobject]@{
            Result = 'Reused'
            ServicePrincipal = $existing
            SecretReturned = $false
        }
    }

    if ($existing -and -not $ReuseExistingPrincipal) {
        throw "A service principal named '$ResolvedDisplayName' already exists. Re-run with -ReuseExisting or choose another name."
    }

    if ($PSCmdlet.ShouldProcess($ResolvedDisplayName, 'Create Microsoft Entra service principal')) {
        $newParameters = @{
            DisplayName = $ResolvedDisplayName
            EndDate = (Get-Date).AddYears($CredentialLifetimeYears)
        }
        $servicePrincipal = New-AzADServicePrincipal @newParameters
        return [pscustomobject]@{
            Result = 'Created'
            ServicePrincipal = $servicePrincipal
            SecretReturned = [bool]$servicePrincipal.Secret
        }
    }

    [pscustomobject]@{
        Result = 'Previewed'
        ServicePrincipal = [pscustomobject]@{
            DisplayName = $ResolvedDisplayName
            Id = $null
            ApplicationId = $null
        }
        SecretReturned = $false
    }
}

function Set-ServicePrincipalKeyVaultPolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ServicePrincipal
    )

    if ($SkipKeyVaultPolicy) {
        return 'Skipped'
    }

    $servicePrincipalObjectId = Get-ObjectPropertyValue -InputObject $ServicePrincipal -Name @('Id', 'ObjectId')
    if (-not $servicePrincipalObjectId) {
        return 'Previewed'
    }

    if ($PSCmdlet.ShouldProcess($KeyVaultName, "Grant Key Vault access policy to $($ServicePrincipal.DisplayName)")) {
        $policyParameters = @{
            VaultName = $KeyVaultName
            ObjectId = $servicePrincipalObjectId
            PassThru = $true
        }
        if ($KeyVaultResourceGroupName) {
            $policyParameters.ResourceGroupName = $KeyVaultResourceGroupName
        }
        if ($CertificatePermissions.Count -gt 0) {
            $policyParameters.PermissionsToCertificates = $CertificatePermissions
        }
        if ($SecretPermissions.Count -gt 0) {
            $policyParameters.PermissionsToSecrets = $SecretPermissions
        }
        if ($KeyPermissions.Count -gt 0) {
            $policyParameters.PermissionsToKeys = $KeyPermissions
        }

        Set-AzKeyVaultAccessPolicy @policyParameters | Out-Null
        return 'Granted'
    }

    'Previewed'
}

function Get-RollbackGuidance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ServicePrincipal,

        [Parameter(Mandatory = $true)]
        [string]$PrincipalResult
    )

    $servicePrincipalObjectId = Get-ObjectPropertyValue -InputObject $ServicePrincipal -Name @('Id', 'ObjectId')
    $policyCommand = if (-not $SkipKeyVaultPolicy -and $servicePrincipalObjectId) {
        "Remove-AzKeyVaultAccessPolicy -VaultName '$KeyVaultName' -ObjectId '$servicePrincipalObjectId'"
    } else {
        'No Key Vault policy rollback command was generated.'
    }

    $principalCommand = if ($PrincipalResult -eq 'Created' -and $servicePrincipalObjectId) {
        "Remove-AzADServicePrincipal -ObjectId '$servicePrincipalObjectId'"
    } else {
        'No service-principal removal command was generated because the principal was not created by this run.'
    }

    [pscustomobject]@{
        KeyVaultPolicyRollback = $policyCommand
        ServicePrincipalRollback = $principalCommand
        Note = 'Review dependencies before removing a service principal or access policy.'
    }
}

$resolvedDisplayName = Get-ResolvedDisplayName -ExplicitDisplayName $DisplayName -EnvironmentSlug $EnvironmentName -ApplicationSlug $ApplicationShortName
if (-not $resolvedDisplayName -or (-not $SkipKeyVaultPolicy -and -not $KeyVaultName)) {
    Show-Usage
    exit 2
}

if (-not (Get-AzContext)) {
    $connectParameters = @{}
    if ($TenantId) {
        $connectParameters.Tenant = $TenantId
    }
    Connect-AzAccount @connectParameters | Out-Null
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$resolvedReportDirectory = Resolve-ReportDirectory -Path $ReportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$planPath = Join-Path $resolvedReportDirectory "keyvault-serviceprincipal-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "keyvault-serviceprincipal-state-$timestamp.json"
$rollbackPath = Join-Path $resolvedReportDirectory "keyvault-serviceprincipal-rollback-$timestamp.json"

$plan = Get-ServicePrincipalPlan -ResolvedDisplayName $resolvedDisplayName -ReuseExistingPrincipal ([bool]$ReuseExisting) -CredentialLifetimeYears $CredentialYears
Set-Content -LiteralPath $planPath -Value ($plan | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false

$principalResult = New-OrReuseServicePrincipal -ResolvedDisplayName $resolvedDisplayName -ReuseExistingPrincipal ([bool]$ReuseExisting) -CredentialLifetimeYears $CredentialYears -WhatIf:$WhatIfPreference
$servicePrincipal = $principalResult.ServicePrincipal
$policyResult = Set-ServicePrincipalKeyVaultPolicy -ServicePrincipal $servicePrincipal -WhatIf:$WhatIfPreference

$servicePrincipalSecret = Get-ObjectPropertyValue -InputObject $servicePrincipal -Name @('Secret')
$servicePrincipalObjectId = Get-ObjectPropertyValue -InputObject $servicePrincipal -Name @('Id', 'ObjectId')
$servicePrincipalApplicationId = Get-ObjectPropertyValue -InputObject $servicePrincipal -Name @('ApplicationId', 'AppId')

if ($ShowGeneratedSecret -and $principalResult.Result -eq 'Created' -and $servicePrincipalSecret) {
    $plainSecret = ConvertFrom-SecureStringToPlainText -SecureString $servicePrincipalSecret
    try {
        Write-Warning 'Generated client secret follows. Store it in the approved secret vault now. It is not written to report files.'
        Write-Information $plainSecret -InformationAction Continue
    } finally {
        $plainSecret = $null
    }
} elseif ($principalResult.Result -eq 'Created' -and $servicePrincipalSecret) {
    Write-Warning 'A client secret was generated but not displayed. Re-run intentionally with -ShowGeneratedSecret only if policy allows showing the secret in this shell.'
}

$state = [pscustomobject]@{
    GeneratedAt = Get-Date
    DisplayName = $servicePrincipal.DisplayName
    ServicePrincipalObjectId = $servicePrincipalObjectId
    ApplicationId = $servicePrincipalApplicationId
    SubscriptionId = (Get-AzContext).Subscription.Id
    TenantId = (Get-AzContext).Tenant.Id
    PrincipalResult = $principalResult.Result
    KeyVaultPolicyResult = $policyResult
    KeyVaultName = $KeyVaultName
    KeyVaultResourceGroupName = $KeyVaultResourceGroupName
    CertificatePermissions = $CertificatePermissions -join ';'
    SecretPermissions = $SecretPermissions -join ';'
    KeyPermissions = $KeyPermissions -join ';'
    SecretReturnedByCmdlet = [bool]$principalResult.SecretReturned
    SecretWrittenToReports = $false
}

$rollback = Get-RollbackGuidance -ServicePrincipal $servicePrincipal -PrincipalResult $principalResult.Result
Set-Content -LiteralPath $statePath -Value ($state | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false
Set-Content -LiteralPath $rollbackPath -Value ($rollback | ConvertTo-Json -Depth 6) -Encoding utf8 -WhatIf:$false

[pscustomobject]@{
    DisplayName = $state.DisplayName
    ServicePrincipalObjectId = $state.ServicePrincipalObjectId
    ApplicationId = $state.ApplicationId
    PrincipalResult = $state.PrincipalResult
    KeyVaultPolicyResult = $state.KeyVaultPolicyResult
    PlanPath = (Resolve-Path -LiteralPath $planPath).Path
    StatePath = (Resolve-Path -LiteralPath $statePath).Path
    RollbackPath = (Resolve-Path -LiteralPath $rollbackPath).Path
    SecretWrittenToReports = $false
}
