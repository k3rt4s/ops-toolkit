<#
.SYNOPSIS
Create an Azure service principal and grant certificate permissions on a Key Vault.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\New-AzKeyVaultServicePrincipal.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$EnvironmentName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$ApplicationShortName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName,

    [Parameter()]
    [string[]]$CertificatePermissions = @('backup', 'delete', 'get', 'list', 'create', 'update', 'purge')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$az = Get-Command az -ErrorAction Stop
$applicationName = "$EnvironmentName-$ApplicationShortName-serviceprincipal"

Write-Information 'Signing in to Azure CLI if needed...' -InformationAction Continue
& $az.Source account show --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    & $az.Source login --output none
}

& $az.Source account set --subscription $SubscriptionId
if ($LASTEXITCODE -ne 0) {
    throw "Unable to select subscription $SubscriptionId."
}

if ($PSCmdlet.ShouldProcess($applicationName, 'Create Azure AD service principal')) {
    $servicePrincipal = & $az.Source ad sp create-for-rbac --name $applicationName --skip-assignment --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create service principal $applicationName."
    }

    Write-Warning 'The client secret is shown only once. Store it in the approved secret vault before closing this shell.'
    $servicePrincipal | Select-Object appId, password, tenant, displayName | Format-List

    if ($PSCmdlet.ShouldProcess($KeyVaultName, "Grant certificate permissions to $($servicePrincipal.appId)")) {
        & $az.Source keyvault set-policy --name $KeyVaultName --spn $servicePrincipal.appId --certificate-permissions $CertificatePermissions --output none
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to update Key Vault policy on $KeyVaultName."
        }
    }
}


