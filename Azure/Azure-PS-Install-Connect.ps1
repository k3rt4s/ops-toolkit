# Created and authored by Jon Bowker 09/24/2020

# Create a service principal and configure its access to Azure resources
# Documentation - https://github.com/Azure/azure-sdk-for-net/tree/2d11c6664e68c145a988729e6598449bba130694/sdk/keyvault/Azure.Security.KeyVault.Certificates#azure-key-vault-certificate-client-library-for-net
# A keyvault should already exist. If not, please create one in the correct resource group. "az keyvault create --resource-group <your-resource-group-name> --name <your-key-vault-name>"

## Pre-Req ##
#check for AzureRM and Report
if ($PSVersionTable.PSEdition -eq 'Desktop' -and (Get-Module -Name AzureRM* -ListAvailable)) {
        Write-Warning -Message ('AzureRM is Installed. Having both the AzureRM and Az modules installed at the same time is not supported. Removing AzureRM')
} else {
    Write-Warning -Message ('AzureRM is Not Installed. Continuing.....')
}

#check for AzureRM and uninstall
if ($PSVersionTable.PSEdition -eq 'Desktop' -and (Get-Module -Name AzureRM* -ListAvailable)) {
        Get-Module -Name AzureRM* -ListAvailable | Uninstall-Module -Force -Verbose -ErrorAction Continue
}

#check for AZ Module and install if missing
if ($PSVersionTable.PSEdition -eq 'Desktop' -and (Get-Module -Name Az.* -ListAvailable)) {
    Write-Warning -Message ('Az module installed. Skipping module install.')
} else {
    Install-Module -Name Az -AllowClobber -Force
}

#Import AZ Module
Import-Module -Name Az

#Log into Azure using powershell and pull a list of subscriptions
az login
#az account list
