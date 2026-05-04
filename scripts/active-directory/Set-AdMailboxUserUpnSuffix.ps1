<#
.SYNOPSIS
Set the UPN suffix for AD users that have mailbox attributes.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass -NewSuffix explicitly; do not edit the script for environment-specific values.
- Use -SearchBase to limit scope before running in production.
- Run with -WhatIf first before changing user principal names.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$NewSuffix,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Set-AdMailboxUserUpnSuffix.ps1 -NewSuffix example.com -SearchBase "OU=Users,DC=example,DC=com" -WhatIf

Options:
  -NewSuffix   UPN suffix to apply, for example example.com.
  -SearchBase  Optional distinguished name used to limit the AD search scope.
  -Server      Optional domain controller to target.
  -WhatIf      Preview UPN updates without changing AD.
'@
}

if (-not $NewSuffix) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop

$queryParameters = @{
    Filter = '*'
    Properties = 'homeMDB', 'SamAccountName', 'UserPrincipalName'
}
if ($SearchBase) {
    $queryParameters.SearchBase = $SearchBase
}
if ($Server) {
    $queryParameters.Server = $Server
}

Get-ADUser @queryParameters |
    Where-Object { $_.homeMDB } |
    ForEach-Object {
        $newUpn = '{0}@{1}' -f $_.SamAccountName, $NewSuffix
        if ($_.UserPrincipalName -ne $newUpn -and $PSCmdlet.ShouldProcess($_.DistinguishedName, "Set UPN to $newUpn")) {
            $setParameters = @{
                Identity = $_.DistinguishedName
                UserPrincipalName = $newUpn
            }
            if ($Server) {
                $setParameters.Server = $Server
            }

            Set-ADUser @setParameters
        }
    }
