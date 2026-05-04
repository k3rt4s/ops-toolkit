<#
.SYNOPSIS
Replace the UPN suffix for AD users in a specific OU.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass -SearchBase, -OldSuffix, and -NewSuffix explicitly.
- Run with -WhatIf first before changing user principal names.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$OldSuffix,

    [Parameter()]
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$NewSuffix,

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
  pwsh -File .\scripts\active-directory\Set-AdUserUpnSuffixForOu.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf

Options:
  -SearchBase  Distinguished name of the OU to update.
  -OldSuffix   Current UPN suffix to replace, for example old.example.com.
  -NewSuffix   New UPN suffix to apply, for example example.com.
  -Server      Optional domain controller to target.
  -WhatIf      Preview UPN updates without changing AD.
'@
}

if (-not $SearchBase -or -not $OldSuffix -or -not $NewSuffix) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop

$queryParameters = @{
    SearchBase = $SearchBase
    Filter = '*'
    Properties = 'UserPrincipalName'
}
if ($Server) {
    $queryParameters.Server = $Server
}

Get-ADUser @queryParameters |
    Where-Object { $_.UserPrincipalName -like "*@$OldSuffix" } |
    ForEach-Object {
        $newUpn = $_.UserPrincipalName -replace "@$([regex]::Escape($OldSuffix))$", "@$NewSuffix"
        if ($PSCmdlet.ShouldProcess($_.DistinguishedName, "Set UPN to $newUpn")) {
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
