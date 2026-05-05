<#
.SYNOPSIS
Set the UPN suffix for mailbox-enabled Active Directory users.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass -NewSuffix explicitly; do not edit the script for environment-specific values.
- Use -SearchBase and -OldSuffix to limit scope before running in production.
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
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]
    [string]$OldSuffix,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [switch]$IncludeDisabledUsers
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Set-AdMailboxEnabledUserUpnSuffix.ps1 -NewSuffix example.com -SearchBase "OU=Users,DC=example,DC=com" -WhatIf
  pwsh -File .\scripts\active-directory\Set-AdMailboxEnabledUserUpnSuffix.ps1 -OldSuffix old.example.com -NewSuffix example.com -SearchBase "OU=Users,DC=example,DC=com" -WhatIf

Options:
  -NewSuffix             UPN suffix to apply, for example example.com.
  -OldSuffix             Optional current UPN suffix filter, for example old.example.com.
  -SearchBase            Optional distinguished name used to limit the AD search scope.
  -Server                Optional domain controller to target.
  -IncludeDisabledUsers  Include disabled mailbox-enabled AD user accounts.
  -WhatIf                Preview UPN updates without changing AD.
'@
}

if (-not $NewSuffix) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop

$queryParameters = @{
    Filter = '*'
    Properties = 'Enabled', 'homeMDB', 'SamAccountName', 'UserPrincipalName'
}
if ($SearchBase) {
    $queryParameters.SearchBase = $SearchBase
}
if ($Server) {
    $queryParameters.Server = $Server
}

$changedCount = 0
$skippedCount = 0

$results = Get-ADUser @queryParameters |
    Where-Object {
        $_.homeMDB -and
        ($IncludeDisabledUsers -or $_.Enabled) -and
        (-not $OldSuffix -or $_.UserPrincipalName -like "*@$OldSuffix")
    } |
    Sort-Object SamAccountName |
    ForEach-Object {
        $oldUpn = [string]$_.UserPrincipalName
        $newUpn = '{0}@{1}' -f $_.SamAccountName, $NewSuffix
        $changed = $false

        if ($oldUpn -eq $newUpn) {
            $skippedCount++
            [pscustomobject]@{
                SamAccountName = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                OldUserPrincipalName = $oldUpn
                NewUserPrincipalName = $newUpn
                Changed = $false
                Reason = 'Already set'
            }
            return
        }

        if ($PSCmdlet.ShouldProcess($_.DistinguishedName, "Set UPN to $newUpn")) {
            $setParameters = @{
                Identity = $_.DistinguishedName
                UserPrincipalName = $newUpn
            }
            if ($Server) {
                $setParameters.Server = $Server
            }

            Set-ADUser @setParameters
            $changed = $true
            $changedCount++
        }

        [pscustomobject]@{
            SamAccountName = $_.SamAccountName
            DistinguishedName = $_.DistinguishedName
            OldUserPrincipalName = $oldUpn
            NewUserPrincipalName = $newUpn
            Changed = $changed
            Reason = if ($changed) { 'Updated' } else { 'Previewed' }
        }
    }

[pscustomobject]@{
    NewSuffix = $NewSuffix
    OldSuffix = $OldSuffix
    SearchBase = $SearchBase
    IncludeDisabledUsers = [bool]$IncludeDisabledUsers
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    Results = @($results)
}
