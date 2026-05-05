<#
.SYNOPSIS
Set the UPN suffix for Active Directory users in one OU scope.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Pass -SearchBase, -OldSuffix, and -NewSuffix explicitly.
- Use -SearchScope to choose Base, OneLevel, or Subtree; the default is Subtree.
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
    [string]$Server,

    [Parameter()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [Parameter()]
    [switch]$IncludeDisabledUsers
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\active-directory\Set-AdOuUserUpnSuffix.ps1 -SearchBase "OU=Users,DC=example,DC=com" -OldSuffix old.example.com -NewSuffix example.com -WhatIf

Options:
  -SearchBase            Distinguished name of the OU search base to update.
  -OldSuffix             Current UPN suffix to replace, for example old.example.com.
  -NewSuffix             New UPN suffix to apply, for example example.com.
  -Server                Optional domain controller to target.
  -SearchScope           AD search scope: Base, OneLevel, or Subtree. Defaults to Subtree.
  -IncludeDisabledUsers  Include disabled AD user accounts.
  -WhatIf                Preview UPN updates without changing AD.
'@
}

if (-not $SearchBase -or -not $OldSuffix -or -not $NewSuffix) {
    Show-Usage
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop

$queryParameters = @{
    SearchBase = $SearchBase
    SearchScope = $SearchScope
    Filter = '*'
    Properties = 'Enabled', 'SamAccountName', 'UserPrincipalName'
}
if ($Server) {
    $queryParameters.Server = $Server
}

$changedCount = 0
$skippedCount = 0
$oldSuffixPattern = '@{0}$' -f [regex]::Escape($OldSuffix)

$results = Get-ADUser @queryParameters |
    Where-Object {
        ($IncludeDisabledUsers -or $_.Enabled) -and
        $_.UserPrincipalName -like "*@$OldSuffix"
    } |
    Sort-Object SamAccountName |
    ForEach-Object {
        $oldUpn = [string]$_.UserPrincipalName
        $newUpn = $oldUpn -replace $oldSuffixPattern, "@$NewSuffix"
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
    SearchBase = $SearchBase
    SearchScope = $SearchScope
    OldSuffix = $OldSuffix
    NewSuffix = $NewSuffix
    IncludeDisabledUsers = [bool]$IncludeDisabledUsers
    ChangedCount = $changedCount
    SkippedCount = $skippedCount
    Results = @($results)
}
