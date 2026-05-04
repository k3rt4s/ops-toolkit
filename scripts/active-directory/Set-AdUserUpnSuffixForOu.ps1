<#
.SYNOPSIS
Replace the UPN suffix for AD users in a specific OU.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-AdUserUpnSuffixForOu.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Replace with the old suffix 
$oldSuffix = 'SUFFIX1'
#Replace with the new suffix
$newSuffix = 'SUFFIX2'
#Replace with the OU you want to change suffixes for
$ou = "OU"
#Replace with the name of your AD server
$server = "Server"
Get-ADUser -SearchBase $ou -filter * | ForEach-Object {
    $newUpn = $_.UserPrincipalName.Replace($oldSuffix, $newSuffix)
    $_ | Set-ADUser -server $server -UserPrincipalName $newUpn
}


