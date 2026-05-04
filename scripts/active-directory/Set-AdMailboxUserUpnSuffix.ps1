<#
.SYNOPSIS
Set the UPN suffix for AD users that have mailbox attributes.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Set-AdMailboxUserUpnSuffix.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
#Mass Change UPN Suffix 
#http://technet.microsoft.com/en-us/library/cc772007.aspx
#Replace DOMAINNAME

Get-ADUser -Filter * -properties homemdb | Where-Object { $_.homemdb -ne $null } | ForEach-Object ($_.SamAccountName) { $CompleteUPN = $_.SamAccountName + "@DOMAINNAME"; Set-ADUser -Identity $_.DistinguishedName -UserPrincipalName $CompleteUPN }

#The above script:

#Gets all users with something in their homemdb attribute (i.e. mailbox users)

#Creates a temporary variable called $completeUPN which is a combination of every user’s samaccountname plus @contoso.com

#Sets each user to this new upn


