#Mass Change UPN Suffix 
#http://technet.microsoft.com/en-us/library/cc772007.aspx
#Replace DOMAINNAME

Get-ADUser -Filter * -properties homemdb | where {$_.homemdb -ne $null} | ForEach-Object ($_.SamAccountName) {$CompleteUPN = $_.SamAccountName + "@DOMAINNAME"; Set-ADUser -Identity $_.DistinguishedName -UserPrincipalName $CompleteUPN}

#The above script:

#Gets all users with something in their homemdb attribute (i.e. mailbox users)

#Creates a temporary variable called $completeUPN which is a combination of every user’s samaccountname plus @contoso.com

#Sets each user to this new upn
