# === AI REVIEWER - READ BEFORE EDITING ==============================
# Before changing this file, read the master workspace README at
#   d:\Proton Drive\My files\Code\README.md   ("AI Session Rules" section)
# and the README(s) for this project and sub-product. Those documents
# are the single source of truth for venvs, path conventions,
# archive/backup rules, markdown conventions, and every repo-wide rule.
# Do not guess - reference the READMEs first.
# =====================================================================

#Mass Change UPN Suffix 
#http://technet.microsoft.com/en-us/library/cc772007.aspx
#Replace DOMAINNAME

Get-ADUser -Filter * -properties homemdb | where {$_.homemdb -ne $null} | ForEach-Object ($_.SamAccountName) {$CompleteUPN = $_.SamAccountName + "@DOMAINNAME"; Set-ADUser -Identity $_.DistinguishedName -UserPrincipalName $CompleteUPN}

#The above script:

#Gets all users with something in their homemdb attribute (i.e. mailbox users)

#Creates a temporary variable called $completeUPN which is a combination of every user’s samaccountname plus @contoso.com

#Sets each user to this new upn
