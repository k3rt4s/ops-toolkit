#Replace with the old suffix 
$oldSuffix = 'SUFFIX1'
#Replace with the new suffix
$newSuffix = 'SUFFIX2'
#Replace with the OU you want to change suffixes for
$ou = "OU"
#Replace with the name of your AD server
$server = "Server"
Get-ADUser -SearchBase $ou -filter * | ForEach-Object {
$newUpn = $_.UserPrincipalName.Replace($oldSuffix,$newSuffix)
$_ | Set-ADUser -server $server -UserPrincipalName $newUpn
}
