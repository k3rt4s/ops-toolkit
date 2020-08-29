#delete existing drive
net use s: /delete

#store creds in credential vault
cmd.exe /C "cmdkey /add:`<IP>`" /user:`"<DOMAIN>\<UN>`" /pass:`"<Password>`""

#map drive
New-PSDrive -Name S -PSProvider FileSystem -Root "<Drive>" -Persist
