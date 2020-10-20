Import-Module WebAdministration
Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add"
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Content-Security-Policy';value=' frame-ancestors https://ncontracts.com https://*.ncontracts.com http://ncontracts.com http://*.ncontracts.com'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='X-Powered-By';value='Apache 2.0.59 Commodore C64'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='X-Content-Type-Options';value='Nosniff'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Referrer-Policy';value='strict-origin'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='X-XSS-Protection';value='1; mode=block'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Strict-Transport-Security';value='max-age=31536000; includeSubDomains'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Feature-Policy';value='self'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Cache-Control';value='no-cache, no-store'}
Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders "IIS:\sites\" -AtIndex 0 -Name collection -value @{name='Pragma';value='no-cache'}
IISreset /restart
#Rollback
Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add"
IISreset /restart