# Created by Jon Bowker on 10/21/2020
$ErrorActionPreference = 'SilentlyContinue'
#add X-forwarded-For Logging
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='X-Forwarded-For';sourceName='X-Forwarded-For';sourceType='RequestHeader'}
#Add Additional Custom Logging
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='Name';sourceName='Source';sourceType='Type'}
#Remove