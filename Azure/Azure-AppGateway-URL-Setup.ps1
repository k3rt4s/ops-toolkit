#Written by R.C. Martinez

#Work in Dev Subscription
#Set-AzContext -Subscription <Subscription>
#Work in Prod Subscription
#Set-AzContext -Subscription <Subscription>

# Retrieve the resource group
$rg = Get-AzResourceGroup -ResourcegroupName "LABNAME"
# Retrieve an existing application gateway
$gw = Get-AzApplicationGateway -Name APPGATEWAYNAME -ResourceGroupName $rg.ResourceGroupName


# FQDN of the web app
$webappFQDN = "FQDN"
$appName = "APPNAME"
$poolName = "POOLNAME"
$backendPool = Get-AzApplicationGatewayBackendAddressPool -ApplicationGateway $gw -Name $poolName
$ipName = "appGatewayFrontendIP"
$portName = "443"
$port = Get-AzApplicationGatewayFrontendPort -ApplicationGateway $gw -Name appGatewayFrontendPort
$FEC= Get-AzApplicationGatewayFrontendIPConfig -ApplicationGateway $gw -Name appGatewayFrontendIP
$sslCert = Get-AzApplicationGatewaySslCertificate -ApplicationGateway $gw -Name CERTIFICATE
$PoolSetting = Get-AzApplicationGatewayBackendHttpSettings -ApplicationGateway $gw -Name $appName-HttpSettings
$listener = Get-AzApplicationGatewayHttpListener -ApplicationGateway $gw -Name $appName-listener

# Define the status codes to match for the probe
$match=New-AzApplicationGatewayProbeHealthResponseMatch -StatusCode 200-399

# Add a new probe to the application gateway
Add-AzApplicationGatewayProbeConfig -name $appName-probe -ApplicationGateway $gw -Protocol Https -Path / -Interval 30 -Timeout 30 -UnhealthyThreshold 3 -HostName $webappFQDN -Match $match
Get-AzApplicationGatewayProbeConfig -ApplicationGateway $gw

# Retrieve the newly added probe
$probe = Get-AzApplicationGatewayProbeConfig -name $appName-probe -ApplicationGateway $gw

# Configure an existing backend http settings
#Add-AzApplicationGatewayBackendHttpSetting -Name $appName-HttpSettings -ApplicationGateway $gw -PickHostNameFromBackendAddress -Port 443 -Protocol https -CookieBasedAffinity Disabled -RequestTimeout 30 -Probe $probe
Add-AzApplicationGatewayBackendHttpSetting -Name $appName-HttpSettings -ApplicationGateway $gw -Port 443 -Protocol Https -CookieBasedAffinity Disabled  -RequestTimeout 30 -Probe $probe
Get-AzApplicationGatewayBackendHttpSetting -ApplicationGateway $gw

# Add the web app to a listener
Add-AzApplicationGatewayHttpListener -ApplicationGateway $gw -Name $appName-listener -FrontendIPConfiguration $FEC -FrontendPort $port -Protocol Https -HostName $webappFQDN -SslCertificate $sslCert
Get-AzApplicationGatewayHttpListener -ApplicationGateway $gw

#Add the Routing Rule
Add-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $gw -Name $appName-Rule -RuleType Basic -BackendAddressPool $backendPool -BackendHttpSettings $PoolSetting -HttpListener $listener
Get-AzApplicationGatewayRequestRoutingRule -ApplicationGateway $gw

# Update the application gateway
Set-AzApplicationGateway -ApplicationGateway $gw
