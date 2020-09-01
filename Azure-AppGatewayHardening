#List Subscriptions
az account list --output table

#set Subscription
az account set --subscription "SUBSCRIPTION-NAME"

#retrieve existing policy
Get-AzApplicationGatewaySslPredefinedPolicy

#set gw variable
$gw = Get-AzApplicationGateway -Name APPGATEWAY-NAME -ResourceGroup RESOURCEGROUP

#Create new policy with hardened ciphers
Set-AzApplicationGatewaySslPolicy -ApplicationGateway $gw -PolicyType Custom -MinProtocolVersion TLSv1_2 -CipherSuite "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"

#Retrive new polcy
Get-AzApplicationGatewaySslPolicy -ApplicationGateway $gw

#Apply Policy
Set-AzApplicationGateway -ApplicationGateway $gw
