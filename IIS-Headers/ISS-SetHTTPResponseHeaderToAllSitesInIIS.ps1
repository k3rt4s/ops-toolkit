param
(
   #[string]$WebSiteName = $(throw "The web site name must be provided."),
   [string]$HeaderName = $(throw "The header name must be provided."),
   [string]$HeaderValue = $(throw "The header vale must be provided.")
)
cls
# Initialize the default script exit code.
$exitCode = 0

try
{
	$iisVersion = Get-ItemProperty "HKLM:\software\microsoft\InetStp";
	if ($iisVersion.MajorVersion -eq 7)
	{
		if ($iisVersion.MinorVersion -ge 5)
		{
			Import-Module WebAdministration;
		}           
		else
		{
			if (-not (Get-PSSnapIn | Where {$_.Name -eq "WebAdministration";})) {
				Add-PSSnapIn WebAdministration;
			}
		}
	}

    $iis = new-object Microsoft.Web.Administration.ServerManager
	foreach ($webapp in Get-ChildItem -Path IIS:\Sites)
    {
        $WebSiteName = $webapp.name

	    $PSPath =  'MACHINE/WEBROOT/APPHOST/' + $WebSiteName
    
        Remove-WebConfigurationProperty -PSPath $PSPath -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name =$HeaderName }
             
	
        $config = $iis.GetWebConfiguration($WebSiteName) #i.e. "Default Web Site"
        $httpProtocolSection = $config.GetSection("system.webServer/httpProtocol")
        $customHeadersCollection = $httpProtocolSection.GetCollection("customHeaders")

        $addElement = $customHeadersCollection.CreateElement("add")
        $addElement["name"] = $HeaderName
        $addElement["value"] = $HeaderValue

        $customHeadersCollection.Add($addElement)
    }
    $iis.CommitChanges() 
    write-host $iis
}
Catch [System.Exception]
{
    $exitCode = 1
    write-host "Error" $_.Exception.Message
}
# Indicate the resulting exit code to the calling process.
if ($exitCode -gt 0)
{
    "`nERROR: Operation failed with error code $exitCode."
}
"`nDone."
exit $exitCode