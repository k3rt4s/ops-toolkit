<#
.SYNOPSIS
Import VPN configuration from rasphone.pbk file into Azure VPN Client
.DESCRIPTION
Script is used to create rasphone.pbk file with VPN configuration used in Azure VPN Client and create a new VPN connection ready to be used. Code should determine whether the folder with installation already
exists and create it if it's missing. Additionally, if you run the script multiple times, old rasphone.pbk file should be just renamed in case it's required later or as a backup. Log / transcript will track all
actions which were performed by the script and capture possible errors.
* HOW TO USE SCRIPT WITH INTUNE? *
1. Take file "azurvpnconfig.xml" containing your custom VPN configuration and import it manually to your Azure VPN Client using the command "AzureVpn.exe -i azurevpnconfig.xml" run from CMD
2. When you run the command, file rasphone.pbk will be created in "C:\Users\$UserName\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState" - this file contains the actual configuration used by VPN client
3. Open rasphone.pbk file with notepad and copy the whole content (CTRL + A) to variable $PBKFileDetails
4. Save the script
5. Run it from Powershell ISE, it should create two files in "C:\Users\$UserName\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState":
NewAzureVPNConnectionLog_$Date - Log/Transcript of the processed steps in the script (for example "NewAzureVPNConnectionLog_05-05-2020_12_23_05.log")
rasphone.pbk - File serving as a "bridge" for VPN configuration, configuration is not visible in Azure VPN Client without this file
6. When you determine that VPN connection is working successfully, upload the script to Intune and insert your clients in the scope (choose "Yes" when determining "Run this script using the logged on credentials")
.LINK
https://github.com/Peha1906
#>


# DEFINE DETAILS WHICH WILL BE INJECTED TO PBK FILE

$PBKFileDetails = '[CorpVPN]
Encoding=1
PBVersion=6
Type=2
AutoLogon=1
UseRasCredentials=1
LowDateTime=776101872
HighDateTime=30829568
DialParamsUID=55163265
Guid=0E66ADB5C6333646B84839B55B8F1D6C
VpnStrategy=5
ExcludedProtocols=0
LcpExtensions=1
DataEncryption=0
SwCompression=0
NegotiateMultilinkAlways=1
SkipDoubleDialDialog=0
DialMode=0
OverridePref=15
RedialAttempts=0
RedialSeconds=0
IdleDisconnectSeconds=0
RedialOnLinkFailure=0
CallbackMode=0
CustomDialDll=
CustomDialFunc=
CustomRasDialDll=
ForceSecureCompartment=0
DisableIKENameEkuCheck=0
AuthenticateServer=0
ShareMsFilePrint=1
BindMsNetClient=1
SharedPhoneNumbers=0
GlobalDeviceSettings=0
PrerequisiteEntry=
PrerequisitePbk=
PreferredPort=
PreferredDevice=
PreferredBps=0
PreferredHwFlow=0
PreferredProtocol=0
PreferredCompression=0
PreferredSpeaker=0
PreferredMdmProtocol=0
PreviewUserPw=0
PreviewDomain=0
PreviewPhoneNumber=0
ShowDialingProgress=0
ShowMonitorIconInTaskBar=0
CustomAuthKey=0
AuthRestrictions=552
IpPrioritizeRemote=0
IpInterfaceMetric=0
IpHeaderCompression=0
IpAddress=0.0.0.0
IpDnsAddress=0.0.0.0
IpDns2Address=0.0.0.0
IpWinsAddress=0.0.0.0
IpWins2Address=0.0.0.0
IpAssign=1
IpNameAssign=1
IpDnsFlags=0
IpNBTFlags=1
TcpWindowSize=0
UseFlags=2
IpSecFlags=0
IpDnsSuffix=
Ipv6Assign=1
Ipv6Address=::
Ipv6PrefixLength=0
Ipv6PrioritizeRemote=0
Ipv6InterfaceMetric=0
Ipv6NameAssign=1
Ipv6DnsAddress=::
Ipv6Dns2Address=::
Ipv6Prefix=0000000000000000
Ipv6InterfaceId=0000000000000000
DisableClassBasedDefaultRoute=0
DisableMobility=0
NetworkOutageTime=0
IDI=
IDR=
ImsConfig=0
IdiType=0
IdrType=0
ProvisionType=0
PreSharedKey=
CacheCredentials=0
NumCustomPolicy=0
NumEku=0
UseMachineRootCert=0
Disable_IKEv2_Fragmentation=0
PlumbIKEv2TSAsRoutes=0
NumServers=1
ServerListServerName=<insert Servername>
ServerListFriendlyName=
RouteVersion=1
NumRoutes=0
NumNrptRules=0
AutoTiggerCapable=1
NumAppIds=0
NumClassicAppIds=0
SecurityDescriptor=
ApnInfoProviderId=
ApnInfoUsername=
ApnInfoPassword=
ApnInfoAccessPoint=
ApnInfoAuthentication=1
ApnInfoCompression=0
DeviceComplianceEnabled=0
DeviceComplianceSsoEnabled=0
DeviceComplianceSsoEku=
DeviceComplianceSsoIssuer=
WebAuthEnabled=0
WebAuthClientId=
FlagsSet=0
Options=0
DisableDefaultDnsSuffixes=0
NumTrustedNetworks=0
ThirdPartyProfileInfo=680A00004D006900630072006F0073006F00660074002E0041007A00750072006500560070006E005F003800770065006B007900620033006400380062006200
ThirdPartyProfileInfo=77006500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ThirdPartyProfileInfo=00000000000000000000000000000000D06BBA52250200003C0061007A00760070006E00700072006F00660069006C0065003E003C0076006500720073006900
ThirdPartyProfileInfo=6F006E003E0031003C002F00760065007200730069006F006E003E003C006E0061006D0065003E0043006F0072007000560050004E003C002F006E0061006D00
ThirdPartyProfileInfo=65003E003C007300650072007600650072006C006900730074003E003C0073006500720076006500720065006E007400720079003E003C006600710064006E00
ThirdPartyProfileInfo=3E0061007A0075007200650067006100740065007700610079002D00650034003900320030003000370035002D0035003200340061002D003400390065003200
ThirdPartyProfileInfo=2D0062006200630064002D003800640036003900340039003900370030003800300066002D006300380032006500330061003700300065006300390038002E00
ThirdPartyProfileInfo=760070006E002E0061007A007500720065002E0063006F006D003C002F006600710064006E003E003C002F0073006500720076006500720065006E0074007200
ThirdPartyProfileInfo=79003E003C002F007300650072007600650072006C006900730074003E003C00700072006F0074006F0063006F006E006600690067003E003C00730073006C00
ThirdPartyProfileInfo=700072006F0074006F0063006F006E006600690067003E003C007400720061006E00730070006F0072007400700072006F0074006F0063006F006C003E007400
ThirdPartyProfileInfo=630070003C002F007400720061006E00730070006F0072007400700072006F0074006F0063006F006C003E003C002F00730073006C00700072006F0074006F00
ThirdPartyProfileInfo=63006F006E006600690067003E003C002F00700072006F0074006F0063006F006E006600690067003E003C00730065007200760065007200760061006C006900
ThirdPartyProfileInfo=64006100740069006F006E003E003C0074007900700065003E0063006500720074003C002F0074007900700065003E003C0063006500720074003E003C006800
ThirdPartyProfileInfo=6100730068003E006100380039003800350064003300610036003500650035006500350063003400620032006400370064003600360064003400300063003600
ThirdPartyProfileInfo=6400640032006600620031003900630035003400330036003C002F0068006100730068003E003C002F0063006500720074003E003C0073006500720076006500
ThirdPartyProfileInfo=72007300650063007200650074003E00390038006300620034003500390034006500320064006300390034003900640064006400660063003800640061006600
ThirdPartyProfileInfo=64003300390034003900340030003300360038003700300037003500390031003000310062006400610037003900660066006600380036003900660039003300
ThirdPartyProfileInfo=63006100360035003700360039003100320061003600350038006600610065003400350030003500610031006600630037006100370066003800360063003500
ThirdPartyProfileInfo=63003400330065003500340036003700390039006100610065003100320032003900390030003100360065006400320033003500370031006100310038003800
ThirdPartyProfileInfo=65006600610032006600610033006500380062006100360061003100610034003100660065003400340038003200380065003100310066003600660038003900
ThirdPartyProfileInfo=37003900310066006300630066003100610032003000620033006500640064003100620034003000300037003700350035006500300034003700370033003200
ThirdPartyProfileInfo=37003900350036003200390061006600320031003700320061003300620032003800610039006300340038006600650036003500380061003400300061003200
ThirdPartyProfileInfo=65003800610066003200320036006300340039006600300031003000630065003700660061003100660036006100340030003500640039003500630037006100
ThirdPartyProfileInfo=38006600360031006300320038003500390031003600630033003600340061006400380034006500610030006200610030006400630039003300320032003000
ThirdPartyProfileInfo=39003200350036006500300039003500350034003300370066006300310035003800370066006500660035003800620061003900350063003600620061003600
ThirdPartyProfileInfo=63006100310032006500300034003100320062003600620037006600310033006300370031006100330032006400300038003800310036003800360033003700
ThirdPartyProfileInfo=64003700380062003400350033006100370066006200310033006100630038003900380061006100350064006400640032006100360033003300330030003700
ThirdPartyProfileInfo=64006600610033006400380036003900640034003500340066003100360061006300620036003800310033006500650036003000350061003200650030003500
ThirdPartyProfileInfo=34003700320034003300610034003800350036003200340036006300320037003100380038003200650066006400660061006100380034003800350065006100
ThirdPartyProfileInfo=39006600370030006500630031003700300039003300650037003700380038003400320030006500320037006600320062006500300037003800610065003500
ThirdPartyProfileInfo=31006300360034006600610065003500620062006100340033006500360066006400370030003200330064003900310030003500630031003200630063003600
ThirdPartyProfileInfo=360036003900350061003600640061003C002F007300650072007600650072007300650063007200650074003E003C002F007300650072007600650072007600
ThirdPartyProfileInfo=61006C00690064006100740069006F006E003E003C0063006C00690065006E00740061007500740068003E003C0074007900700065003E006100610064003C00
ThirdPartyProfileInfo=2F0074007900700065003E003C006100610064003E003C006900730073007500650072003E00680074007400700073003A002F002F007300740073002E007700
ThirdPartyProfileInfo=69006E0064006F00770073002E006E00650074002F00620031003600650033006400630031002D0034003100350062002D0034003400330064002D0039003300
ThirdPartyProfileInfo=620038002D003200360061006600380065003900350032003600300062002F003C002F006900730073007500650072003E003C00740065006E0061006E007400
ThirdPartyProfileInfo=3E00680074007400700073003A002F002F006C006F00670069006E002E006D006900630072006F0073006F00660074006F006E006C0069006E0065002E006300
ThirdPartyProfileInfo=6F006D002F00620031003600650033006400630031002D0034003100350062002D0034003400330064002D0039003300620038002D0032003600610066003800
ThirdPartyProfileInfo=65003900350032003600300062003C002F00740065006E0061006E0074003E003C00610075006400690065006E00630065003E00340031006200320033006500
ThirdPartyProfileInfo=360031002D0036006300310065002D0034003500340035002D0062003300360037002D006300640030003500340065003000650064003400620034003C002F00
ThirdPartyProfileInfo=610075006400690065006E00630065003E003C00630061006300680065007300690067006E0069006E0075007300650072003E0074007200750065003C002F00
ThirdPartyProfileInfo=630061006300680065007300690067006E0069006E0075007300650072003E003C00640069007300610062006C006500730073006F003E00660061006C007300
ThirdPartyProfileInfo=65003C002F00640069007300610062006C006500730073006F003E003C002F006100610064003E003C002F0063006C00690065006E0074006100750074006800
ThirdPartyProfileInfo=3E003C0063006C00690065006E00740063006F006E006600690067002F003E003C002F0061007A00760070006E00700072006F00660069006C0065003E000000
NumDnsSearchSuffixes=0
PowershellCreatedProfile=0
ProxyFlags=0
ProxySettingsModified=0
ProvisioningAuthority=
AuthTypeOTP=0
GREKeyDefined=0
NumPerAppTrafficFilters=0
AlwaysOnCapable=1
DeviceTunnel=0
PrivateNetwork=1

NETCOMPONENTS=
ms_msclient=1
ms_server=1

MEDIA=rastapi
Port=
Device=

DEVICE=vpn
PhoneNumber=<insert Servername>
AreaCode=
CountryCode=0
CountryID=0
UseDialingRules=0
Comment=
FriendlyName=
LastSelectedPhone=0
PromoteAlternates=0
TryNextAlternateOnFail=1'



# OBTAIN USERNAME OF THE LOGGED IN USER
$UserName = (Get-WmiObject -Class Win32_Process -Filter 'Name="explorer.exe"').GetOwner().User

# CLEAR VARIABLE
$SecondFolderLog = $Null


#========================================#
# === FIRST FOLDER PROCESSING START ==== #
#========================================#


# CREATE FOLDER IF IT DOESN'T EXISTS

$RequiredFolder = "%userprofile%\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState"
$CheckRequiredFolder = Test-Path $RequiredFolder
if ($CheckRequiredFolder -eq $false)
{

  # CREATE REQUIRED FOLDER
  New-Item $RequiredFolder -ItemType Directory | Out-Null 

  # SET LOG LOCATION
  $LogLocation = "$RequiredFolder\NewAzureVPNConnectionLog_$(Get-Date -Format 'dd-MM-yyyy_HH_mm_ss').log"

  # START TRANSCRIPT
  Start-Transcript -Path $LogLocation -Force -Append

  # WRITE TO LOG
  Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Required folder $RequiredFolder was created on the machine since it wasn't found."

  # CREATE EMPTY PBK FILE
  New-Item "$RequiredFolder\rasphone.pbk" -ItemType File | Out-Null

  # WRITE TO LOG
  Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been created in $RequiredFolder."

  # POPULATE PBK FILE WITH CONFIGURATION DATA
  Set-Content "$RequiredFolder\rasphone.pbk" $PBKFileDetails

  # WRITE TO LOG
  Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details."

  # STOP TRANSCRIPT
  Stop-Transcript | Out-Null

}

# IN CASE THE FOLDER ALREADY EXISTS

else 
{
  # SET LOG LOCATION
  $LogLocation = "$RequiredFolder\NewAzureVPNConnectionLog_$(Get-Date -Format 'dd-MM-yyyy_HH_mm_ss').log"

  # START TRANSCRIPT
  Start-Transcript -Path $LogLocation -Force -Append

  # WRITE TO LOG
  Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $RequiredFolder already exists, that means that Azure VPN Client is already installed."

  # CHECK IF RASPHONE.PBK FILE ALREADY EXISTS
  $CheckRasphoneFile = Test-Path "$RequiredFolder\rasphone.pbk"

  if ($CheckRasphoneFile -eq $false)
  {
    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk doesn't exist in $RequiredFolder."

    # CREATE EMPTY PBK FILE
    New-Item "$RequiredFolder\rasphone.pbk" -ItemType File | Out-Null

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been created in $RequiredFolder."

    # POPULATE PBK FILE WITH CONFIGURATION DATA
    Set-Content "$RequiredFolder\rasphone.pbk" $PBKFileDetails

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details."

    # STOP TRANSCRIPT
    Stop-Transcript | Out-Null

  }
  else
  {
    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk already exists in $RequiredFolder."

    # REMOVE RASPHONE.PBK FILE
    Rename-Item -Path "$RequiredFolder\rasphone.pbk" -NewName "$RequiredFolder\rasphone.pbk_$(Get-Date -Format 'ddMMyyyy-HHmmss')"
    
    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been renamed to rasphone.pbk_$(Get-Date -Format 'ddMMyyyy-HHmmss'). This file contains old configuration if it will be required in the future (in case it is, just rename it back to rasphone.pbk)."

    # CREATE NEW RASPHONE.PBK FILE
    New-Item "$RequiredFolder\rasphone.pbk" -ItemType File | Out-Null

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] New rasphone.pbk file has been created in $RequiredFolder."

    # POPULATE PBK FILE WITH CONFIGURATION DATA
    Set-Content "$RequiredFolder\rasphone.pbk" $PBKFileDetails

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details."

    # STOP TRANSCRIPT
    Stop-Transcript | Out-Null

  }


}

#========================================#
# === FIRST FOLDER PROCESSING STOP ===== #
#========================================#


#========================================#
# === SECOND FOLDER PROCESSING START === #
#========================================#

$SecondUserFolder = "%userprofile%"
$CheckSecondFolder = Test-Path $SecondUserFolder

# CHECK IF SECOND USER FOLDER EXISTS - IF NO

if ($CheckSecondFolder -eq $false)
{

  # START TRANSCRIPT
  Start-Transcript -Path $LogLocation -Force -Append -IncludeInvocationHeader

  # WRITE TO LOG
  Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $SecondUserFolder doesn't exist."

  # STOP TRANSCRIPT
  Stop-Transcript | Out-Null
   
}

# IF SECOND USER FOLDER EXISTS, CREATE NECESSARY FOLDER

else 
    
{

  $SecondUserFolderPath = "$SecondUserFolder\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState"
  $CatchSecondFolderPath = Test-Path $SecondUserFolderPath
  if ($CatchSecondFolderPath -eq $true)
  {

    # SET LOG LOCATION
    $LogLocationSecondFolder = "$SecondUserFolderPath\NewAzureVPNConnectionLog_$(Get-Date -Format 'dd-MM-yyyy_HH_mm_ss').log"

    # START TRANSCRIPT
    Start-Transcript -Path $LogLocationSecondFolder -Force -Append

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $SecondUserFolder exists."

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $SecondUserFolderPath already exists."

    # CHECK IF RASPHONE.PBK FILE ALREADY EXISTS
    $CheckRasphoneFileSecondUserFolderPath = Test-Path "$SecondUserFolderPath\rasphone.pbk"
    if ($CheckRasphoneFileSecondUserFolderPath -eq $true)
    {
      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk already exists in $SecondUserFolderPath."

      # REMOVE RASPHONE.PBK FILE
      Rename-Item -Path "$SecondUserFolderPath\rasphone.pbk" -NewName "$SecondUserFolderPath\rasphone.pbk_$(Get-Date -Format 'ddMMyyyy-HHmmss')"

      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been renamed to rasphone.pbk_$(Get-Date -Format 'ddMMyyyy-HHmmss'). This file contains old configuration if it will be required in the future (in case it is, just rename it back to rasphone.pbk)."

      # CREATE EMPTY PBK FILE
      New-Item "$SecondUserFolderPath\rasphone.pbk" -ItemType File | Out-Null

      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] New rasphone.pbk file has been created in $SecondUserFolderPath."

      # POPULATE PBK FILE WITH CONFIGURATION DATA
      Set-Content "$SecondUserFolderPath\rasphone.pbk" $PBKFileDetails

      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details."

      # STOP TRANSCRIPT
      Stop-Transcript | Out-Null

    }
    else
    {
      # CREATE EMPTY PBK FILE
      New-Item "$SecondUserFolderPath\rasphone.pbk" -ItemType File | Out-Null

      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] New rasphone.pbk file has been created in $SecondUserFolderPath."

      # POPULATE PBK FILE WITH CONFIGURATION DATA
      Set-Content "$SecondUserFolderPath\rasphone.pbk" $PBKFileDetails

      # WRITE TO LOG
      Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details.."

      # STOP TRANSCRIPT
      Stop-Transcript | Out-Null
    }

  }
  else
  {
    # SET LOG LOCATION
    $LogLocationSecondFolder = "$SecondUserFolderPath\NewAzureVPNConnectionLog_$(Get-Date -Format 'dd-MM-yyyy_HH_mm_ss').log"

    # START TRANSCRIPT
    Start-Transcript -Path $LogLocationSecondFolder -Force -Append

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $SecondUserFolder exists."

    # CREATE NEW FOLDER
    New-Item $SecondUserFolder\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState -ItemType Directory | Out-Null
    $CatchSecondFolderPath = "$SecondUserFolder\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState"

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Path $SecondUserFolderPath doesn't exist, we will create one."

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] Folder $CatchSecondFolderPath has been created."

    # CREATE EMPTY PBK FILE
    New-Item "$SecondUserFolder\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\rasphone.pbk" -ItemType File | Out-Null

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] New rasphone.pbk file has been created in $SecondUserFolderPath."

    # POPULATE PBK FILE WITH CONFIGURATION DATA
    Set-Content "$SecondUserFolder\AppData\Local\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\rasphone.pbk" $PBKFileDetails

    # WRITE TO LOG
    Write-Output "[$(Get-Date -Format 'dd-MM-yyyy_HH:mm:ss')] File rasphone.pbk has been populated with configuration details."

    # STOP TRANSCRIPT
    Stop-Transcript | Out-Null

  }
    

}


#========================================#
# === SECOND FOLDER PROCESSING STOP ==== #
#========================================#
