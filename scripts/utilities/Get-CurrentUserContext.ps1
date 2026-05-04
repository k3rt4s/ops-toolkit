<#
.SYNOPSIS
Display current Windows user, domain, group, and network context.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Get-CurrentUserContext.ps1 -Full.

.STATUS
Active PowerShell replacement for Show-CurrentUser.vbs.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$network = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' |
    Select-Object -Property Description, MACAddress, IPAddress, DefaultIPGateway, DNSServerSearchOrder

[pscustomobject]@{
    UserName = $identity.Name
    Authentication = $identity.AuthenticationType
    IsAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Groups = ($identity.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }) -join ';'
    ComputerName = $env:COMPUTERNAME
    UserDomain = $env:USERDOMAIN
    LogonServer = $env:LOGONSERVER
    NetworkAdapters = $network
}
