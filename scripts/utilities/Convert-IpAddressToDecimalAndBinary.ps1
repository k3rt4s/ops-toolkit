<#
.SYNOPSIS
Convert an IPv4 address to binary and decimal formats.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Convert-IpAddressToDecimalAndBinary.ps1 -Full.

.STATUS
Active PowerShell replacement for Convert-IpAddressToDecimalAndBinary.vbs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ [ipaddress]::TryParse($_, [ref]([ipaddress]$null)) -and ([ipaddress]$_).AddressFamily -eq 'InterNetwork' })]
    [string]$IpAddress,

    [Parameter()]
    [switch]$PingDecimalAddress
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$bytes = [ipaddress]::Parse($IpAddress).GetAddressBytes()
$binary = ($bytes | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''
$decimal = [uint32](
    ($bytes[0] -shl 24) -bor
    ($bytes[1] -shl 16) -bor
    ($bytes[2] -shl 8) -bor
    $bytes[3]
)

$result = [pscustomobject]@{
    IpAddress = $IpAddress
    Binary = $binary
    Decimal = $decimal
}

if ($PingDecimalAddress) {
    $result | Add-Member -MemberType NoteProperty -Name PingSucceeded -Value (Test-Connection -ComputerName ([string]$decimal) -Count 1 -Quiet)
}

$result
