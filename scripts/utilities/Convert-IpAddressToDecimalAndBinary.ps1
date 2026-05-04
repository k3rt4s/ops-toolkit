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
    [Parameter()]
    [ValidateScript({ [ipaddress]::TryParse($_, [ref]([ipaddress]$null)) -and ([ipaddress]$_).AddressFamily -eq 'InterNetwork' })]
    [string]$IpAddress,

    [Parameter()]
    [switch]$PingDecimalAddress
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Missing required arguments.

Usage:
  pwsh -File .\scripts\utilities\Convert-IpAddressToDecimalAndBinary.ps1 -IpAddress 192.0.2.10

Options:
  -IpAddress            IPv4 address to convert.
  -PingDecimalAddress   Also ping the decimal representation.
'@
}

if (-not $IpAddress) {
    Show-Usage
    exit 2
}

$bytes = [ipaddress]::Parse($IpAddress).GetAddressBytes()
$binary = ($bytes | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''
$decimal = [uint32](
    ([uint32]$bytes[0] * 16777216) +
    ([uint32]$bytes[1] * 65536) +
    ([uint32]$bytes[2] * 256) +
    [uint32]$bytes[3]
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
