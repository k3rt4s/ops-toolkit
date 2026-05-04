<#
.SYNOPSIS
Launch BGInfo with a selected .bgi configuration file.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Start-BgInfo.ps1 -Full.

.STATUS
Active PowerShell replacement for Start-BgInfoForLegacyWindows.cmd.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BgInfoPath = $(if (Test-Path 'C:\ProgramData\bginfo.exe') { 'C:\ProgramData\bginfo.exe' } else { 'C:\Documents and Settings\All Users\bginfo.exe' }),

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ConfigPath = $(if (Test-Path 'C:\ProgramData\default.bgi') { 'C:\ProgramData\default.bgi' } else { 'C:\Documents and Settings\All Users\default.bgi' })
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Start-Process -FilePath $BgInfoPath -ArgumentList @(
    $ConfigPath,
    '/timer:0',
    '/nolicprompt',
    '/silent'
) -Wait
