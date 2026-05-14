<#
.SYNOPSIS
Report current Windows user, group, privilege, and network context.

.INSTRUCTIONS
- Read the root README.md and IT operations README.md before running this script.
- This script is read-only and does not require elevation.
- Use -OutputDirectory to write JSON and CSV reports under reports\it-operations\user-context.
- Use -IncludeGroups only when group membership detail is needed; it can be noisy on domain-joined systems.

.PURPOSE
Use this during endpoint triage to capture who is logged on, whether the session
is elevated, what network adapters are active, and optionally what groups are
present in the current token.

.REQUIRED SYNTAX
pwsh -File .\scripts\it-operations\utilities\Get-CurrentUserContext.ps1
pwsh -File .\scripts\it-operations\utilities\Get-CurrentUserContext.ps1 -IncludeGroups -OutputDirectory .\reports\it-operations\user-context

.OUTPUTS
Returns a summary object. When -OutputDirectory is supplied, writes JSON plus
separate CSV files for adapters and groups.

.STATUS
Active PowerShell replacement for Show-CurrentUser.vbs.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeGroups,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-TokenGroupName {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.WindowsIdentity]$Identity
    )

    foreach ($group in $Identity.Groups) {
        try {
            $group.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $group.Value
        }
    }
}

function Get-NetworkAdapterContext {
    @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | ForEach-Object {
            [pscustomobject]@{
                Description = $_.Description
                MACAddress = $_.MACAddress
                IPAddress = @($_.IPAddress) -join ';'
                DefaultIPGateway = @($_.DefaultIPGateway) -join ';'
                DNSServerSearchOrder = @($_.DNSServerSearchOrder) -join ';'
                DHCPEnabled = $_.DHCPEnabled
                DHCPServer = $_.DHCPServer
                DNSDomain = $_.DNSDomain
            }
        })
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$network = @(Get-NetworkAdapterContext)
$groups = if ($IncludeGroups) { @(Get-TokenGroupName -Identity $identity | Sort-Object -Unique) } else { @() }

$result = [pscustomobject]@{
    UserName = $identity.Name
    Authentication = $identity.AuthenticationType
    IsAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    IsSystem = $identity.IsSystem
    IsGuest = $identity.IsGuest
    IsAnonymous = $identity.IsAnonymous
    ImpersonationLevel = $identity.ImpersonationLevel
    ComputerName = $env:COMPUTERNAME
    UserDomain = $env:USERDOMAIN
    LogonServer = $env:LOGONSERVER
    UserProfile = $env:USERPROFILE
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    ProcessId = $PID
    CollectedAt = (Get-Date).ToString('o')
    NetworkAdapters = @($network)
    Groups = @($groups)
}

if ($OutputDirectory) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $jsonPath = Join-Path $resolvedOutputDirectory "current-user-context-$timestamp.json"
    $adapterCsvPath = Join-Path $resolvedOutputDirectory "current-user-network-adapters-$timestamp.csv"
    $groupCsvPath = Join-Path $resolvedOutputDirectory "current-user-groups-$timestamp.csv"

    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding utf8
    $network | Export-Csv -LiteralPath $adapterCsvPath -NoTypeInformation -Encoding utf8
    if ($IncludeGroups) {
        $groups | ForEach-Object { [pscustomobject]@{ GroupName = $_ } } |
            Export-Csv -LiteralPath $groupCsvPath -NoTypeInformation -Encoding utf8
    }

    $result | Add-Member -NotePropertyName JsonPath -NotePropertyValue $jsonPath -Force
    $result | Add-Member -NotePropertyName AdapterCsvPath -NotePropertyValue $adapterCsvPath -Force
    $result | Add-Member -NotePropertyName GroupCsvPath -NotePropertyValue $(if ($IncludeGroups) { $groupCsvPath } else { $null }) -Force
}

$result
