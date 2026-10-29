<#
.SYNOPSIS
Stand-in for the Microsoft.PowerShell.LocalAccounts module so tests never read or change real local accounts.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_LOCALUSERS to semicolon-separated `Name|SID|Enabled` entries (Enabled is
  True or False) describing the local users on the pretend machine. Unset or empty means no users.
- Set OPSTOOLKIT_TEST_LOCALADMINS to semicolon-separated `Name|SID|ObjectClass` entries describing
  the members of the local Administrators group. Unset or empty means an empty group.
- Set OPSTOOLKIT_TEST_LOCALUSERS_ERROR or OPSTOOLKIT_TEST_LOCALADMINS_ERROR to 1 to make the read
  throw, as Get-LocalGroupMember does when the group holds an orphaned SID.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Disabling, enabling, or renaming a local account is a change to the machine that a script-scope
function stub does not reliably intercept for a module command. The real module is never loaded
because this one is found first. Get-LocalUser and Get-LocalGroupMember are the reads the existing
scripts use; the three mutating commands are the ones the account-policy script calls.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeLocalAccountMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-LocalUser {
    [CmdletBinding()]
    param([Parameter()]$Name, [Parameter()]$SID)

    if ($env:OPSTOOLKIT_TEST_LOCALUSERS_ERROR -eq '1') { throw 'Fake Get-LocalUser failure.' }
    foreach ($entry in @(([string]$env:OPSTOOLKIT_TEST_LOCALUSERS -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 3) { continue }
        if ($Name -and [string]$Name -ne $parts[0]) { continue }
        if ($SID -and [string]$SID -ne $parts[1]) { continue }
        [pscustomobject]@{
            Name    = $parts[0]
            SID     = [System.Security.Principal.SecurityIdentifier]::new($parts[1])
            Enabled = ($parts[2] -eq 'True')
        }
    }
}

function Get-LocalGroupMember {
    [CmdletBinding()]
    param([Parameter()]$Group, [Parameter()]$SID, [Parameter()]$Member)

    if ($env:OPSTOOLKIT_TEST_LOCALADMINS_ERROR -eq '1') { throw 'Fake Get-LocalGroupMember failure.' }
    foreach ($entry in @(([string]$env:OPSTOOLKIT_TEST_LOCALADMINS -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 3) { continue }
        [pscustomobject]@{
            Name            = $parts[0]
            SID             = [System.Security.Principal.SecurityIdentifier]::new($parts[1])
            ObjectClass     = $parts[2]
            PrincipalSource = 'Local'
        }
    }
}

function Disable-LocalUser {
    [CmdletBinding()]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject)
    Write-FakeLocalAccountMutation -Command 'Disable-LocalUser' -Target ([string]$SID + [string]$Name)
}

function Enable-LocalUser {
    [CmdletBinding()]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject)
    Write-FakeLocalAccountMutation -Command 'Enable-LocalUser' -Target ([string]$SID + [string]$Name)
}

function Rename-LocalUser {
    [CmdletBinding()]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject, [Parameter()]$NewName)
    Write-FakeLocalAccountMutation -Command 'Rename-LocalUser' -Target ([string]$SID + [string]$Name) -Detail ([string]$NewName)
}

Export-ModuleMember -Function 'Get-LocalUser', 'Get-LocalGroupMember', 'Disable-LocalUser', 'Enable-LocalUser', 'Rename-LocalUser'
