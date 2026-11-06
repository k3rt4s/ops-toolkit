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
- Set OPSTOOLKIT_TEST_EVENTLOGREADERS to `Name|SID|ObjectClass` entries describing the members of the
  Event Log Readers group, which Get-LocalGroupMember answers when called with -SID S-1-5-32-573.
  OPSTOOLKIT_TEST_EVENTLOGREADERS_ERROR=1 makes that read throw.
- Add-LocalGroupMember and Remove-LocalGroupMember only record to the mutation log (Target is the
  group SID or name, Detail is the member); OPSTOOLKIT_TEST_LOCALGROUP_WRITE_FAIL=1 makes them throw.
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
    Add-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

function Get-LocalUser {
    [CmdletBinding()]
    param([Parameter()][string[]]$Name, [Parameter()]$SID)

    if ($env:OPSTOOLKIT_TEST_LOCALUSERS_ERROR -eq '1') { throw 'Fake Get-LocalUser failure.' }
    foreach ($entry in @(([string]$env:OPSTOOLKIT_TEST_LOCALUSERS -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 3) { continue }
        # -Name takes an array of names and wildcards; -SID takes an array of SIDs (or SecurityIdentifier objects).
        if ($Name -and -not (@($Name) | Where-Object { $parts[0] -like $_ })) { continue }
        if ($SID -and -not (@($SID) | Where-Object { [string]$_ -eq $parts[1] })) { continue }
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
    # The group is picked by -Group (name) or -SID, as the real cmdlet does: Administrators (S-1-5-32-544)
    # answers from OPSTOOLKIT_TEST_LOCALADMINS and Event Log Readers (S-1-5-32-573) from its own variable.
    # Any other group throws, like the real cmdlet's GroupNotFound.
    $groupKey = $null
    if ($SID) { $groupKey = switch ([string]$SID) { 'S-1-5-32-544' { 'Admins' } 'S-1-5-32-573' { 'Readers' } default { $null } } }
    elseif ($Group) { $groupKey = switch -Regex ([string]$Group) { '^(.*\\)?Administrators$' { 'Admins' } '^(.*\\)?Event Log Readers$' { 'Readers' } default { $null } } }
    else { throw 'Fake Get-LocalGroupMember: one of -Group or -SID is required.' }
    if ($null -eq $groupKey) { throw 'Fake Get-LocalGroupMember: group not found.' }
    $source = $env:OPSTOOLKIT_TEST_LOCALADMINS
    if ($groupKey -eq 'Readers') {
        if ($env:OPSTOOLKIT_TEST_EVENTLOGREADERS_ERROR -eq '1') { throw 'Fake Get-LocalGroupMember failure (Event Log Readers).' }
        $source = $env:OPSTOOLKIT_TEST_EVENTLOGREADERS
    }
    foreach ($entry in @(([string]$source -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 3) { continue }
        # -Member filters on the account name (wildcards allowed, the part after any DOMAIN\ counts too) or the SID.
        if ($Member -and -not (@($Member) | Where-Object { [string]$_ -eq $parts[1] -or $parts[0] -like [string]$_ -or ($parts[0] -split '\\')[-1] -like [string]$_ })) { continue }
        [pscustomobject]@{
            Name            = $parts[0]
            SID             = [System.Security.Principal.SecurityIdentifier]::new($parts[1])
            ObjectClass     = $parts[2]
            PrincipalSource = 'Local'
        }
    }
}

function Add-LocalGroupMember {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter()]$Group, [Parameter()]$SID, [Parameter()]$Member)
    if (-not $PSCmdlet.ShouldProcess(([string]$SID + [string]$Group), 'Add-LocalGroupMember')) { return }
    if ($env:OPSTOOLKIT_TEST_LOCALGROUP_WRITE_FAIL -eq '1') { throw 'Fake Add-LocalGroupMember failure.' }
    Write-FakeLocalAccountMutation -Command 'Add-LocalGroupMember' -Target ([string]$SID + [string]$Group) -Detail ([string]$Member)
}

function Remove-LocalGroupMember {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter()]$Group, [Parameter()]$SID, [Parameter()]$Member)
    if (-not $PSCmdlet.ShouldProcess(([string]$SID + [string]$Group), 'Remove-LocalGroupMember')) { return }
    if ($env:OPSTOOLKIT_TEST_LOCALGROUP_WRITE_FAIL -eq '1') { throw 'Fake Remove-LocalGroupMember failure.' }
    Write-FakeLocalAccountMutation -Command 'Remove-LocalGroupMember' -Target ([string]$SID + [string]$Group) -Detail ([string]$Member)
}

function Disable-LocalUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject)
    if (-not $PSCmdlet.ShouldProcess(([string]$SID + [string]$Name), 'Disable-LocalUser')) { return }
    Write-FakeLocalAccountMutation -Command 'Disable-LocalUser' -Target ([string]$SID + [string]$Name)
}

function Enable-LocalUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject)
    if (-not $PSCmdlet.ShouldProcess(([string]$SID + [string]$Name), 'Enable-LocalUser')) { return }
    Write-FakeLocalAccountMutation -Command 'Enable-LocalUser' -Target ([string]$SID + [string]$Name)
}

function Rename-LocalUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter()]$Name, [Parameter()]$SID, [Parameter()]$InputObject, [Parameter()]$NewName)
    if (-not $PSCmdlet.ShouldProcess(([string]$SID + [string]$Name), 'Rename-LocalUser')) { return }
    Write-FakeLocalAccountMutation -Command 'Rename-LocalUser' -Target ([string]$SID + [string]$Name) -Detail ([string]$NewName)
}

Export-ModuleMember -Function 'Get-LocalUser', 'Get-LocalGroupMember', 'Add-LocalGroupMember', 'Remove-LocalGroupMember', 'Disable-LocalUser', 'Enable-LocalUser', 'Rename-LocalUser'
