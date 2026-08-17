<#
.SYNOPSIS
Stand-in for the ActiveDirectory module so directory scripts can be run end to end without a domain.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeActiveDirectory` in TestHelpers.psm1 stages it
  on PSModulePath under the name ActiveDirectory and hands back the path.
- Populate `$global:FakeAdData` before running a script under test. Every function
  here reads from it and nothing else.
- Add a cmdlet here only when a script under test actually calls it, and make it
  behave the way the real one does in the cases that matter, including the failure
  cases. A stub that always succeeds proves less than no stub at all.

Purpose:
The directory scripts declare `#Requires -Modules ActiveDirectory`, so on a machine
without RSAT they refuse to start and none of their logic can be exercised. Staging a
module with this name on PSModulePath satisfies that requirement and supplies the
handful of cmdlets they call, which lets the whole pipeline run against a synthetic
domain: query, classify, aggregate, sort, write reports, and summarise.

What this proves and what it does not: it proves the script's own logic against the
shapes it expects. It cannot prove that a real domain controller returns those
shapes. That second half needs a domain and is recorded as unproven on the work
board.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Get-FakeAdData {
    param([string]$Name)
    if (-not $global:FakeAdData) { throw 'FakeAdData is not set. A test must populate $global:FakeAdData before running a script under test.' }
    if ($global:FakeAdData.Contains($Name)) { return $global:FakeAdData[$Name] }
    @()
}

function Write-FakeAdMutation {
    <#
    .SYNOPSIS
    Append one attempted directory change to the mutation log a test is watching.

    .DESCRIPTION
    This is what makes "-WhatIf changed nothing" a checkable claim rather than an
    assumption. Every write cmdlet below records here instead of changing anything, so
    a test can assert the log is empty after a -WhatIf run and populated after a real
    one. Without the second assertion the first is unfalsifiable: a script that does
    nothing at all also writes no mutations.

    Recording is off unless OPSTOOLKIT_TEST_MUTATION_LOG names a file, so a script run
    outside a test still calls a cmdlet that changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter()]$Identity,
        [Parameter()][hashtable]$Detail = @{}
    )

    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }

    $record = [ordered]@{ Command = $Command; Identity = [string]$Identity }
    foreach ($key in $Detail.Keys) { $record[$key] = [string]$Detail[$key] }
    Add-Content -LiteralPath $path -Value ([pscustomobject]$record | ConvertTo-Json -Compress) -Encoding utf8
}

function Get-ADDomain {
    [CmdletBinding()]
    param([Parameter()]$Server, [Parameter()][pscredential]$Credential, [Parameter()]$Identity)
    Get-FakeAdData -Name 'Domain'
}

function Get-ADForest {
    [CmdletBinding()]
    param([Parameter()]$Server, [Parameter()][pscredential]$Credential, [Parameter()]$Identity)
    Get-FakeAdData -Name 'Forest'
}

function Get-ADGroup {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$Server,
        [Parameter()][pscredential]$Credential, [Parameter()]$ResultSetSize
    )

    $groups = @(Get-FakeAdData -Name 'Groups')
    if ($Identity) {
        # The real cmdlet throws when the identity does not exist, and the scripts
        # rely on that to skip forest-root-only groups in a child domain.
        $match = @($groups | Where-Object { $_.SID -eq [string]$Identity -or $_.DistinguishedName -eq [string]$Identity })
        if ($match.Count -eq 0) {
            throw "Cannot find an object with identity: '$Identity' under: 'fake'."
        }

        return $match[0]
    }

    $groups
}

function Get-ADUser {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$SearchScope,
        [Parameter()]$Server, [Parameter()][pscredential]$Credential, [Parameter()]$ResultSetSize
    )

    $users = @(Get-FakeAdData -Name 'Users')
    if ($Identity) {
        $match = @($users | Where-Object { $_.SamAccountName -eq [string]$Identity })
        if ($match.Count -eq 0) {
            throw "Cannot find an object with identity: '$Identity' under: 'fake'."
        }

        return $match[0]
    }

    $users
}

function Get-ADComputer {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$Server,
        [Parameter()][pscredential]$Credential, [Parameter()]$ResultSetSize
    )

    $computers = @(Get-FakeAdData -Name 'Computers')
    if ($Identity) {
        $match = @($computers | Where-Object { $_.SamAccountName -eq [string]$Identity -or $_.Name -eq [string]$Identity })
        if ($match.Count -eq 0) { throw "Cannot find an object with identity: '$Identity'." }
        return $match[0]
    }

    # Honour the enabled filter. The stale-computer script relies on the directory
    # excluding disabled accounts unless it asks for them, so a fixture that returned
    # everything regardless would have the test assert behaviour the real cmdlet does
    # not have.
    $normalized = ([string]$Filter) -replace '\s', ''
    if (-not $Filter -or $normalized -eq '*') {
        return $computers
    }

    if ($normalized -in @('Enabled-eq$true', 'Enabled-eq$True')) {
        return @($computers | Where-Object { $_.Enabled })
    }

    # Throw rather than fall through. Returning everything for a filter this fixture
    # does not understand is how a test passes while the script asks for something
    # entirely different, and it fails silently in the direction of looking fine. Add
    # the filter here when a script under test starts using it.
    throw "FakeActiveDirectory does not interpret the Get-ADComputer filter '$Filter'. Add it to the fixture rather than letting it match everything."
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$Server,
        [Parameter()][pscredential]$Credential, [Parameter()]$ResultSetSize
    )

    # Nested tier-0 membership is read with the LDAP in-chain matching rule, so the
    # fixture keys group membership on the group distinguished name inside the filter.
    if ($LDAPFilter -and $LDAPFilter -match '1\.2\.840\.113556\.1\.4\.1941:=(?<dn>[^)]+)\)') {
        $groupDn = $Matches['dn']
        $membership = Get-FakeAdData -Name 'GroupMembers'
        if ($membership -is [System.Collections.IDictionary] -and $membership.Contains($groupDn)) {
            return @($membership[$groupDn])
        }

        return @()
    }

    if ($LDAPFilter -or $Filter) {
        return @(Get-FakeAdData -Name 'Objects')
    }

    @(Get-FakeAdData -Name 'Objects')
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()][switch]$Recursive,
        [Parameter()]$Server, [Parameter()][pscredential]$Credential
    )

    $membership = Get-FakeAdData -Name 'GroupMembers'
    if ($membership -is [System.Collections.IDictionary] -and $membership.Contains([string]$Identity)) {
        return @($membership[[string]$Identity])
    }

    # The real cmdlet throws for a group that does not exist rather than returning
    # nothing, and a report that silently comes back empty for a typo'd group name is
    # worse than one that fails.
    throw "Cannot find an object with identity: '$Identity' under: 'fake'."
}

function Search-ADAccount {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$PasswordNeverExpires, [Parameter()][switch]$UsersOnly,
        [Parameter()][switch]$AccountDisabled, [Parameter()][switch]$AccountExpired,
        [Parameter()]$Server, [Parameter()][pscredential]$Credential
    )

    $users = @(Get-FakeAdData -Name 'Users')
    if ($PasswordNeverExpires) {
        return @($users | Where-Object { $_.PasswordNeverExpires })
    }

    $users
}

# ---------------------------------------------------------------------------
# Write cmdlets. These never change anything; they record the attempt so a test
# can assert what a script would have done. They deliberately do not declare
# SupportsShouldProcess: the scripts gate their own calls with ShouldProcess and
# must not be able to lean on the cmdlet doing it for them, or a missing gate
# would still pass a -WhatIf test.
# ---------------------------------------------------------------------------

function Disable-ADAccount {
    [CmdletBinding()]
    param([Parameter()]$Identity, [Parameter()]$Server, [Parameter()][pscredential]$Credential)
    Write-FakeAdMutation -Command 'Disable-ADAccount' -Identity $Identity
}

function Enable-ADAccount {
    [CmdletBinding()]
    param([Parameter()]$Identity, [Parameter()]$Server, [Parameter()][pscredential]$Credential)
    Write-FakeAdMutation -Command 'Enable-ADAccount' -Identity $Identity
}

function Move-ADObject {
    [CmdletBinding()]
    param([Parameter()]$Identity, [Parameter()]$TargetPath, [Parameter()]$Server, [Parameter()][pscredential]$Credential)
    Write-FakeAdMutation -Command 'Move-ADObject' -Identity $Identity -Detail @{ TargetPath = $TargetPath }
}

function Set-ADUser {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$UserPrincipalName, [Parameter()]$Replace,
        [Parameter()]$Add, [Parameter()]$Clear, [Parameter()]$Server, [Parameter()][pscredential]$Credential
    )
    Write-FakeAdMutation -Command 'Set-ADUser' -Identity $Identity -Detail @{ UserPrincipalName = $UserPrincipalName }
}

Export-ModuleMember -Function 'Get-ADDomain', 'Get-ADForest', 'Get-ADGroup', 'Get-ADUser',
'Get-ADComputer', 'Get-ADObject', 'Get-ADGroupMember', 'Search-ADAccount',
'Disable-ADAccount', 'Enable-ADAccount', 'Move-ADObject', 'Set-ADUser'
