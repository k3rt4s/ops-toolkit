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

function Get-ADDomain {
    [CmdletBinding()]
    param([Parameter()]$Server, [Parameter()]$Credential, [Parameter()]$Identity)
    Get-FakeAdData -Name 'Domain'
}

function Get-ADForest {
    [CmdletBinding()]
    param([Parameter()]$Server, [Parameter()]$Credential, [Parameter()]$Identity)
    Get-FakeAdData -Name 'Forest'
}

function Get-ADGroup {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$Server,
        [Parameter()]$Credential, [Parameter()]$ResultSetSize
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
        [Parameter()]$Server, [Parameter()]$Credential, [Parameter()]$ResultSetSize
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
        [Parameter()]$Credential, [Parameter()]$ResultSetSize
    )

    $computers = @(Get-FakeAdData -Name 'Computers')
    if ($Identity) {
        $match = @($computers | Where-Object { $_.SamAccountName -eq [string]$Identity -or $_.Name -eq [string]$Identity })
        if ($match.Count -eq 0) { throw "Cannot find an object with identity: '$Identity'." }
        return $match[0]
    }

    $computers
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [Parameter()]$Identity, [Parameter()]$Filter, [Parameter()]$LDAPFilter,
        [Parameter()]$Properties, [Parameter()]$SearchBase, [Parameter()]$Server,
        [Parameter()]$Credential, [Parameter()]$ResultSetSize
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

Export-ModuleMember -Function 'Get-ADDomain', 'Get-ADForest', 'Get-ADGroup', 'Get-ADUser', 'Get-ADComputer', 'Get-ADObject'
