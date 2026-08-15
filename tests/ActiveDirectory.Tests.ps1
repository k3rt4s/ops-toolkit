#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1'
    Import-ScriptFunction -RelativePath 'scripts\active-directory\Export-AdAclRiskReport.ps1'
    Import-ScriptFunction -RelativePath 'scripts\active-directory\Test-LdapSigningReadiness.ps1'

    $script:asOf = [datetime]::new(2026, 8, 14, 0, 0, 0, [DateTimeKind]::Utc)

    function New-AccessRule {
        param($Rights, $Type = 'Allow', $ObjectType = '00000000-0000-0000-0000-000000000000', $Inherited = $false)
        [pscustomobject]@{
            ActiveDirectoryRights = $Rights; AccessControlType = $Type
            ObjectType = $ObjectType; IsInherited = $Inherited; IdentityReference = 'CONTOSO\someone'
        }
    }
}

Describe 'Test-UacFlag' {
    It 'detects disabled Kerberos pre-authentication, the AS-REP roast precondition' {
        Test-UacFlag -UserAccountControl 4194816 -FlagName 'DoesNotRequirePreAuth' | Should -BeTrue
    }

    It 'does not report the flag on a normal account' {
        Test-UacFlag -UserAccountControl 512 -FlagName 'DoesNotRequirePreAuth' | Should -BeFalse
    }

    It 'detects a disabled account' {
        Test-UacFlag -UserAccountControl 514 -FlagName 'AccountDisabled' | Should -BeTrue
    }

    It 'detects unconstrained delegation' {
        Test-UacFlag -UserAccountControl 524800 -FlagName 'TrustedForDelegation' | Should -BeTrue
    }

    It 'detects PASSWD_NOTREQD' {
        Test-UacFlag -UserAccountControl 544 -FlagName 'PasswordNotRequired' | Should -BeTrue
    }

    It 'detects protocol transition' {
        Test-UacFlag -UserAccountControl 17235968 -FlagName 'TrustedToAuthForDelegation' | Should -BeTrue
    }

    It 'treats a null userAccountControl as no flags rather than throwing' {
        Test-UacFlag -UserAccountControl $null -FlagName 'AccountDisabled' | Should -BeFalse
    }

    It 'throws on an unknown flag name rather than silently returning false' {
        # A typo in a flag name must fail loudly. Returning false would silently drop
        # a whole class of finding.
        { Test-UacFlag -UserAccountControl 512 -FlagName 'NotARealFlag' } | Should -Throw
    }
}

Describe 'Test-ManagedServiceAccount' {
    It 'identifies a group managed service account' {
        Test-ManagedServiceAccount -AdObject ([pscustomobject]@{ ObjectClass = 'msDS-GroupManagedServiceAccount' }) | Should -BeTrue
    }

    It 'identifies a standalone managed service account' {
        Test-ManagedServiceAccount -AdObject ([pscustomobject]@{ ObjectClass = 'msDS-ManagedServiceAccount' }) | Should -BeTrue
    }

    It 'does not treat an ordinary user as managed' {
        Test-ManagedServiceAccount -AdObject ([pscustomobject]@{ ObjectClass = 'user' }) | Should -BeFalse
    }

    It 'handles a full class chain array' {
        Test-ManagedServiceAccount -AdObject ([pscustomobject]@{ ObjectClass = @('top', 'person', 'msDS-GroupManagedServiceAccount') }) | Should -BeTrue
    }

    It 'does not match a user class chain' {
        Test-ManagedServiceAccount -AdObject ([pscustomobject]@{ ObjectClass = @('top', 'person', 'user') }) | Should -BeFalse
    }

    It 'handles a null object' {
        Test-ManagedServiceAccount -AdObject $null | Should -BeFalse
    }
}

Describe 'Get-FindingRecord' {
    It 'rejects a severity outside the allowed set' {
        $adObject = [pscustomobject]@{ SamAccountName = 'x'; Name = 'x'; ObjectClass = 'user'; Enabled = $true; DistinguishedName = 'CN=x' }
        { Get-FindingRecord -FindingId 'x' -Category 'c' -Severity 'Catastrophic' -AdObject $adObject -Detail 'd' -Recommendation 'r' } | Should -Throw
    }

    It 'carries the password age through to the record' {
        $adObject = [pscustomobject]@{ SamAccountName = 'svc'; Name = 'svc'; ObjectClass = 'user'; Enabled = $true; DistinguishedName = 'CN=svc' }
        $record = Get-FindingRecord -FindingId 'AD-KRBRST-001' -Category 'Kerberos' -Severity 'High' -AdObject $adObject `
            -Detail 'd' -Recommendation 'r' -PwdLastSetAgeDays 400 -LastLogonDays 5 -IsTier0 $false
        $record.PasswordAgeDays | Should -Be 400
        $record.Severity | Should -Be 'High'
        $record.IsTier0 | Should -BeFalse
    }
}

Describe 'Tier-0 group table' {
    It 'identifies privileged groups by well-known SID rather than by name' {
        # Group names are localized and can be renamed. SIDs cannot.
        $rids = @($Tier0Group | Where-Object { $_.PSObject.Properties['Rid'] } | ForEach-Object { $_.Rid })
        $rids | Should -Contain 512
        $rids | Should -Contain 519
        $builtins = @($Tier0Group | Where-Object { $_.PSObject.Properties['Sid'] } | ForEach-Object { $_.Sid })
        $builtins | Should -Contain 'S-1-5-32-544'
        $builtins | Should -Contain 'S-1-5-32-548'
    }

    It 'marks forest-root-only groups so a child domain does not report them missing' {
        (@($Tier0Group | Where-Object { $_.Key -eq 'EnterpriseAdmins' }).ForestRootOnly) | Should -BeTrue
        (@($Tier0Group | Where-Object { $_.Key -eq 'DomainAdmins' }).ForestRootOnly) | Should -BeFalse
    }
}

Describe 'Get-DangerousRight' {
    It 'rates GenericAll as Critical' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'GenericAll'))[0]).Severity | Should -Be 'Critical'
    }

    It 'detects WriteDacl' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'WriteDacl'))[0]).Right | Should -Be 'WriteDacl'
    }

    It 'does not treat a Deny ACE as a grant' {
        @(Get-DangerousRight -AccessRule (New-AccessRule 'GenericAll' 'Deny')).Count | Should -Be 0
    }

    It 'ignores a harmless right' {
        @(Get-DangerousRight -AccessRule (New-AccessRule 'ReadProperty')).Count | Should -Be 0
    }

    It 'returns every dangerous right in a combined mask' {
        @(Get-DangerousRight -AccessRule (New-AccessRule 'GenericAll, WriteDacl, WriteOwner')).Count | Should -Be 3
    }

    It 'names the DCSync replication right and rates it Critical' {
        $right = @(Get-DangerousRight -AccessRule (New-AccessRule 'ExtendedRight' 'Allow' '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))[0]
        $right.Right | Should -Be 'DS-Replication-Get-Changes-All'
        $right.Severity | Should -Be 'Critical'
    }

    It 'names the force password change right' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'ExtendedRight' 'Allow' '00299570-246d-11d0-a768-00aa006e0529'))[0]).Right | Should -Be 'User-Force-Change-Password'
    }

    It 'treats an all-zero object type on ExtendedRight as every extended right' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'ExtendedRight'))[0]).Right | Should -Be 'AllExtendedRights'
    }

    It 'treats an all-zero object type on WriteProperty as every property' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'WriteProperty'))[0]).Right | Should -Be 'WriteAllProperties'
    }

    It 'names Self-Membership when WriteProperty targets the member attribute' {
        (@(Get-DangerousRight -AccessRule (New-AccessRule 'WriteProperty' 'Allow' 'bf9679c0-0de6-11d0-a285-00aa003049e2'))[0]).Right | Should -Be 'Self-Membership (member)'
    }

    It 'ignores an extended right that is not on the dangerous list' {
        @(Get-DangerousRight -AccessRule (New-AccessRule 'ExtendedRight' 'Allow' 'aaaaaaaa-0000-0000-0000-000000000000')).Count | Should -Be 0
    }
}

Describe 'Test-ExpectedPrincipal' {
    It 'suppresses principals that hold broad rights by design' {
        Test-ExpectedPrincipal -Sid 'S-1-5-18' -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
        Test-ExpectedPrincipal -Sid 'S-1-5-32-544' -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
        Test-ExpectedPrincipal -Sid 'S-1-5-21-1-2-3-512' -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
    }

    It 'does not suppress an ordinary user' {
        Test-ExpectedPrincipal -Sid 'S-1-5-21-1-2-3-1105' -DomainSid 'S-1-5-21-1-2-3' | Should -BeFalse
    }

    It 'does not suppress a privileged group from a different domain' {
        # A Domain Admin of another domain holding rights here is a finding, not a default.
        Test-ExpectedPrincipal -Sid 'S-1-5-21-9-9-9-512' -DomainSid 'S-1-5-21-1-2-3' | Should -BeFalse
    }

    It 'does not suppress an empty SID' {
        Test-ExpectedPrincipal -Sid '' -DomainSid 'S-1-5-21-1-2-3' | Should -BeFalse
    }
}

Describe 'Get-LdapClientDetail' {
    It 'extracts an IPv4 address, port, and identity from a 2889 event' {
        $message = @'
The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without requesting signing (integrity verification), or performed a simple bind over a clear text (non-SSL/TLS-encrypted) LDAP connection.

Client IP address:
10.20.30.40:51772
Identity the client attempted to authenticate as:
CONTOSO\svc_scanner
Binding Type:
0
'@
        $detail = Get-LdapClientDetail -Message $message
        $detail.ClientAddress | Should -Be '10.20.30.40'
        $detail.ClientPort | Should -Be '51772'
        $detail.Identity | Should -Be 'CONTOSO\svc_scanner'
    }

    It 'extracts a bracketed IPv6 address and port from a 3039 event' {
        $message = @'
The following client performed a SASL bind without requesting a channel binding token.

Client IP address:
[fe80::1c2d:3e4f:5a6b:7c8d]:49812
Identity the client attempted to authenticate as:
CONTOSO\appliance01$
'@
        $detail = Get-LdapClientDetail -Message $message
        $detail.ClientAddress | Should -Be 'fe80::1c2d:3e4f:5a6b:7c8d'
        $detail.ClientPort | Should -Be '49812'
    }

    It 'returns an empty address rather than a guess when none can be parsed' {
        # A wrong address sends someone to remediate the wrong device.
        (Get-LdapClientDetail -Message 'A message with no address in it at all.').ClientAddress | Should -Be ''
    }
}
