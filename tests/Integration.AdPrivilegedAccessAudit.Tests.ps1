#Requires -Modules Pester

# End-to-end run of the AD audit against a synthetic domain with known findings
# planted, on a machine with no RSAT and no domain. Proves the whole pipeline:
# query, classify, aggregate, sort, write reports, summarise. It does not prove that
# a real domain controller returns these shapes; that remains unproven by design.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:modulePath = Use-FakeActiveDirectory

    # One planted fault per finding type, plus two things that must NOT be reported:
    # a gMSA with an SPN, and a domain controller with unconstrained delegation.
    $script:setup = @'
$domainSid = 'S-1-5-21-1-2-3'
$old = (Get-Date).AddDays(-800)
$recent = (Get-Date).AddDays(-10)

function New-User {
    param($Sam, $Uac = 512, $Spn = @(), $AdminCount = $null, $Class = 'user', $PwdSet = $recent)
    [pscustomobject]@{
        SamAccountName = $Sam; Name = $Sam; ObjectClass = $Class
        Enabled = -not ([int]$Uac -band 0x2)
        DistinguishedName = "CN=$Sam,DC=test,DC=local"
        userAccountControl = $Uac
        servicePrincipalName = $Spn
        pwdLastSet = $PwdSet.ToFileTimeUtc()
        lastLogonTimestamp = $recent.ToFileTimeUtc()
        adminCount = $AdminCount
        'msDS-AllowedToDelegateTo' = @()
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = $null
        SID = "$domainSid-$([Math]::Abs($Sam.GetHashCode()) % 9000 + 1000)"
    }
}

function New-Computer {
    param($Name, $Uac = 4096, $PrimaryGroupId = 515)
    [pscustomobject]@{
        SamAccountName = "$Name`$"; Name = $Name; ObjectClass = 'computer'
        Enabled = $true; DistinguishedName = "CN=$Name,DC=test,DC=local"
        userAccountControl = $Uac
        servicePrincipalName = @()
        pwdLastSet = $recent.ToFileTimeUtc(); lastLogonTimestamp = $recent.ToFileTimeUtc()
        'msDS-AllowedToDelegateTo' = @()
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = $null
        PrimaryGroupID = $PrimaryGroupId
        SID = "$domainSid-$([Math]::Abs($Name.GetHashCode()) % 9000 + 1000)"
    }
}

$daDn = "CN=Domain Admins,DC=test,DC=local"

$global:FakeAdData = @{
    Domain = [pscustomobject]@{ DNSRoot = 'test.local'; DomainSID = $domainSid; DistinguishedName = 'DC=test,DC=local' }
    Forest = [pscustomobject]@{ RootDomain = 'test.local' }
    Groups = @(
        [pscustomobject]@{ Name = 'Domain Admins'; SID = "$domainSid-512"; DistinguishedName = $daDn; Members = @() }
    )
    GroupMembers = @{
        $daDn = @(
            [pscustomobject]@{
                SamAccountName = 'da_stale'; Name = 'da_stale'; ObjectClass = 'user'
                DistinguishedName = 'CN=da_stale,DC=test,DC=local'
                userAccountControl = 514                       # disabled but still a member
                pwdLastSet = $old.ToFileTimeUtc(); lastLogonTimestamp = $old.ToFileTimeUtc()
                adminCount = 1; objectSid = "$domainSid-1101"
            }
        )
    }
    Users = @(
        New-User -Sam 'asrep_user' -Uac 4194816                                  # DONT_REQ_PREAUTH
        New-User -Sam 'svc_sql' -Spn @('MSSQLSvc/sql01.test.local:1433') -PwdSet $old
        New-User -Sam 'gmsa_web' -Spn @('HTTP/web01.test.local') -Class 'msDS-GroupManagedServiceAccount'
        New-User -Sam 'nopassword' -Uac 544                                      # PASSWD_NOTREQD
        New-User -Sam 'orphan_admin' -AdminCount 1                               # adminCount, not in a group
        New-User -Sam 'normal_user'
        [pscustomobject]@{
            SamAccountName = 'krbtgt'; Name = 'krbtgt'; ObjectClass = 'user'; Enabled = $false
            DistinguishedName = 'CN=krbtgt,DC=test,DC=local'; userAccountControl = 514
            servicePrincipalName = @(); pwdLastSet = $old.ToFileTimeUtc()
            lastLogonTimestamp = 0; adminCount = 1
            'msDS-AllowedToDelegateTo' = @(); 'msDS-AllowedToActOnBehalfOfOtherIdentity' = $null
            SID = "$domainSid-502"
        }
    )
    Computers = @(
        New-Computer -Name 'MEMBER01' -Uac 528384                                # unconstrained, member server
        New-Computer -Name 'DC01' -Uac 528384 -PrimaryGroupId 516                # unconstrained, domain controller
        New-Computer -Name 'PLAIN01'
    )
}
'@
}

AfterAll {
    if ($script:modulePath -and (Test-Path $script:modulePath)) {
        Remove-Item $script:modulePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Export-AdPrivilegedAccessAudit end to end' {
    BeforeAll {
        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\active-directory\Export-AdPrivilegedAccessAudit.ps1' `
            -Setup $script:setup -ModulePath $script:modulePath `
            -Argument @{ OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "adaudit-$([guid]::NewGuid().ToString('N'))") }

        $script:summary = $script:run.Summary
        if ($script:summary) {
            $script:findings = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'findings.csv'))
        } else {
            $script:findings = @()
        }
    }

    It 'runs to completion on a machine with no RSAT and no domain' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'reads the synthetic domain' {
        $script:summary.Domain | Should -Be 'test.local'
        $script:summary.UsersRead | Should -Be 7
        $script:summary.ComputersRead | Should -Be 3
    }

    It 'finds the AS-REP roastable account' {
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-ASREP-001' }).SamAccountName | Should -Be 'asrep_user'
    }

    It 'finds the Kerberoastable service account' {
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-KRBRST-001' }).SamAccountName | Should -Be 'svc_sql'
    }

    It 'does not report the gMSA as Kerberoastable' {
        # A gMSA password is 240 characters and domain-rotated, so it is not crackable
        # offline. Reporting it buries the service account that is.
        @($script:findings | Where-Object { $_.SamAccountName -eq 'gmsa_web' }).Count | Should -Be 0
    }

    It 'finds the unconstrained member server and rates it Critical' {
        $finding = @($script:findings | Where-Object { $_.FindingId -eq 'AD-DELEG-001' })
        $finding.Count | Should -Be 1
        $finding[0].Name | Should -Be 'MEMBER01'
        $finding[0].Severity | Should -Be 'Critical'
    }

    It 'reports the unconstrained domain controller as Informational, not Critical' {
        # A DC is unconstrained by design. Flagging it hides the member server.
        $finding = @($script:findings | Where-Object { $_.FindingId -eq 'AD-DELEG-005' })
        $finding.Count | Should -Be 1
        $finding[0].Name | Should -Be 'DC01'
        $finding[0].Severity | Should -Be 'Informational'
    }

    It 'finds the account that does not require a password' {
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-PWD-001' }).SamAccountName | Should -Be 'nopassword'
    }

    It 'finds the orphaned adminCount object' {
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-ADMCNT-001' }).SamAccountName | Should -Contain 'orphan_admin'
    }

    It 'flags the stale krbtgt password' {
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-KRBTGT-001' }).Count | Should -Be 1
    }

    It 'flags the disabled account still in Domain Admins' {
        # Disabling is not removal. A disabled tier-0 account is a re-enable away from
        # full privilege and is rarely monitored.
        @($script:findings | Where-Object { $_.FindingId -eq 'AD-TIER0-001' }).SamAccountName | Should -Be 'da_stale'
    }

    It 'does not report the ordinary user at all' {
        @($script:findings | Where-Object { $_.SamAccountName -eq 'normal_user' }).Count | Should -Be 0
    }

    It 'sorts the most severe finding first' {
        $script:findings[0].Severity | Should -Be 'Critical'
    }

    It 'writes every report plus a summary' {
        foreach ($name in 'findings', 'finding-rollup', 'tier0-membership', 'tier0-groups') {
            Test-Path (Join-Path $script:summary.OutputDirectory "$name.csv") | Should -BeTrue
            Test-Path (Join-Path $script:summary.OutputDirectory "$name.json") | Should -BeTrue
        }
        Test-Path (Join-Path $script:summary.OutputDirectory 'summary.json') | Should -BeTrue
    }

    It 'counts severities in the summary consistently with the findings file' {
        $script:summary.CriticalCount | Should -Be @($script:findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $script:summary.FindingCount | Should -Be $script:findings.Count
    }
}
