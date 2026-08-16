#Requires -Modules Pester

# The Active Directory scripts that change user accounts or mail them. Same shape as
# Integration.StateChanging.Ad.Tests.ps1: every script runs twice against one fixture,
# once with -WhatIf which must attempt nothing, and once executing which must attempt
# exactly what the plan described. The executing run is what stops the -WhatIf
# assertion from being satisfied by a script that has quietly stopped working.
#
# Nothing is really changed and no mail is really sent. The write cmdlets record the
# attempt and return.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:adModulePath = Use-FakeActiveDirectory
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-aduser-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    function Get-MutationRecord {
        <#
        .SYNOPSIS
        Read the changes a run attempted, as objects.
        #>
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }
}

AfterAll {
    foreach ($p in $script:adModulePath, $script:workRoot) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-AdUserUpnSuffix' {
    BeforeAll {
        # One account proves each exclusion rule, so a rule that stops working takes a
        # test with it rather than hiding behind another rule that also excludes.
        # Only the properties the script asks the directory for are present.
        $script:upnFixture = @'
$global:FakeAdData = @{
    Users = @(
        [pscustomobject]@{ SamAccountName = 'alice'; UserPrincipalName = 'alice@old.example.com'
            DistinguishedName = 'CN=Alice,OU=Users,DC=test,DC=local'; Enabled = $true; homeMDB = 'CN=DB1' }
        [pscustomobject]@{ SamAccountName = 'bob'; UserPrincipalName = 'bob@other.example.com'
            DistinguishedName = 'CN=Bob,OU=Users,DC=test,DC=local'; Enabled = $true; homeMDB = 'CN=DB1' }
        [pscustomobject]@{ SamAccountName = 'carol'; UserPrincipalName = 'carol@old.example.com'
            DistinguishedName = 'CN=Carol,OU=Users,DC=test,DC=local'; Enabled = $false; homeMDB = 'CN=DB1' }
        [pscustomobject]@{ SamAccountName = 'dave'; UserPrincipalName = 'dave@example.com'
            DistinguishedName = 'CN=Dave,OU=Users,DC=test,DC=local'; Enabled = $true; homeMDB = 'CN=DB1' }
        [pscustomobject]@{ SamAccountName = 'erin'; UserPrincipalName = 'erin@old.example.com'
            DistinguishedName = 'CN=Erin,OU=Users,DC=test,DC=local'; Enabled = $true; homeMDB = $null }
    )
}
'@

        $script:upnWhatIfLog = Join-Path $script:workRoot 'upn-whatif.log'
        $script:upnWhatIf = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Set-AdUserUpnSuffix.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:upnWhatIfLog)'`n$($script:upnFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'upn-whatif')
            OldSuffix       = 'old.example.com'
            NewSuffix       = 'example.com'
            WhatIf          = $true
        }

        $script:upnExecuteLog = Join-Path $script:workRoot 'upn-execute.log'
        $script:upnExecute = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Set-AdUserUpnSuffix.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:upnExecuteLog)'`n$($script:upnFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'upn-execute')
            OldSuffix       = 'old.example.com'
            NewSuffix       = 'example.com'
            Confirm         = $false
        }
    }

    It 'runs to completion in both modes' {
        $script:upnWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:upnWhatIf.Output)"
        $script:upnExecute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:upnExecute.Output)"
    }

    It 'plans only the in-scope accounts, with one exclusion each' {
        $script:upnWhatIf.Summary.UserCount | Should -Be 5
        $script:upnWhatIf.Summary.PlannedChangeCount | Should -Be 2

        $plan = @(Import-Csv $script:upnWhatIf.Summary.PlanCsvPath)
        @($plan | Where-Object { $_.Action -eq 'SetUserPrincipalName' } | ForEach-Object { $_.SamAccountName }) |
            Should -Be @('alice', 'erin')

        ($plan | Where-Object { $_.SamAccountName -eq 'bob' }).Reason | Should -Match 'OldSuffix'
        ($plan | Where-Object { $_.SamAccountName -eq 'carol' }).Reason | Should -Match 'Disabled'
        # Dave already has the target UPN, but the OldSuffix filter is applied first
        # and excludes him before that is ever considered. Order matters here: the
        # NoChange case is only reachable when no OldSuffix filter is in play.
        ($plan | Where-Object { $_.SamAccountName -eq 'dave' }).Action | Should -Be 'Skipped'
        ($plan | Where-Object { $_.SamAccountName -eq 'dave' }).Reason | Should -Match 'OldSuffix'
    }

    It 'recognises an account that already has the requested UPN' {
        # Without an OldSuffix filter every account is in scope, which is where
        # NoChange has to do its job. Re-stamping an identical UPN is a pointless
        # directory write and, on a large estate, a pointless replication storm.
        $log = Join-Path $script:workRoot 'upn-nochange.log'
        $run = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Set-AdUserUpnSuffix.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'`n$($script:upnFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'upn-nochange')
            NewSuffix       = 'example.com'
            Confirm         = $false
        }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        $plan = @(Import-Csv $run.Summary.PlanCsvPath)
        ($plan | Where-Object { $_.SamAccountName -eq 'dave' }).Action | Should -Be 'NoChange'
        @(Get-MutationRecord -Path $log | ForEach-Object { $_.Identity }) |
            Should -Not -Contain 'CN=Dave,OU=Users,DC=test,DC=local'
    }

    It 'attempts no directory change under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:upnWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf attempted: $($mutations | ConvertTo-Json -Compress)"
        $script:upnWhatIf.Summary.ChangedCount | Should -Be 0
        $script:upnWhatIf.Summary.PreviewedCount | Should -Be 2
    }

    It 'sets exactly the planned UPNs when executing' {
        $mutations = Get-MutationRecord -Path $script:upnExecuteLog
        $mutations.Count | Should -Be 2
        @($mutations | ForEach-Object { $_.Command }) | Should -Not -Contain 'Disable-ADAccount'
        @($mutations | ForEach-Object { $_.UserPrincipalName }) |
            Should -Be @('alice@example.com', 'erin@example.com')
        $script:upnExecute.Summary.ChangedCount | Should -Be 2
    }

    It 'excludes the account with no mailbox when MailboxEnabledOnly is requested' {
        $log = Join-Path $script:workRoot 'upn-mailbox.log'
        $run = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Set-AdUserUpnSuffix.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'`n$($script:upnFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory    = (Join-Path $script:workRoot 'upn-mailbox')
            OldSuffix          = 'old.example.com'
            NewSuffix          = 'example.com'
            MailboxEnabledOnly = $true
            Confirm            = $false
        }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        $mutations = Get-MutationRecord -Path $log
        $mutations.Count | Should -Be 1
        $mutations[0].UserPrincipalName | Should -Be 'alice@example.com'
    }

    It 'builds the new UPN from the account name when asked to' {
        # The local part decides whether anyone can still sign in, so which source it
        # came from is worth pinning down.
        $log = Join-Path $script:workRoot 'upn-sam.log'
        $run = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Set-AdUserUpnSuffix.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'`n$($script:upnFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            ReportDirectory = (Join-Path $script:workRoot 'upn-sam')
            OldSuffix       = 'old.example.com'
            NewSuffix       = 'example.com'
            LocalPartSource = 'SamAccountName'
            Confirm         = $false
        }

        $run.ExitCode | Should -Be 0 -Because "the run failed: $($run.Output)"
        @(Get-MutationRecord -Path $log | ForEach-Object { $_.UserPrincipalName }) |
            Should -Be @('alice@example.com', 'erin@example.com')
    }
}

Describe 'Send-AdPasswordExpiryReminderEmails' {
    BeforeAll {
        # Send-MailMessage is a built-in cmdlet rather than part of the AD module, so
        # it is stubbed here as a recorder. Every user satisfies the script's own
        # directory filter (enabled, password does expire), because the fake Get-ADUser
        # does not interpret a scriptblock filter and would otherwise let this test
        # assert on accounts the real cmdlet would never have returned.
        $script:expiryFixture = @'
# A real param block, not $args. Splatting an array into $args stringifies it to
# "System.String[]", which hides the very thing this records: who was mailed.
function Send-MailMessage {
    param($SmtpServer, $From, $To, $Subject, $Body, [switch]$BodyAsHtml)
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value (
        [pscustomobject]@{
            Command    = 'Send-MailMessage'
            Recipients = ($To -join ';')
            Subject    = [string]$Subject
        } | ConvertTo-Json -Compress)
}
$global:FakeAdData = @{
    Users = @(
        [pscustomobject]@{ Name = 'Alice'; SamAccountName = 'alice'; mail = 'alice@test.local'
            givenName = 'Alice'; Enabled = $true; PasswordNeverExpires = $false
            'msDS-UserPasswordExpiryTimeComputed' = (Get-Date).AddDays(3).ToFileTime() }
        [pscustomobject]@{ Name = 'Bob'; SamAccountName = 'bob'; mail = 'bob@test.local'
            givenName = 'Bob'; Enabled = $true; PasswordNeverExpires = $false
            'msDS-UserPasswordExpiryTimeComputed' = (Get-Date).AddDays(45).ToFileTime() }
        [pscustomobject]@{ Name = 'Carol'; SamAccountName = 'carol'; mail = $null
            givenName = 'Carol'; Enabled = $true; PasswordNeverExpires = $false
            'msDS-UserPasswordExpiryTimeComputed' = (Get-Date).AddDays(1).ToFileTime() }
        [pscustomobject]@{ Name = 'Dan'; SamAccountName = 'dan'; mail = 'dan@test.local'
            givenName = 'Dan'; Enabled = $true; PasswordNeverExpires = $false
            'msDS-UserPasswordExpiryTimeComputed' = 9223372036854775807 }
    )
}
'@

        $script:expiryWhatIfLog = Join-Path $script:workRoot 'expiry-whatif.log'
        $script:expiryWhatIf = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:expiryWhatIfLog)'`n$($script:expiryFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            OutputDirectory = (Join-Path $script:workRoot 'expiry-whatif')
            SmtpServer      = 'smtp.test.local'
            From            = 'noreply@test.local'
            AdminTo         = 'admin@test.local'
            ResetUrl        = 'https://reset.test.local'
            SendUserEmails  = $true
            SendAdminReport = $true
            WhatIf          = $true
        }

        $script:expirySendLog = Join-Path $script:workRoot 'expiry-send.log'
        $script:expirySend = Invoke-ScriptUnderTest `
            -RelativePath 'scripts\active-directory\Send-AdPasswordExpiryReminderEmails.ps1' `
            -Setup "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$($script:expirySendLog)'`n$($script:expiryFixture)" `
            -ModulePath $script:adModulePath `
            -Argument @{
            OutputDirectory = (Join-Path $script:workRoot 'expiry-send')
            SmtpServer      = 'smtp.test.local'
            From            = 'noreply@test.local'
            AdminTo         = 'admin@test.local'
            ResetUrl        = 'https://reset.test.local'
            SendUserEmails  = $true
            SendAdminReport = $true
            Confirm         = $false
        }
    }

    It 'runs to completion in both modes' {
        $script:expiryWhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:expiryWhatIf.Output)"
        $script:expirySend.ExitCode | Should -Be 0 -Because "the sending run failed: $($script:expirySend.Output)"
    }

    It 'selects only the accounts inside the reminder window' {
        # Bob expires in 45 days and Dan never expires, so neither should be chased. A
        # reminder sent to everyone is how people learn to ignore reminders.
        $script:expiryWhatIf.Summary.AccountCount | Should -Be 2
        $names = @(Import-Csv $script:expiryWhatIf.Summary.CsvPath | ForEach-Object { $_.SamAccountName })
        $names | Should -Contain 'alice'
        $names | Should -Contain 'carol'
        $names | Should -Not -Contain 'bob'
        $names | Should -Not -Contain 'dan'
    }

    It 'sends nothing under -WhatIf' {
        $mutations = Get-MutationRecord -Path $script:expiryWhatIfLog
        $mutations.Count | Should -Be 0 -Because "-WhatIf sent: $($mutations | ConvertTo-Json -Compress)"
        $script:expiryWhatIf.Summary.SentCount | Should -Be 0
        $script:expiryWhatIf.Summary.PreviewedCount | Should -BeGreaterThan 0
    }

    It 'sends a reminder per account, an admin fallback for the unaddressable one, and the report' {
        # Three sends, not two. Carol has no mail attribute, and rather than dropping
        # her the script sends the notice to the administrators instead, which is the
        # only way anyone finds out her password is about to expire. Dropping her
        # silently would be the easy behaviour and the wrong one.
        $mutations = Get-MutationRecord -Path $script:expirySendLog
        $script:expirySend.Summary.FailedCount | Should -Be 0
        $mutations.Count | Should -Be 3
        $script:expirySend.Summary.SentCount | Should -Be 3

        $plan = @(Import-Csv $script:expirySend.Summary.EmailPlanCsvPath)
        ($plan | Where-Object { $_.SamAccountName -eq 'carol' }).Recipient | Should -Be 'admin@test.local'
        ($plan | Where-Object { $_.SamAccountName -eq 'carol' }).Reason | Should -Match 'no mail attribute'
        ($plan | Where-Object { $_.PlanType -eq 'AdminReport' }) | Should -Not -BeNullOrEmpty

        $sent = ($mutations | ForEach-Object { $_.Recipients }) -join ' '
        $sent | Should -Match 'alice@test\.local'
        $sent | Should -Match 'admin@test\.local'
        $sent | Should -Not -Match 'bob@test\.local'
    }
}
