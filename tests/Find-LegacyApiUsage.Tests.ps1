#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    $script:scannerPath = Get-RepositoryScriptPath -RelativePath 'scripts\utilities\Find-LegacyApiUsage.ps1'

    $script:fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "legacy-scan-fixture-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:fixtureRoot -Force | Out-Null

    # One line per rule, so a rule that stops firing is obvious.
    Set-Content -LiteralPath (Join-Path $script:fixtureRoot 'legacy.ps1') -Encoding utf8 -Value @'
Connect-MsolService
Import-Module AzureAD
Get-AzureRmVM -Name web01
[Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($a)
Connect-ExchangeOnline -Credential $cred -Organization contoso.com
$svc = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
Add-MailboxPermission -User svc -AccessRights ApplicationImpersonation
Get-MessageTrace -StartDate $s -EndDate $e
Send-MailMessage -To a@b.com -From c@d.com -SmtpServer mail
# Connect-MsolService is only mentioned in this comment
'@

    # The modern replacements. Any hit here is a false positive.
    Set-Content -LiteralPath (Join-Path $script:fixtureRoot 'modern.ps1') -Encoding utf8 -Value @'
Connect-MgGraph -Scopes Application.Read.All
Connect-ExchangeOnline -CertificateThumbprint $tp -AppId $id -Organization contoso.com
Get-MessageTraceV2 -StartDate $s -EndDate $e
Get-AzVM -Name web01
Connect-AzAccount -Tenant $t
Import-Module Az.Accounts
$msal = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($id)
'@

    Set-Content -LiteralPath (Join-Path $script:fixtureRoot 'runbook.md') -Encoding utf8 -Value @'
# Runbook

This runbook used to tell you to use Connect-MsolService in prose.

```powershell
Connect-MsolService
```
'@

    $script:outputRoot = Join-Path $script:fixtureRoot 'out'
    $script:summary = & $script:scannerPath -Path $script:fixtureRoot -OutputDirectory $script:outputRoot
    $script:findings = @(Import-Csv (Join-Path $script:summary.OutputDirectory 'findings.csv'))
}

AfterAll {
    if (Test-Path -LiteralPath $script:fixtureRoot) {
        Remove-Item -LiteralPath $script:fixtureRoot -Recurse -Force
    }
}

Describe 'Rule coverage' {
    # Named rather than $_, because the Where-Object pipeline below shadows $_.
    It 'fires rule <Rule>' -ForEach @(
        @{ Rule = 'MSOL-001' }, @{ Rule = 'AAD-001' }, @{ Rule = 'ARM-001' }, @{ Rule = 'ADAL-001' }
        @{ Rule = 'EXO-001' }, @{ Rule = 'EWS-001' }, @{ Rule = 'EXO-002' }, @{ Rule = 'EXO-003' }
        @{ Rule = 'SMTP-001' }
    ) {
        @($script:findings | Where-Object { $_.RuleId -eq $Rule }).Count | Should -BeGreaterThan 0
    }
}

Describe 'False positives' {
    It 'produces no finding against the modern replacements' {
        # Get-MessageTraceV2, certificate-based Connect-ExchangeOnline, Get-AzVM, and
        # Connect-MgGraph must never match the rules that target what they replaced.
        @($script:findings | Where-Object { $_.File -like '*modern.ps1' }).Count | Should -Be 0
    }
}

Describe 'Comment and prose handling' {
    It 'flags a commented occurrence rather than dropping it' {
        $commented = @($script:findings | Where-Object { $_.File -like '*legacy.ps1' -and $_.InComment -eq 'True' })
        $commented.Count | Should -Be 1
    }

    It 'treats a markdown prose mention as prose, not as live code' {
        $prose = @($script:findings | Where-Object { $_.File -like '*runbook.md' -and $_.InComment -eq 'True' })
        $prose.Count | Should -BeGreaterThan 0
    }

    It 'treats a markdown fenced command as live code' {
        # A command someone will paste is not the same as a name in a sentence.
        $fenced = @($script:findings | Where-Object { $_.File -like '*runbook.md' -and $_.InComment -eq 'False' })
        $fenced.Count | Should -BeGreaterThan 0
    }
}

Describe 'Self-exclusion' {
    It 'does not report its own rule table when scanning a tree it lives in' {
        $selfScan = & $script:scannerPath -Path (Split-Path $script:scannerPath -Parent) -OutputDirectory (Join-Path $script:fixtureRoot 'selfout')
        $selfFindings = @(Import-Csv (Join-Path $selfScan.OutputDirectory 'findings.csv'))
        @($selfFindings | Where-Object { $_.File -like '*Find-LegacyApiUsage.ps1' }).Count | Should -Be 0
    }
}

Describe 'Usage contract' {
    It 'exits 2 and prints usage when -Path is missing' {
        # The repo forbids interactive prompts in automation, so a missing required
        # argument must fail with usage rather than block waiting for input.
        $null = & pwsh -NoProfile -NonInteractive -File $script:scannerPath 2>&1
        $LASTEXITCODE | Should -Be 2
    }
}
