#Requires -Modules Pester

# Invoke-EntraUserContainment against a stubbed Graph and a staged fake Exchange Online
# module, with null and edge user shapes planted: a cloud user enabled, a cloud user
# already disabled, a synced user, a UPN that 404s, a lookup that fails 403, a user with
# no mailbox, and a user with no inbox rules and null forwarding fields.
#
# The script is run as the pair this repository requires: once with -WhatIf, which must
# attempt no write and still produce the plan and the exports, and once executing, which
# must attempt exactly the writes the plan described. "-WhatIf wrote nothing" is
# unfalsifiable alone, because a script that silently does nothing writes nothing too.
#
# Nothing is ever really changed. The Graph stub records each write to a log; a generated
# password is replaced by a marker in that log and its real value is kept in a separate
# secret log, so a test can search every file the script wrote for it.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    $script:scriptPath = 'scripts\entra\Invoke-EntraUserContainment.ps1'
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-entracontain-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null

    $script:allUpn = @(
        'cloud.on@contoso.com', 'cloud.off@contoso.com', 'synced@contoso.com',
        'missing@contoso.com', 'denied@contoso.com', 'nomailbox@contoso.com', 'norules@contoso.com')
    $script:cloudIds = @('id-cloud-on', 'id-cloud-off', 'id-nomailbox', 'id-norules')

    # Import the real Graph module first, then define the stubs: a module imported after a
    # function of the same name replaces it, so stubs defined first are silently clobbered.
    $script:graphStub = @'
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Connect-MgGraph { param($Scopes, $TenantId, $UseDeviceCode) }
function Get-MgContext { [pscustomobject]@{ TenantId = 'contoso-tenant-id'; Account = 'admin@contoso.com' } }

# Cloud-only users return onPremisesSyncEnabled as null, which is the ordinary shape.
$global:FailDisableFor = $null
$global:EchoBodyOnPasswordFailure = $false

$global:FakeGraphUsers = @{
    'cloud.on@contoso.com'   = @{ id = 'id-cloud-on';   userPrincipalName = 'cloud.on@contoso.com';   accountEnabled = $true;  onPremisesSyncEnabled = $null }
    'cloud.off@contoso.com'  = @{ id = 'id-cloud-off';  userPrincipalName = 'cloud.off@contoso.com';  accountEnabled = $false; onPremisesSyncEnabled = $false }
    'synced@contoso.com'     = @{ id = 'id-synced';     userPrincipalName = 'synced@contoso.com';     accountEnabled = $true;  onPremisesSyncEnabled = $true }
    'nomailbox@contoso.com'  = @{ id = 'id-nomailbox';  userPrincipalName = 'nomailbox@contoso.com';  accountEnabled = $true;  onPremisesSyncEnabled = $null }
    'norules@contoso.com'    = @{ id = 'id-norules';    userPrincipalName = 'norules@contoso.com';    accountEnabled = $true;  onPremisesSyncEnabled = $null }
}

function Write-FakeLog {
    param([hashtable]$Data)
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value ($Data | ConvertTo-Json -Depth 6 -Compress)
}

function Invoke-MgGraphRequest {
    param($Method, $Uri, $Body, $ContentType, $OutputType, $ErrorAction)
    $path = $Uri -replace '^https://graph\.microsoft\.com/v1\.0', ''

    if ($Method -eq 'GET') {
        if ($path -notmatch '^/users/([^/?]+)\?') { throw "unexpected GET $path" }
        $key = [uri]::UnescapeDataString($Matches[1])
        if ($path -notmatch 'select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled') { throw "unexpected select in $path" }
        if ($key -eq 'missing@contoso.com') { throw 'Response status code does not indicate success: NotFound (Not Found). Request_ResourceNotFound: Resource does not exist.' }
        if ($key -eq 'denied@contoso.com') { throw 'Response status code does not indicate success: Forbidden (Forbidden). Authorization_RequestDenied: Insufficient privileges to complete the operation.' }
        $found = $global:FakeGraphUsers.Values | Where-Object { $_.userPrincipalName -eq $key -or $_.id -eq $key } | Select-Object -First 1
        if (-not $found) { throw 'Response status code does not indicate success: NotFound (Not Found). Request_ResourceNotFound.' }
        return $found
    }

    $entry = @{ Kind = 'Write'; Method = $Method; Path = $path; Body = $null }
    $secret = $null
    $parsed = $null
    if ($Body) {
        $parsed = $Body | ConvertFrom-Json -AsHashtable
        if ($parsed.ContainsKey('passwordProfile')) {
            $secret = $parsed.passwordProfile.password
            $parsed.passwordProfile.password = '<GENERATED-PASSWORD>'
        }
        $entry.Body = $parsed
    }
    Write-FakeLog -Data $entry
    if ($secret) {
        Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_SECRET_LOG -Encoding utf8 -Value (@{ Path = $path; Password = $secret } | ConvertTo-Json -Compress)
        # A server that echoes the request back in its error is the leak the script must survive.
        if ($global:EchoBodyOnPasswordFailure) { throw "Bad request. The request body was: $Body" }
    }
    if ($global:FailDisableFor -and $Method -eq 'PATCH' -and $path -eq "/users/$($global:FailDisableFor)" -and $parsed -and $parsed.ContainsKey('accountEnabled') -and -not $parsed.accountEnabled) {
        throw 'Response status code does not indicate success: Forbidden (Forbidden). Authorization_RequestDenied.'
    }
    if ($path -like '*/revokeSignInSessions') { return @{ value = $true } }
    $null
}
'@

    # The Exchange data. nomailbox is absent from the mailbox table on purpose.
    $script:exoData = @'
$global:FakeExoMailboxes = @{
    'cloud.on@contoso.com'  = [pscustomobject]@{ ForwardingAddress = $null; ForwardingSmtpAddress = 'smtp:fwd@evil.example'; DeliverToMailboxAndForward = $true }
    'cloud.off@contoso.com' = [pscustomobject]@{ ForwardingAddress = 'Some Contact'; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
    'synced@contoso.com'    = [pscustomobject]@{ ForwardingAddress = $null; ForwardingSmtpAddress = $null }
    'norules@contoso.com'   = [pscustomobject]@{ ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $null }
}
$global:FakeExoRules = @{
    'cloud.on@contoso.com'  = @([pscustomobject]@{ Name = 'Forward all'; Enabled = $true; Priority = 1; ForwardTo = @('attacker@evil.example'); DeleteMessage = $false; StopProcessingRules = $true; Description = 'forward everything' })
    'cloud.off@contoso.com' = @([pscustomobject]@{ Name = 'Hide'; Enabled = $true; Priority = 1; MoveToFolder = 'RSS Feeds'; MarkAsRead = $true })
    'synced@contoso.com'    = @([pscustomobject]@{ Name = 'Delete alerts'; Enabled = $false; Priority = 2; DeleteMessage = $true })
    'norules@contoso.com'   = $null
}
'@

    function Get-FakeExoModuleManifest {
        <#
        .SYNOPSIS
        Stage a fake module under the given name exporting Get-Mailbox and Get-InboxRule, and return its manifest path.
        #>
        param([string]$Root, [string]$Name)
        $dir = Join-Path $Root $Name
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir "$Name.psm1") -Encoding utf8 -Value @'
function Write-FakeExoLog {
    param([hashtable]$Data)
    Add-Content -LiteralPath $env:OPSTOOLKIT_TEST_MUTATION_LOG -Encoding utf8 -Value ($Data | ConvertTo-Json -Compress)
}
function Get-Mailbox {
    [CmdletBinding()] param($Identity)
    Write-FakeExoLog -Data @{ Kind = 'Read'; Command = 'Get-Mailbox'; Identity = $Identity }
    if (-not $global:FakeExoMailboxes.ContainsKey($Identity)) {
        throw "The operation couldn't be performed because object '$Identity' couldn't be found on 'AM6PR01.prod.outlook.com'."
    }
    $global:FakeExoMailboxes[$Identity]
}
function Get-InboxRule {
    [CmdletBinding()] param($Mailbox)
    Write-FakeExoLog -Data @{ Kind = 'Read'; Command = 'Get-InboxRule'; Identity = $Mailbox }
    $global:FakeExoRules[$Mailbox]
}
# The script must never change a rule or a forward. A call to any of these is a recorded failure.
function Set-InboxRule { [CmdletBinding()] param($Identity, $Mailbox) Write-FakeExoLog -Data @{ Kind = 'Write'; Command = 'Set-InboxRule' } }
function Remove-InboxRule { [CmdletBinding()] param($Identity, $Mailbox) Write-FakeExoLog -Data @{ Kind = 'Write'; Command = 'Remove-InboxRule' } }
function Disable-InboxRule { [CmdletBinding()] param($Identity, $Mailbox) Write-FakeExoLog -Data @{ Kind = 'Write'; Command = 'Disable-InboxRule' } }
function Set-Mailbox { [CmdletBinding()] param($Identity) Write-FakeExoLog -Data @{ Kind = 'Write'; Command = 'Set-Mailbox' } }
Export-ModuleMember -Function Get-Mailbox, Get-InboxRule, Set-InboxRule, Remove-InboxRule, Disable-InboxRule, Set-Mailbox
'@
        New-ModuleManifest -Path (Join-Path $dir "$Name.psd1") -RootModule "$Name.psm1" -ModuleVersion '1.0.0' `
            -FunctionsToExport @('Get-Mailbox', 'Get-InboxRule', 'Set-InboxRule', 'Remove-InboxRule', 'Disable-InboxRule', 'Set-Mailbox')
        Join-Path $dir "$Name.psd1"
    }

    $script:exoRoot = Join-Path $script:workRoot 'fakemodules'
    $script:exoManifest = Get-FakeExoModuleManifest -Root $script:exoRoot -Name 'ExchangeOnlineManagement'
    $script:onPremManifest = Get-FakeExoModuleManifest -Root $script:exoRoot -Name 'tmp_securitycompliance_proxy'

    function Get-SetupText {
        <#
        .SYNOPSIS
        Compose the child-process setup: logs, Graph stub, Exchange data and module, and any extra lines.
        #>
        param([string]$Tag, [ValidateSet('ExchangeOnline', 'None', 'Other')][string]$Exchange = 'ExchangeOnline', [string]$Extra = '')
        $log = Join-Path $script:workRoot "$Tag.log"
        $secretLog = Join-Path $script:workRoot "$Tag.secret.log"
        $lines = @(
            "`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'"
            "`$env:OPSTOOLKIT_TEST_SECRET_LOG = '$secretLog'"
            $script:graphStub
            $script:exoData
        )
        if ($Exchange -eq 'ExchangeOnline') { $lines += "Import-Module '$($script:exoManifest)' -Force -Global" }
        if ($Exchange -eq 'Other') { $lines += "Import-Module '$($script:onPremManifest)' -Force -Global" }
        $lines += $Extra
        $lines -join "`n"
    }

    function Get-LogRecord {
        <#
        .SYNOPSIS
        Read the events a run logged, in order.
        #>
        param([string]$Tag)
        $path = Join-Path $script:workRoot "$Tag.log"
        if (-not (Test-Path -LiteralPath $path)) { return @() }
        @(Get-Content -LiteralPath $path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }

    function Get-WriteRecord {
        <#
        .SYNOPSIS
        Read only the write attempts a run logged.
        #>
        param([string]$Tag)
        @(Get-LogRecord -Tag $Tag | Where-Object { $_.Kind -eq 'Write' })
    }

    function Get-SecretRecord {
        <#
        .SYNOPSIS
        Read the real generated passwords the Graph stub received.
        #>
        param([string]$Tag)
        $path = Join-Path $script:workRoot "$Tag.secret.log"
        if (-not (Test-Path -LiteralPath $path)) { return @() }
        @(Get-Content -LiteralPath $path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    }

    function Get-StateResult {
        <#
        .SYNOPSIS
        Return the Result of one action for one user from a state CSV.
        #>
        param([object[]]$Row, [string]$Upn, [string]$Action)
        $match = @($Row | Where-Object { $_.UserPrincipalName -eq $Upn -and $_.Action -eq $Action })
        if ($match.Count -ne 1) { return "<$($match.Count) rows>" }
        $match[0].Result
    }

    function Invoke-Containment {
        <#
        .SYNOPSIS
        Run the script once under the stubs and return the run record with its tag.
        #>
        param(
            [string]$Tag,
            [hashtable]$Argument,
            [ValidateSet('ExchangeOnline', 'None', 'Other')][string]$Exchange = 'ExchangeOnline',
            [string]$Extra = '',
            [string]$ReportName = ''
        )
        $reportDirectory = Join-Path $script:workRoot $(if ($ReportName) { $ReportName } else { $Tag })
        $arguments = @{ ReportDirectory = $reportDirectory } + $Argument
        $run = Invoke-ScriptUnderTest -RelativePath $script:scriptPath -Setup (Get-SetupText -Tag $Tag -Exchange $Exchange -Extra $Extra) -Argument $arguments
        $run | Add-Member -NotePropertyName Tag -NotePropertyValue $Tag -PassThru
    }

    function Assert-SecretAbsent {
        <#
        .SYNOPSIS
        Fail if any secret appears in the text of any file under a directory.
        #>
        param([string]$Directory, [string[]]$Secret)
        $files = @(Get-ChildItem -LiteralPath $Directory -Recurse -File)
        $files.Count | Should -BeGreaterThan 6 -Because 'a search over an empty directory proves nothing'
        foreach ($file in $files) {
            $text = "$(Get-Content -LiteralPath $file.FullName -Raw)"
            foreach ($value in $Secret) {
                $text.Contains($value) | Should -BeFalse -Because "$($file.Name) must not contain a generated password"
            }
        }
    }

    # Paired runs against the same fixture.
    $script:whatIfRun = Invoke-Containment -Tag 'whatif' -Argument @{ UserPrincipalName = $script:allUpn; WhatIf = $true }
    $script:executeRun = Invoke-Containment -Tag 'execute' -Argument @{ UserPrincipalName = $script:allUpn; Confirm = $false }

    # Password runs.
    $script:resetRun = Invoke-Containment -Tag 'reset' -Argument @{ UserPrincipalName = $script:allUpn; ResetPassword = $true; Confirm = $false }
    $script:resetWhatIfRun = Invoke-Containment -Tag 'resetwhatif' -Argument @{ UserPrincipalName = $script:allUpn; ResetPassword = $true; WhatIf = $true }
    $script:resetEchoRun = Invoke-Containment -Tag 'resetecho' -Extra '$global:EchoBodyOnPasswordFailure = $true' `
        -Argument @{ UserPrincipalName = 'norules@contoso.com'; ResetPassword = $true; Confirm = $false }

    # Exchange availability.
    $script:noExoRun = Invoke-Containment -Tag 'noexo' -Exchange None -Argument @{ UserPrincipalName = $script:allUpn; Confirm = $false }
    $script:otherExoRun = Invoke-Containment -Tag 'otherexo' -Exchange Other -Argument @{ UserPrincipalName = $script:allUpn; Confirm = $false }

    # Export only, and a comma-joined list as the evidence pack's launcher passes it.
    $script:exportOnlyRun = Invoke-Containment -Tag 'exportonly' -Argument @{ UserPrincipalName = ($script:allUpn -join ','); ExportOnly = $true; Confirm = $false }

    # A write that fails must not read as Done.
    $script:failRun = Invoke-Containment -Tag 'failwrite' -Extra '$global:FailDisableFor = ''id-cloud-on''' `
        -Argument @{ UserPrincipalName = @('cloud.on@contoso.com', 'norules@contoso.com'); Confirm = $false }

    # Nothing left after splitting.
    $script:emptyRun = Invoke-Containment -Tag 'empty' -Argument @{ UserPrincipalName = ' , ,'; Confirm = $false }

    # Rollback. The fixture is changed so the three accounts the executing run disabled are
    # disabled now, as they would be after that run; cloud.off was disabled before it began.
    $script:disabledNow = @'
foreach ($key in @('cloud.on@contoso.com', 'nomailbox@contoso.com', 'norules@contoso.com')) { $global:FakeGraphUsers[$key].accountEnabled = $false }
'@
    $script:rollbackRun = Invoke-Containment -Tag 'rollback' -Extra $script:disabledNow `
        -Argument @{ Rollback = $true; RollbackStatePath = $script:executeRun.Summary.RollbackJsonPath; Confirm = $false }
    $script:rollbackWhatIfRun = Invoke-Containment -Tag 'rollbackwhatif' -Extra $script:disabledNow `
        -Argument @{ Rollback = $true; RollbackStatePath = $script:executeRun.Summary.RollbackJsonPath; WhatIf = $true }

    # Default rollback selection: an executing run, then a newer -WhatIf run in the same
    # report directory. The newest file is the empty one, and it must be passed over.
    $script:pickExecute = Invoke-Containment -Tag 'pickexecute' -ReportName 'pick' -Argument @{ UserPrincipalName = 'cloud.on@contoso.com'; Confirm = $false }
    $script:pickWhatIf = Invoke-Containment -Tag 'pickwhatif' -ReportName 'pick' -Argument @{ UserPrincipalName = 'cloud.on@contoso.com'; WhatIf = $true }
    $script:pickRollback = Invoke-Containment -Tag 'pickrollback' -ReportName 'pick' -Extra $script:disabledNow `
        -Argument @{ Rollback = $true; Confirm = $false }

    $script:whatIfState = if ($script:whatIfRun.Summary) { @(Import-Csv $script:whatIfRun.Summary.StateCsvPath) } else { @() }
    $script:executeState = if ($script:executeRun.Summary) { @(Import-Csv $script:executeRun.Summary.StateCsvPath) } else { @() }
}

AfterAll {
    if ($script:workRoot -and (Test-Path $script:workRoot)) {
        Remove-Item $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-EntraUserContainment' {
    It 'runs to completion in both modes' {
        $script:whatIfRun.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:whatIfRun.Output)"
        $script:executeRun.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:executeRun.Output)"
    }

    Context 'WhatIf and execute pair' {
        It 'attempts no write under -WhatIf' {
            $writes = Get-WriteRecord -Tag 'whatif'
            $writes.Count | Should -Be 0 -Because "-WhatIf attempted: $($writes | ConvertTo-Json -Compress -Depth 5)"
            @($script:whatIfState | Where-Object { $_.Action -in 'RevokeSessions', 'DisableAccount' -and $_.Result -eq 'Done' }).Count | Should -Be 0
            $script:whatIfRun.Summary.PreviewedCount | Should -Be 8
        }

        It 'still writes the plan, the state and the exports under -WhatIf' {
            foreach ($name in 'containment-plan', 'containment-state', 'inbox-rules', 'mailbox-forwarding') {
                Test-Path (Join-Path $script:whatIfRun.Summary.RunDirectory "$name.csv") | Should -BeTrue -Because "$name.csv must exist"
                Test-Path (Join-Path $script:whatIfRun.Summary.RunDirectory "$name.json") | Should -BeTrue -Because "$name.json must exist"
            }
            Test-Path (Join-Path $script:whatIfRun.Summary.RunDirectory 'summary.json') | Should -BeTrue
            $script:whatIfRun.Summary.RunDirectory | Should -Match 'entra-containment-\d{8}_\d{6}$'
            @(Import-Csv (Join-Path $script:whatIfRun.Summary.RunDirectory 'inbox-rules.csv')).Count | Should -Be 3
        }

        It 'plans the same writes under -WhatIf that the executing run attempts' {
            $planned = @(Import-Csv $script:whatIfRun.Summary.PlanCsvPath | Where-Object { $_.Result -eq 'Planned' -and $_.Action -in 'RevokeSessions', 'DisableAccount' })
            $planned.Count | Should -Be 8

            # Without this the -WhatIf assertion above proves nothing: a script that had
            # stopped working entirely would satisfy it perfectly.
            $writes = Get-WriteRecord -Tag 'execute'
            $writes.Count | Should -Be 8
            $script:executeRun.Summary.DoneCount | Should -BeGreaterOrEqual 8
        }

        It 'revokes five users and disables only the three enabled cloud accounts' {
            $writes = Get-WriteRecord -Tag 'execute'
            $revoked = @($writes | Where-Object { $_.Method -eq 'POST' -and $_.Path -like '*/revokeSignInSessions' } | ForEach-Object { $_.Path })
            $revoked.Count | Should -Be 5
            $disabled = @($writes | Where-Object { $_.Method -eq 'PATCH' } | ForEach-Object { $_.Path } | Sort-Object)
            $disabled | Should -Be @('/users/id-cloud-on', '/users/id-nomailbox', '/users/id-norules')
            foreach ($patch in @($writes | Where-Object { $_.Method -eq 'PATCH' })) {
                $patch.Body.accountEnabled | Should -BeFalse
            }
        }

        It 'attempts nothing for a NotFound user, a NotAssessed user, an already-disabled account, or a synced disable' {
            $writes = Get-WriteRecord -Tag 'execute'
            foreach ($forbidden in 'missing', 'denied', 'id-cloud-off/', 'id-synced/') {
                @($writes | Where-Object { $_.Path -like "*$forbidden*" -and $_.Method -eq 'PATCH' }).Count | Should -Be 0
            }
            @($writes | Where-Object { $_.Path -like '*missing*' -or $_.Path -like '*denied*' }).Count | Should -Be 0
            @($writes | Where-Object { $_.Path -eq '/users/id-cloud-off' }).Count | Should -Be 0
            @($writes | Where-Object { $_.Path -eq '/users/id-synced' }).Count | Should -Be 0
        }

        It 'still revokes sessions for the synced and the already-disabled users' {
            $writes = Get-WriteRecord -Tag 'execute'
            @($writes | Where-Object { $_.Path -eq '/users/id-synced/revokeSignInSessions' }).Count | Should -Be 1
            @($writes | Where-Object { $_.Path -eq '/users/id-cloud-off/revokeSignInSessions' }).Count | Should -Be 1
        }

        It 'reports each user and action with the right result' {
            $s = $script:executeState
            Get-StateResult $s 'cloud.on@contoso.com' 'RevokeSessions' | Should -Be 'Done'
            Get-StateResult $s 'cloud.on@contoso.com' 'DisableAccount' | Should -Be 'Done'
            Get-StateResult $s 'cloud.off@contoso.com' 'RevokeSessions' | Should -Be 'Done'
            Get-StateResult $s 'cloud.off@contoso.com' 'DisableAccount' | Should -Be 'AlreadyDisabled'
            Get-StateResult $s 'synced@contoso.com' 'RevokeSessions' | Should -Be 'Done'
            Get-StateResult $s 'synced@contoso.com' 'DisableAccount' | Should -Be 'RequiresOnPremises'
            Get-StateResult $s 'missing@contoso.com' 'Lookup' | Should -Be 'NotFound'
            Get-StateResult $s 'denied@contoso.com' 'Lookup' | Should -Be 'NotAssessed'
            Get-StateResult $s 'nomailbox@contoso.com' 'DisableAccount' | Should -Be 'Done'
            Get-StateResult $s 'norules@contoso.com' 'DisableAccount' | Should -Be 'Done'

            $w = $script:whatIfState
            Get-StateResult $w 'cloud.on@contoso.com' 'RevokeSessions' | Should -Be 'Previewed'
            Get-StateResult $w 'cloud.on@contoso.com' 'DisableAccount' | Should -Be 'Previewed'
            Get-StateResult $w 'synced@contoso.com' 'DisableAccount' | Should -Be 'RequiresOnPremises'
        }

        It 'tells the operator to disable a synced account in AD, and says why a user was skipped' {
            $script:executeRun.Summary.Status | Should -Be 'Incomplete'
            $script:executeRun.Summary.RequiresOnPremisesCount | Should -Be 1
            (@($script:executeRun.Summary.Findings) -join ' ') | Should -Match 'synced@contoso.com.*Active Directory.*scripts\\active-directory'
            (@($script:executeRun.Summary.Findings) -join ' ') | Should -Match 'missing@contoso.com'
            (@($script:executeRun.Summary.Findings) -join ' ') | Should -Match 'denied@contoso.com'
            $script:executeRun.Summary.NotFoundCount | Should -Be 1
            $script:executeRun.Summary.NotAssessedCount | Should -Be 1
        }
    }

    Context 'Exchange Online evidence' {
        It 'exports inbox rules and forwarding for users with mailboxes and says NoMailbox for the rest' {
            $s = $script:executeState
            Get-StateResult $s 'cloud.on@contoso.com' 'ExportInboxRules' | Should -Be 'Done'
            Get-StateResult $s 'cloud.on@contoso.com' 'ExportForwarding' | Should -Be 'Done'
            Get-StateResult $s 'norules@contoso.com' 'ExportInboxRules' | Should -Be 'Done'
            Get-StateResult $s 'nomailbox@contoso.com' 'ExportInboxRules' | Should -Be 'NoMailbox'
            Get-StateResult $s 'nomailbox@contoso.com' 'ExportForwarding' | Should -Be 'NoMailbox'
            $script:executeRun.Summary.NoMailboxCount | Should -Be 2

            $rules = @(Import-Csv $script:executeRun.Summary.InboxRulesCsvPath)
            $rules.Count | Should -Be 3
            ($rules | Where-Object { $_.UserPrincipalName -eq 'cloud.on@contoso.com' }).ForwardTo | Should -Be 'attacker@evil.example'
            ($rules | Where-Object { $_.UserPrincipalName -eq 'cloud.on@contoso.com' }).ForwardsOrRedirects | Should -Be 'True'
            ($rules | Where-Object { $_.UserPrincipalName -eq 'cloud.off@contoso.com' }).ForwardsOrRedirects | Should -Be 'False'

            $forwarding = @(Import-Csv $script:executeRun.Summary.ForwardingCsvPath)
            $forwarding.Count | Should -Be 4
            $on = $forwarding | Where-Object { $_.UserPrincipalName -eq 'cloud.on@contoso.com' }
            $on.ForwardingSmtpAddress | Should -Be 'fwd@evil.example'
            $on.DeliverToMailboxAndForward | Should -Be 'True'
            $none = $forwarding | Where-Object { $_.UserPrincipalName -eq 'norules@contoso.com' }
            $none.ForwardingAddress | Should -BeNullOrEmpty
            $none.HasForwarding | Should -Be 'False'
        }

        It 'reads the evidence before the first containment write and never changes a rule or a forward' {
            $events = Get-LogRecord -Tag 'execute'
            $lastRead = -1
            $firstWrite = -1
            for ($n = 0; $n -lt $events.Count; $n++) {
                if ($events[$n].Kind -eq 'Read') { $lastRead = $n }
                if ($events[$n].Kind -eq 'Write' -and $firstWrite -lt 0) { $firstWrite = $n }
            }
            $lastRead | Should -BeGreaterOrEqual 0
            $firstWrite | Should -BeGreaterThan $lastRead
            @($events | Where-Object { $_.Kind -eq 'Write' -and $_.Command }).Count | Should -Be 0
        }

        It 'runs the export under -WhatIf too' {
            @(Get-LogRecord -Tag 'whatif' | Where-Object { $_.Kind -eq 'Read' -and $_.Command -eq 'Get-Mailbox' }).Count | Should -Be 5
        }

        It 'reports the export NotAssessed with the Connect-ExchangeOnline instruction when there is no Exchange Online session, and still contains' {
            $run = $script:noExoRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            Get-StateResult $state 'cloud.on@contoso.com' 'ExportInboxRules' | Should -Be 'NotAssessed'
            Get-StateResult $state 'cloud.on@contoso.com' 'ExportForwarding' | Should -Be 'NotAssessed'
            (@($run.Summary.Findings) -join ' ') | Should -Match 'Connect-ExchangeOnline.*-ExportOnly'
            $run.Summary.Status | Should -Be 'Incomplete'
            @(Get-WriteRecord -Tag 'noexo').Count | Should -Be 8
            @(Import-Csv $run.Summary.InboxRulesCsvPath).Count | Should -Be 0
        }

        It 'does not trust an Exchange cmdlet that comes from a non-Exchange-Online module' {
            $run = $script:otherExoRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            Get-StateResult $state 'cloud.on@contoso.com' 'ExportInboxRules' | Should -Be 'NotAssessed'
            (@($run.Summary.Findings) -join ' ') | Should -Match 'tmp_securitycompliance_proxy'
            @(Get-LogRecord -Tag 'otherexo' | Where-Object { $_.Kind -eq 'Read' }).Count | Should -Be 0 -Because 'the untrusted cmdlet must not be called'
            @(Get-WriteRecord -Tag 'otherexo').Count | Should -Be 8
        }

        It 'with -ExportOnly attempts no write and still exports' {
            $run = $script:exportOnlyRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            Get-WriteRecord -Tag 'exportonly' | Should -HaveCount 0
            @(Import-Csv $run.Summary.InboxRulesCsvPath).Count | Should -Be 3
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            @($state | Where-Object { $_.Action -in 'RevokeSessions', 'DisableAccount', 'ResetPassword' }).Count | Should -Be 0
            Get-StateResult $state 'cloud.on@contoso.com' 'ExportInboxRules' | Should -Be 'Done'
            Get-StateResult $state 'missing@contoso.com' 'Lookup' | Should -Be 'NotFound'
        }
    }

    Context 'Password reset' {
        It 'writes a password PATCH only for the non-synced users, with force-change set' {
            $script:resetRun.ExitCode | Should -Be 0 -Because $script:resetRun.Output
            $writes = Get-WriteRecord -Tag 'reset'
            $resets = @($writes | Where-Object { $_.Body -and $_.Body.passwordProfile })
            $resets.Count | Should -Be 4
            @($resets | ForEach-Object { $_.Path.Replace('/users/', '') } | Sort-Object) | Should -Be @($script:cloudIds | Sort-Object)
            foreach ($reset in $resets) { $reset.Body.passwordProfile.forceChangePasswordNextSignIn | Should -BeTrue }
            Get-StateResult @(Import-Csv $script:resetRun.Summary.StateCsvPath) 'synced@contoso.com' 'ResetPassword' | Should -Be 'RequiresOnPremises'
            Get-StateResult @(Import-Csv $script:resetRun.Summary.StateCsvPath) 'cloud.on@contoso.com' 'ResetPassword' | Should -Be 'Done'
        }

        It 'generates a distinct, complex password per user and shows each once on the console' {
            $secrets = @(Get-SecretRecord -Tag 'reset')
            $secrets.Count | Should -Be 4
            @($secrets | ForEach-Object { $_.Password } | Select-Object -Unique).Count | Should -Be 4
            foreach ($secret in $secrets) {
                $secret.Password.Length | Should -BeGreaterOrEqual 20
                $secret.Password | Should -MatchExactly '[A-Z]'
                $secret.Password | Should -MatchExactly '[a-z]'
                $secret.Password | Should -MatchExactly '[0-9]'
                $secret.Password | Should -MatchExactly '[^A-Za-z0-9]'
                ([regex]::Matches($script:resetRun.Output, [regex]::Escape($secret.Password))).Count | Should -Be 1
            }
            $script:resetRun.Output | Should -Match 'TEMPORARY PASSWORD for cloud\.on@contoso\.com'
        }

        It 'puts the generated password in no file the script wrote, and not in the returned summary' {
            $secrets = @(Get-SecretRecord -Tag 'reset' | ForEach-Object { $_.Password })
            $secrets.Count | Should -Be 4
            Assert-SecretAbsent -Directory $script:resetRun.Summary.RunDirectory -Secret $secrets
            $summaryText = $script:resetRun.Summary | ConvertTo-Json -Depth 10
            foreach ($secret in $secrets) { $summaryText.Contains($secret) | Should -BeFalse }
            # The log the stub keeps must carry only the marker, which is what the writes recorded.
            (Get-Content -LiteralPath (Join-Path $script:workRoot 'reset.log') -Raw) | Should -Match '<GENERATED-PASSWORD>'
        }

        It 'generates and shows no password under -WhatIf and attempts no write' {
            $script:resetWhatIfRun.ExitCode | Should -Be 0 -Because $script:resetWhatIfRun.Output
            Get-WriteRecord -Tag 'resetwhatif' | Should -HaveCount 0
            @(Get-SecretRecord -Tag 'resetwhatif').Count | Should -Be 0
            $script:resetWhatIfRun.Output | Should -Not -Match 'TEMPORARY PASSWORD'
            Get-StateResult @(Import-Csv $script:resetWhatIfRun.Summary.StateCsvPath) 'cloud.on@contoso.com' 'ResetPassword' | Should -Be 'Previewed'
        }

        It 'attempts no password write without -ResetPassword' {
            $writes = Get-WriteRecord -Tag 'execute'
            @($writes | Where-Object { $_.Body -and $_.Body.passwordProfile }).Count | Should -Be 0
            @($script:executeState | Where-Object { $_.Action -eq 'ResetPassword' }).Count | Should -Be 0
            @(Get-SecretRecord -Tag 'execute').Count | Should -Be 0
        }

        It 'redacts the password from an error that echoes the request body, and reports the reset Failed' {
            $run = $script:resetEchoRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            $secret = @(Get-SecretRecord -Tag 'resetecho')
            $secret.Count | Should -Be 1
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            $result = Get-StateResult $state 'norules@contoso.com' 'ResetPassword'
            $result | Should -Match '^Failed:'
            $result | Should -Match '\[redacted\]'
            Assert-SecretAbsent -Directory $run.Summary.RunDirectory -Secret @($secret[0].Password)
            # A failed reset must not print a password that was never set.
            $run.Output | Should -Not -Match 'TEMPORARY PASSWORD'
        }
    }

    Context 'Failures and refusals' {
        It 'reports a failed disable as Failed, not Done, and does not offer it for rollback' {
            $run = $script:failRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            Get-StateResult $state 'cloud.on@contoso.com' 'DisableAccount' | Should -Match '^Failed:'
            Get-StateResult $state 'norules@contoso.com' 'DisableAccount' | Should -Be 'Done'
            $run.Summary.FailedCount | Should -Be 1
            $run.Summary.Status | Should -Be 'Incomplete'
            $rollback = Get-Content -LiteralPath $run.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
            @($rollback.Entries | Where-Object { $_.DisabledByScript }).UserPrincipalName | Should -Be 'norules@contoso.com'
        }

        It 'refuses before any write when nothing remains after splitting -UserPrincipalName' {
            $script:emptyRun.ExitCode | Should -Not -Be 0
            $script:emptyRun.Output | Should -Match 'No user principal names remain'
            Get-WriteRecord -Tag 'empty' | Should -HaveCount 0
            @(Get-LogRecord -Tag 'empty').Count | Should -Be 0
        }

        It 'splits a comma-joined -UserPrincipalName into every user' {
            $script:exportOnlyRun.Summary.UserCount | Should -Be 7
        }
    }

    Context 'Rollback' {
        It 'records the prior state and which accounts the run disabled' {
            $rollback = Get-Content -LiteralPath $script:executeRun.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
            $rollback.Mode | Should -Be 'Contain'
            @($rollback.Entries | Where-Object { $_.DisabledByScript } | ForEach-Object { $_.UserPrincipalName } | Sort-Object) |
                Should -Be @('cloud.on@contoso.com', 'nomailbox@contoso.com', 'norules@contoso.com')
            ($rollback.Entries | Where-Object { $_.UserPrincipalName -eq 'cloud.off@contoso.com' -and $_.Action -eq 'DisableAccount' }).DisabledByScript | Should -BeFalse
            ($rollback.Entries | Where-Object { $_.Action -eq 'RevokeSessions' } | Select-Object -First 1).Reversible | Should -Be 'No'
        }

        It 're-enables only the accounts the run disabled, never the one already disabled before it' {
            $run = $script:rollbackRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            $writes = Get-WriteRecord -Tag 'rollback'
            @($writes | ForEach-Object { $_.Path } | Sort-Object) | Should -Be @('/users/id-cloud-on', '/users/id-nomailbox', '/users/id-norules')
            foreach ($write in $writes) {
                $write.Method | Should -Be 'PATCH'
                $write.Body.accountEnabled | Should -BeTrue
            }
            $run.Summary.RolledBackCount | Should -Be 3
            $state = @(Import-Csv $run.Summary.StateCsvPath)
            ($state | Where-Object { $_.UserPrincipalName -eq 'cloud.off@contoso.com' -and $_.Action -eq 'EnableAccount' }).Result | Should -Be 'Skipped'
            ($state | Where-Object { $_.UserPrincipalName -eq 'cloud.off@contoso.com' -and $_.Action -eq 'EnableAccount' }).Detail | Should -Match 'did not disable'
            @($state | Where-Object { $_.Action -eq 'RollbackRevokeSessions' } | ForEach-Object { $_.Result } | Select-Object -Unique) | Should -Be 'Skipped'
            @($writes | Where-Object { $_.Body -and $_.Body.passwordProfile }).Count | Should -Be 0
        }

        It 'attempts no write when the rollback runs under -WhatIf' {
            $run = $script:rollbackWhatIfRun
            $run.ExitCode | Should -Be 0 -Because $run.Output
            Get-WriteRecord -Tag 'rollbackwhatif' | Should -HaveCount 0
            $run.Summary.PreviewedCount | Should -Be 3
        }

        It 'selects the newest run that disabled an account, passing over a newer -WhatIf run' {
            $script:pickExecute.ExitCode | Should -Be 0 -Because $script:pickExecute.Output
            $script:pickWhatIf.ExitCode | Should -Be 0 -Because $script:pickWhatIf.Output
            $script:pickRollback.ExitCode | Should -Be 0 -Because $script:pickRollback.Output
            $script:pickWhatIf.Summary.RunDirectory | Should -Not -Be $script:pickExecute.Summary.RunDirectory
            $script:pickRollback.Summary.RollbackSourcePath | Should -Be $script:pickExecute.Summary.RollbackJsonPath
            @(Get-WriteRecord -Tag 'pickrollback').Count | Should -Be 1
        }
    }
}
