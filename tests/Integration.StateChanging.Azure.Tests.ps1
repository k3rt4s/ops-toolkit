#Requires -Modules Pester

# The five Azure scripts that create or change something: a VPN profile on disk, a
# signed-in session, a mapped drive backed by a stored credential, a service principal
# with a generated secret, and an application gateway TLS policy.
#
# Same two-run shape as the other state-changing specs. What is different here is that
# two of them handle secrets, so alongside "-WhatIf changed nothing" these assert that
# a storage account key and a generated client secret never reach a report file. That
# is a standing rule for this repository, and it is the kind of rule that is only ever
# broken by accident.
#
# Az.Network, Az.Resources, and Az.KeyVault are not installed here, and Az.Accounts is.
# Placeholder modules are staged under all four names so #Requires is satisfied and the
# real Az.Accounts is never loaded, leaving the setup block's stubs in charge.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:azModulePath = Use-FakePlaceholderModule -Name @('Az.Accounts', 'Az.Resources', 'Az.KeyVault', 'Az.Network')
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-az-$([guid]::NewGuid().ToString('N'))"
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

    function Get-ReportText {
        <#
        .SYNOPSIS
        Return every report file a run wrote, concatenated, for secret-leak assertions.

        .DESCRIPTION
        Reads whatever is in the directory rather than the paths the summary names, so
        a secret written to a file the summary forgot to mention is still caught.
        #>
        param([string]$Directory)
        if (-not (Test-Path -LiteralPath $Directory)) { return '' }
        (Get-ChildItem -LiteralPath $Directory -Recurse -File | Get-Content -Raw) -join "`n"
    }
}

AfterAll {
    foreach ($p in $script:azModulePath, $script:workRoot) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'New-AzFileShareMappedDrive' {
    BeforeAll {
        # A key shaped like a real one, distinctive enough to grep for.
        $script:storageKey = 'ZmFrZWtleUZPUlRFU1RJTkdPTkxZbm90YXJlYWxzZWNyZXQxMjM0NTY3ODkwPT0='

        function New-DriveRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            $reports = Join-Path $script:workRoot "$Tag-reports"
            $setup = @"
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Write-OpsTestMutation {
    param([string]`$Command, [string]`$Target)
    Add-Content -LiteralPath '$log' -Encoding utf8 -Value ([pscustomobject]@{ Command = `$Command; Target = `$Target } | ConvertTo-Json -Compress)
}
function cmdkey.exe { Write-OpsTestMutation -Command 'cmdkey.exe' -Target (`$args -join ' ') }
function New-PSDrive { param(`$Name, `$PSProvider, `$Root, [switch]`$Persist, `$Credential, `$Scope) Write-OpsTestMutation -Command 'New-PSDrive' -Target "`$Name=`$Root" }
function Remove-PSDrive { param(`$Name, [switch]`$Force) Write-OpsTestMutation -Command 'Remove-PSDrive' -Target ([string]`$Name) }
function Get-PSDrive { param(`$Name, `$ErrorAction) }
"@
            $argument = @{
                Action             = 'Map'
                DriveLetter        = 'Z'
                StorageAccountName = 'examplestorage'
                ShareName          = 'data'
                StorageAccountKey  = $script:storageKey
                ReportDirectory    = $reports
            } + $Extra

            [pscustomobject]@{
                Run       = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\New-AzFileShareMappedDrive.ps1' `
                    -Setup $setup -ModulePath $script:azModulePath -Argument $argument
                Log       = $log
                Reports   = $reports
            }
        }

        $script:driveWhatIf = New-DriveRun -Tag 'drive-whatif' -Extra @{ WhatIf = $true }
        $script:driveExecute = New-DriveRun -Tag 'drive-execute' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:driveWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:driveWhatIf.Run.Output)"
        $script:driveExecute.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:driveExecute.Run.Output)"
    }

    It 'stores no credential and maps no drive under -WhatIf' {
        $mutations = @(Get-MutationRecord -Path $script:driveWhatIf.Log)
        $mutations.Count | Should -Be 0 -Because "-WhatIf attempted: $($mutations | ConvertTo-Json -Compress)"
    }

    It 'stores the credential and maps the drive when executing' {
        $mutations = @(Get-MutationRecord -Path $script:driveExecute.Log)
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'cmdkey.exe'
        @($mutations | ForEach-Object { $_.Command }) | Should -Contain 'New-PSDrive'
    }

    It 'never writes the storage account key into a report' {
        # The key is a credential for the whole storage account, not just the share.
        # A report is the artifact most likely to be mailed, committed, or attached to
        # a ticket, so this is the one place it must never appear.
        foreach ($run in $script:driveWhatIf, $script:driveExecute) {
            $text = Get-ReportText -Directory $run.Reports
            $text | Should -Not -BeNullOrEmpty -Because 'the run should have written reports to assert against'
            $text | Should -Not -Match ([regex]::Escape($script:storageKey))
        }

        # And it says so explicitly, so a reader does not have to take it on trust.
        $script:driveExecute.Run.Summary.StorageAccountKeyWrittenToReports | Should -BeFalse
    }
}

Describe 'New-AzKeyVaultServicePrincipal' {
    BeforeAll {
        $script:generatedSecret = 'FAKE-CLIENT-SECRET-vB7q2Xn9LmPd4KtZ-NOT-REAL'

        function New-SpRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            $reports = Join-Path $script:workRoot "$Tag-reports"
            $setup = @"
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Write-OpsTestMutation {
    param([string]`$Command, [string]`$Target)
    Add-Content -LiteralPath '$log' -Encoding utf8 -Value ([pscustomobject]@{ Command = `$Command; Target = `$Target } | ConvertTo-Json -Compress)
}
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' }; Tenant = [pscustomobject]@{ Id = 'tenant-1' } } }
function Set-AzContext { param(`$SubscriptionId, `$TenantId) }
function Connect-AzAccount { param(`$Tenant, `$Subscription, `$Environment) Write-OpsTestMutation -Command 'Connect-AzAccount' -Target 'interactive' }
function Get-AzADServicePrincipal { param(`$DisplayName, `$ErrorAction) }
function New-AzADServicePrincipal {
    param(`$DisplayName, `$EndDate, `$StartDate)
    Write-OpsTestMutation -Command 'New-AzADServicePrincipal' -Target ([string]`$DisplayName)
    [pscustomobject]@{
        Id = 'sp-object-id'; AppId = 'app-id-guid'; DisplayName = `$DisplayName
        Secret = (ConvertTo-SecureString '$($script:generatedSecret)' -AsPlainText -Force)
    }
}
function Remove-AzADServicePrincipal { param(`$ObjectId, [switch]`$Force) Write-OpsTestMutation -Command 'Remove-AzADServicePrincipal' -Target ([string]`$ObjectId) }
function Set-AzKeyVaultAccessPolicy {
    param(`$VaultName, `$ResourceGroupName, `$ObjectId, `$PermissionsToCertificates, `$PermissionsToSecrets, `$PermissionsToKeys)
    Write-OpsTestMutation -Command 'Set-AzKeyVaultAccessPolicy' -Target ([string]`$VaultName)
}
function Remove-AzKeyVaultAccessPolicy { param(`$VaultName, `$ObjectId) Write-OpsTestMutation -Command 'Remove-AzKeyVaultAccessPolicy' -Target ([string]`$VaultName) }
"@
            $argument = @{
                DisplayName            = 'test-app-serviceprincipal'
                KeyVaultName           = 'kv-test'
                SecretPermissions      = @('Get')
                ReportDirectory        = $reports
            } + $Extra

            [pscustomobject]@{
                Run     = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\New-AzKeyVaultServicePrincipal.ps1' `
                    -Setup $setup -ModulePath $script:azModulePath -Argument $argument
                Log     = $log
                Reports = $reports
            }
        }

        $script:spWhatIf = New-SpRun -Tag 'sp-whatif' -Extra @{ WhatIf = $true }
        $script:spExecute = New-SpRun -Tag 'sp-execute' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:spWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:spWhatIf.Run.Output)"
        $script:spExecute.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:spExecute.Run.Output)"
    }

    It 'creates no identity under -WhatIf' {
        # A service principal created by a preview run is a live credential nobody
        # knows exists.
        @(Get-MutationRecord -Path $script:spWhatIf.Log |
                Where-Object { $_.Command -eq 'New-AzADServicePrincipal' }).Count | Should -Be 0
    }

    It 'creates the principal and grants the vault policy when executing' {
        $commands = @(Get-MutationRecord -Path $script:spExecute.Log | ForEach-Object { $_.Command })
        $commands | Should -Contain 'New-AzADServicePrincipal'
        $commands | Should -Contain 'Set-AzKeyVaultAccessPolicy'
    }

    It 'never writes the generated client secret into a report' {
        # The header promises this in writing. It is worth a test precisely because
        # nothing about a passing run would reveal the breach.
        foreach ($run in $script:spWhatIf, $script:spExecute) {
            $text = Get-ReportText -Directory $run.Reports
            $text | Should -Not -BeNullOrEmpty -Because 'the run should have written reports to assert against'
            $text | Should -Not -Match ([regex]::Escape($script:generatedSecret))
        }
    }

    It 'records where the secret went rather than staying silent about it' {
        # Without -ShowGeneratedSecret the secret is neither displayed nor stored, and
        # the plan has to say which, or the operator cannot tell whether they have just
        # lost the only copy. The disposition is recorded in the plan file rather than
        # the returned summary.
        $plan = Get-Content -LiteralPath $script:spExecute.Run.Summary.PlanPath -Raw | ConvertFrom-Json
        $plan.ClientSecretStorage | Should -Be 'NotDisplayedOrStored'
    }
}

Describe 'Set-AzAppGatewayTlsPolicy' {
    BeforeAll {
        function New-GatewayRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            $reports = Join-Path $script:workRoot "$Tag-reports"
            $setup = @"
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Write-OpsTestMutation {
    param([string]`$Command, [string]`$Target)
    Add-Content -LiteralPath '$log' -Encoding utf8 -Value ([pscustomobject]@{ Command = `$Command; Target = `$Target } | ConvertTo-Json -Compress)
}
function Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' } } }
function Connect-AzAccount { Write-OpsTestMutation -Command 'Connect-AzAccount' -Target 'interactive' }
function Get-AzApplicationGateway {
    param(`$Name, `$ResourceGroupName)
    [pscustomobject]@{ Name = `$Name; ResourceGroupName = `$ResourceGroupName
        SslPolicy = [pscustomobject]@{ PolicyType = 'Predefined'; PolicyName = 'AppGwSslPolicy20150501'; MinProtocolVersion = 'TLSv1_0'; CipherSuites = @(); DisabledSslProtocols = @() } }
}
function Get-AzApplicationGatewaySslPolicy { param(`$ApplicationGateway) `$ApplicationGateway.SslPolicy }
function Set-AzApplicationGatewaySslPolicy {
    param(`$ApplicationGateway, `$PolicyType, `$PolicyName, `$MinProtocolVersion, `$CipherSuite)
    Write-OpsTestMutation -Command 'Set-AzApplicationGatewaySslPolicy' -Target "`$PolicyType/`$MinProtocolVersion"
    `$ApplicationGateway
}
function Set-AzApplicationGateway { param(`$ApplicationGateway) Write-OpsTestMutation -Command 'Set-AzApplicationGateway' -Target ([string]`$ApplicationGateway.Name) }
"@
            $argument = @{
                ResourceGroupName      = 'rg-edge'
                ApplicationGatewayName = 'agw-prod'
                ReportDirectory        = $reports
            } + $Extra

            [pscustomobject]@{
                Run = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Set-AzAppGatewayTlsPolicy.ps1' `
                    -Setup $setup -ModulePath $script:azModulePath -Argument $argument
                Log = $log
            }
        }

        $script:gwWhatIf = New-GatewayRun -Tag 'gw-whatif' -Extra @{ WhatIf = $true }
        $script:gwExecute = New-GatewayRun -Tag 'gw-execute' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:gwWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:gwWhatIf.Run.Output)"
        $script:gwExecute.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:gwExecute.Run.Output)"
    }

    It 'commits nothing to the gateway under -WhatIf' {
        # Set-AzApplicationGateway is the commit. Everything before it is local object
        # editing, so this is the single call that must not happen on a preview.
        @(Get-MutationRecord -Path $script:gwWhatIf.Log |
                Where-Object { $_.Command -eq 'Set-AzApplicationGateway' }).Count | Should -Be 0
    }

    It 'commits the hardened policy when executing' {
        $commands = @(Get-MutationRecord -Path $script:gwExecute.Log | ForEach-Object { $_.Command })
        $commands | Should -Contain 'Set-AzApplicationGateway'
    }
}

Describe 'Import-AzureVpnClientXmlProfile' {
    BeforeAll {
        $script:profileSource = Join-Path $script:workRoot 'profile.xml'
        Set-Content -LiteralPath $script:profileSource -Value '<AzVpnProfile><name>test</name></AzVpnProfile>' -Encoding utf8

        # A real command file rather than a function stub. The script resolves its
        # command with Get-Command and then uses the .Source property, which is empty
        # for a function, so a function stub resolves to an empty string and the
        # invocation fails. Only something with a path on disk stands in here.
        $script:vpnCommand = Join-Path $script:workRoot 'azurevpn.cmd'
        Set-Content -LiteralPath $script:vpnCommand -Encoding ascii -Value @(
            '@echo off'
            'echo azurevpn %* >> "%OPSTOOLKIT_TEST_MUTATION_LOG%.cmd.txt"'
        )

        function New-VpnRun {
            param([string]$Tag, [hashtable]$Extra = @{})

            $log = Join-Path $script:workRoot "$Tag.log"
            $userProfile = Join-Path $script:workRoot "$Tag-userprofile"
            New-Item -ItemType Directory -Path $userProfile -Force | Out-Null

            $setup = @"
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Write-OpsTestMutation {
    param([string]`$Command, [string]`$Target)
    Add-Content -LiteralPath '$log' -Encoding utf8 -Value ([pscustomobject]@{ Command = `$Command; Target = `$Target } | ConvertTo-Json -Compress)
}
function azurevpn { Write-OpsTestMutation -Command 'azurevpn' -Target (`$args -join ' ') }
"@
            $argument = @{
                ProfileXmlPath  = $script:profileSource
                UserProfilePath = $userProfile
                AzureVpnCommand = $script:vpnCommand
                ReportDirectory = (Join-Path $script:workRoot "$Tag-reports")
            } + $Extra

            [pscustomobject]@{
                Run         = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Import-AzureVpnClientXmlProfile.ps1' `
                    -Setup $setup -ModulePath $script:azModulePath -Argument $argument
                Log         = $log
                UserProfile = $userProfile
            }
        }

        $script:vpnWhatIf = New-VpnRun -Tag 'vpn-whatif' -Extra @{ WhatIf = $true }
        $script:vpnExecute = New-VpnRun -Tag 'vpn-execute' -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:vpnWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:vpnWhatIf.Run.Output)"
        $script:vpnExecute.Run.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:vpnExecute.Run.Output)"
    }

    It 'writes nothing into the user profile under -WhatIf' {
        # This is checked on the file system rather than through a stub, because the
        # change this script makes is a file appearing in a real directory.
        @(Get-ChildItem -LiteralPath $script:vpnWhatIf.UserProfile -Recurse -File).Count |
            Should -Be 0 -Because '-WhatIf must not stage the profile'
    }

    It 'stages the profile when executing' {
        @(Get-ChildItem -LiteralPath $script:vpnExecute.UserProfile -Recurse -File).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Initialize-AzPowerShellSession' {
    BeforeAll {
        function New-SessionRun {
            param([string]$Tag, [hashtable]$Extra = @{}, [switch]$AlreadySignedIn)

            $log = Join-Path $script:workRoot "$Tag.log"
            # Environment is read as well as Subscription and Tenant. A context object
            # missing it is not a shape Az ever returns, and leaving it out only proves
            # that strict mode throws on a property read through nothing.
            $context = if ($AlreadySignedIn) {
                "[pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'Contoso' }; Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Account = [pscustomobject]@{ Id = 'me@test' }; Environment = [pscustomobject]@{ Name = 'AzureCloud' } }"
            } else {
                '$null'
            }

            $setup = @"
`$env:OPSTOOLKIT_TEST_MUTATION_LOG = '$log'
function Write-OpsTestMutation {
    param([string]`$Command, [string]`$Target)
    Add-Content -LiteralPath '$log' -Encoding utf8 -Value ([pscustomobject]@{ Command = `$Command; Target = `$Target } | ConvertTo-Json -Compress)
}
function Get-AzContext { $context }
function Set-AzContext { param(`$SubscriptionId, `$TenantId) Write-OpsTestMutation -Command 'Set-AzContext' -Target ([string]`$SubscriptionId) }
function Connect-AzAccount {
    param(`$Tenant, `$Subscription, `$Environment, [switch]`$UseDeviceAuthentication)
    Write-OpsTestMutation -Command 'Connect-AzAccount' -Target ([string]`$Tenant)
}
"@
            $argument = @{ ReportDirectory = (Join-Path $script:workRoot "$Tag-reports") } + $Extra

            [pscustomobject]@{
                Run = Invoke-ScriptUnderTest -RelativePath 'scripts\azure\Initialize-AzPowerShellSession.ps1' `
                    -Setup $setup -ModulePath $script:azModulePath -Argument $argument
                Log = $log
            }
        }

        $script:sessionWhatIf = New-SessionRun -Tag 'session-whatif' -Extra @{ WhatIf = $true }
        $script:sessionSignedIn = New-SessionRun -Tag 'session-signedin' -AlreadySignedIn -Extra @{ Confirm = $false }
    }

    It 'runs to completion in both modes' {
        $script:sessionWhatIf.Run.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:sessionWhatIf.Run.Output)"
        $script:sessionSignedIn.Run.ExitCode | Should -Be 0 -Because "the signed-in run failed: $($script:sessionSignedIn.Run.Output)"
    }

    It 'starts no sign-in under -WhatIf' {
        # An interactive sign-in from a preview run is a browser window nobody asked
        # for, and on a shared or automated host it simply hangs.
        @(Get-MutationRecord -Path $script:sessionWhatIf.Log |
                Where-Object { $_.Command -eq 'Connect-AzAccount' }).Count | Should -Be 0
    }

    It 'does not sign in again when a session already exists' {
        # Reconnecting an existing session is the difference between a script you can
        # put at the top of another script and one you cannot.
        @(Get-MutationRecord -Path $script:sessionSignedIn.Log |
                Where-Object { $_.Command -eq 'Connect-AzAccount' }).Count | Should -Be 0
    }
}
