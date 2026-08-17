#Requires -Modules Pester

# End-to-end runs of the Defender for Endpoint device collector against a stubbed API,
# with known facts planted and the null shapes a real service returns.
#
# There is no licensed Defender for Endpoint tenant available, so this stub is the only
# coverage this collector has. What that means is stated plainly in FUTURE_FEATURES.md:
# these specs prove the collector's decisions, its paging, and its refusals. They cannot
# prove that api.securitycenter.microsoft.com returns the shapes stubbed here.
#
# The fixture deliberately plants a device with no lastSeen and a device with an empty
# onboardingStatus, because a fully populated fixture proves only the happy path. That
# is how both Azure collectors shipped scanning nothing.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

    # Two pages, because a collector that reads page one and stops writes a truncated
    # inventory that looks exactly like a small estate.
    $script:apiStub = @'
$now = Get-Date

function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $Body, $ContentType, $ErrorAction)

    if ($Uri -match 'oauth2') {
        return [pscustomobject]@{ access_token = 'stub-token'; expires_in = 3599 }
    }

    if ($Uri -match 'skiptoken=page2') {
        return [pscustomobject]@{
            value = @(
                # Page two exists solely to prove paging is followed. This device is
                # only ever seen if the collector reads the nextLink.
                [pscustomobject]@{
                    id = 'dev-page2'; computerDnsName = 'PAGE2.contoso.com'; aadDeviceId = 'aad-6'
                    onboardingStatus = 'Onboarded'; healthStatus = 'Active'
                    firstSeen = $now.AddDays(-200).ToString('o'); lastSeen = $now.AddHours(-2).ToString('o')
                    osPlatform = 'Windows11'; version = '24H2'; agentVersion = '10.8040'
                    lastIpAddress = '10.0.0.6'; riskScore = 'None'; exposureLevel = 'Low'
                    rbacGroupName = 'UnassignedGroup'; machineTags = @(); isExcluded = $false
                    defenderAvStatus = 'Updated'
                }
            )
        }
    }

    [pscustomobject]@{
        'value' = @(
            [pscustomobject]@{
                id = 'dev-healthy'; computerDnsName = 'PC01.contoso.com'; aadDeviceId = 'aad-1'
                onboardingStatus = 'Onboarded'; healthStatus = 'Active'
                firstSeen = $now.AddDays(-400).ToString('o'); lastSeen = $now.AddHours(-1).ToString('o')
                osPlatform = 'Windows11'; version = '24H2'; agentVersion = '10.8040'
                lastIpAddress = '10.0.0.1'; lastExternalIpAddress = '203.0.113.1'
                riskScore = 'None'; exposureLevel = 'Low'; rbacGroupName = 'Workstations'
                machineTags = @('finance', 'laptop'); isExcluded = $false; defenderAvStatus = 'Updated'
            }
            [pscustomobject]@{
                id = 'dev-silent'; computerDnsName = 'PC02.contoso.com'; aadDeviceId = 'aad-2'
                onboardingStatus = 'Onboarded'; healthStatus = 'Inactive'
                firstSeen = $now.AddDays(-400).ToString('o'); lastSeen = $now.AddDays(-10).ToString('o')
                osPlatform = 'Windows11'; version = '24H2'; agentVersion = '10.8040'
                lastIpAddress = '10.0.0.2'; riskScore = 'Medium'; exposureLevel = 'Medium'
                rbacGroupName = 'Workstations'; machineTags = @(); isExcluded = $false
                defenderAvStatus = 'Updated'
            }
            [pscustomobject]@{
                id = 'dev-inactive'; computerDnsName = 'PC03.contoso.com'; aadDeviceId = 'aad-3'
                onboardingStatus = 'Onboarded'; healthStatus = 'Inactive'
                firstSeen = $now.AddDays(-400).ToString('o'); lastSeen = $now.AddDays(-60).ToString('o')
                osPlatform = 'Windows10'; version = '22H2'; agentVersion = '10.7900'
                lastIpAddress = '10.0.0.3'; riskScore = 'High'; exposureLevel = 'High'
                rbacGroupName = 'Workstations'; machineTags = @(); isExcluded = $false
                defenderAvStatus = 'NotUpdated'
            }
            [pscustomobject]@{
                # The coverage gap: the service can see it and it is not protected.
                id = 'dev-gap'; computerDnsName = 'SRV04.contoso.com'; aadDeviceId = 'aad-4'
                onboardingStatus = 'CanBeOnboarded'; healthStatus = 'Unknown'
                firstSeen = $now.AddDays(-30).ToString('o'); lastSeen = $now.AddHours(-3).ToString('o')
                osPlatform = 'WindowsServer2019'; version = '1809'; agentVersion = ''
                lastIpAddress = '10.0.0.4'; riskScore = 'None'; exposureLevel = 'None'
                rbacGroupName = ''; machineTags = @(); isExcluded = $false; defenderAvStatus = ''
            }
            [pscustomobject]@{
                # No lastSeen at all. This is the null shape that decides whether the
                # collector reports honestly or optimistically.
                id = 'dev-nolastseen'; computerDnsName = 'PC05.contoso.com'; aadDeviceId = ''
                onboardingStatus = ''; healthStatus = 'Unknown'
                firstSeen = $now.AddDays(-5).ToString('o'); lastSeen = $null
                osPlatform = 'Linux'; version = ''; agentVersion = ''
                lastIpAddress = ''; riskScore = ''; exposureLevel = ''
                rbacGroupName = ''; machineTags = @(); isExcluded = $false; defenderAvStatus = ''
            }
            [pscustomobject]@{
                id = 'dev-unsupported'; computerDnsName = 'APPLIANCE.contoso.com'; aadDeviceId = ''
                onboardingStatus = 'Unsupported'; healthStatus = 'Unknown'
                firstSeen = $now.AddDays(-100).ToString('o'); lastSeen = $now.AddDays(-100).ToString('o')
                osPlatform = 'Other'; version = ''; agentVersion = ''
                lastIpAddress = '10.0.0.9'; riskScore = ''; exposureLevel = ''
                rbacGroupName = ''; machineTags = @(); isExcluded = $false; defenderAvStatus = ''
            }
        )
        '@odata.nextLink' = 'https://api.securitycenter.microsoft.com/api/machines?$skiptoken=page2'
    }
}
'@
}

Describe 'Export-DefenderEndpointDeviceInventory end to end' {
    BeforeAll {
        $script:run = Invoke-ScriptUnderTest -RelativePath 'scripts\logging\Export-DefenderEndpointDeviceInventory.ps1' `
            -Setup $script:apiStub `
            -RawArgument @{ AccessToken = "(ConvertTo-SecureString 'stub' -AsPlainText -Force)" }
        $script:summary = $script:run.Summary
        $script:devices = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'devices.csv')) } else { @() }
        $script:attention = if ($script:summary) { @(Import-Csv (Join-Path $script:summary.OutputDirectory 'devices-needing-attention.csv')) } else { @() }
    }

    It 'runs to completion against a stubbed API' {
        $script:run.ExitCode | Should -Be 0 -Because "the script failed: $($script:run.Output)"
        $script:summary | Should -Not -BeNullOrEmpty
    }

    It 'follows every page rather than stopping at the first' {
        # A collector that reads page one and stops writes a short inventory that reads
        # as a complete one, and a reconciliation built on it invents coverage gaps
        # for every machine on page two.
        $script:summary.PagesRead | Should -Be 2
        $script:devices.Count | Should -Be 7
        @($script:devices | Where-Object { $_.DeviceId -eq 'dev-page2' }).Count | Should -Be 1
    }

    It 'grades a recently reporting device as Protected' {
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-healthy' }).Verdict | Should -Be 'Protected'
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-healthy' }).ContactStatus | Should -Be 'Reporting'
    }

    It 'separates a silenced agent from a departed one' {
        # Ten days quiet is an agent that stopped talking on a machine that still
        # exists. Sixty days is a machine that has gone. They need different actions,
        # so they cannot share a status.
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-silent' }).Verdict | Should -Be 'Silent'
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-inactive' }).Verdict | Should -Be 'Inactive'
    }

    It 'reports the days of silence, not only the status' {
        # A threshold crossed is a fact; how far past it decides what gets looked at
        # first.
        [double](($script:devices | Where-Object { $_.DeviceId -eq 'dev-silent' }).DaysSinceLastSeen) |
            Should -BeGreaterOrEqual 9
    }

    It 'surfaces a device the service can see and does not protect' {
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-gap' }).Verdict | Should -Be 'NotOnboarded'
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-gap' }).CoverageStatus | Should -Be 'NotOnboarded'
    }

    It 'never reports a device with no last contact as reporting' {
        # The load-bearing assertion. A device the API returned with no lastSeen has
        # not been shown to be healthy, and calling it Protected is how a silenced
        # agent stays inside the managed device count.
        $device = $script:devices | Where-Object { $_.DeviceId -eq 'dev-nolastseen' }
        $device.ContactStatus | Should -Be 'Unmeasured'
        $device.Verdict | Should -Not -Be 'Protected'
        $device.DaysSinceLastSeen | Should -BeNullOrEmpty
    }

    It 'does not count an unsupported device as a coverage gap' {
        # Nothing would fix it, so listing it as a gap trains the operator to ignore
        # the gap list.
        ($script:devices | Where-Object { $_.DeviceId -eq 'dev-unsupported' }).Verdict | Should -Be 'Unsupported'
        @($script:attention | Where-Object { $_.DeviceId -eq 'dev-unsupported' }).Count | Should -Be 0
    }

    It 'counts every device into exactly one verdict' {
        $counted = $script:summary.ProtectedCount + $script:summary.SilentCount + $script:summary.InactiveCount +
        $script:summary.NotOnboardedCount + $script:summary.UnsupportedCount + $script:summary.UndeterminedCount
        $counted | Should -Be $script:summary.DeviceCount
        $script:summary.DeviceCount | Should -Be $script:devices.Count
    }

    It 'names the devices behind the attention count' {
        $script:attention.Count | Should -Be $script:summary.NeedsAttentionCount
        foreach ($device in $script:attention) {
            $device.Verdict | Should -BeIn @('Silent', 'Inactive', 'NotOnboarded', 'Undetermined')
        }
    }

    It 'writes no secret or token into any report' {
        # The token is the one value in this script that must never reach disk.
        foreach ($file in (Get-ChildItem -LiteralPath $script:summary.OutputDirectory -File)) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $content | Should -Not -Match 'stub-token'
            $content | Should -Not -Match 'Bearer'
        }
    }
}

Describe 'Export-DefenderEndpointDeviceInventory refusals' {
    It 'refuses without credentials and writes nothing' {
        $work = Join-Path ([System.IO.Path]::GetTempPath()) "mde-nocreds-$([guid]::NewGuid().ToString('N'))"
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\logging\Export-DefenderEndpointDeviceInventory.ps1' `
            -Setup 'function Invoke-RestMethod { throw "should not be called" }' `
            -Argument @{ OutputDirectory = $work }

        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'No credentials supplied'
        # A run that could not authenticate must leave no report, or the empty report
        # becomes evidence of an estate with no devices in it.
        Test-Path $work | Should -BeFalse
    }

    It 'fails rather than writing a partial device list when a page errors' {
        $work = Join-Path ([System.IO.Path]::GetTempPath()) "mde-pagefail-$([guid]::NewGuid().ToString('N'))"
        $stub = @'
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $Body, $ContentType, $ErrorAction)
    if ($Uri -match 'skiptoken=page2') { throw 'HTTP 503 from the device list' }
    [pscustomobject]@{
        'value' = @([pscustomobject]@{ id = 'dev-1'; computerDnsName = 'PC01'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; lastSeen = (Get-Date).ToString('o'); osPlatform = 'Windows11' })
        '@odata.nextLink' = 'https://api.securitycenter.microsoft.com/api/machines?$skiptoken=page2'
    }
}
'@
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\logging\Export-DefenderEndpointDeviceInventory.ps1' `
            -Setup $stub `
            -Argument @{ OutputDirectory = $work } `
            -RawArgument @{ AccessToken = "(ConvertTo-SecureString 'stub' -AsPlainText -Force)" }

        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'page 2'
        # One device written from a two-page estate is worse than no report, because
        # the reconciliation downstream would report every other machine as a gap.
        Test-Path $work | Should -BeFalse
    }

    It 'refuses to write a truncated inventory when the page cap is reached' {
        $work = Join-Path ([System.IO.Path]::GetTempPath()) "mde-cap-$([guid]::NewGuid().ToString('N'))"
        $stub = @'
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $Body, $ContentType, $ErrorAction)
    [pscustomobject]@{
        'value' = @([pscustomobject]@{ id = "dev-$(Get-Random)"; computerDnsName = 'PC'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; lastSeen = (Get-Date).ToString('o'); osPlatform = 'Windows11' })
        '@odata.nextLink' = 'https://api.securitycenter.microsoft.com/api/machines?$skiptoken=next'
    }
}
'@
        $run = Invoke-ScriptUnderTest -RelativePath 'scripts\logging\Export-DefenderEndpointDeviceInventory.ps1' `
            -Setup $stub `
            -Argument @{ OutputDirectory = $work; MaxPage = 3 } `
            -RawArgument @{ AccessToken = "(ConvertTo-SecureString 'stub' -AsPlainText -Force)" }

        $run.ExitCode | Should -Not -Be 0
        $run.Output | Should -Match 'exceeded 3 pages'
        Test-Path $work | Should -BeFalse
    }
}
