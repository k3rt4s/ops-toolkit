#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\entra\Export-EntraConditionalAccessBaseline.ps1'

    function New-CaPolicy {
        param(
            $Id = '1', $Name = 'Policy', $State = 'enabled',
            $ClientAppTypes = @('all'), $Controls = @('mfa'),
            $IncludeRoles = @(), $IncludeUsers = @('All'), $ExcludeUsers = @(), $Strength = $null
        )

        # Shaped as Invoke-MgGraphRequest -OutputType Hashtable returns it.
        @{
            id = $Id; displayName = $Name; state = $State
            conditions = @{
                users = @{
                    includeUsers = $IncludeUsers; excludeUsers = $ExcludeUsers
                    includeGroups = @(); excludeGroups = @(); includeRoles = $IncludeRoles; excludeRoles = @()
                }
                applications = @{ includeApplications = @('All'); excludeApplications = @() }
                clientAppTypes = $ClientAppTypes
                signInRiskLevels = @(); userRiskLevels = @()
            }
            grantControls = @{ operator = 'OR'; builtInControls = $Controls; authenticationStrength = $Strength }
            sessionControls = $null
        }
    }
}

Describe 'Get-PolicyRecord' {
    It 'flattens the fields a reader needs' {
        $record = Get-PolicyRecord -Policy (New-CaPolicy -Name 'Block legacy' -ClientAppTypes @('exchangeActiveSync', 'other') -Controls @('block'))
        $record.DisplayName | Should -Be 'Block legacy'
        $record.ClientAppTypes | Should -Be 'exchangeActiveSync;other'
        $record.BuiltInControls | Should -Be 'block'
        $record.IncludeUsers | Should -Be 'All'
    }

    It 'surfaces the authentication strength name' {
        $record = Get-PolicyRecord -Policy (New-CaPolicy -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') -Strength @{ displayName = 'Phishing-resistant MFA' })
        $record.AuthenticationStrength | Should -Be 'Phishing-resistant MFA'
        $record.IncludeRoles | Should -Be '62e90394-69f5-4237-9190-012177145e10'
    }
}

Describe 'Get-PolicySignature' {
    It 'ignores a change that does not alter enforced behaviour' {
        # modifiedDateTime moves without the policy changing. Treating that as drift
        # would make every report noise and train people to ignore it.
        $before = New-CaPolicy
        $before['modifiedDateTime'] = '2020-01-01T00:00:00Z'
        $after = New-CaPolicy
        $after['modifiedDateTime'] = '2026-08-14T00:00:00Z'
        Get-PolicySignature -Policy $before | Should -Be (Get-PolicySignature -Policy $after)
    }

    It 'detects a state change' {
        Get-PolicySignature -Policy (New-CaPolicy -State 'enabled') |
            Should -Not -Be (Get-PolicySignature -Policy (New-CaPolicy -State 'disabled'))
    }

    It 'detects a grant control change' {
        Get-PolicySignature -Policy (New-CaPolicy -Controls @('block')) |
            Should -Not -Be (Get-PolicySignature -Policy (New-CaPolicy -Controls @('mfa')))
    }

    It 'detects a new user exclusion' {
        # An added exclusion is how a policy quietly stops covering someone.
        Get-PolicySignature -Policy (New-CaPolicy) |
            Should -Not -Be (Get-PolicySignature -Policy (New-CaPolicy -ExcludeUsers @('breakglass-guid')))
    }

    It 'detects a client app type change' {
        Get-PolicySignature -Policy (New-CaPolicy -ClientAppTypes @('all')) |
            Should -Not -Be (Get-PolicySignature -Policy (New-CaPolicy -ClientAppTypes @('exchangeActiveSync', 'other')))
    }
}
