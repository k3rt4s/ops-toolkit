#Requires -Modules Pester

# Set-WindowsCredentialProtection changes only HKLM registry values. Every registry write is
# stubbed as a recorder by Get-WindowsMutationStubText. Registry READS are real in the other
# test files; here Get-ItemProperty and Test-Path are shadowed for HKLM paths so that the
# starting state is a fixture and not whatever this machine happens to have. The fixture is a
# JSON map in OPSTOOLKIT_TEST_REGISTRY: key path -> object of value name -> value. A key that
# is not in the map does not exist.
#
# The session is normally not elevated, so assertions that depend on the executing half
# applying admin-only changes are skipped there. The plan JSON, written regardless, is
# asserted in every session.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-cred-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $script:scriptRelative = 'scripts\it-operations\windows-hardening\Set-WindowsCredentialProtection.ps1'
    $script:lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $script:wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $script:deviceGuard = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $script:hvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'

    $script:registryShadow = @'

function Get-ItemProperty {
    param($Path, $LiteralPath, $Name, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($env:OPSTOOLKIT_TEST_REGISTRY_ON -ne '1' -or $target -notlike 'HKLM:*') {
        return Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
    }
    $map = $env:OPSTOOLKIT_TEST_REGISTRY | ConvertFrom-Json
    $entry = $map.PSObject.Properties[$target]
    if ($null -eq $entry) { throw [System.Management.Automation.ItemNotFoundException]::new("Cannot find path '$target'") }
    $entry.Value
}

function Test-Path {
    param($Path, $LiteralPath, $PathType, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($env:OPSTOOLKIT_TEST_REGISTRY_ON -ne '1' -or $target -notlike 'HKLM:*') {
        return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
    }
    $map = $env:OPSTOOLKIT_TEST_REGISTRY | ConvertFrom-Json
    return ($null -ne $map.PSObject.Properties[$target])
}
'@

    function Get-Fixture {
        param([hashtable]$Registry)
        $json = ($Registry | ConvertTo-Json -Depth 5 -Compress)
        "`$env:OPSTOOLKIT_TEST_REGISTRY_ON = '1'`n`$env:OPSTOOLKIT_TEST_REGISTRY = '$json'`n"
    }

    function Invoke-CredPair {
        param([string]$Tag, [hashtable]$Argument, [hashtable]$Registry = @{})
        $Argument.ReportDirectory = (Join-Path $script:workRoot $Tag)
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptRelative -Argument $Argument -Tag $Tag `
            -ExtraSetup $script:registryShadow -FixtureEnvironment (Get-Fixture -Registry $Registry)
    }

    function Get-PlanItem {
        param($Run, [string]$Setting)
        $plan = @(Get-Content -LiteralPath $Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        @($plan | Where-Object { $_.Setting -eq $Setting })
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WindowsCredentialProtection default run' {
    BeforeAll {
        $script:def = Invoke-CredPair -Tag 'credDefault' -Argument @{}
    }

    It 'runs to completion in both modes' {
        $script:def.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:def.WhatIf.Output)"
        $script:def.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:def.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:def
    }

    It 'plans the no-UEFI-lock LSA protection value 2 and the NTLM and WDigest values' {
        $s = $script:def.WhatIf
        (Get-PlanItem -Run $s -Setting 'RunAsPPL').DesiredValue | Should -Be 2
        (Get-PlanItem -Run $s -Setting 'UseLogonCredential').DesiredValue | Should -Be 0
        (Get-PlanItem -Run $s -Setting 'LmCompatibilityLevel').DesiredValue | Should -Be 5
        (Get-PlanItem -Run $s -Setting 'NoLMHash').DesiredValue | Should -Be 1
    }

    It 'does not plan Credential Guard, VBS or memory integrity by default' {
        foreach ($name in 'LsaCfgFlags', 'EnableVirtualizationBasedSecurity', 'RequirePlatformSecurityFeatures', 'Enabled') {
            @(Get-PlanItem -Run $script:def.WhatIf -Setting $name).Count | Should -Be 0
        }
    }

    It 'lists the report-only rows with a value for each and never changes them' {
        foreach ($name in 'VbsRunning', 'CredentialGuardRunning', 'MemoryIntegrityRunning', 'SecureBoot', 'TpmPresent') {
            $row = @(Get-PlanItem -Run $script:def.WhatIf -Setting $name)
            $row.Count | Should -Be 1
            "$($row[0].CurrentValue)" | Should -Not -BeNullOrEmpty
            $row[0].Category | Should -Be 'Report'
        }
        $script:def.WhatIf.Summary.ReportOnlyCount | Should -Be 5
    }

    It 'writes the planned values when executing' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $writes = @(Get-OpsMutationRecord -Path $script:def.ExecuteLog | Where-Object { $_.Command -eq 'Set-ItemProperty' })
        $byName = @{}
        foreach ($w in $writes) { $byName[($w.Target -split '\\')[-1]] = $w }
        $byName['RunAsPPL'].Detail | Should -Be '2'
        $byName['RunAsPPL'].Target | Should -Be "$($script:lsa)\RunAsPPL"
        $byName['UseLogonCredential'].Detail | Should -Be '0'
        $byName['LmCompatibilityLevel'].Detail | Should -Be '5'
        $byName['NoLMHash'].Detail | Should -Be '1'
        # The WDigest key is absent in the fixture, so it has to be created, never forced.
        @(Get-OpsMutationRecord -Path $script:def.ExecuteLog | Where-Object { $_.Command -eq 'New-Item' -and $_.Target -eq $script:wdigest }).Count | Should -Be 1
        $script:def.Execute.Summary.RebootRequired | Should -BeTrue
        $script:def.Execute.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
    }

    It 'marks admin items as skipped when not elevated' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a non-elevated session'; return }
        @($script:def.Execute.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 4
        $script:def.Execute.Summary.RebootRequired | Should -BeFalse
    }
}

Describe 'Set-WindowsCredentialProtection opt-in controls' {
    BeforeAll {
        $script:full = Invoke-CredPair -Tag 'credFull' -Argument @{ EnableCredentialGuard = $true; EnableMemoryIntegrity = $true }
        $script:locked = Invoke-CredPair -Tag 'credLocked' -Argument @{ UefiLock = $true; EnableCredentialGuard = $true; RequireDmaProtection = $true }
    }

    It 'runs to completion in both modes' {
        foreach ($r in $script:full, $script:locked) {
            $r.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($r.WhatIf.Output)"
            $r.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($r.Execute.Output)"
        }
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:full
        Assert-OpsNoChangeUnderWhatIf -Pair $script:locked
    }

    It 'plans VBS, memory integrity and Credential Guard without UEFI lock by default' {
        $s = $script:full.WhatIf
        (Get-PlanItem -Run $s -Setting 'EnableVirtualizationBasedSecurity').DesiredValue | Should -Be 1
        (Get-PlanItem -Run $s -Setting 'RequirePlatformSecurityFeatures').DesiredValue | Should -Be 1
        (Get-PlanItem -Run $s -Setting 'Enabled').DesiredValue | Should -Be 1
        (Get-PlanItem -Run $s -Setting 'Enabled').RegistryPath | Should -Be $script:hvci
        (Get-PlanItem -Run $s -Setting 'LsaCfgFlags').DesiredValue | Should -Be 2
        (Get-PlanItem -Run $s -Setting 'RunAsPPL').DesiredValue | Should -Be 2
    }

    It '-UefiLock changes RunAsPPL and LsaCfgFlags to 1, and -RequireDmaProtection changes the platform value to 3' {
        $s = $script:locked.WhatIf
        (Get-PlanItem -Run $s -Setting 'RunAsPPL').DesiredValue | Should -Be 1
        (Get-PlanItem -Run $s -Setting 'LsaCfgFlags').DesiredValue | Should -Be 1
        (Get-PlanItem -Run $s -Setting 'RequirePlatformSecurityFeatures').DesiredValue | Should -Be 3
        @(Get-PlanItem -Run $s -Setting 'Enabled').Count | Should -Be 0
    }

    It 'writes the VBS, HVCI and Credential Guard values when executing' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $writes = @(Get-OpsMutationRecord -Path $script:full.ExecuteLog | Where-Object { $_.Command -eq 'Set-ItemProperty' })
        ($writes | Where-Object { $_.Target -eq "$($script:deviceGuard)\EnableVirtualizationBasedSecurity" }).Detail | Should -Be '1'
        ($writes | Where-Object { $_.Target -eq "$($script:hvci)\Enabled" }).Detail | Should -Be '1'
        ($writes | Where-Object { $_.Target -eq "$($script:lsa)\LsaCfgFlags" }).Detail | Should -Be '2'
    }
}

Describe 'Set-WindowsCredentialProtection already compliant' {
    BeforeAll {
        # RunAsPPL = 1 (UEFI-locked) already protects LSASS, so asking for the unlocked
        # value 2 must not lower or rewrite it.
        $registry = @{
            $script:lsa = @{ RunAsPPL = 1; LmCompatibilityLevel = 5; NoLMHash = 1 }
            $script:wdigest = @{ UseLogonCredential = 0 }
        }
        $script:ok = Invoke-CredPair -Tag 'credOk' -Argument @{} -Registry $registry
    }

    It 'reports NoChange for every setting and records nothing, even when executing' {
        $script:ok.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:ok.Execute.Output)"
        $items = @($script:ok.Execute.Summary.Items | Where-Object { $_.Category -ne 'Report' })
        $items.Count | Should -Be 4
        @($items | Where-Object { $_.Result -ne 'NoChange' }).Count | Should -Be 0
        $script:ok.Execute.Summary.AppliedCount | Should -Be 0
        $script:ok.Execute.Summary.RebootRequired | Should -BeFalse
        $script:ok.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
        @(Get-OpsMutationRecord -Path $script:ok.ExecuteLog).Count | Should -Be 0
    }
}

Describe 'Set-WindowsCredentialProtection rollback' {
    BeforeAll {
        $dir = Join-Path $script:workRoot 'credRollback'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [pscustomobject]@{
            Timestamp = '20260101_000000'
            ChangedSettings = @(
                [pscustomobject]@{ Category = 'LsaProtection'; Setting = 'RunAsPPL'; RegistryPath = $script:lsa; RequiresReboot = $true; PriorValue = 0; AppliedValue = 2 }
                [pscustomobject]@{ Category = 'Ntlm'; Setting = 'NoLMHash'; RegistryPath = $script:lsa; RequiresReboot = $true; PriorValue = 'absent'; AppliedValue = 1 }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'credential-protection-rollback-20260101_000000.json') -Encoding utf8

        $script:rb = Invoke-CredPair -Tag 'credRollback' -Argument @{ Rollback = $true } `
            -Registry @{ $script:lsa = @{ RunAsPPL = 2; NoLMHash = 1 } }
    }

    It 'runs to completion in both modes' {
        $script:rb.WhatIf.ExitCode | Should -Be 0 -Because "the -WhatIf run failed: $($script:rb.WhatIf.Output)"
        $script:rb.Execute.ExitCode | Should -Be 0 -Because "the executing run failed: $($script:rb.Execute.Output)"
    }

    It 'changes nothing under -WhatIf' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:rb
    }

    It 'plans the prior value, and removal for a value that was absent' {
        (Get-PlanItem -Run $script:rb.WhatIf -Setting 'RunAsPPL').DesiredValue | Should -Be 0
        (Get-PlanItem -Run $script:rb.WhatIf -Setting 'NoLMHash').DesiredValue | Should -Be 'absent'
    }

    It 'restores the prior value and removes the absent one when executing' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $records = @(Get-OpsMutationRecord -Path $script:rb.ExecuteLog)
        $set = @($records | Where-Object { $_.Command -eq 'Set-ItemProperty' -and $_.Target -eq "$($script:lsa)\RunAsPPL" })
        $set.Count | Should -Be 1
        $set[0].Detail | Should -Be '0'
        @($records | Where-Object { $_.Command -eq 'Remove-ItemProperty' -and $_.Target -eq "$($script:lsa)\NoLMHash" }).Count | Should -Be 1
    }

    It 'stops with a clear error when there is no rollback file' {
        $empty = Invoke-CredPair -Tag 'credRollbackNone' -Argument @{ Rollback = $true }
        $empty.WhatIf.ExitCode | Should -Not -Be 0
        $empty.WhatIf.Output | Should -Match 'No credential-protection-rollback-\*\.json found'
    }
}

Describe 'Set-WindowsCredentialProtection rollback safety' {
    BeforeAll {
        $script:rbDirCounter = 0
        $script:credScriptFullPath = Join-Path (Get-RepositoryRoot) $script:scriptRelative

        function Get-LiftedFunctionText {
            param([string]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:credScriptFullPath, [ref]$tokens, [ref]$parseErrors)
            $hit = @($ast.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $Name
                })
            $hit.Count | Should -Be 1 -Because "the script must define $Name once at its top level"
            $hit[0].Extent.Text
        }

        function New-RollbackDir {
            $script:rbDirCounter++
            $dir = Join-Path $script:workRoot "credSafety$($script:rbDirCounter)"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }

        function New-CredEntry {
            param($Category = 'LsaProtection', $Setting = 'RunAsPPL', $Path = $script:lsa, $Prior = 0, $Applied = 2)
            [pscustomobject]@{ Category = $Category; Setting = $Setting; RegistryPath = $Path; RequiresReboot = $true; PriorValue = $Prior; AppliedValue = $Applied }
        }

        function Write-CredRollbackFile {
            param([string]$Dir, [string]$Name, [object[]]$Entry)
            $path = Join-Path $Dir $Name
            [pscustomobject]@{ Timestamp = '20260101_000000'; ChangedSettings = @($Entry) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }

        function Invoke-CredRollback {
            param([string]$Dir, [string]$Tag, [switch]$Execute, [hashtable]$Registry = @{})
            $log = Join-Path $script:workRoot "$Tag.log"
            $argument = @{ ReportDirectory = $Dir; Rollback = $true }
            if ($Execute) { $argument.Confirm = $false } else { $argument.WhatIf = $true }
            $setup = (Get-WindowsMutationStubText -MutationLogPath $log) + (Get-Fixture -Registry $Registry) + $script:registryShadow
            $run = Invoke-ScriptUnderTest -RelativePath $script:scriptRelative -ModulePath $script:systemModulePath -Setup $setup -Argument $argument
            [pscustomobject]@{ Run = $run; Log = $log }
        }

        function Assert-CredRefused {
            param([string]$Dir, [string]$FileName, [string]$Because)
            $r = Invoke-CredRollback -Dir $Dir -Tag "refused$($script:rbDirCounter)"
            $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused"
            $r.Run.Output | Should -Match 'refused' -Because $Because
            $r.Run.Output | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
            $r.Run.Output | Should -Match 'Move this file aside' -Because $Because
            @(Get-ChildItem -LiteralPath $Dir -Filter 'credential-protection-rollback-plan-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because "$Because must be refused before any plan file is written"
            @(Get-ChildItem -LiteralPath $Dir -Filter 'credential-protection-rollback-state-*' -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because $Because
            @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because $Because
            Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
        }
    }

    It 'refuses a planted entry outside the controls the forward plan sets, under -Rollback -WhatIf' {
        $cases = @(
            @{ Name = 'foreign registry path'; Entry = (New-CredEntry -Path 'HKLM:\SOFTWARE\Evil') },
            @{ Name = 'known path, unknown value name'; Entry = (New-CredEntry -Setting 'DisableAntiSpyware') },
            @{ Name = 'known setting, wrong path'; Entry = (New-CredEntry -Path $script:wdigest) },
            @{ Name = 'known setting, wrong category'; Entry = (New-CredEntry -Category 'Ntlm') }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $name = 'credential-protection-rollback-20260101_000000.json'
            $null = Write-CredRollbackFile -Dir $dir -Name $name -Entry @((New-CredEntry), $case.Entry)
            Assert-CredRefused -Dir $dir -FileName $name -Because $case.Name
        }
    }

    It 'names the first offending entry by index' {
        $dir = New-RollbackDir
        $name = 'credential-protection-rollback-20260101_000000.json'
        $null = Write-CredRollbackFile -Dir $dir -Name $name -Entry @((New-CredEntry), (New-CredEntry -Path 'HKLM:\SOFTWARE\Evil'))
        $r = Invoke-CredRollback -Dir $dir -Tag 'credIndex'
        $r.Run.ExitCode | Should -Not -Be 0
        $r.Run.Output | Should -Match 'entry 1 '
        $r.Run.Output | Should -Match ([regex]::Escape('HKLM:\SOFTWARE\Evil'))
    }

    It 'refuses a rollback file that is not JSON, or has no usable ChangedSettings array' {
        $name = 'credential-protection-rollback-20260101_000000.json'
        $bodies = [ordered]@{
            'not JSON'                  = 'this is { not json'
            'ChangedSettings missing'   = '{ "Timestamp": "20260101_000000" }'
            'ChangedSettings an object' = '{ "ChangedSettings": { "Category": "LsaProtection" } }'
            'ChangedSettings a string'  = '{ "ChangedSettings": "RunAsPPL" }'
            'ChangedSettings one valid entry, not in an array' = ('{ "ChangedSettings": { "Category": "LsaProtection", "Setting": "RunAsPPL", "RegistryPath": "' + ($script:lsa -replace '\\', '\\') + '", "PriorValue": 0, "AppliedValue": 2 } }')
            'top level is an array'     = '[ { "Category": "LsaProtection" } ]'
            'entry is null'             = '{ "ChangedSettings": [ null ] }'
            'entry is a string'         = '{ "ChangedSettings": [ "RunAsPPL" ] }'
            'entry lacks AppliedValue'  = ('{ "ChangedSettings": [ { "Category": "LsaProtection", "Setting": "RunAsPPL", "RegistryPath": "' + ($script:lsa -replace '\\', '\\') + '", "PriorValue": 0 } ] }')
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-RollbackDir
            Set-Content -LiteralPath (Join-Path $dir $name) -Value $bodies[$label] -Encoding utf8
            Assert-CredRefused -Dir $dir -FileName $name -Because $label
        }
    }

    It 'refuses a value of the wrong type' {
        $name = 'credential-protection-rollback-20260101_000000.json'
        $cases = @(
            @{ Name = 'PriorValue abc'; Entry = (New-CredEntry -Prior 'abc') },
            @{ Name = 'PriorValue numeric string'; Entry = (New-CredEntry -Prior '2') },
            @{ Name = 'PriorValue boolean'; Entry = (New-CredEntry -Prior $true) },
            @{ Name = 'PriorValue array'; Entry = (New-CredEntry -Prior @(1, 2)) },
            @{ Name = 'PriorValue null'; Entry = (New-CredEntry -Prior $null) },
            @{ Name = 'PriorValue out of DWORD range'; Entry = (New-CredEntry -Prior 99999999999) },
            @{ Name = 'AppliedValue abc'; Entry = (New-CredEntry -Applied 'abc') },
            @{ Name = 'AppliedValue unknown'; Entry = (New-CredEntry -Applied 'unknown') }
        )
        foreach ($case in $cases) {
            $dir = New-RollbackDir
            $null = Write-CredRollbackFile -Dir $dir -Name $name -Entry @($case.Entry)
            Assert-CredRefused -Dir $dir -FileName $name -Because $case.Name
        }
    }

    It 'does not pick a consumed file: the older unconsumed file is planned instead' {
        $dir = New-RollbackDir
        # The consumed file is newer and deliberately unreadable, so picking it would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'credential-protection-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        $older = Write-CredRollbackFile -Dir $dir -Name 'credential-protection-rollback-20260101_000000.json' `
            -Entry @((New-CredEntry -Category 'Ntlm' -Setting 'NoLMHash' -Prior 'absent' -Applied 1))
        $r = Invoke-CredRollback -Dir $dir -Tag 'credConsumedNotPicked'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $older)
        $plan = @(Get-Content -LiteralPath $r.Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        @($plan | ForEach-Object { $_.Setting }) | Should -Be @('NoLMHash')
        $plan[0].DesiredValue | Should -Be 'absent'
    }

    It 'leaves the file unconsumed when an executing rollback skips every item for lack of elevation' {
        if ($script:isElevated) { Set-ItResult -Skipped -Because 'only meaningful in a session that is not elevated'; return }
        $dir = New-RollbackDir
        $name = 'credential-protection-rollback-20260101_000000.json'
        $file = Write-CredRollbackFile -Dir $dir -Name $name -Entry @((New-CredEntry))
        $r = Invoke-CredRollback -Dir $dir -Tag 'credUnelevatedExec' -Execute -Registry @{ $script:lsa = @{ RunAsPPL = 2 } }
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | Where-Object { $_.Result -like 'Skipped:*' }).Count | Should -Be 1
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $name
        $r.Run.Summary.RollbackNote | Should -Match 'unconsumed'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0
    }

    It 'never consumes the rollback file under -WhatIf' {
        $dir = New-RollbackDir
        $name = 'credential-protection-rollback-20260101_000000.json'
        $file = Write-CredRollbackFile -Dir $dir -Name $name -Entry @((New-CredEntry))
        $r = Invoke-CredRollback -Dir $dir -Tag 'credWhatIfKeeps' -Registry @{ $script:lsa = @{ RunAsPPL = 2 } }
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        Test-Path -LiteralPath $file | Should -BeTrue
        $r.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $name
        @(Get-ChildItem -LiteralPath $dir -Filter '*.consumed-*').Count | Should -Be 0

        # Where nothing is left to revert every item reads NoChange even under -WhatIf, so only the
        # -WhatIf rule itself keeps the file.
        $dir2 = New-RollbackDir
        $name2 = 'credential-protection-rollback-20260101_000000.json'
        $file2 = Write-CredRollbackFile -Dir $dir2 -Name $name2 -Entry @((New-CredEntry -Prior 'unknown'))
        $r2 = Invoke-CredRollback -Dir $dir2 -Tag 'credWhatIfKeeps2'
        $r2.Run.ExitCode | Should -Be 0 -Because $r2.Run.Output
        @($r2.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('NoChange')
        Test-Path -LiteralPath $file2 | Should -BeTrue
        $r2.Run.Summary.RollbackConsumedPath | Should -BeNullOrEmpty
    }

    It 'consumes the file after an executing rollback in which every item needed no change' {
        $dir = New-RollbackDir
        $name = 'credential-protection-rollback-20260101_000000.json'
        $file = Write-CredRollbackFile -Dir $dir -Name $name -Entry @((New-CredEntry -Prior 'unknown'))
        $r = Invoke-CredRollback -Dir $dir -Tag 'credConsumeNoChange' -Execute
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items | ForEach-Object { $_.Result }) | Should -Be @('NoChange')
        Test-Path -LiteralPath $file | Should -BeFalse -Because 'the used file is renamed'
        $r.Run.Summary.RollbackConsumedPath | Should -Match 'credential-protection-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        Test-Path -LiteralPath $r.Run.Summary.RollbackConsumedPath | Should -BeTrue
        (Split-Path -Leaf $r.Run.Summary.RollbackSourcePath) | Should -Be $name
        # The consumed file is not found by the next rollback.
        $again = Invoke-CredRollback -Dir $dir -Tag 'credConsumeNoChange2' -Execute
        $again.Run.ExitCode | Should -Not -Be 0
        $again.Run.Output | Should -Match 'Nothing to roll back'
    }

    It 'decides consumption in a pure function lifted from the script' {
        $text = Get-LiftedFunctionText -Name 'Test-RollbackFileConsumable'
        $decide = [scriptblock]::Create("param(`$State, [bool]`$Preview)`n$text`nTest-RollbackFileConsumable -State `$State -Preview `$Preview")
        function New-State { param([string[]]$Result) @($Result | ForEach-Object { [pscustomobject]@{ Result = $_ } }) }

        & $decide (New-State 'Reverted', 'NoChange', 'Reverted') $false | Should -BeTrue
        & $decide (New-State 'NoChange') $false | Should -BeTrue
        & $decide (New-State 'Reverted', 'Failed: access denied') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Skipped: requires elevation') $false | Should -BeFalse
        & $decide (New-State 'Previewed', 'Previewed') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Previewed') $false | Should -BeFalse
        & $decide (New-State 'Reverted', 'Reverted') $true | Should -BeFalse -Because '-WhatIf never consumes'
        & $decide (New-State 'NoChange') $true | Should -BeFalse
    }

    It 'validates one entry in a pure function lifted from the script, against whatever control table it is given' {
        $text = Get-LiftedFunctionText -Name 'Get-RollbackEntryProblem'
        $check = [scriptblock]::Create("param(`$Entry, `$Controls)`n$text`nGet-RollbackEntryProblem -Entry `$Entry -Controls `$Controls")
        $controls = @([pscustomobject]@{ Id = 'X'; Category = 'Cat'; Path = 'HKLM:\A'; Name = 'N' })
        function New-Probe { param($Prior = 1, $Applied = 2, $Path = 'HKLM:\A') [pscustomobject]@{ Category = 'Cat'; Setting = 'N'; RegistryPath = $Path; PriorValue = $Prior; AppliedValue = $Applied } }

        & $check (New-Probe) $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Prior 'absent' -Applied 'absent') $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Prior 'unknown') $controls | Should -BeNullOrEmpty
        & $check (New-Probe -Path 'HKLM:\B') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Prior 'abc') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe -Applied 'unknown') $controls | Should -Not -BeNullOrEmpty
        & $check (New-Probe) @([pscustomobject]@{ Id = 'Y'; Category = 'Other'; Path = 'HKLM:\A'; Name = 'N' }) | Should -Not -BeNullOrEmpty -Because 'a table without the entry allows nothing'
    }

    It 'accepts every control the forward plan can produce with all switches on, so the validator cannot drift from it' {
        $dir = New-RollbackDir
        $log = Join-Path $script:workRoot 'credDriftApply.log'
        $apply = Invoke-ScriptUnderTest -RelativePath $script:scriptRelative -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + (Get-Fixture -Registry @{}) + $script:registryShadow) `
            -Argument @{ ReportDirectory = (Join-Path $script:workRoot 'credDriftPlan'); EnableCredentialGuard = $true; EnableMemoryIntegrity = $true; WhatIf = $true }
        $apply.ExitCode | Should -Be 0 -Because $apply.Output
        $forward = @(Get-Content -LiteralPath $apply.Summary.PlanJsonPath -Raw | ConvertFrom-Json | Where-Object { $_.Category -ne 'Report' })
        $forward.Count | Should -Be 8
        $entries = @($forward | ForEach-Object {
                New-CredEntry -Category $_.Category -Setting $_.Setting -Path $_.RegistryPath -Prior 'absent' -Applied ([int]$_.DesiredValue)
            })
        $null = Write-CredRollbackFile -Dir $dir -Name 'credential-protection-rollback-20260101_000000.json' -Entry $entries
        $r = Invoke-CredRollback -Dir $dir -Tag 'credDriftRollback'
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        @($r.Run.Summary.Items).Count | Should -Be 8
    }

    It 'rolls back newest first and consumes each file as it goes' {
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'requires an elevated session'; return }
        $dir = New-RollbackDir
        $apply1 = $null
        $apply2 = $null
        # Apply 1 sets the default controls; apply 2 (a second later) adds memory integrity on top of
        # a machine that already has the defaults. Registry reads are a fixture, so the fixture for
        # apply 2 shows the defaults in place.
        $log1 = Join-Path $script:workRoot 'credLifoApply1.log'
        $log2 = Join-Path $script:workRoot 'credLifoApply2.log'
        $done = @{ $script:lsa = @{ RunAsPPL = 2; LmCompatibilityLevel = 5; NoLMHash = 1 }; $script:wdigest = @{ UseLogonCredential = 0 } }
        $apply1 = Invoke-ScriptUnderTest -RelativePath $script:scriptRelative -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log1) + (Get-Fixture -Registry @{}) + $script:registryShadow) `
            -Argument @{ ReportDirectory = $dir; Confirm = $false }
        $apply1.ExitCode | Should -Be 0 -Because $apply1.Output
        Start-Sleep -Milliseconds 1200
        $apply2 = Invoke-ScriptUnderTest -RelativePath $script:scriptRelative -ModulePath $script:systemModulePath `
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log2) + (Get-Fixture -Registry $done) + $script:registryShadow) `
            -Argument @{ ReportDirectory = $dir; EnableMemoryIntegrity = $true; Confirm = $false }
        $apply2.ExitCode | Should -Be 0 -Because $apply2.Output
        $apply1.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty
        $apply2.Summary.RollbackJsonPath | Should -Not -BeNullOrEmpty

        $rb1 = Invoke-CredRollback -Dir $dir -Tag 'credLifoRollback1' -Execute -Registry $done
        $rb1.Run.ExitCode | Should -Be 0 -Because $rb1.Run.Output
        (Split-Path -Leaf $rb1.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply2.Summary.RollbackJsonPath)
        $rb1.Run.Summary.RollbackConsumedPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $rb1.Run.Summary.RollbackConsumedPath | Should -BeTrue
        Test-Path -LiteralPath $apply2.Summary.RollbackJsonPath | Should -BeFalse -Because 'the used file is renamed'
        $rb1.Run.Summary.RollbackConsumedPath | Should -Match 'rollback-\d{8}_\d{6}\.consumed-\d{8}_\d{6}\.json$'
        $targets1 = @(Get-OpsMutationRecord -Path $rb1.Log | ForEach-Object { $_.Target })
        $targets1 | Should -Contain "$($script:hvci)\Enabled"
        $targets1 | Should -Not -Contain "$($script:lsa)\RunAsPPL"

        $rb2 = Invoke-CredRollback -Dir $dir -Tag 'credLifoRollback2' -Execute -Registry @{}
        $rb2.Run.ExitCode | Should -Be 0 -Because $rb2.Run.Output
        (Split-Path -Leaf $rb2.Run.Summary.RollbackSourcePath) | Should -Be (Split-Path -Leaf $apply1.Summary.RollbackJsonPath)
        Test-Path -LiteralPath $apply1.Summary.RollbackJsonPath | Should -BeFalse
        $targets2 = @(Get-OpsMutationRecord -Path $rb2.Log | ForEach-Object { $_.Target })
        $targets2 | Should -Contain "$($script:lsa)\RunAsPPL"
        $targets2 | Should -Not -Contain "$($script:hvci)\Enabled"

        $rb3 = Invoke-CredRollback -Dir $dir -Tag 'credLifoRollback3' -Execute
        $rb3.Run.ExitCode | Should -Not -Be 0
        $rb3.Run.Output | Should -Match 'Nothing to roll back'
    }
}
