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
