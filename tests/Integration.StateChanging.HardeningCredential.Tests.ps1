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
    $script:ntVersion = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

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

# Child keys of a fixture key are the map keys one level below it. A key not in the map does not exist.
function Get-ChildItem {
    param($Path, $LiteralPath, $Filter, [switch]$File, [switch]$Recurse, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
    if ($env:OPSTOOLKIT_TEST_REGISTRY_ON -ne '1' -or $target -notlike 'HKLM:*') {
        return Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
    }
    $map = $env:OPSTOOLKIT_TEST_REGISTRY | ConvertFrom-Json
    if ($null -eq $map.PSObject.Properties[$target]) { throw [System.Management.Automation.ItemNotFoundException]::new("Cannot find path '$target'") }
    $prefix = "$target\"
    foreach ($p in $map.PSObject.Properties) {
        if ($p.Name.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -and $p.Name.Substring($prefix.Length) -notmatch '\\') {
            [pscustomobject]@{ PSChildName = $p.Name.Substring($prefix.Length) }
        }
    }
}

# Signatures are a fixture too: file path -> Status, Subject, Issuer. A path with no staged entry
# throws, as the real cmdlet does for a file it cannot open, so the script must call it Unread.
function Get-AuthenticodeSignature {
    param($FilePath, $LiteralPath, $ErrorAction)
    $target = if ($LiteralPath) { [string]$LiteralPath } else { [string]$FilePath }
    $map = $env:OPSTOOLKIT_TEST_SIGNATURES | ConvertFrom-Json
    $entry = $map.PSObject.Properties[$target]
    if ($null -eq $entry) { throw "no staged signature for '$target'" }
    $v = $entry.Value
    $cert = $null
    if ($v.PSObject.Properties['Subject'] -and $v.Subject) { $cert = [pscustomobject]@{ Subject = $v.Subject; Issuer = $v.Issuer } }
    [pscustomobject]@{ Status = $v.Status; SignerCertificate = $cert }
}
'@

    function Get-Fixture {
        param([hashtable]$Registry, [string]$SecureBoot = 'false', [hashtable]$Signature = @{})
        $json = ($Registry | ConvertTo-Json -Depth 5 -Compress)
        $sigJson = ($Signature | ConvertTo-Json -Depth 5 -Compress)
        "`$env:OPSTOOLKIT_TEST_REGISTRY_ON = '1'`n`$env:OPSTOOLKIT_TEST_REGISTRY = '$json'`n`$env:OPSTOOLKIT_TEST_SECUREBOOT = '$SecureBoot'`n`$env:OPSTOOLKIT_TEST_SIGNATURES = '$sigJson'`n"
    }

    # A machine that licenses Credential Guard with Secure Boot on, unless the caller says otherwise.
    function Get-CapableRegistry {
        param([string]$Edition = 'Enterprise')
        @{ $script:ntVersion = @{ EditionID = $Edition } }
    }

    function Invoke-CredPair {
        param([string]$Tag, [hashtable]$Argument, [hashtable]$Registry = @{}, [string]$SecureBoot = 'true', [hashtable]$Signature = @{}, [string]$MoreSetup = '')
        $Argument.ReportDirectory = (Join-Path $script:workRoot $Tag)
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:scriptRelative -Argument $Argument -Tag $Tag `
            -ExtraSetup ($script:registryShadow + $MoreSetup) -FixtureEnvironment (Get-Fixture -Registry $Registry -SecureBoot $SecureBoot -Signature $Signature)
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
        $script:full = Invoke-CredPair -Tag 'credFull' -Argument @{ EnableCredentialGuard = $true; EnableMemoryIntegrity = $true } -Registry (Get-CapableRegistry)
        $script:locked = Invoke-CredPair -Tag 'credLocked' -Argument @{ UefiLock = $true; EnableCredentialGuard = $true; RequireDmaProtection = $true } -Registry (Get-CapableRegistry)
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
            -Setup ((Get-WindowsMutationStubText -MutationLogPath $log) + (Get-Fixture -Registry (Get-CapableRegistry) -SecureBoot 'true') + $script:registryShadow) `
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

Describe 'Set-WindowsCredentialProtection Credential Guard edition gate and Secure Boot guard' {
    BeforeAll {
        function Get-Row {
            param($Run, [string]$Setting)
            @($Run.Summary.Items | Where-Object { $_.Setting -eq $Setting })
        }
        $script:cgArg = @{ EnableCredentialGuard = $true }
        $script:editionRuns = @{}
        foreach ($edition in 'Professional', 'Enterprise', 'Education', 'EnterpriseN', 'EnterpriseS', 'EducationN', 'EnterpriseSN', 'CoreSingleLanguage', 'ProfessionalEducation') {
            $script:editionRuns[$edition] = Invoke-CredPair -Tag "credEd$edition" -Argument $script:cgArg -Registry (Get-CapableRegistry -Edition $edition)
        }
        $script:editionRuns['unreadable'] = Invoke-CredPair -Tag 'credEdNone' -Argument $script:cgArg -Registry @{}
        $script:editionRuns['keyOnly'] = Invoke-CredPair -Tag 'credEdKeyOnly' -Argument $script:cgArg -Registry @{ $script:ntVersion = @{ ProductName = 'x' } }
        $script:sbRuns = @{}
        foreach ($sb in 'true', 'false', 'error') {
            $script:sbRuns[$sb] = Invoke-CredPair -Tag "credSb$sb" -Argument @{ EnableMemoryIntegrity = $true } -Registry @{} -SecureBoot $sb
        }
    }

    It 'runs every variant to completion in both modes' {
        foreach ($r in @($script:editionRuns.Values) + @($script:sbRuns.Values)) {
            $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
            $r.Execute.ExitCode | Should -Be 0 -Because $r.Execute.Output
        }
    }

    It 'does not apply Credential Guard on Pro and says why, naming the edition and the licensing requirement' {
        $run = $script:editionRuns['Professional']
        foreach ($mode in $run.WhatIf, $run.Execute) {
            $cg = @(Get-Row -Run $mode -Setting 'LsaCfgFlags')
            $cg.Count | Should -Be 1
            $cg[0].Result | Should -Match '^Skipped: .*Professional.*Enterprise or Education'
            $cg[0].Action | Should -Match 'Not applied'
            $mode.Summary.PreconditionNotes.Count | Should -Be 1
            $mode.Summary.PreconditionNotes[0] | Should -Match 'LsaCfgFlags: Skipped: .*Professional'
        }
        # Credential Guard alone: the VBS prerequisites are not planned either, so nothing is written.
        @(Get-PlanItem -Run $run.WhatIf -Setting 'RequirePlatformSecurityFeatures').Count | Should -Be 0
        @(Get-PlanItem -Run $run.WhatIf -Setting 'EnableVirtualizationBasedSecurity').Count | Should -Be 0
        @(Get-OpsMutationRecord -Path $run.ExecuteLog).Count | Should -Be 0 -Because 'an unlicensed edition must not write RequirePlatformSecurityFeatures or anything else'
        $run.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty -Because 'no Credential Guard value was changed'
    }

    It 'plans Credential Guard on every licensed edition' {
        foreach ($edition in 'Enterprise', 'Education', 'EnterpriseN', 'EnterpriseS', 'EducationN', 'EnterpriseSN') {
            $row = @(Get-PlanItem -Run $script:editionRuns[$edition].WhatIf -Setting 'LsaCfgFlags')
            $row.Count | Should -Be 1 -Because $edition
            $row[0].Action | Should -Match 'Set LsaCfgFlags = 2' -Because $edition
            $row[0].Precondition | Should -BeNullOrEmpty -Because $edition
            @($script:editionRuns[$edition].WhatIf.Summary.Items | Where-Object { $_.Result -like 'Skipped: Windows edition*' -or $_.Result -like 'Failed:*' }).Count | Should -Be 0 -Because $edition
            @(Get-PlanItem -Run $script:editionRuns[$edition].WhatIf -Setting 'RequirePlatformSecurityFeatures').Count | Should -Be 1 -Because $edition
        }
    }

    It 'refuses editions that are close to but not on the licensed list' {
        foreach ($edition in 'CoreSingleLanguage', 'ProfessionalEducation') {
            $cg = @(Get-Row -Run $script:editionRuns[$edition].WhatIf -Setting 'LsaCfgFlags')
            $cg[0].Result | Should -Match '^Skipped: ' -Because $edition
        }
    }

    It 'fails the precondition, never passes, when the edition cannot be read' {
        foreach ($key in 'unreadable', 'keyOnly') {
            foreach ($mode in $script:editionRuns[$key].WhatIf, $script:editionRuns[$key].Execute) {
                $cg = @(Get-Row -Run $mode -Setting 'LsaCfgFlags')
                $cg.Count | Should -Be 1
                $cg[0].Result | Should -Match '^Failed: .*edition could not be read' -Because $key
                $mode.Summary.FailedCount | Should -Be 1 -Because $key
            }
            @(Get-OpsMutationRecord -Path $script:editionRuns[$key].ExecuteLog).Count | Should -Be 0 -Because $key
        }
    }

    It 'leaves a Credential Guard value that is already in place as No change on an unlicensed edition' {
        $r = Invoke-CredPair -Tag 'credEdProDone' -Argument $script:cgArg -Registry @{
            $script:ntVersion = @{ EditionID = 'Professional' }
            $script:lsa = @{ LsaCfgFlags = 2; RunAsPPL = 2; LmCompatibilityLevel = 5; NoLMHash = 1 }
            $script:wdigest = @{ UseLogonCredential = 0 }
        }
        $r.Execute.ExitCode | Should -Be 0 -Because $r.Execute.Output
        (Get-Row -Run $r.Execute -Setting 'LsaCfgFlags')[0].Result | Should -Be 'NoChange'
    }

    It 'leaves the default run and -EnableMemoryIntegrity alone: no edition gate without -EnableCredentialGuard' {
        $def = Invoke-CredPair -Tag 'credEdDefault' -Argument @{} -Registry @{}
        @($def.WhatIf.Summary.Items | Where-Object { $_.Result -like '*edition*' }).Count | Should -Be 0
        $def.WhatIf.Summary.PreconditionNotes.Count | Should -Be 0
        $mi = $script:sbRuns['true']
        @(Get-PlanItem -Run $mi.WhatIf -Setting 'Enabled').Count | Should -Be 1
        $mi.WhatIf.Summary.PreconditionNotes.Count | Should -Be 0
    }

    It 'writes RequirePlatformSecurityFeatures only when Secure Boot reads True' {
        $row = Get-Row -Run $script:sbRuns['true'].WhatIf -Setting 'RequirePlatformSecurityFeatures'
        $row.Count | Should -Be 1
        $row[0].Precondition | Should -BeNullOrEmpty
        $row[0].Action | Should -Match 'Set RequirePlatformSecurityFeatures = 1'
        if ($script:isElevated) {
            $targets = @(Get-OpsMutationRecord -Path $script:sbRuns['true'].ExecuteLog | ForEach-Object { $_.Target })
            $targets | Should -Contain "$($script:deviceGuard)\RequirePlatformSecurityFeatures"
        }
    }

    It 'skips only RequirePlatformSecurityFeatures when Secure Boot is off or cannot be read, and still plans the HVCI rows' {
        foreach ($sb in 'false', 'error') {
            $run = $script:sbRuns[$sb]
            foreach ($mode in $run.WhatIf, $run.Execute) {
                $platform = @(Get-Row -Run $mode -Setting 'RequirePlatformSecurityFeatures')
                $platform.Count | Should -Be 1 -Because $sb
                $platform[0].Result | Should -Match '^Skipped: Secure Boot is not confirmed' -Because $sb
                $platform[0].Action | Should -Match 'Not applied' -Because $sb
                $mode.Summary.PreconditionNotes.Count | Should -Be 1 -Because $sb
            }
            (Get-PlanItem -Run $run.WhatIf -Setting 'Enabled').Action | Should -Match 'Set Enabled = 1' -Because $sb
            (Get-PlanItem -Run $run.WhatIf -Setting 'EnableVirtualizationBasedSecurity').Action | Should -Match 'Set EnableVirtualizationBasedSecurity = 1' -Because $sb
            $targets = @(Get-OpsMutationRecord -Path $run.ExecuteLog | ForEach-Object { $_.Target })
            $targets | Should -Not -Contain "$($script:deviceGuard)\RequirePlatformSecurityFeatures" -Because $sb
            if ($script:isElevated) {
                $targets | Should -Contain "$($script:hvci)\Enabled" -Because $sb
            }
        }
    }

    It 'applies the Secure Boot guard to -RequireDmaProtection (value 3) as well' {
        $r = Invoke-CredPair -Tag 'credSbDma' -Argument @{ EnableMemoryIntegrity = $true; RequireDmaProtection = $true } -Registry @{} -SecureBoot 'false'
        $row = @(Get-Row -Run $r.WhatIf -Setting 'RequirePlatformSecurityFeatures')
        $row[0].DesiredValue | Should -Be 3
        $row[0].Result | Should -Match '^Skipped: Secure Boot'
    }

    It 'reports Secure Boot unconfirmed for Credential Guard on a licensed edition, with the edition gate passing' {
        $r = Invoke-CredPair -Tag 'credCgNoSb' -Argument $script:cgArg -Registry (Get-CapableRegistry) -SecureBoot 'false'
        (Get-Row -Run $r.WhatIf -Setting 'LsaCfgFlags')[0].Action | Should -Match 'Set LsaCfgFlags = 2'
        (Get-Row -Run $r.WhatIf -Setting 'RequirePlatformSecurityFeatures')[0].Result | Should -Match '^Skipped: Secure Boot'
    }
}

Describe 'Set-WindowsCredentialProtection LSA protection preflight' {
    BeforeAll {
        $script:modDir = Join-Path $script:workRoot 'lsaModules'
        New-Item -ItemType Directory -Path $script:modDir -Force | Out-Null
        $msSubject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
        $msIssuer = 'CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
        $vendorSubject = 'CN=Apple Inc., O=Apple Inc., L=Cupertino, S=California, C=US'
        $vendorIssuer = 'CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=DigiCert, Inc., C=US'

        # Every module file exists except the one named missing.dll.
        $script:mod = @{}
        foreach ($n in 'ms_auth', 'vendor_auth', 'unsigned_notify', 'spoof_auth', 'tampered_auth', 'noread_auth', 'mdnsNSP') {
            $p = Join-Path $script:modDir "$n.dll"
            Set-Content -LiteralPath $p -Value 'x' -Encoding ascii
            $script:mod[$n] = $p
        }
        $script:mod['missing'] = Join-Path $script:modDir 'missing.dll'

        $script:sig = @{
            $script:mod['ms_auth'] = @{ Status = 'Valid'; Subject = $msSubject; Issuer = $msIssuer }
            $script:mod['vendor_auth'] = @{ Status = 'Valid'; Subject = $vendorSubject; Issuer = $vendorIssuer }
            $script:mod['unsigned_notify'] = @{ Status = 'NotSigned' }
            # A valid signature whose subject claims Microsoft but whose issuer does not is not Microsoft.
            $script:mod['spoof_auth'] = @{ Status = 'Valid'; Subject = $msSubject; Issuer = $vendorIssuer }
            $script:mod['tampered_auth'] = @{ Status = 'HashMismatch'; Subject = $msSubject; Issuer = $msIssuer }
            # noread_auth has no staged entry, so the signature call throws.
            $script:mod['mdnsNSP'] = @{ Status = 'Valid'; Subject = $vendorSubject; Issuer = $vendorIssuer }
        }

        $script:nsParent64 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries64'
        $script:nsParent32 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries'
        $script:reg = @{
            $script:lsa = @{
                'Authentication Packages' = @($script:mod['ms_auth'], $script:mod['vendor_auth'], $script:mod['spoof_auth'], $script:mod['tampered_auth'], $script:mod['noread_auth'])
                'Notification Packages'   = @($script:mod['unsigned_notify'], $script:mod['missing'])
                'Security Packages'       = @('')
            }
            "$($script:lsa)\OSConfig" = @{ 'Security Packages' = @() }
            $script:nsParent64 = @{}
            "$($script:nsParent64)\000000000001" = @{ LibraryPath = $script:mod['mdnsNSP']; DisplayString = 'Bonjour' }
            $script:nsParent32 = @{}
        }
        $script:pf = Invoke-CredPair -Tag 'credPreflight' -Argument @{} -Registry $script:reg -Signature $script:sig

        function Get-PreflightRow {
            param($Run)
            @(Get-Content -LiteralPath $Run.Summary.LsaPreflightJsonPath -Raw | ConvertFrom-Json)
        }
        function Get-RowFor {
            param($Run, [string]$Name)
            $rows = @(Get-PreflightRow -Run $Run | Where-Object { $_.ResolvedPath -eq $script:mod[$Name] })
            $rows.Count | Should -Be 1 -Because "exactly one row for $Name"
            $rows[0]
        }
    }

    It 'runs to completion in both modes, writes the preflight report in both, and changes nothing under -WhatIf' {
        $script:pf.Execute.ExitCode | Should -Be 0 -Because $script:pf.Execute.Output
        Assert-OpsNoChangeUnderWhatIf -Pair $script:pf
        foreach ($mode in $script:pf.WhatIf, $script:pf.Execute) {
            Test-Path -LiteralPath $mode.Summary.LsaPreflightCsvPath | Should -BeTrue
            Test-Path -LiteralPath $mode.Summary.LsaPreflightJsonPath | Should -BeTrue
            $mode.Summary.LsaPreflightCsvPath | Should -Match 'credential-protection-lsa-preflight-\d{8}_\d{6}\.csv$'
            $mode.Summary.LsaPreflightError | Should -BeNullOrEmpty
        }
    }

    It 'does not list a Microsoft-signed module' {
        foreach ($mode in $script:pf.WhatIf, $script:pf.Execute) {
            $row = Get-RowFor -Run $mode -Name 'ms_auth'
            $row.Verdict | Should -Be 'Microsoft'
            $row.Listed | Should -BeFalse
            $row.Source | Should -Be 'Lsa\Authentication Packages'
        }
    }

    It 'lists a validly signed third-party module with its signer' {
        $row = Get-RowFor -Run $script:pf.WhatIf -Name 'vendor_auth'
        $row.Verdict | Should -Be 'ThirdParty'
        $row.Listed | Should -BeTrue
        $row.Signer | Should -Match 'Apple Inc'
    }

    It 'lists a Winsock name-space provider such as mdnsNSP.dll that is not Microsoft-signed' {
        $row = Get-RowFor -Run $script:pf.WhatIf -Name 'mdnsNSP'
        $row.Source | Should -Be 'Winsock namespace providers'
        $row.Verdict | Should -Be 'ThirdParty'
        $row.Listed | Should -BeTrue
    }

    It 'lists an unsigned module' {
        $row = Get-RowFor -Run $script:pf.WhatIf -Name 'unsigned_notify'
        $row.Verdict | Should -Be 'Unsigned'
        $row.Listed | Should -BeTrue
        $row.Source | Should -Be 'Lsa\Notification Packages'
    }

    It 'does not accept a Microsoft subject from a non-Microsoft issuer, or a signature that no longer matches the file' {
        $spoof = Get-RowFor -Run $script:pf.WhatIf -Name 'spoof_auth'
        $spoof.Verdict | Should -Be 'ThirdParty'
        $spoof.Listed | Should -BeTrue
        $bad = Get-RowFor -Run $script:pf.WhatIf -Name 'tampered_auth'
        $bad.Verdict | Should -Be 'InvalidSignature'
        $bad.Listed | Should -BeTrue
    }

    It 'lists a missing file as Unread, never as safe' {
        $row = Get-RowFor -Run $script:pf.WhatIf -Name 'missing'
        $row.Verdict | Should -Be 'Unread'
        $row.Listed | Should -BeTrue
        $row.Unread | Should -BeTrue
        $row.Detail | Should -Match 'file not found'
    }

    It 'lists a module whose signature cannot be read as Unread, never as safe' {
        $row = Get-RowFor -Run $script:pf.WhatIf -Name 'noread_auth'
        $row.Verdict | Should -Be 'Unread'
        $row.Listed | Should -BeTrue
        $row.Unread | Should -BeTrue
    }

    It 'counts modules, listed and unread, and the CSV matches the JSON' {
        # 8 rows: ms_auth is not listed; the other 7 are, and 2 of those (missing, noread_auth) are Unread.
        foreach ($mode in $script:pf.WhatIf, $script:pf.Execute) {
            $mode.Summary.LsaPreflightModuleCount | Should -Be 8
            $mode.Summary.LsaPreflightListedCount | Should -Be 7
            $mode.Summary.LsaPreflightUnreadCount | Should -Be 2
            @(Import-Csv -LiteralPath $mode.Summary.LsaPreflightCsvPath).Count | Should -Be 8
            $mode.Summary.LsaPreflightNote | Should -Match '7 module\(s\) will stop loading'
        }
    }

    It 'is a report, not a blocker: LSA protection is still planned and applied with modules listed' {
        (Get-PlanItem -Run $script:pf.WhatIf -Setting 'RunAsPPL').DesiredValue | Should -Be 2
        (Get-PlanItem -Run $script:pf.Execute -Setting 'RunAsPPL').Action | Should -Match 'Set RunAsPPL = 2'
        $script:pf.Execute.Summary.FailedCount | Should -Be 0
        if (-not $script:isElevated) { Set-ItResult -Skipped -Because 'applying requires an elevated session'; return }
        $targets = @(Get-OpsMutationRecord -Path $script:pf.ExecuteLog | ForEach-Object { $_.Target })
        $targets | Should -Contain "$($script:lsa)\RunAsPPL"
    }

    It 'treats empty package lists as nothing to check, not as one blank module (the @($null) trap)' {
        $empty = @{
            $script:lsa = @{ 'Authentication Packages' = @(); 'Notification Packages' = @(''); 'Security Packages' = @('', '  ') }
            "$($script:lsa)\OSConfig" = @{ 'Security Packages' = @() }
            $script:nsParent64 = @{}
            $script:nsParent32 = @{}
        }
        $r = Invoke-CredPair -Tag 'credPreflightEmpty' -Argument @{} -Registry $empty
        foreach ($mode in $r.WhatIf, $r.Execute) {
            $mode.ExitCode | Should -Be 0 -Because $mode.Output
            $mode.Summary.LsaPreflightModuleCount | Should -Be 0
            $mode.Summary.LsaPreflightListedCount | Should -Be 0
            @(Get-Content -LiteralPath $mode.Summary.LsaPreflightJsonPath -Raw | ConvertFrom-Json).Count | Should -Be 0
            # An empty report still has its header.
            (Get-Content -LiteralPath $mode.Summary.LsaPreflightCsvPath -Raw) | Should -Match '"Source"'
            $mode.Summary.LsaPreflightNote | Should -Match 'No module outside Microsoft-signed'
        }
    }

    It 'reports an absent Winsock name-space catalog as Unread, never as an empty and safe list' {
        $r = Invoke-CredPair -Tag 'credPreflightNoCatalog' -Argument @{} -Registry @{ $script:lsa = @{ 'Authentication Packages' = @() } }
        $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
        $rows = @(Get-PreflightRow -Run $r.WhatIf)
        $rows.Count | Should -Be 1
        $rows[0].Verdict | Should -Be 'Unread'
        $rows[0].Source | Should -Be 'Winsock namespace providers'
        $r.WhatIf.Summary.LsaPreflightUnreadCount | Should -Be 1
    }

    It 'reports a provider entry with no LibraryPath as Unread' {
        $reg = @{
            $script:nsParent64 = @{}
            "$($script:nsParent64)\000000000002" = @{ DisplayString = 'no library' }
            $script:nsParent32 = @{}
        }
        $r = Invoke-CredPair -Tag 'credPreflightNoLib' -Argument @{} -Registry $reg
        $rows = @(Get-PreflightRow -Run $r.WhatIf)
        $rows.Count | Should -Be 1
        $rows[0].Verdict | Should -Be 'Unread'
        $rows[0].Detail | Should -Match 'no readable LibraryPath'
    }

    It 'never lets a preflight failure stop the apply' {
        $failing = @'

function Export-Csv {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Path, [switch]$NoTypeInformation, [string]$Encoding)
    begin { $rows = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $rows.Add($InputObject) } }
    end {
        if ($Path -like '*lsa-preflight*') { throw 'staged preflight failure' }
        $rows | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation -Encoding $Encoding -WhatIf:$false
    }
}
'@
        $r = Invoke-CredPair -Tag 'credPreflightFails' -Argument @{} -Registry $script:reg -Signature $script:sig -MoreSetup $failing
        foreach ($mode in $r.WhatIf, $r.Execute) {
            $mode.ExitCode | Should -Be 0 -Because $mode.Output
            $mode.Summary.LsaPreflightError | Should -Match 'staged preflight failure'
            $mode.Summary.LsaPreflightCsvPath | Should -BeNullOrEmpty
        }
        (Get-PlanItem -Run $r.WhatIf -Setting 'RunAsPPL').DesiredValue | Should -Be 2
        $r.Execute.Summary.FailedCount | Should -Be 0
    }

    It 'does not run under -Rollback' {
        $dir = Join-Path $script:workRoot 'credPreflightRollback'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [pscustomobject]@{
            Timestamp = '20260101_000000'
            ChangedSettings = @([pscustomobject]@{ Category = 'LsaProtection'; Setting = 'RunAsPPL'; RegistryPath = $script:lsa; RequiresReboot = $true; PriorValue = 0; AppliedValue = 2 })
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'credential-protection-rollback-20260101_000000.json') -Encoding utf8
        $r = Invoke-CredPair -Tag 'credPreflightRollback' -Argument @{ Rollback = $true } -Registry $script:reg -Signature $script:sig
        $r.WhatIf.ExitCode | Should -Be 0 -Because $r.WhatIf.Output
        $r.WhatIf.Summary.LsaPreflightCsvPath | Should -BeNullOrEmpty
        $r.WhatIf.Summary.LsaPreflightModuleCount | Should -Be 0
        @(Get-ChildItem -LiteralPath $dir -Filter '*lsa-preflight*').Count | Should -Be 0
    }

    It 'resolves a registered name to a file in a pure function lifted from the script' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-RepositoryRoot) $script:scriptRelative), [ref]$tokens, [ref]$parseErrors)
        $hit = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Resolve-LsaModulePath' })
        $hit.Count | Should -Be 1
        $resolve = [scriptblock]::Create("param(`$Entry, `$Dir)`n$($hit[0].Extent.Text)`nResolve-LsaModulePath -Entry `$Entry -SystemDirectory `$Dir")
        $dir = 'C:\SysDir'
        & $resolve 'msv1_0' $dir | Should -Be 'C:\SysDir\msv1_0.dll'
        & $resolve 'scecli.dll' $dir | Should -Be 'C:\SysDir\scecli.dll'
        & $resolve '"D:\Vendor\auth.dll"' $dir | Should -Be 'D:\Vendor\auth.dll'
        & $resolve '' $dir | Should -BeNullOrEmpty
        & $resolve '   ' $dir | Should -BeNullOrEmpty
        & $resolve $null $dir | Should -BeNullOrEmpty
    }
}
