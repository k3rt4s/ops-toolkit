#Requires -Modules Pester

# Set-WdacEnforcedPolicy.ps1: the reviewed path from the audit-mode base policy to an enforced one.
#
# Built and tested against fakes only. The ConfigCI cmdlets come from a staged fake module and CiTool.exe
# is a function stub (or a .cmd stand-in reached through -CiToolPath), so nothing here reads or changes
# this machine's code integrity policy. Each changing mode runs as a -WhatIf and an executing run.
#
# The suite is normally not elevated. The script skips its deploy steps without elevation, so the
# assertions on the executing half that need it are skipped, and the plan and state JSON that an
# unelevated run still writes are asserted instead. Every refusal is a precondition row, which is
# evaluated without elevation, so refusals are proved in both kinds of session.
#
# What this proves: enforcement is impossible without an operator-supplied supplemental file for the
# toolkit's own audit base, which is active, allows supplemental policies and carries the boot safety
# options; Audit Mode is removed from that one policy and nothing else; rollback validates its whole
# file first, restores audit mode before removing the supplemental policy, and never removes the base.
# It does not prove the real ConfigCI or CiTool accept the calls.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-wdacenf-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:systemModulePath = Use-FakeSystemModule

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $script:enfScript = 'scripts\it-operations\windows-hardening\Set-WdacEnforcedPolicy.ps1'
    $script:enfFullPath = Get-RepositoryScriptPath -RelativePath $script:enfScript
    $script:counter = 0

    $script:baseId = '{AAAAAAAA-1111-4222-8333-444444444444}'
    $script:suppId = '{BBBBBBBB-1111-4222-8333-444444444444}'
    $script:otherId = '{CCCCCCCC-1111-4222-8333-444444444444}'
    $script:baseName = 'ops-toolkit WDAC audit'
    $script:suppName = 'ops-toolkit WDAC allow rules'
    $script:optionText = @{
        0 = 'Enabled:UMCI'; 3 = 'Enabled:Audit Mode'; 6 = 'Enabled:Unsigned System Integrity Policy'
        9 = 'Enabled:Advanced Boot Options Menu'; 10 = 'Enabled:Boot Audit on Failure'; 17 = 'Enabled:Allow Supplemental Policies'
    }

    $script:ciStub = @'
function CiTool.exe {
    $a = $args -join ' '
    if ($a -like '--list-policies*') { $env:OPSTOOLKIT_TEST_CITOOL_POLICIES; return }
    Write-OpsTestMutation -Command 'CiTool.exe' -Target $a -Detail ''
    if ($env:OPSTOOLKIT_TEST_CITOOL_FAIL_UPDATE -and $a -like '--update-policy*') { '{"OperationResult":-2147024891}'; return }
    '{"OperationResult":0}'
}
'@

    function Get-FlatText {
        param([string]$Text)
        $plain = $Text -replace ([char]27 + '\[[0-9;]*m'), ''
        $plain -replace '\s*\|\s*', ' ' -replace '\s+', ' '
    }

    function New-WorkDirectory {
        param([string]$Name)
        $script:counter++
        $path = Join-Path $script:workRoot "$Name-$($script:counter)"
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $path
    }

    function Get-StateItem {
        param([string]$ReportDirectory, [string]$Mode = 'apply', [string]$Setting)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter "*-$Mode-state-*.json" -File | Sort-Object LastWriteTime | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Setting -eq $Setting }
    }

    function Get-StateByCategory {
        param([string]$ReportDirectory, [string]$Mode = 'apply', [string]$Category)
        $file = Get-ChildItem -LiteralPath $ReportDirectory -Filter "*-$Mode-state-*.json" -File | Sort-Object LastWriteTime | Select-Object -Last 1
        @(Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.Category -eq $Category }
    }

    function Get-CiCall {
        param([string]$Log)
        @(Get-OpsMutationRecord -Path $Log | Where-Object { $_.Command -eq 'CiTool.exe' } | ForEach-Object { $_.Target })
    }

    function Get-EnvText {
        param([hashtable]$Environment = @{})
        (@($Environment.Keys | ForEach-Object { "`$env:$_ = '$($Environment[$_])'" }) -join "`n") + "`n"
    }

    function Get-PolicyJson {
        param([string]$Id, [string]$Name, [bool]$Enforced = $false)
        $bare = $Id.Trim('{', '}').ToLowerInvariant()
        '{"PolicyID":"' + $bare + '","BasePolicyID":"' + $bare + '","FriendlyName":"' + $Name + '","IsEnforced":' + $Enforced.ToString().ToLowerInvariant() + ',"IsSystemPolicy":false}'
    }

    function Get-ActiveJson {
        param([string[]]$Policy = @())
        '{"Policies":[' + ($Policy -join ',') + '],"OperationResult":0}'
    }

    # The audit report directory Set-WdacAuditPolicy.ps1 leaves: a rollback file and the policy XML it names.
    function New-AuditDirectory {
        param([int[]]$Omit = @(), [switch]$NoRecord, [string]$PolicyName = $script:baseName)
        $dir = New-WorkDirectory 'audit'
        $options = foreach ($n in 0, 3, 6, 9, 10, 17) { if ($n -notin $Omit) { '<Rule><Option>' + $script:optionText[$n] + '</Option></Rule>' } }
        $xmlName = 'wdac-audit-policy-20260101_000000.xml'
        ('<?xml version="1.0" encoding="utf-8"?><SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy"><VersionEx>10.0.3.0</VersionEx><PolicyID>' + $script:baseId + '</PolicyID><BasePolicyID>' + $script:baseId + '</BasePolicyID><Rules>' + ($options -join '') + '</Rules></SiPolicy>') |
            Set-Content -LiteralPath (Join-Path $dir $xmlName) -Encoding utf8
        if (-not $NoRecord) {
            $rec = [ordered]@{ PolicyName = $PolicyName; PolicyId = $script:baseId; CipPath = (Join-Path $dir 'x.cip'); XmlPath = (Join-Path $dir $xmlName); BasePolicy = 'DefaultWindows' }
            $file = [ordered]@{ Timestamp = '20260101_000000' }
            foreach ($k in $rec.Keys) { $file[$k] = $rec[$k] }
            $file['ChangedSettings'] = @([pscustomobject](@{ Category = 'DeployAuditPolicy' } + $rec))
            [pscustomobject]$file | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir 'wdac-audit-rollback-20260101_000000.json') -Encoding utf8
        }
        $dir
    }

    # The reviewed supplemental allow-rules file.
    function New-ReviewedFile {
        param(
            [string]$Type = 'Supplemental Policy', [string]$ForBase = $script:baseId, [string]$Id = $script:suppId,
            [int]$Rules = 2, [switch]$AuditMode, [string]$Raw
        )
        $dir = New-WorkDirectory 'reviewed'
        $path = Join-Path $dir 'reviewed-allow-rules.xml'
        if ($Raw) { Set-Content -LiteralPath $path -Value $Raw -Encoding utf8; return $path }
        $allow = (@(if ($Rules -gt 0) { 1..$Rules }) | ForEach-Object { '<Allow ID="ID_ALLOW_A_' + $_ + '" FriendlyName="reviewed ' + $_ + '" Hash="00"/>' }) -join ''
        $auditRule = if ($AuditMode) { '<Rule><Option>Enabled:Audit Mode</Option></Rule>' } else { '' }
        ('<?xml version="1.0" encoding="utf-8"?><SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="' + $Type + '"><VersionEx>10.0.0.0</VersionEx><PolicyID>' + $Id + '</PolicyID><BasePolicyID>' + $ForBase + '</BasePolicyID><Rules><Rule><Option>Enabled:UMCI</Option></Rule>' + $auditRule + '</Rules><FileRules>' + $allow + '</FileRules></SiPolicy>') |
            Set-Content -LiteralPath $path -Encoding utf8
        $path
    }

    function Get-GoodActive { Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name $script:baseName)) }

    # A -WhatIf run and an executing run of one mode, sharing one report directory.
    function Invoke-EnfPair {
        param([hashtable]$Argument, [string]$Active = (Get-GoodActive), [hashtable]$Environment = @{})
        $script:counter++
        $env = @{ OPSTOOLKIT_TEST_CITOOL_POLICIES = $Active } + $Environment
        Invoke-OpsWindowsScriptPair -WorkRoot $script:workRoot -ModulePath $script:systemModulePath `
            -RelativePath $script:enfScript -Argument $Argument -Tag "enf$($script:counter)" `
            -FixtureEnvironment ((Get-EnvText -Environment $env) + "`n") -ExtraSetup $script:ciStub
    }

    function Invoke-EnfOnce {
        param([hashtable]$Argument, [switch]$Execute, [string]$Active = (Get-GoodActive), [hashtable]$Environment = @{})
        $script:counter++
        $log = Join-Path $script:workRoot "enfone$($script:counter).log"
        $arg = $Argument.Clone()
        if ($Execute) { $arg.Confirm = $false } else { $arg.WhatIf = $true }
        $env = @{ OPSTOOLKIT_TEST_CITOOL_POLICIES = $Active } + $Environment
        $setup = (Get-WindowsMutationStubText -MutationLogPath $log) + "`n" + (Get-EnvText -Environment $env) + $script:ciStub
        $run = Invoke-ScriptUnderTest -RelativePath $script:enfScript -ModulePath $script:systemModulePath -Setup $setup -Argument $arg
        [pscustomobject]@{ Run = $run; Log = $log }
    }

    function Get-EnforceArgument {
        param([string]$AuditDir, [string]$Reviewed, [string]$Reports)
        @{ Mode = 'Enforce'; AuditReportDirectory = $AuditDir; AllowRulesPolicyPath = $Reviewed; ReportDirectory = $Reports }
    }

    # Rollback fixtures: a rollback file as the forward run writes it, and the audit-restore binary it names.
    function New-EnfRecord {
        param([string]$Dir, [hashtable]$Override = @{}, [switch]$Entry, [string]$Base = $script:baseId, [string]$Supp = $script:suppId, [string]$Sha)
        $bareBase = $Base.Trim('{', '}').ToLowerInvariant()
        $bareSupp = $Supp.Trim('{', '}').ToLowerInvariant()
        $r = [ordered]@{}
        if ($Entry) { $r['Category'] = 'DeploySupplementalPolicy' }
        $r['PolicyName'] = $script:baseName
        $r['BasePolicyId'] = $Base
        $r['SupplementalPolicyName'] = $script:suppName
        $r['SupplementalPolicyId'] = $Supp
        $r['AuditCipPath'] = Join-Path $Dir "wdac-enforce-audit-restore-$bareBase.cip"
        $r['AuditCipSha256'] = $Sha
        $r['SupplementalCipPath'] = Join-Path $Dir "wdac-enforce-allow-rules-$bareSupp.cip"
        foreach ($key in @($Override.Keys)) {
            if ($Override[$key] -is [string] -and $Override[$key] -ceq '__remove__') { $r.Remove($key) } else { $r[$key] = $Override[$key] }
        }
        [pscustomobject]$r
    }

    function New-EnfRollbackDir {
        param(
            [string]$Name = 'wdac-enforce-rollback-20260101_000000.json', [hashtable]$Top = @{}, [object[]]$Entries,
            [string]$Dir, [string]$Base = $script:baseId, [string]$Supp = $script:suppId, [switch]$NoCip, [switch]$TamperCip
        )
        if (-not $Dir) { $Dir = New-WorkDirectory 'enfrb' }
        $bareBase = $Base.Trim('{', '}').ToLowerInvariant()
        $cip = Join-Path $Dir "wdac-enforce-audit-restore-$bareBase.cip"
        Set-Content -LiteralPath $cip -Value "AUDIT-RESTORE-$Name" -Encoding ascii
        $sha = (Get-FileHash -LiteralPath $cip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($TamperCip) { Add-Content -LiteralPath $cip -Value 'tampered' -Encoding ascii }
        if ($NoCip) { Remove-Item -LiteralPath $cip -Force }
        if (-not $PSBoundParameters.ContainsKey('Entries')) {
            $Entries = @((New-EnfRecord -Dir $Dir -Entry -Base $Base -Supp $Supp -Sha $sha), (New-EnfRecord -Dir $Dir -Entry -Base $Base -Supp $Supp -Sha $sha -Override @{ Category = 'EnforceBasePolicy' }))
        }
        $record = New-EnfRecord -Dir $Dir -Override $Top -Base $Base -Supp $Supp -Sha $sha
        $file = [ordered]@{ Timestamp = '20260101_000000' }
        foreach ($p in $record.PSObject.Properties) { $file[$p.Name] = $p.Value }
        $file['ChangedSettings'] = @($Entries)
        [pscustomobject]$file | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Dir $Name) -Encoding utf8
        [pscustomobject]@{ Dir = $Dir; Cip = $cip; Sha = $sha }
    }

    function Get-EnfActive {
        param([switch]$Base, [switch]$Supp, [bool]$BaseEnforced = $true)
        $list = @()
        if ($Base) { $list += Get-PolicyJson -Id $script:baseId -Name $script:baseName -Enforced $BaseEnforced }
        if ($Supp) { $list += Get-PolicyJson -Id $script:suppId -Name $script:suppName -Enforced $true }
        Get-ActiveJson -Policy $list
    }

    function Invoke-EnfRollback {
        param([string]$Dir, [switch]$Execute, [string]$Active = (Get-EnfActive -Base -Supp), [hashtable]$Environment = @{})
        Invoke-EnfOnce -Argument @{ ReportDirectory = $Dir; Rollback = $true } -Execute:$Execute -Active $Active -Environment $Environment
    }

    function Assert-EnfRollbackRefused {
        param([string]$Dir, [string]$FileName, [string]$Because, [string]$Active = (Get-EnfActive -Base -Supp), [string]$Why = '')
        $r = Invoke-EnfRollback -Dir $Dir -Active $Active
        $r.Run.ExitCode | Should -Not -Be 0 -Because "$Because must be refused, also under -WhatIf"
        $flat = Get-FlatText $r.Run.Output
        $flat | Should -Match 'refused' -Because $Because
        if ($Why) { $flat | Should -Match $Why -Because "$Because must be refused for its own reason" }
        $flat | Should -Match ([regex]::Escape($FileName)) -Because "$Because must name the file"
        @(Get-ChildItem -LiteralPath $Dir -Filter 'wdac-enforce-rollback-plan-*' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because "$Because must be refused before any plan file is written"
        @(Get-ChildItem -LiteralPath $Dir -Filter 'wdac-enforce-rollback-state-*' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because $Because
        @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0 -Because "$Because must be refused before any change"
        Test-Path -LiteralPath (Join-Path $Dir $FileName) | Should -BeTrue -Because 'a refused file stays where it is'
    }
}

AfterAll {
    foreach ($p in $script:workRoot, $script:systemModulePath) {
        if ($p -and (Test-Path $p)) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Set-WdacEnforcedPolicy shape' {
    It 'is a separate script: ConfirmImpact High, -WhatIf, a mandatory report directory and no default path' {
        $cmd = Get-Command $script:enfFullPath
        $attr = $cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.SupportsShouldProcess | Should -BeTrue
        [string]$attr.ConfirmImpact | Should -Be 'High'
        $cmd.Parameters.Keys | Should -Contain 'ReportDirectory'
        $cmd.Parameters.Keys | Should -Contain 'CiToolPath'
        $cmd.Parameters['ReportDirectory'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.Mandatory } | Should -Contain $true
    }

    It 'says plainly that it was tested against fakes only and names a disposable test host and the Learn pages' {
        $text = Get-Content -LiteralPath $script:enfFullPath -Raw
        $text | Should -Match 'tested against fakes only'
        $text | Should -Match 'never been run on a real\s+machine'
        $text | Should -Match 'disposable virtual machine'
        $text | Should -Match 'stop a machine from starting normally'
        foreach ($title in 'Understand App Control policy rules and\s+file rules', 'Use multiple App Control policies', 'New-CIPolicy', 'CiTool commands') {
            $text | Should -Match $title
        }
    }

    It 'is ASCII only and its synopsis is one standalone line' {
        $bytes = [System.IO.File]::ReadAllBytes($script:enfFullPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        $text = Get-Content -LiteralPath $script:enfFullPath -Raw
        $text | Should -Match '(?s)\.SYNOPSIS\r?\n[^\r\n]+\r?\n\r?\n\.DESCRIPTION'
        $text | Should -Not -Match '\.SYNOPSIS\r?\nThis '
    }

    It 'has no caller: no other script, module or test runs it' {
        $root = Split-Path -Parent $PSScriptRoot
        $self = (Resolve-Path -LiteralPath $script:enfFullPath).Path
        $hits = foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1', '*.psm1', '*.cmd', '*.bat', '*.json' -ErrorAction SilentlyContinue) {
            if ($f.FullName -like '*\reports\*' -or $f.FullName -like '*\.git\*') { continue }
            if ($f.FullName -eq $self -or $f.FullName -like '*\tests\*') { continue }
            if (Select-String -LiteralPath $f.FullName -Pattern 'Set-WdacEnforcedPolicy' -Quiet) { $f.Name }
        }
        # The two companion scripts name it in their help, as text; nothing else may.
        @($hits | Where-Object { $_ -notin 'Set-WdacAuditPolicy.ps1', 'Export-WdacAuditEvent.ps1' }) | Should -BeNullOrEmpty
        foreach ($name in 'Set-WdacAuditPolicy.ps1', 'Export-WdacAuditEvent.ps1') {
            $file = Get-ChildItem -LiteralPath $root -Recurse -File -Filter $name | Where-Object { $_.FullName -notlike '*\reports\*' } | Select-Object -First 1
            $code = (Get-Content -LiteralPath $file.FullName -Raw) -replace '(?s)<#.*?#>', '' -replace '(?m)^\s*#.*$', ''
            $code | Should -Not -Match 'Set-WdacEnforcedPolicy' -Because "$name must not call it"
        }
    }
}

Describe 'Set-WdacEnforcedPolicy -Mode BuildAllowRules' {
    BeforeAll {
        $script:audit = New-AuditDirectory
        $script:buildReports = New-WorkDirectory 'build-reports'
        $script:build = Invoke-EnfPair -Argument @{ Mode = 'BuildAllowRules'; AuditReportDirectory = $script:audit; ReportDirectory = $script:buildReports }
    }

    It 'runs to completion in both modes' {
        $script:build.WhatIf.ExitCode | Should -Be 0 -Because $script:build.WhatIf.Output
        $script:build.Execute.ExitCode | Should -Be 0 -Because $script:build.Execute.Output
    }

    It 'writes a reviewable supplemental policy for the audit base into the report directory and deploys nothing' {
        foreach ($run in $script:build.WhatIf, $script:build.Execute) {
            $xmlPath = $run.Summary.AllowRulesXmlPath
            $xmlPath | Should -Not -BeNullOrEmpty
            (Split-Path -Parent $xmlPath) | Should -Be (Resolve-Path -LiteralPath $script:buildReports).Path
            Split-Path -Leaf $xmlPath | Should -Match '^wdac-enforce-allow-rules-\d{8}_\d{6}\.xml$'
            $xml = [xml](Get-Content -LiteralPath $xmlPath -Raw)
            $xml.SiPolicy.PolicyType | Should -Be 'Supplemental Policy'
            $xml.SiPolicy.BasePolicyID | Should -Be $script:baseId
            $xml.SiPolicy.PolicyID | Should -Not -Be $script:baseId
            @($xml.SiPolicy.FileRules.Allow).Count | Should -BeGreaterThan 0
            (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Not -Contain 'Enabled:Audit Mode'
        }
        @(Get-ChildItem -LiteralPath $script:buildReports -Filter '*.cip').Count | Should -Be 0 -Because 'build mode makes no binary to deploy'
        foreach ($log in $script:build.WhatIfLog, $script:build.ExecuteLog) {
            @(Get-CiCall -Log $log).Count | Should -Be 0
        }
    }

    It 'builds from the audit events at Publisher level with a Hash fallback' {
        $new = @(Get-OpsMutationRecord -Path $script:build.ExecuteLog | Where-Object { $_.Command -eq 'New-CIPolicy' })
        $new.Count | Should -Be 1
        $new[0].Detail | Should -Be 'level=Publisher;fallback=Hash;audit=True;userpes=True;multi=True'
        $ids = @(Get-OpsMutationRecord -Path $script:build.ExecuteLog | Where-Object { $_.Command -eq 'Set-CIPolicyIdInfo' })
        $ids[0].Detail | Should -Be "name=$($script:suppName);reset=True;supplements=$($script:baseId)"
    }

    It 'removes Audit Mode from what it builds, and refuses when that removal does not take' {
        $audit = New-AuditDirectory
        $reports = New-WorkDirectory 'build-audit-opt'
        $arg = @{ Mode = 'BuildAllowRules'; AuditReportDirectory = $audit; ReportDirectory = $reports }
        $ok = Invoke-EnfOnce -Argument $arg -Execute -Environment @{ OPSTOOLKIT_TEST_CI_NEWPOLICY_AUDIT_OPTION = '1' }
        $ok.Run.ExitCode | Should -Be 0 -Because $ok.Run.Output
        $xml = [xml](Get-Content -LiteralPath $ok.Run.Summary.AllowRulesXmlPath -Raw)
        (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Not -Contain 'Enabled:Audit Mode'
        $ignored = Invoke-EnfOnce -Argument $arg -Execute -Environment @{ OPSTOOLKIT_TEST_CI_NEWPOLICY_AUDIT_OPTION = '1'; OPSTOOLKIT_TEST_CI_IGNORE_OPTION = '3' }
        $ignored.Run.ExitCode | Should -Not -Be 0
        (Get-StateItem -ReportDirectory $reports -Mode 'build' -Setting 'AllowRulesBuilt').Result | Should -Match 'still carries Audit Mode'
    }

    It 'treats no events, no rules and a failing New-CIPolicy as a failed build, never a pass' {
        foreach ($case in @(
                @{ Name = 'New-CIPolicy throws'; Env = @{ OPSTOOLKIT_TEST_CI_NEWPOLICY_FAIL = '1' }; Match = 'no audit events' },
                @{ Name = 'zero rules'; Env = @{ OPSTOOLKIT_TEST_CI_ALLOW_COUNT = '0' }; Match = 'no allow rules' }
            )) {
            $reports = New-WorkDirectory 'build-fail'
            $arg = @{ Mode = 'BuildAllowRules'; AuditReportDirectory = (New-AuditDirectory); ReportDirectory = $reports }
            $whatIf = Invoke-EnfOnce -Argument $arg -Environment $case.Env
            $whatIf.Run.ExitCode | Should -Be 0 -Because "$($case.Name): a preview only previews"
            $live = Invoke-EnfOnce -Argument $arg -Execute -Environment $case.Env
            $live.Run.ExitCode | Should -Not -Be 0 -Because $case.Name
            (Get-StateItem -ReportDirectory $reports -Mode 'build' -Setting 'AllowRulesBuilt').Result | Should -Match "^Failed: .*$($case.Match)" -Because $case.Name
        }
    }

    It 'refuses to build against an audit base that lacks option 17, 9 or 10, or whose record is missing' {
        $cases = @(
            @{ Name = 'no 17'; Dir = (New-AuditDirectory -Omit 17); Setting = 'AllowsSupplementalPolicies'; Match = 'option 17' },
            @{ Name = 'no 9'; Dir = (New-AuditDirectory -Omit 9); Setting = 'BootSafetyOptions'; Match = 'option 9' },
            @{ Name = 'no 10'; Dir = (New-AuditDirectory -Omit 10); Setting = 'BootSafetyOptions'; Match = 'option 9.*or 10' },
            @{ Name = 'no record'; Dir = (New-AuditDirectory -NoRecord); Setting = 'AuditBaseRecord'; Match = 'no unconsumed' }
        )
        foreach ($case in $cases) {
            $reports = New-WorkDirectory 'build-refuse'
            $r = Invoke-EnfOnce -Argument @{ Mode = 'BuildAllowRules'; AuditReportDirectory = $case.Dir; ReportDirectory = $reports } -Execute
            $r.Run.ExitCode | Should -Not -Be 0 -Because $case.Name
            (Get-StateItem -ReportDirectory $reports -Mode 'build' -Setting $case.Setting).Result | Should -Match "^Failed: .*$($case.Match)" -Because $case.Name
            @(Get-ChildItem -LiteralPath $reports -Filter 'wdac-enforce-allow-rules-*.xml').Count | Should -Be 0 -Because "$($case.Name): no rules are built against a base that cannot enforce safely"
        }
    }

    It 'rejects -AllowRulesPolicyPath, which belongs to Enforce' {
        $reports = New-WorkDirectory 'build-reject'
        $r = Invoke-EnfOnce -Argument @{ Mode = 'BuildAllowRules'; AuditReportDirectory = $script:audit; ReportDirectory = $reports; AllowRulesPolicyPath = (New-ReviewedFile) }
        $r.Run.ExitCode | Should -Not -Be 0
        Get-FlatText $r.Run.Output | Should -Match 'applies to -Mode Enforce only'
    }
}

Describe 'Set-WdacEnforcedPolicy -Mode Enforce' {
    BeforeAll {
        $script:enfAudit = New-AuditDirectory
        $script:enfReviewed = New-ReviewedFile
        $script:enfReports = New-WorkDirectory 'enf-reports'
        $script:enf = Invoke-EnfPair -Argument (Get-EnforceArgument -AuditDir $script:enfAudit -Reviewed $script:enfReviewed -Reports $script:enfReports)
    }

    It 'runs to completion in both modes' {
        $script:enf.WhatIf.ExitCode | Should -Be 0 -Because $script:enf.WhatIf.Output
        $script:enf.Execute.ExitCode | Should -Be 0 -Because $script:enf.Execute.Output
    }

    It 'refuses without -AllowRulesPolicyPath, before anything is written or deployed' {
        $reports = Join-Path $script:workRoot 'enf-noreviewed-reports'
        $r = Invoke-EnfOnce -Argument @{ Mode = 'Enforce'; AuditReportDirectory = $script:enfAudit; ReportDirectory = $reports } -Execute
        $r.Run.ExitCode | Should -Not -Be 0
        Get-FlatText $r.Run.Output | Should -Match 'requires -AllowRulesPolicyPath'
        Test-Path -LiteralPath $reports | Should -BeFalse
        @(Get-OpsMutationRecord -Path $r.Log).Count | Should -Be 0
    }

    It 'deploys nothing under -WhatIf, though it still builds the policy files for review' {
        Assert-OpsNoChangeUnderWhatIf -Pair $script:enf -IgnoreCommand 'Set-CIPolicyIdInfo', 'Set-RuleOption', 'ConvertFrom-CIPolicy'
        @(Get-CiCall -Log $script:enf.WhatIfLog).Count | Should -Be 0
        $s = $script:enf.WhatIf.Summary
        Test-Path -LiteralPath $s.SupplementalCipPath | Should -BeTrue
        Test-Path -LiteralPath $s.EnforcedCipPath | Should -BeTrue
        Test-Path -LiteralPath $s.AuditRestoreCipPath | Should -BeTrue
        $s.RollbackJsonPath | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $script:enfReports -Filter 'wdac-enforce-rollback-*.json' | Where-Object { $_.LastWriteTime -le (Get-Date) }).Count |
            Should -Be $(if ($script:isElevated) { 1 } else { 0 }) -Because 'only an elevated executing run changes anything, so only it writes a rollback file'
    }

    It 'plans the supplemental policy first, then the base without Audit Mode, and nothing else' {
        $plan = @(Get-Content -LiteralPath $script:enf.WhatIf.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        $changes = @($plan | Where-Object { $_.Category -in 'DeploySupplementalPolicy', 'EnforceBasePolicy' })
        $changes.Count | Should -Be 2
        $changes[0].Category | Should -Be 'DeploySupplementalPolicy'
        $changes[1].Category | Should -Be 'EnforceBasePolicy'
        $changes[0].Action | Should -Match '--update-policy'
        $changes[1].Action | Should -Match '--update-policy'
        $changes[1].Action | Should -Match 'Audit Mode removed'
        @($plan | Where-Object { $_.Action -match '--remove-policy' }).Count | Should -Be 0
    }

    It 'builds the enforced base from the audit XML: option 3 gone, 6 9 10 and 17 and the same policy ID kept' {
        $s = $script:enf.WhatIf.Summary
        $xmlFile = Get-ChildItem -LiteralPath $script:enfReports -Filter 'wdac-enforce-base-enforced-*.xml' -File | Sort-Object LastWriteTime | Select-Object -Last 1
        $xml = [xml](Get-Content -LiteralPath $xmlFile.FullName -Raw)
        $opts = @($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })
        $opts | Should -Not -Contain 'Enabled:Audit Mode'
        foreach ($n in 6, 9, 10, 17) { $opts | Should -Contain $script:optionText[$n] }
        $xml.SiPolicy.PolicyID | Should -Be $script:baseId
        $s.BasePolicyId | Should -Be $script:baseId
        # Option 3 is removed from the one copy of the toolkit's own base, once.
        $deletes = @(Get-OpsMutationRecord -Path $script:enf.ExecuteLog | Where-Object { $_.Command -eq 'Set-RuleOption' -and $_.Detail -match 'option=3;delete=True' })
        $deletes.Count | Should -Be 1
        $deletes[0].Target | Should -Match 'base-enforced'
    }

    It 'keeps an audit-mode copy of the base for rollback and names the reviewed file for the toolkit' {
        $restoreXml = Get-ChildItem -LiteralPath $script:enfReports -Filter 'wdac-enforce-audit-restore-*.xml' -File | Select-Object -First 1
        $xml = [xml](Get-Content -LiteralPath $restoreXml.FullName -Raw)
        (@($xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })) | Should -Contain 'Enabled:Audit Mode'
        $names = @(Get-OpsMutationRecord -Path $script:enf.ExecuteLog | Where-Object { $_.Command -eq 'Set-CIPolicyIdInfo' })
        $names.Count | Should -Be 1
        $names[0].Detail | Should -Be "name=$($script:suppName);reset=False;supplements="
        # The reviewed file itself is never edited.
        ([xml](Get-Content -LiteralPath $script:enfReviewed -Raw)).SiPolicy.PolicyID | Should -Be $script:suppId
    }

    It 'deploys the supplemental policy then the enforced base with CiTool, and records a rollback file, when elevated' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $calls = @(Get-CiCall -Log $script:enf.ExecuteLog)
        $calls.Count | Should -Be 2
        $calls[0] | Should -Match '^--update-policy .*wdac-enforce-allow-rules-bbbbbbbb-1111-4222-8333-444444444444\.cip --json$'
        $calls[1] | Should -Match '^--update-policy .*wdac-enforce-base-enforced-aaaaaaaa-1111-4222-8333-444444444444\.cip --json$'
        $rb = Get-Content -LiteralPath $script:enf.Execute.Summary.RollbackJsonPath -Raw | ConvertFrom-Json
        $rb.PolicyName | Should -Be $script:baseName
        $rb.BasePolicyId | Should -Be $script:baseId
        $rb.SupplementalPolicyId | Should -Be $script:suppId
        $rb.AuditCipSha256 | Should -Match '^[0-9a-f]{64}$'
        @($rb.ChangedSettings).Count | Should -Be 2
    }

    It 'skips both deployments and writes no rollback file when not elevated' {
        if ($script:isElevated) {
            Set-ItResult -Skipped -Because 'only meaningful in an unelevated session'
            return
        }
        @(Get-CiCall -Log $script:enf.ExecuteLog).Count | Should -Be 0
        (Get-StateByCategory -ReportDirectory $script:enfReports -Category 'EnforceBasePolicy').Result | Should -Be 'Skipped: requires elevation'
        (Get-StateByCategory -ReportDirectory $script:enfReports -Category 'DeploySupplementalPolicy').Result | Should -Be 'Skipped: requires elevation'
        $script:enf.Execute.Summary.RollbackJsonPath | Should -BeNullOrEmpty
    }

    It 'stops after a failed supplemental deployment and never touches the base (elevated only)' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $reports = New-WorkDirectory 'enf-failupdate'
        $r = Invoke-EnfOnce -Argument (Get-EnforceArgument -AuditDir $script:enfAudit -Reviewed $script:enfReviewed -Reports $reports) -Execute -Environment @{ OPSTOOLKIT_TEST_CITOOL_FAIL_UPDATE = '1' }
        $r.Run.ExitCode | Should -Not -Be 0
        $calls = @(Get-CiCall -Log $r.Log)
        $calls.Count | Should -Be 1
        $calls[0] | Should -Match 'allow-rules'
    }

    It 'refuses every unsafe starting point, under -WhatIf and when executing, and changes nothing' {
        $noSupp = Get-GoodActive
        $cases = @(
            @{ Name = 'audit base not active'; Active = (Get-ActiveJson); Setting = 'AuditBaseActive'; Match = 'not an active policy' },
            @{ Name = 'audit base under a foreign name'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name 'Microsoft Windows Driver Policy'))); Setting = 'AuditBaseActive'; Match = 'another name' },
            @{ Name = 'audit base differs in case'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name 'OPS-TOOLKIT WDAC AUDIT'))); Setting = 'AuditBaseActive'; Match = 'another name' },
            @{ Name = 'audit base already enforced'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name $script:baseName -Enforced $true))); Setting = 'AuditBaseActive'; Match = 'already reports as enforced' },
            @{ Name = 'base lacks option 17'; Audit = (New-AuditDirectory -Omit 17); Setting = 'AllowsSupplementalPolicies'; Match = 'option 17' },
            @{ Name = 'base lacks option 9'; Audit = (New-AuditDirectory -Omit 9); Setting = 'BootSafetyOptions'; Match = 'option 9' },
            @{ Name = 'base lacks option 10'; Audit = (New-AuditDirectory -Omit 10); Setting = 'BootSafetyOptions'; Match = 'or 10' },
            @{ Name = 'base xml lacks Audit Mode (already enforced on disk)'; Audit = (New-AuditDirectory -Omit 3); Setting = 'AuditBaseRecord'; Match = 'Audit Mode' },
            @{ Name = 'no audit record'; Audit = (New-AuditDirectory -NoRecord); Setting = 'AuditBaseRecord'; Match = 'no unconsumed' },
            @{ Name = 'audit record names another policy'; Audit = (New-AuditDirectory -PolicyName 'Microsoft Windows Driver Policy'); Setting = 'AuditBaseRecord'; Match = 'not .ops-toolkit WDAC audit' },
            @{ Name = 'reviewed file supplements another base'; Reviewed = (New-ReviewedFile -ForBase $script:otherId); Setting = 'AllowRulesFile'; Match = 'not the audit base' },
            @{ Name = 'reviewed file is a base policy'; Reviewed = (New-ReviewedFile -Type 'Base Policy'); Setting = 'AllowRulesFile'; Match = 'not a Supplemental Policy' },
            @{ Name = 'reviewed file has no rules'; Reviewed = (New-ReviewedFile -Rules 0); Setting = 'AllowRulesFile'; Match = 'no allow rules' },
            @{ Name = 'reviewed file carries Audit Mode'; Reviewed = (New-ReviewedFile -AuditMode); Setting = 'AllowRulesFile'; Match = 'Audit Mode' },
            @{ Name = 'reviewed file has the base ID as its own'; Reviewed = (New-ReviewedFile -Id $script:baseId); Setting = 'AllowRulesFile'; Match = 'no policy ID of its own' },
            @{ Name = 'reviewed file is not XML'; Reviewed = (New-ReviewedFile -Raw 'this is not xml'); Setting = 'AllowRulesFile'; Match = 'could not be read as XML' },
            @{ Name = 'reviewed file declares a DTD'; Reviewed = (New-ReviewedFile -Raw '<?xml version="1.0"?><!DOCTYPE SiPolicy [<!ENTITY x "y">]><SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"/>'); Setting = 'AllowRulesFile'; Match = 'could not be read as XML' },
            @{ Name = 'reviewed file is missing'; Reviewed = (Join-Path $script:workRoot 'missing-reviewed.xml'); Setting = 'AllowRulesFile'; Match = 'was not found' },
            @{ Name = 'an allow-rules policy is already active by name'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name $script:baseName), (Get-PolicyJson -Id $script:otherId -Name $script:suppName))); Setting = 'NoActiveAllowRules'; Match = 'already active' },
            @{ Name = 'the reviewed ID is already active'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name $script:baseName), (Get-PolicyJson -Id $script:suppId -Name 'Something else'))); Setting = 'NoActiveAllowRules'; Match = 'already active' },
            @{ Name = 'removal of Audit Mode does not take'; Environment = @{ OPSTOOLKIT_TEST_CI_IGNORE_OPTION = '3' }; Setting = 'EnforcedPolicyBuilt'; Match = 'still carries Enabled:Audit Mode' }
        )
        foreach ($case in $cases) {
            $audit = if ($case.Audit) { $case.Audit } else { $script:enfAudit }
            $reviewed = if ($case.Reviewed) { $case.Reviewed } else { $script:enfReviewed }
            $active = if ($case.Active) { $case.Active } else { $noSupp }
            $environment = if ($case.Environment) { $case.Environment } else { @{} }
            $reports = New-WorkDirectory 'enf-refuse'
            $arg = Get-EnforceArgument -AuditDir $audit -Reviewed $reviewed -Reports $reports
            $pair = Invoke-EnfPair -Argument $arg -Active $active -Environment $environment
            $pair.WhatIf.ExitCode | Should -Be 0 -Because "$($case.Name): a preview only previews: $($pair.WhatIf.Output)"
            $pair.Execute.ExitCode | Should -Not -Be 0 -Because "$($case.Name) must be refused"
            (Get-StateItem -ReportDirectory $reports -Setting $case.Setting).Result | Should -Match "^Failed: .*$($case.Match)" -Because $case.Name
            foreach ($log in $pair.WhatIfLog, $pair.ExecuteLog) {
                @(Get-CiCall -Log $log).Count | Should -Be 0 -Because "$($case.Name): nothing is deployed or removed"
            }
            @(Get-ChildItem -LiteralPath $reports -Filter 'wdac-enforce-rollback-*.json').Count | Should -Be 0 -Because $case.Name
            $deploy = Get-StateByCategory -ReportDirectory $reports -Category 'EnforceBasePolicy'
            $deploy.Result | Should -Match '^Skipped' -Because "$($case.Name): the base is never redeployed"
        }
    }

    It 'does not treat an unreadable policy list as a pass' {
        $reports = New-WorkDirectory 'enf-unread'
        $arg = Get-EnforceArgument -AuditDir $script:enfAudit -Reviewed $script:enfReviewed -Reports $reports
        $r = Invoke-EnfOnce -Argument $arg -Execute -Active '{"OperationResult":-2147024891}'
        @(Get-CiCall -Log $r.Log).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $reports -Setting 'ActivePolicies').Result | Should -Match '^(Skipped: requires elevation|Failed: active policies could not be read)'
        (Get-StateItem -ReportDirectory $reports -Setting 'AuditBaseActive').Result | Should -Match '^(Skipped: requires elevation|Failed: not verified because active policies could not be read)'
        if ($script:isElevated) {
            $r.Run.ExitCode | Should -Not -Be 0
        }
    }

    It 'imports ConfigCI itself, so a -WhatIf run started as the entry point still builds and previews (direct pwsh -File, .cmd stand-in)' {
        $reports = Join-Path $script:workRoot 'enf-direct-reports'
        $log = Join-Path $script:workRoot 'enf-direct.log'
        $fakeCiTool = Join-Path $script:workRoot 'enf-direct-citool.cmd'
        $ciLog = Join-Path $script:workRoot 'enf-direct-citool.log'
        @(
            '@echo off'
            '>> "%OPSTOOLKIT_TEST_CITOOL_LOG%" echo %*'
            'if "%1"=="--list-policies" goto list'
            'echo {"OperationResult":0}'
            'exit /b 0'
            ':list'
            'echo %OPSTOOLKIT_TEST_CITOOL_POLICIES%'
            'exit /b 0'
        ) | Set-Content -LiteralPath $fakeCiTool -Encoding ascii
        $names = 'PSModulePath', 'OPSTOOLKIT_TEST_CITOOL_POLICIES', 'OPSTOOLKIT_TEST_CITOOL_LOG'
        $saved = @{}
        foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
        try {
            [Environment]::SetEnvironmentVariable('PSModulePath', "$script:systemModulePath$([IO.Path]::PathSeparator)$($saved['PSModulePath'])")
            [Environment]::SetEnvironmentVariable('OPSTOOLKIT_TEST_CITOOL_POLICIES', (Get-GoodActive))
            [Environment]::SetEnvironmentVariable('OPSTOOLKIT_TEST_CITOOL_LOG', $ciLog)
            $process = Start-Process -FilePath (Get-Process -Id $PID).Path -NoNewWindow -Wait -PassThru `
                -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$script:enfFullPath`"", '-Mode', 'Enforce', '-AuditReportDirectory', "`"$($script:enfAudit)`"", '-AllowRulesPolicyPath', "`"$($script:enfReviewed)`"", '-ReportDirectory', "`"$reports`"", '-CiToolPath', "`"$fakeCiTool`"", '-WhatIf') `
                -RedirectStandardOutput $log -RedirectStandardError "$log.err"
        } finally {
            foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        }
        $process.ExitCode | Should -Be 0 -Because ((Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath "$log.err" -Raw -ErrorAction SilentlyContinue))
        $calls = @(Get-Content -LiteralPath $ciLog -ErrorAction SilentlyContinue)
        @($calls | Where-Object { $_ -match '--list-policies' }).Count | Should -BeGreaterThan 0 -Because 'the script must have used the stand-in CiTool'
        @($calls | Where-Object { $_ -match '--update-policy|--remove-policy' }).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $reports -Setting 'ConfigCI').Result | Should -Be 'Met'
        (Get-StateItem -ReportDirectory $reports -Setting 'EnforcedPolicyBuilt').Result | Should -Be 'Met'
        $expected = if ($script:isElevated) { 'Previewed' } else { 'Skipped: requires elevation' }
        (Get-StateByCategory -ReportDirectory $reports -Category 'EnforceBasePolicy').Result | Should -Be $expected
    }
}

Describe 'Set-WdacEnforcedPolicy -Rollback' {
    It 'restores audit mode first, then removes the supplemental policy, and never removes the base' {
        $fx = New-EnfRollbackDir
        $pair = Invoke-EnfOnce -Argument @{ ReportDirectory = $fx.Dir; Rollback = $true } -Active (Get-EnfActive -Base -Supp)
        $pair.Run.ExitCode | Should -Be 0 -Because $pair.Run.Output
        @(Get-OpsMutationRecord -Path $pair.Log).Count | Should -Be 0 -Because '-WhatIf changes nothing'
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue -Because '-WhatIf never consumes the file'
        $plan = @(Get-Content -LiteralPath $pair.Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        $rows = @($plan | Where-Object { $_.Category -in 'RestoreAuditBase', 'RemoveSupplementalPolicy' })
        $rows.Count | Should -Be 2
        $rows[0].Category | Should -Be 'RestoreAuditBase'
        $rows[0].Setting | Should -Be $script:baseId
        $rows[0].DesiredValue | Should -Be 'audit mode'
        $rows[1].Category | Should -Be 'RemoveSupplementalPolicy'
        $rows[1].Setting | Should -Be $script:suppId
        @($plan | Where-Object { $_.Action -match '--remove-policy' -and $_.Setting -eq $script:baseId }).Count | Should -Be 0

        $live = Invoke-EnfRollback -Dir $fx.Dir -Execute
        if (-not $script:isElevated) {
            $live.Run.ExitCode | Should -Be 0 -Because $live.Run.Output
            @(Get-CiCall -Log $live.Log).Count | Should -Be 0
            (Get-StateItem -ReportDirectory $fx.Dir -Mode 'rollback' -Setting $script:baseId).Result | Should -Be 'Skipped: requires elevation'
            Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue -Because 'a run that skipped its items leaves the file for a retry'
            Set-ItResult -Skipped -Because 'requires an elevated session to record the CiTool calls'
            return
        }
        $live.Run.ExitCode | Should -Be 0 -Because $live.Run.Output
        $calls = @(Get-CiCall -Log $live.Log)
        $calls.Count | Should -Be 2
        $calls[0] | Should -Be "--update-policy $($fx.Cip) --json"
        $calls[1] | Should -Be "--remove-policy $($script:suppId) --json"
        @($calls | Where-Object { $_ -match 'remove-policy' -and $_ -match 'AAAAAAAA' }).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeFalse
        @(Get-ChildItem -LiteralPath $fx.Dir -Filter 'wdac-enforce-rollback-20260101_000000.consumed-*.json').Count | Should -Be 1
    }

    It 'validates the whole file before any plan or change, under -WhatIf, and names the file' {
        $other = '{DDDDDDDD-1111-4222-8333-444444444444}'
        $cases = @(
            @{ Name = 'top level names another policy'; Why = "PolicyName '[^']*' is not"; Top = @{ PolicyName = 'Microsoft Windows Driver Policy' } },
            @{ Name = 'top level name differs in case'; Why = "PolicyName '[^']*' is not"; Top = @{ PolicyName = 'OPS-TOOLKIT WDAC AUDIT' } },
            @{ Name = 'supplemental name is another'; Why = "SupplementalPolicyName 'Evil' is not"; Top = @{ SupplementalPolicyName = 'Evil' } },
            @{ Name = 'base ID is an option'; Top = @{ BasePolicyId = '--remove-policy' } },
            @{ Name = 'base ID has an extra token'; Top = @{ BasePolicyId = "$($script:baseId) --json" } },
            @{ Name = 'base ID has a trailing newline'; Top = @{ BasePolicyId = "$($script:baseId)`n" } },
            @{ Name = 'supplemental ID is not a GUID'; Top = @{ SupplementalPolicyId = 'all' } },
            @{ Name = 'supplemental ID equals the base ID'; Why = 'are the same'; Top = @{ SupplementalPolicyId = $script:baseId } },
            @{ Name = 'audit cip names another file'; Why = "AuditCipPath '[^']*' is not the"; Top = @{ AuditCipPath = 'E:\reports\evil.cip' } },
            @{ Name = 'audit cip names another policy'; Why = "AuditCipPath '[^']*' is not the"; Top = @{ AuditCipPath = "E:\reports\wdac-enforce-audit-restore-$($other.Trim('{','}').ToLower()).cip" } },
            @{ Name = 'supplemental cip names another file'; Why = "SupplementalCipPath '[^']*' is not the"; Top = @{ SupplementalCipPath = 'E:\reports\evil.cip' } },
            @{ Name = 'sha is not a SHA-256'; Why = 'is not a SHA-256 hash'; Top = @{ AuditCipSha256 = 'abc' } },
            @{ Name = 'top level lacks the sha'; Top = @{ AuditCipSha256 = '__remove__' } },
            @{ Name = 'top level lacks the base ID'; Top = @{ BasePolicyId = '__remove__' } },
            @{ Name = 'a value is the wrong type'; Top = @{ BasePolicyId = 5 } },
            @{ Name = 'entry category is another one'; Entry = @{ Category = 'RemoveAuditPolicy' } },
            @{ Name = 'entry lacks a category'; Entry = @{ Category = '__remove__' } },
            @{ Name = 'entry carries another base ID'; Entry = @{ BasePolicyId = $other } },
            @{ Name = 'entry names another policy'; Why = "PolicyName 'Evil' is not"; Entry = @{ PolicyName = 'Evil' } }
        )
        foreach ($case in $cases) {
            $dir = New-WorkDirectory 'enfrb-safety'
            $fx = New-EnfRollbackDir -Dir $dir
            $top = if ($case.Top) { $case.Top } else { @{} }
            $sha = $fx.Sha
            $entry = if ($case.Entry) { New-EnfRecord -Dir $dir -Entry -Sha $sha -Override $case.Entry } else { New-EnfRecord -Dir $dir -Entry -Sha $sha }
            $null = New-EnfRollbackDir -Dir $dir -Top $top -Entries @($entry)
            Assert-EnfRollbackRefused -Dir $dir -FileName 'wdac-enforce-rollback-20260101_000000.json' -Because $case.Name -Why $(if ($case.Why) { $case.Why } else { '' })
        }
    }

    It 'refuses a file that is not JSON or has no usable ChangedSettings array, and names the offending entry by index' {
        $bodies = [ordered]@{
            'not JSON'                = 'this is { not json'
            'ChangedSettings missing' = '{ "BasePolicyId": "{AAAAAAAA-1111-4222-8333-444444444444}" }'
            'ChangedSettings a string' = '{ "ChangedSettings": "all" }'
            'ChangedSettings empty'   = '{ "ChangedSettings": [] }'
            'top level is an array'   = '[ { "BasePolicyId": "x" } ]'
            'entry is null'           = '{ "ChangedSettings": [ null ] }'
        }
        foreach ($label in $bodies.Keys) {
            $dir = New-WorkDirectory 'enfrb-shape'
            Set-Content -LiteralPath (Join-Path $dir 'wdac-enforce-rollback-20260101_000000.json') -Value $bodies[$label] -Encoding utf8
            Assert-EnfRollbackRefused -Dir $dir -FileName 'wdac-enforce-rollback-20260101_000000.json' -Because $label
        }
        $dir = New-WorkDirectory 'enfrb-index'
        $fx = New-EnfRollbackDir -Dir $dir
        $good = New-EnfRecord -Dir $dir -Entry -Sha $fx.Sha
        $bad = New-EnfRecord -Dir $dir -Entry -Sha $fx.Sha -Override @{ PolicyName = 'Evil' }
        $null = New-EnfRollbackDir -Dir $dir -Entries @($good, $good, $bad)
        $r = Invoke-EnfRollback -Dir $dir
        $r.Run.ExitCode | Should -Not -Be 0
        Get-FlatText $r.Run.Output | Should -Match 'entry 2 \(zero-based\)'
    }

    It 'refuses to touch a recorded policy ID that is active under another name' {
        foreach ($case in @(
                @{ Name = 'base'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name 'Microsoft Windows Driver Policy' -Enforced $true))) },
                @{ Name = 'supplemental'; Active = (Get-ActiveJson -Policy @((Get-PolicyJson -Id $script:baseId -Name $script:baseName), (Get-PolicyJson -Id $script:suppId -Name 'Somebody else'))) }
            )) {
            $fx = New-EnfRollbackDir
            Assert-EnfRollbackRefused -Dir $fx.Dir -FileName 'wdac-enforce-rollback-20260101_000000.json' -Because "$($case.Name) under a foreign name" -Active $case.Active
            Get-FlatText (Invoke-EnfRollback -Dir $fx.Dir -Active $case.Active).Run.Output | Should -Match 'did not deploy it and will not change it'
        }
    }

    It 'does not treat an unreadable policy list as a pass, and leaves the file unconsumed' {
        $fx = New-EnfRollbackDir
        $r = Invoke-EnfRollback -Dir $fx.Dir -Execute -Active '{"OperationResult":-2147024891}'
        $r.Run.ExitCode | Should -Not -Be 0
        @(Get-CiCall -Log $r.Log).Count | Should -Be 0
        (Get-StateItem -ReportDirectory $fx.Dir -Mode 'rollback' -Setting 'ActivePolicies').Result | Should -Match '^Failed: active policies could not be read'
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue
        # Under -WhatIf the refusal is in the state report and the run still exits 0.
        $w = Invoke-EnfRollback -Dir $fx.Dir -Active '{"OperationResult":-2147024891}'
        $w.Run.ExitCode | Should -Be 0
        (Get-StateItem -ReportDirectory $fx.Dir -Mode 'rollback' -Setting $script:baseId).Action | Should -Match '^Refused'
    }

    It 'does not redeploy an audit-mode binary that is missing or no longer matches its recorded hash' {
        foreach ($case in @(@{ Name = 'tampered'; Splat = @{ TamperCip = $true } }, @{ Name = 'missing'; Splat = @{ NoCip = $true } })) {
            $splat = $case.Splat
            $fx = New-EnfRollbackDir @splat
            $r = Invoke-EnfRollback -Dir $fx.Dir -Execute
            $r.Run.ExitCode | Should -Not -Be 0 -Because $case.Name
            @(Get-CiCall -Log $r.Log).Count | Should -Be 0 -Because "$($case.Name): nothing is deployed or removed"
            (Get-StateItem -ReportDirectory $fx.Dir -Mode 'rollback' -Setting 'AuditRestoreFile').Result | Should -Match '^Failed: ' -Because $case.Name
            Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue -Because $case.Name
        }
    }

    It 'never resurrects a base that is no longer active, and removes only the supplemental policy' {
        $fx = New-EnfRollbackDir
        $r = Invoke-EnfRollback -Dir $fx.Dir -Execute -Active (Get-EnfActive -Supp)
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        (Get-StateItem -ReportDirectory $fx.Dir -Mode 'rollback' -Setting $script:baseId).Result | Should -Be 'NoChange'
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session to record the CiTool calls'
            return
        }
        $calls = @(Get-CiCall -Log $r.Log)
        $calls.Count | Should -Be 1
        $calls[0] | Should -Be "--remove-policy $($script:suppId) --json"
    }

    It 'skips the removal when restoring the base fails (elevated only)' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $fx = New-EnfRollbackDir
        $r = Invoke-EnfRollback -Dir $fx.Dir -Execute -Environment @{ OPSTOOLKIT_TEST_CITOOL_FAIL_UPDATE = '1' }
        $r.Run.ExitCode | Should -Not -Be 0
        $calls = @(Get-CiCall -Log $r.Log)
        $calls.Count | Should -Be 1
        $calls[0] | Should -Match '^--update-policy'
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue -Because 'a failed run leaves the file for a retry'
    }

    It 'uses the newest rollback file by exact name and never a consumed one' {
        $dir = New-WorkDirectory 'enfrb-newest'
        $null = New-EnfRollbackDir -Dir $dir -Name 'wdac-enforce-rollback-20260101_000000.json'
        $newBase = '{EEEEEEEE-1111-4222-8333-444444444444}'
        $newSupp = '{FFFFFFFF-1111-4222-8333-444444444444}'
        $null = New-EnfRollbackDir -Dir $dir -Name 'wdac-enforce-rollback-20260201_000000.json' -Base $newBase -Supp $newSupp
        # A newer consumed file and a lookalike are unreadable on purpose: picking either would fail loudly.
        Set-Content -LiteralPath (Join-Path $dir 'wdac-enforce-rollback-20260301_000000.consumed-20260302_000000.json') -Value 'garbage' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $dir 'wdac-enforce-rollback-20260401_000000.json.bak') -Value 'garbage' -Encoding utf8
        $r = Invoke-EnfOnce -Argument @{ ReportDirectory = $dir; Rollback = $true } -Active (Get-ActiveJson)
        $r.Run.ExitCode | Should -Be 0 -Because $r.Run.Output
        $r.Run.Summary.RollbackSourcePath | Should -Match 'wdac-enforce-rollback-20260201_000000\.json$'
        $plan = @(Get-Content -LiteralPath $r.Run.Summary.PlanJsonPath -Raw | ConvertFrom-Json)
        ($plan | Where-Object Category -eq 'RestoreAuditBase').Setting | Should -Be $newBase
        ($plan | Where-Object Category -eq 'RemoveSupplementalPolicy').Setting | Should -Be $newSupp
    }

    It 'renames the file to .consumed- only after a clean executing run' {
        if (-not $script:isElevated) {
            Set-ItResult -Skipped -Because 'requires an elevated session'
            return
        }
        $fx = New-EnfRollbackDir
        $null = Invoke-EnfRollback -Dir $fx.Dir
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeTrue
        $live = Invoke-EnfRollback -Dir $fx.Dir -Execute
        $live.Run.ExitCode | Should -Be 0 -Because $live.Run.Output
        Test-Path -LiteralPath (Join-Path $fx.Dir 'wdac-enforce-rollback-20260101_000000.json') | Should -BeFalse
        $live.Run.Summary.RollbackConsumedPath | Should -Match 'wdac-enforce-rollback-20260101_000000\.consumed-\d{8}_\d{6}\.json$'
        # With the consumed file the only one left, a second rollback has nothing to do.
        $again = Invoke-EnfRollback -Dir $fx.Dir -Execute
        $again.Run.ExitCode | Should -Not -Be 0
        Get-FlatText $again.Run.Output | Should -Match 'Nothing to roll back'
    }
}
