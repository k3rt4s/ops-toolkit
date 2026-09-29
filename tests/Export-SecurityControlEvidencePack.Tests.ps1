#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ScriptFunction -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
        -FunctionName @('Get-OpsEndpointCoverageStatus', 'Get-OpsControlConclusion')
}

Describe 'Security evidence-pack endpoint coverage decisions' {
    It 'reports a known management-plane or reconciliation gap as NotMet' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 1 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotMet'
    }

    It 'keeps the result NotAssessed when a required authority was unread' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 1 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }

    It 'keeps the result NotAssessed when inventory could not be read or was empty' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $false -DeviceCount 0 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 0 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }

    It 'reports Met only when both evidence sources are readable and complete' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'Met'
    }

    It 'requires two readable required authorities including the Defender inventory' {
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 1 -DefenderAuthorityIncluded $true `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
        Get-OpsEndpointCoverageStatus -InventoryReadable $true -DeviceCount 2 `
            -CoverageReadable $true -ReconciledPopulationCount 2 `
            -RequiredAuthoritiesRead 2 -DefenderAuthorityIncluded $false `
            -AttentionCount 0 -CoverageGapCount 0 -UnreadRequiredCount 0 -UndeterminedCount 0 |
            Should -Be 'NotAssessed'
    }
}

Describe 'Security evidence-pack conclusion language' {
    It 'describes evidence without declaring framework conformance' {
        foreach ($status in @('Met', 'NotMet', 'Partial', 'NotAssessed')) {
            $conclusion = Get-OpsControlConclusion -Status $status
            $conclusion | Should -Not -Match '(?i)compliant|conformant|certified|maturity'
        }
    }
}

Describe 'Security evidence-pack host requirement' {
    It 'fails fast before collectors on Windows PowerShell 5.1' {
        $firstLine = Get-Content `
            (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1') `
            -First 1
        $firstLine | Should -Be '#Requires -Version 7.0'
    }
}

Describe 'Security evidence-pack IR-02 cloud incident readiness wiring' {
    BeforeAll {
        # Add-Control, Invoke-Collector, and Get-CollectorSummary close over
        # top-level $controls / $collectorRuns state that is not $script:-prefixed,
        # so Import-ScriptFunction (which only lifts $script:-prefixed assignments
        # alongside function bodies) cannot bring this wiring into a callable,
        # mockable scope, and running it for real means a live Graph/Azure session
        # for every Entra-gated control, not just this one. That is true today of
        # IAM-01, IAM-02, MFA-01, and MFA-02 as well: none of them have a
        # behavioral test in this suite either. Until that seam exists, these specs
        # verify the wiring in the source itself, the same way the host-requirement
        # spec above verifies the #Requires line, rather than asserting on values a
        # live run would have to produce.
        $script:packSource = Get-Content -Raw `
            (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1')
    }

    It 'calls the cloud incident readiness collector with an argument list built from -Connect plus any opt-in pass-through' {
        $script:packSource | Should -Match (
            [regex]::Escape("Invoke-Collector -Name 'entra-cloud-incident-readiness' -RelativePath 'entra\Export-CloudIncidentReadiness.ps1' -Argument @(`$cloudIrArgument)")
        )
        $script:packSource | Should -Match ([regex]::Escape("`$cloudIr = Get-CollectorSummary -Run `$cloudIrRun"))
    }

    It 'defaults the cloud incident readiness argument list to only -Connect, unchanged from before the pass-through inputs existed' {
        $script:packSource | Should -Match (
            [regex]::Escape("`$cloudIrArgument = [System.Collections.Generic.List[string]]::new()") +
            "\s*" + [regex]::Escape("`$cloudIrArgument.Add('-Connect')")
        )
    }

    It 'forwards -AzureSubscriptionId as -ConnectAzure plus one comma-joined -SubscriptionId value, only when supplied' {
        $script:packSource | Should -Match (
            [regex]::Escape("if (`$AzureSubscriptionId -and `$AzureSubscriptionId.Count -gt 0) {") +
            "[\s\S]{0,40}" + [regex]::Escape("`$cloudIrArgument.Add('-ConnectAzure')") +
            "[\s\S]{0,40}" + [regex]::Escape("`$cloudIrArgument.Add('-SubscriptionId')") +
            "[\s\S]{0,200}" + [regex]::Escape("`$cloudIrArgument.Add((`$AzureSubscriptionId -join ','))")
        )
    }

    It 'forwards -BreakGlassUpn as one comma-joined value, only when supplied' {
        $script:packSource | Should -Match (
            [regex]::Escape("if (`$BreakGlassUpn -and `$BreakGlassUpn.Count -gt 0) {") +
            "[\s\S]{0,40}" + [regex]::Escape("`$cloudIrArgument.Add('-BreakGlassUpn')") +
            "[\s\S]{0,40}" + [regex]::Escape("`$cloudIrArgument.Add((`$BreakGlassUpn -join ','))")
        )
    }

    It 'validates -AzureSubscriptionId values are GUID-shaped and -BreakGlassUpn values are non-empty' {
        $script:packSource | Should -Match ([regex]::Escape("is not a GUID. Supply the subscription's GUID"))
        $script:packSource | Should -Match ([regex]::Escape("-BreakGlassUpn cannot contain an empty or whitespace-only value."))
    }

    It "documents in help that IR-02 stays NotAssessed for those checks without the opt-in inputs" {
        $script:packSource | Should -Match ([regex]::Escape('IR-02 still'))
        $script:packSource | Should -Match ([regex]::Escape('stay NotAssessed'))
    }

    It 'reports IR-02 NotAssessed when the collector produced no summary, without folding it into a pass' {
        $script:packSource | Should -Match (
            "if \(\`$null -eq \`$cloudIr\) \{\s*" +
            [regex]::Escape("Add-Control -Id 'IR-02'") + "[\s\S]{0,150}" +
            [regex]::Escape("-Status 'NotAssessed'")
        )
    }

    It "flows the collector's own OverallStatus straight into the IR-02 grade" {
        $script:packSource | Should -Match (
            [regex]::Escape("`$cloudIrOverallStatus = [string](Get-OpsPropertyValue -InputObject `$cloudIr -Name 'OverallStatus')")
        )
        $script:packSource | Should -Match (
            [regex]::Escape("Add-Control -Id 'IR-02'") +
            "[\s\S]{0,200}-Status `\`$cloudIrOverallStatus"
        )
        $script:packSource | Should -Match ([regex]::Escape("-Collector 'Export-CloudIncidentReadiness.ps1'"))
    }

    It 'falls back to NotAssessed when the collector summary carries an unrecognized OverallStatus' {
        $script:packSource | Should -Match (
            [regex]::Escape("if (`$cloudIrOverallStatus -notin @('Met', 'NotMet', 'Partial', 'NotAssessed')) {") +
            "[\s\S]{0,200}" + [regex]::Escape("-Status 'NotAssessed'")
        )
    }

    It 'uses the same control question text everywhere IR-02 is referenced' {
        $question = 'Could this tenant support an incident investigation today?'
        @($script:packSource | Select-String -Pattern ([regex]::Escape($question)) -AllMatches).Matches.Count |
            Should -BeGreaterOrEqual 2
    }

    It 'lists IR-02 as NotAssessed alongside the other identity controls when -IncludeEntra is off' {
        $script:packSource | Should -Match (
            "@\('IAM-02', 'Are application credentials rotated before they expire\?'\),\s*" +
            [regex]::Escape("@('IR-02', 'Could this tenant support an incident investigation today?')")
        )
    }

    It 'mentions Graph activity logs in the IR-02 finding text so the check list matches what the collector actually runs' {
        $script:packSource | Should -Match (
            [regex]::Escape("Covers Unified Audit Log ingestion, Entra and subscription log export, Graph activity logs, destination workspace retention")
        )
    }
}

Describe 'Security evidence-pack IR-02 scope classification' {
    BeforeAll {
        Import-ScriptFunction -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1' `
            -FunctionName @('Get-OpsControlScopeKind')
    }

    It 'classifies IR-02 as EntraTenant, not EndpointPopulation, despite matching the LOG- pattern' {
        Get-OpsControlScopeKind -ControlId 'IR-02' | Should -Be 'EntraTenant'
    }

    It 'leaves IR-01 classified as Organization, unchanged by the IR-02 addition' {
        Get-OpsControlScopeKind -ControlId 'IR-01' | Should -Be 'Organization'
    }
}

Describe 'Security evidence-pack -AzureSubscriptionId and -BreakGlassUpn validation' {
    BeforeAll {
        $script:packPath = Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1'
        $script:validationWorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) "evidence-pack-validation-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:validationWorkRoot -Force | Out-Null
    }

    AfterAll {
        Remove-Item -LiteralPath $script:validationWorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'rejects an -AzureSubscriptionId value that is not GUID-shaped' {
        {
            & $script:packPath -AzureSubscriptionId 'not-a-guid' `
                -OutputDirectory (Join-Path $script:validationWorkRoot 'bad-subscription-id')
        } | Should -Throw '*is not a GUID*'
    }

    It 'does not reject a GUID-shaped -AzureSubscriptionId value on the GUID check itself' {
        # A full run here would execute the real local collectors (slow, and this
        # repo's own "Read this first" warns those can touch machine state); this
        # asserts the GUID validation specifically, via the same pattern the script
        # uses, against a value the script must accept.
        $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        '11111111-1111-1111-1111-111111111111' -match $guidPattern | Should -BeTrue
        $script:packSource = Get-Content -Raw $script:packPath
        $script:packSource | Should -Match ([regex]::Escape($guidPattern))
    }

    It 'rejects a whitespace-only -BreakGlassUpn value' {
        {
            & $script:packPath -BreakGlassUpn '   ' `
                -OutputDirectory (Join-Path $script:validationWorkRoot 'bad-break-glass-upn')
        } | Should -Throw '*cannot contain an empty or whitespace-only value*'
    }
}

Describe 'Security evidence-pack cloud incident readiness arguments bind as lists under pwsh -File' {
    It 'binds a comma-joined -SubscriptionId and -BreakGlassUpn to real lists, leaving -TenantId unbound' {
        # Invoke-Collector launches each collector with Start-Process and pwsh -File,
        # which hands every argument over as a literal string: a second bare value
        # after -SubscriptionId binds positionally to -TenantId. The pack therefore
        # passes one comma-joined value per parameter and the collector splits it.
        # This runs the collector's real param block and split statement, lifted
        # from its AST, through that same launch, so a change to either breaks it.
        $collectorPath = Join-Path $PSScriptRoot '..\scripts\entra\Export-CloudIncidentReadiness.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $collectorPath).Path, [ref]$tokens, [ref]$parseErrors)
        $splitFunction = @($ast.EndBlock.Statements | Where-Object {
                $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'ConvertTo-OpsSplitList'
            })
        $splitStatement = @($ast.EndBlock.Statements | Where-Object {
                $_ -is [System.Management.Automation.Language.ForEachStatementAst] -and $_.Extent.Text -match 'ConvertTo-OpsSplitList'
            })
        $splitFunction.Count | Should -Be 1
        $splitStatement.Count | Should -Be 1

        $probeBody = @(
            $ast.ParamBlock.Extent.Text
            'Set-StrictMode -Version 3.0'
            '$ErrorActionPreference = ''Stop'''
            $splitFunction[0].Extent.Text
            $splitStatement[0].Extent.Text
            '[ordered]@{ TenantId = $TenantId; SubscriptionId = @($SubscriptionId); BreakGlassUpn = @($BreakGlassUpn) } | ConvertTo-Json | Set-Content -LiteralPath $env:OPS_ARGPROBE_OUT -Encoding utf8'
        ) -join [Environment]::NewLine

        $probeScript = Join-Path ([System.IO.Path]::GetTempPath()) "ops-argprobe-$([guid]::NewGuid().ToString('N')).ps1"
        $outFile = Join-Path ([System.IO.Path]::GetTempPath()) "ops-argprobe-$([guid]::NewGuid().ToString('N')).json"
        Set-Content -LiteralPath $probeScript -Encoding utf8 -Value $probeBody

        $subscriptionIds = @('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
        $breakGlassUpns = @('bg1@contoso.com', 'bg2@contoso.com')
        $packArgument = @('-Connect', '-ConnectAzure', '-SubscriptionId', ($subscriptionIds -join ','), '-BreakGlassUpn', ($breakGlassUpns -join ','))
        $arguments = @('-NoProfile', '-NonInteractive', '-File', $probeScript) + $packArgument

        try {
            $env:OPS_ARGPROBE_OUT = $outFile
            $pwshPath = (Get-Process -Id $PID).Path
            $process = Start-Process -FilePath $pwshPath -ArgumentList $arguments -NoNewWindow -PassThru -Wait
            $process.ExitCode | Should -Be 0
            $received = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        } finally {
            Remove-Item Env:\OPS_ARGPROBE_OUT -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $probeScript -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
        }

        $received.TenantId | Should -BeNullOrEmpty
        @($received.SubscriptionId).Count | Should -Be 2
        @($received.SubscriptionId) | Should -Be $subscriptionIds
        @($received.BreakGlassUpn).Count | Should -Be 2
        @($received.BreakGlassUpn) | Should -Be $breakGlassUpns
    }
}

Describe 'Security evidence-pack Invoke-Collector passes -ComputerName as one comma-joined value' {
    BeforeAll {
        $script:packSource = Get-Content -Raw `
            (Get-RepositoryScriptPath -RelativePath 'scripts\reporting\Export-SecurityControlEvidencePack.ps1')
    }

    It 'builds the fan-out argument as a single comma-joined -ComputerName value, not one argument per target' {
        # Under Start-Process pwsh -File every argument is a literal string, so the old
        # shape (@('-ComputerName') + $resolvedTargets, one array element per target)
        # bound only the first two targets: the second target filled -ComputerName and
        # the third had nowhere to bind and failed the launch. The fix is one joined
        # value that the collector splits back into a list itself.
        $script:packSource | Should -Match (
            [regex]::Escape("`$targetArgument = @('-ComputerName', (`$resolvedTargets -join ','))")
        )
        $script:packSource | Should -Not -Match (
            [regex]::Escape("`$targetArgument = @('-ComputerName') + `$resolvedTargets")
        )
    }
}

Describe 'A collector param block binds -ComputerName as a real list under pwsh -File, at one, two, and three targets' {
    BeforeAll {
        # Same technique as the cloud-incident-readiness probe above: lift a real
        # collector's param block, its OpsToolkit.Reporting import, and its real
        # split-when-bound statement straight from the AST, so a change to any of the
        # three breaks this test rather than a hand-copied stand-in silently drifting
        # from the source.
        $collectorPath = Get-RepositoryScriptPath -RelativePath 'scripts\active-directory\Test-LdapSigningReadiness.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($collectorPath, [ref]$tokens, [ref]$parseErrors)

        $importStatement = @($ast.EndBlock.Statements | Where-Object {
                $_.Extent.Text -match 'Import-Module.*OpsToolkit\.Reporting'
            })
        $splitStatement = @($ast.EndBlock.Statements | Where-Object {
                $_ -is [System.Management.Automation.Language.IfStatementAst] -and
                $_.Extent.Text -match 'ConvertTo-OpsSplitList'
            })
        $importStatement.Count | Should -Be 1
        $splitStatement.Count | Should -Be 1

        $reportingModulePath = Join-Path (Get-RepositoryRoot) 'modules\OpsToolkit.Reporting'
        $script:probeBody = @(
            $ast.ParamBlock.Extent.Text
            'Set-StrictMode -Version 3.0'
            '$ErrorActionPreference = ''Stop'''
            "Import-Module '$reportingModulePath' -Force"
            $splitStatement[0].Extent.Text
            '[ordered]@{ Bound = $PSBoundParameters.ContainsKey(''ComputerName''); ComputerName = @($ComputerName) } | ConvertTo-Json | Set-Content -LiteralPath $env:OPS_ARGPROBE_OUT -Encoding utf8'
        ) -join [Environment]::NewLine
    }

    function script:Invoke-ComputerNameProbe {
        param([string[]]$Targets, [switch]$ExpectFailure)

        $probeScript = Join-Path ([System.IO.Path]::GetTempPath()) "ops-cnprobe-$([guid]::NewGuid().ToString('N')).ps1"
        $outFile = Join-Path ([System.IO.Path]::GetTempPath()) "ops-cnprobe-$([guid]::NewGuid().ToString('N')).json"
        $errFile = Join-Path ([System.IO.Path]::GetTempPath()) "ops-cnprobe-$([guid]::NewGuid().ToString('N')).err"
        Set-Content -LiteralPath $probeScript -Encoding utf8 -Value $script:probeBody

        $arguments = @('-NoProfile', '-NonInteractive', '-File', $probeScript)
        if ($Targets) {
            $arguments += @('-ComputerName', ($Targets -join ','))
        }

        try {
            $env:OPS_ARGPROBE_OUT = $outFile
            $pwshPath = (Get-Process -Id $PID).Path
            $process = Start-Process -FilePath $pwshPath -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
                -RedirectStandardError $errFile
            if ($ExpectFailure) {
                [pscustomobject]@{
                    ExitCode = $process.ExitCode
                    StdErr = if (Test-Path -LiteralPath $errFile) { Get-Content -LiteralPath $errFile -Raw } else { '' }
                }
            } else {
                $process.ExitCode | Should -Be 0
                Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
            }
        } finally {
            Remove-Item Env:\OPS_ARGPROBE_OUT -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $probeScript -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
        }
    }

    It 'binds a single target' {
        $received = Invoke-ComputerNameProbe -Targets @('PC1')
        $received.Bound | Should -BeTrue
        @($received.ComputerName).Count | Should -Be 1
        @($received.ComputerName) | Should -Be @('PC1')
    }

    It 'binds two comma-joined targets, the shape that used to bind fine' {
        $received = Invoke-ComputerNameProbe -Targets @('PC1', 'PC2')
        $received.Bound | Should -BeTrue
        @($received.ComputerName).Count | Should -Be 2
        @($received.ComputerName) | Should -Be @('PC1', 'PC2')
    }

    It 'binds three comma-joined targets, the shape that used to fail the launch outright' {
        $received = Invoke-ComputerNameProbe -Targets @('PC1', 'PC2', 'PC3')
        $received.Bound | Should -BeTrue
        @($received.ComputerName).Count | Should -Be 3
        @($received.ComputerName) | Should -Be @('PC1', 'PC2', 'PC3')
    }

    It 'leaves an unbound -ComputerName completely alone, keeping the script''s own default' {
        $received = Invoke-ComputerNameProbe -Targets @()
        $received.Bound | Should -BeFalse
        @($received.ComputerName) | Should -Be @($env:COMPUTERNAME)
    }

    It 'fails loudly and names the parameter when -ComputerName splits to nothing, never falling back to local-only' {
        # A literal ',' splits to an empty list. ConvertTo-OpsSplitList now returns a
        # real empty [string[]] rather than $null, and assigning that back to the
        # [ValidateNotNullOrEmpty()][string[]]$ComputerName parameter variable must
        # still throw, naming ComputerName, rather than silently keeping the script's
        # single-machine default.
        $result = Invoke-ComputerNameProbe -Targets @(',') -ExpectFailure
        $result.ExitCode | Should -Not -Be 0
        $result.StdErr | Should -Match 'ComputerName'
    }
}

Describe 'Every script declaring [string[]]$ComputerName splits it when bound' {
    It 'contains the split-when-bound pattern, so a future collector added without it fails here' {
        $repositoryRoot = Get-RepositoryRoot
        $scriptsRoot = Join-Path $repositoryRoot 'scripts'
        # Whitespace-tolerant between the type and the variable name, so
        # [string[]] $ComputerName (extra space) is selected the same as
        # [string[]]$ComputerName.
        $declaringScripts = @(Get-ChildItem -Path $scriptsRoot -Filter '*.ps1' -Recurse |
                Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match '\[string\[\]\]\s*\$ComputerName\b' })

        $declaringScripts.Count | Should -Be 10

        $missing = @($declaringScripts | Where-Object {
                $text = Get-Content -LiteralPath $_.FullName -Raw
                -not (
                    $text -match [regex]::Escape("if (`$PSBoundParameters.ContainsKey('ComputerName')) {") -and
                    $text -match [regex]::Escape('$ComputerName = ConvertTo-OpsSplitList -Value $ComputerName')
                )
            } | ForEach-Object { $_.FullName })

        $missing | Should -BeNullOrEmpty -Because "these scripts declare [string[]]`$ComputerName but do not split it when bound: $($missing -join ', ')"

        $splitBeforeImport = @($declaringScripts | Where-Object {
                $text = Get-Content -LiteralPath $_.FullName -Raw
                $importIndex = $text.IndexOf('Import-Module')
                $splitIndex = $text.IndexOf('$ComputerName = ConvertTo-OpsSplitList -Value $ComputerName')
                $importIndex -lt 0 -or $splitIndex -lt 0 -or $splitIndex -lt $importIndex
            } | ForEach-Object { $_.FullName })

        $splitBeforeImport | Should -BeNullOrEmpty -Because "these scripts split -ComputerName before importing OpsToolkit.Reporting: $($splitBeforeImport -join ', ')"
    }
}

Describe 'ConvertTo-OpsSplitList (OpsToolkit.Reporting module)' {
    BeforeAll {
        Import-ReportingModule
    }

    # Captured with @(), the idiom every caller in this repository uses, including
    # the script-local copy in Export-CloudIncidentReadiness.ps1 that this function
    # is required to match. The function emits its entries onto the pipeline, so an
    # empty result emits nothing and @() collects it as a zero-length array.

    It 'splits a comma-separated single string into a flat list' {
        $result = @(ConvertTo-OpsSplitList -Value 'PC1,PC2,PC3')
        $result.Count | Should -Be 3
        $result | Should -Be @('PC1', 'PC2', 'PC3')
    }

    It 'trims whitespace around each split value' {
        $result = @(ConvertTo-OpsSplitList -Value ' PC1 , PC2 ,PC3 ')
        $result.Count | Should -Be 3
        $result | Should -Be @('PC1', 'PC2', 'PC3')
    }

    It 'drops empty segments from leading, trailing, or doubled commas' {
        $result = @(ConvertTo-OpsSplitList -Value ',PC1,,PC2,')
        $result.Count | Should -Be 2
        $result | Should -Be @('PC1', 'PC2')
    }

    It 'returns an empty array for $null input' {
        @(ConvertTo-OpsSplitList -Value $null).Count | Should -Be 0
    }

    It 'returns an empty array for a value that splits to nothing' {
        @(ConvertTo-OpsSplitList -Value ' , , ').Count | Should -Be 0
    }

    It 'passes a real array through unchanged' {
        $result = @(ConvertTo-OpsSplitList -Value @('PC1', 'PC2'))
        $result.Count | Should -Be 2
        $result | Should -Be @('PC1', 'PC2')
    }
}

Describe 'Calling a collector directly with a real array behaves exactly as before' {
    BeforeAll {
        $collectorPath = Get-RepositoryScriptPath -RelativePath 'scripts\active-directory\Test-LdapSigningReadiness.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($collectorPath, [ref]$tokens, [ref]$parseErrors)
        $splitStatement = @($ast.EndBlock.Statements | Where-Object {
                $_ -is [System.Management.Automation.Language.IfStatementAst] -and
                $_.Extent.Text -match 'ConvertTo-OpsSplitList'
            })
        $splitStatement.Count | Should -Be 1

        Import-ReportingModule
        $script:probeBlock = [scriptblock]::Create(
            $ast.ParamBlock.Extent.Text + [Environment]::NewLine +
            $splitStatement[0].Extent.Text + [Environment]::NewLine +
            '@($ComputerName)'
        )
    }

    It 'passes a real PowerShell array straight through, unaffected by the split-when-bound guard' {
        # -OutputDirectory is supplied only so its default value expression, which reads
        # $PSScriptRoot, is never evaluated: this scriptblock was built from lifted text
        # rather than run from a file, so $PSScriptRoot is empty here.
        & $script:probeBlock -ComputerName @('dc01', 'dc02') -OutputDirectory $TestDrive |
            Should -Be @('dc01', 'dc02')
    }

    It "leaves the script's own default (@(`$env:COMPUTERNAME)) untouched when -ComputerName is not supplied" {
        & $script:probeBlock -OutputDirectory $TestDrive | Should -Be @($env:COMPUTERNAME)
    }
}
