<#
.SYNOPSIS
Stand-in for the Defender module so scripts that add exclusions never change real antivirus settings.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_MP_EXCLUSIONPATH and OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS to
  semicolon-separated lists describing the exclusions that already exist.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
Relying on a same-named function in the caller's scope to shadow Add-MpPreference did
not work, and a test run added three real Defender path exclusions to a development
machine before that was noticed. An antivirus exclusion is a security control, so this
module exists to make it impossible for a test to create one: the real Defender module
is never loaded, because this one is found first.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakeMpMutation {
    param([string]$Command, [string]$Target, [string]$Detail = '')
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = $Detail } | ConvertTo-Json -Compress)
}

# Detail and Target for a call that carries ASR, Controlled Folder Access, network, PUA or
# cloud parameters. Exclusion-only calls keep the original Target and an empty Detail.
function Get-FakeMpRecord {
    param([hashtable]$Bound)
    $skip = @('ExclusionPath', 'ExclusionProcess', 'Force', 'ErrorAction')
    $keys = @($Bound.Keys | Where-Object { $_ -notin $skip } | Sort-Object)
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $keys) {
        $values = @($Bound[$key] | ForEach-Object { [string]$_ })
        $parts.Add("$key=$($values -join ',')")
    }
    $detail = $parts -join ';'
    $target = if ($keys.Count -eq 0 -or $Bound.ContainsKey('ExclusionPath') -or $Bound.ContainsKey('ExclusionProcess')) {
        (@($Bound['ExclusionPath']) + @($Bound['ExclusionProcess']) | Where-Object { $_ }) -join ';'
    } elseif ($Bound.ContainsKey('AttackSurfaceReductionRules_Ids')) {
        @($Bound['AttackSurfaceReductionRules_Ids']) -join ';'
    } elseif ($Bound.ContainsKey('ControlledFolderAccessAllowedApplications')) {
        @($Bound['ControlledFolderAccessAllowedApplications']) -join ';'
    } else {
        $keys -join ';'
    }
    [pscustomobject]@{ Target = $target; Detail = $detail }
}

function Get-FakeMpEnvValue {
    param([string]$Name, $Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($value)) { return $Default }
    $value
}

# OPSTOOLKIT_TEST_MP_UNREADABLE=1 makes the read throw, as it does when Defender is not the
# running provider. OPSTOOLKIT_TEST_MP_ASR is 'guid=action;guid=action' (unset = no rules,
# which the real cmdlet reports as null lists). The numeric settings default to the values a
# machine with nothing configured reports.
function Get-MpPreference {
    [CmdletBinding()]
    param()

    if ($env:OPSTOOLKIT_TEST_MP_UNREADABLE -eq '1') { throw 'Fake Get-MpPreference: Defender is not running.' }

    $asrIds = $null
    $asrActions = $null
    $pairs = @(($env:OPSTOOLKIT_TEST_MP_ASR -split ';') | Where-Object { $_ })
    if ($pairs.Count) {
        $asrIds = @($pairs | ForEach-Object { ($_ -split '=')[0] })
        $asrActions = @($pairs | ForEach-Object { [byte](($_ -split '=')[1]) })
    }
    $apps = @(($env:OPSTOOLKIT_TEST_MP_CFAAPPS -split ';') | Where-Object { $_ })

    [pscustomobject]@{
        ExclusionPath = @(($env:OPSTOOLKIT_TEST_MP_EXCLUSIONPATH -split ';') | Where-Object { $_ })
        ExclusionProcess = @(($env:OPSTOOLKIT_TEST_MP_EXCLUSIONPROCESS -split ';') | Where-Object { $_ })
        AttackSurfaceReductionRules_Ids = $asrIds
        AttackSurfaceReductionRules_Actions = $asrActions
        EnableControlledFolderAccess = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_CFA' 0)
        ControlledFolderAccessAllowedApplications = $(if ($apps.Count) { $apps } else { $null })
        EnableNetworkProtection = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_NETPROT' 0)
        PUAProtection = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_PUA' 0)
        MAPSReporting = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_MAPS' 0)
        SubmitSamplesConsent = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_SAMPLES' 1)
        CloudBlockLevel = [byte](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_CLOUDBLOCK' 0)
        CloudExtendedTimeout = [uint32](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_CLOUDTIMEOUT' 0)
    }
}

# OPSTOOLKIT_TEST_MP_UNREADABLE=1 throws; OPSTOOLKIT_TEST_MP_RUNMODE sets AMRunningMode
# ('Normal' by default, 'Passive mode' for a machine whose active antivirus is third-party).
function Get-MpComputerStatus {
    [CmdletBinding()]
    param()

    if ($env:OPSTOOLKIT_TEST_MP_UNREADABLE -eq '1') { throw 'Fake Get-MpComputerStatus: Defender is not running.' }

    [pscustomobject]@{
        AMRunningMode = [string](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_RUNMODE' 'Normal')
        IsTamperProtected = ((Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_TAMPER' '1') -eq '1')
        AntivirusSignatureAge = [uint32](Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_SIGAGE' 1)
        RealTimeProtectionEnabled = ((Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_REALTIME' '1') -eq '1')
        BehaviorMonitorEnabled = ((Get-FakeMpEnvValue 'OPSTOOLKIT_TEST_MP_BEHAVIOR' '1') -eq '1')
    }
}

function Add-MpPreference {
    [CmdletBinding()]
    param(
        [Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force,
        [Parameter()]$AttackSurfaceReductionRules_Ids, [Parameter()]$AttackSurfaceReductionRules_Actions,
        [Parameter()]$ControlledFolderAccessAllowedApplications
    )
    $record = Get-FakeMpRecord -Bound $PSBoundParameters
    Write-FakeMpMutation -Command 'Add-MpPreference' -Target $record.Target -Detail $record.Detail
}

function Set-MpPreference {
    [CmdletBinding()]
    param(
        [Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force,
        [Parameter()]$EnableControlledFolderAccess, [Parameter()]$EnableNetworkProtection,
        [Parameter()]$PUAProtection, [Parameter()]$MAPSReporting, [Parameter()]$SubmitSamplesConsent,
        [Parameter()]$CloudBlockLevel, [Parameter()]$CloudExtendedTimeout
    )
    $record = Get-FakeMpRecord -Bound $PSBoundParameters
    Write-FakeMpMutation -Command 'Set-MpPreference' -Target $record.Target -Detail $record.Detail
}

function Remove-MpPreference {
    [CmdletBinding()]
    param(
        [Parameter()]$ExclusionPath, [Parameter()]$ExclusionProcess, [switch]$Force,
        [Parameter()]$AttackSurfaceReductionRules_Ids, [Parameter()]$ControlledFolderAccessAllowedApplications
    )
    $record = Get-FakeMpRecord -Bound $PSBoundParameters
    Write-FakeMpMutation -Command 'Remove-MpPreference' -Target $record.Target -Detail $record.Detail
}

Export-ModuleMember -Function 'Get-MpPreference', 'Get-MpComputerStatus', 'Add-MpPreference', 'Set-MpPreference', 'Remove-MpPreference'
