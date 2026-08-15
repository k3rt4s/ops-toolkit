<#
.SYNOPSIS
Run the read-only collectors and assemble a dated evidence pack answering the security control questions insurers and assessors ask.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It runs only collectors that change nothing, and writes a bundle. No
  control is remediated, enabled, or altered by this script.
- Run elevated for complete results. Several collectors report Undetermined without
  elevation, and Undetermined is reported as such rather than folded into a pass.
- Without -ComputerName or -TargetListPath the pack covers this machine only, and
  says so on every endpoint control. Estate scope needs WinRM and local
  administrator rights on each target.
- Not every collector can reach a remote machine. The pack detects which ones accept
  -ComputerName by reading their parameter blocks, passes the target list only to
  those, and records the rest as local-only in the collector run log, so a
  machine-scoped claim is never made from a single-machine reading.
- -IncludeEntra and -IncludeActiveDirectory are off by default because they need
  credentials and modules that a workstation may not have. Controls whose collector
  did not run are reported NotAssessed, never Met.
- The pack contains configuration state, not secrets. No password, key, recovery
  value, or certificate private key is collected or written.
- Review the pack before sending it anywhere. It describes your security posture,
  which makes it sensitive in its own right.
- Generated packs are written under reports\evidence by default.

Purpose:
Cyber insurers moved during 2026 from questionnaires to technical verification, and
CMMC assessors ask the same questions with more paperwork. Both want evidence rather
than assertions, and the evidence is scattered across a dozen consoles that each
answer part of one question. This runs the collectors already in this repo, maps
their output to the questions actually asked, and produces one dated bundle with the
raw output attached.

The design rule that makes it usable as evidence: a control whose collector did not
run, or ran and could not read what it needed, is reported NotAssessed. It is never
reported as Met, and the summary counts NotAssessed separately from NotMet, because
an evidence pack that quietly converts "we did not check" into "we are fine" is
worse than no pack at all.

Required syntax:
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -IncludeEntra -IncludeActiveDirectory
pwsh -File .\scripts\reporting\Export-SecurityControlEvidencePack.ps1 -Organization "Example Ltd" -OutputDirectory D:\evidence

.OUTPUTS
Writes a control assessment, a collector run log, a readable summary.md, and every
collector's own reports into one dated pack directory. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Organization = $env:USERDOMAIN,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetListPath,

    [Parameter()]
    [switch]$IncludeEntra,

    [Parameter()]
    [switch]$IncludeActiveDirectory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdServer,

    [Parameter()]
    [ValidateRange(60, 3600)]
    [int]$CollectorTimeoutSeconds = 900,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\evidence'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'security-control-evidence'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

$scriptsRoot = Join-Path $PSScriptRoot '..'
$asOf = Get-Date
$packDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$collectorRoot = Join-Path $packDirectory 'collectors'
New-Item -ItemType Directory -Path $collectorRoot -Force | Out-Null

$isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$pwshPath = (Get-Process -Id $PID).Path

Write-Verbose "Assembling evidence pack in $packDirectory. Per-collector timeout: $CollectorTimeoutSeconds seconds. Elevated: $isElevated."
if (-not $isElevated) {
    Write-Warning 'Not running elevated. Several collectors will report Undetermined, and those controls will be reported NotAssessed rather than Met.'
}

$collectorRuns = [System.Collections.Generic.List[object]]::new()
$controls = [System.Collections.Generic.List[object]]::new()

# Resolve the target list. A file wins nothing over -ComputerName; the two combine,
# because an operator will keep a standing list and add a machine for one run.
$targets = [System.Collections.Generic.List[string]]::new()
foreach ($name in @($ComputerName)) {
    if ($name) { $targets.Add($name) }
}

if ($TargetListPath) {
    if (-not (Test-Path -LiteralPath $TargetListPath)) {
        throw "Target list not found: $TargetListPath. One computer name per line; blank lines and lines starting with # are ignored."
    }

    foreach ($line in [System.IO.File]::ReadAllLines($TargetListPath)) {
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#')) {
            $targets.Add($trimmed)
        }
    }
}

$resolvedTargets = @($targets | Sort-Object -Unique)
$isEstateScope = $resolvedTargets.Count -gt 0
$scopeText = if ($isEstateScope) { "$($resolvedTargets.Count) machine(s)" } else { 'this machine only' }
Write-Verbose "Endpoint scope: $scopeText."

function Test-CollectorSupportsComputerName {
    <#
    .SYNOPSIS
    Return true when a collector script declares a ComputerName parameter.

    .DESCRIPTION
    Read from the script's own parameter block rather than from a maintained list, so
    a collector that gains remote support starts being fanned out without anyone
    remembering to update this script.

    .PARAMETER Path
    Path to the collector script.

    .OUTPUTS
    Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    if (-not $ast.ParamBlock) {
        return $false
    }

    foreach ($parameter in $ast.ParamBlock.Parameters) {
        if ($parameter.Name.VariablePath.UserPath -eq 'ComputerName') {
            return $true
        }
    }

    $false
}

function Invoke-Collector {
    <#
    .SYNOPSIS
    Run one collector in a child process and record whether it produced output.

    .DESCRIPTION
    Each collector runs isolated so that one failing does not abort the pack, and so
    a collector that hangs cannot hold the whole run open indefinitely.

    .PARAMETER Name
    Short collector name, used as its output folder.

    .PARAMETER RelativePath
    Path to the collector script, relative to the scripts root.

    .PARAMETER Argument
    Extra arguments for the collector.

    .OUTPUTS
    PSCustomObject describing the run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Argument = @(),

        # Passed rather than captured from script scope so the timeout is visible
        # where the wait actually happens.
        [Parameter()]
        [int]$TimeoutSeconds = $CollectorTimeoutSeconds
    )

    $scriptPath = Join-Path $scriptsRoot $RelativePath
    $outputPath = Join-Path $collectorRoot $Name
    $result = [pscustomobject]@{
        Collector = $Name
        ScriptPath = $scriptPath
        Status = 'NotRun'
        ExitCode = $null
        OutputPath = $outputPath
        DurationSeconds = 0
        Scope = 'LocalMachine'
        Note = ''
    }

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        $result.Status = 'Missing'
        $result.Note = "Collector script not found at $scriptPath."
        $collectorRuns.Add($result)
        return $result
    }

    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    $stdout = Join-Path $outputPath 'run.log'
    $stderr = Join-Path $outputPath 'run.err.log'
    $started = Get-Date

    # Fan out only to collectors that can actually reach a remote machine. A
    # collector that cannot is recorded as local-only so no estate-wide claim is
    # made from a reading of one machine.
    $targetArgument = @()
    if ($isEstateScope) {
        if (Test-CollectorSupportsComputerName -Path $scriptPath) {
            $targetArgument = @('-ComputerName') + $resolvedTargets
            $result.Scope = "$($resolvedTargets.Count) machine(s)"
        } else {
            $result.Scope = 'LocalMachineOnly'
            $result.Note = 'This collector has no -ComputerName parameter, so it covers only the machine the pack ran on.'
        }
    }

    try {
        $arguments = @('-NoProfile', '-NonInteractive', '-File', $scriptPath, '-OutputDirectory', $outputPath) + $targetArgument + $Argument
        $process = Start-Process -FilePath $pwshPath -ArgumentList $arguments -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $result.Status = 'TimedOut'
            $result.Note = "Exceeded $TimeoutSeconds seconds and was stopped."
        } else {
            $result.ExitCode = $process.ExitCode
            $result.Status = if ($process.ExitCode -eq 0) { 'Completed' } else { 'Failed' }
            if ($process.ExitCode -ne 0) {
                $errorText = if (Test-Path -LiteralPath $stderr) { (Get-Content -LiteralPath $stderr -Raw) } else { '' }
                $result.Note = ($errorText -replace '\s+', ' ').Trim()
            }
        }
    } catch {
        $result.Status = 'Failed'
        $result.Note = $_.Exception.Message
    }

    $result.DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)

    # Record where the output sits relative to the pack, not as an absolute path. The
    # pack should survive being zipped and read somewhere else, and an absolute path
    # also makes every run-over-run comparison show a change that is not one.
    $result | Add-Member -NotePropertyName RelativeOutputPath -NotePropertyValue "collectors\$Name" -Force
    $collectorRuns.Add($result)
    $result
}

function Get-CollectorSummary {
    <#
    .SYNOPSIS
    Read the summary.json a collector wrote, or return null when it produced none.

    .PARAMETER Run
    The collector run record.

    .OUTPUTS
    The parsed summary object, or null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Run
    )

    if ($Run.Status -ne 'Completed') {
        return $null
    }

    $summaryFile = Get-ChildItem -LiteralPath $Run.OutputPath -Filter 'summary.json' -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $summaryFile) {
        return $null
    }

    try {
        Get-Content -LiteralPath $summaryFile.FullName -Raw | ConvertFrom-Json
    } catch {
        $null
    }
}

function Add-Control {
    <#
    .SYNOPSIS
    Record one control assessment.

    .DESCRIPTION
    Status must be one of Met, NotMet, Partial, or NotAssessed. NotAssessed is a
    first-class outcome: it means nobody checked, and it must never be presented as
    a pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Question,
        [Parameter(Mandatory = $true)][ValidateSet('Met', 'NotMet', 'Partial', 'NotAssessed')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Finding,
        [Parameter()][AllowEmptyString()][string]$Evidence = '',
        [Parameter()][AllowEmptyString()][string]$Collector = ''
    )

    $controls.Add([pscustomobject]@{
            ControlId = $Id
            Question = $Question
            Status = $Status
            Finding = $Finding
            Evidence = $Evidence
            Collector = $Collector
            AssessedAt = Get-Date
        })
}

# ---------------------------------------------------------------------------
# Endpoint protection. No existing collector covers Defender, so it is inline.
# ---------------------------------------------------------------------------
$defenderStatus = $null
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
} catch {
    $defenderStatus = $null
}

if ($null -eq $defenderStatus) {
    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status 'NotAssessed' -Finding 'Microsoft Defender status could not be read. A third-party product may be in use, which this script does not detect.' -Collector 'inline:Get-MpComputerStatus'
} else {
    $realTime = [bool](Get-OpsPropertyValue -InputObject $defenderStatus -Name 'RealTimeProtectionEnabled')
    $signatureAge = Get-OpsPropertyValue -InputObject $defenderStatus -Name 'AntivirusSignatureAge'
    $tamper = [bool](Get-OpsPropertyValue -InputObject $defenderStatus -Name 'IsTamperProtected')

    $edrStatus = if ($realTime -and $null -ne $signatureAge -and [int]$signatureAge -le 7) { 'Met' } elseif ($realTime) { 'Partial' } else { 'NotMet' }
    Add-Control -Id 'EDR-01' -Question 'Is endpoint protection deployed and running on all endpoints?' `
        -Status $edrStatus `
        -Finding "Real-time protection: $realTime. Signature age: $signatureAge days. Tamper protection: $tamper. Scope: this machine only, Defender is read locally." `
        -Collector 'inline:Get-MpComputerStatus'

    Add-Control -Id 'EDR-02' -Question 'Is tamper protection enabled so malware cannot disable endpoint protection?' `
        -Status $(if ($tamper) { 'Met' } else { 'NotMet' }) `
        -Finding "Tamper protection is $(if ($tamper) { 'enabled' } else { 'not enabled' }) on this machine." `
        -Collector 'inline:Get-MpComputerStatus'
}

# ---------------------------------------------------------------------------
# Disk encryption and key recoverability.
# ---------------------------------------------------------------------------
$bitlockerRun = Invoke-Collector -Name 'bitlocker' -RelativePath 'it-operations\windows-hardening\Export-BitLockerEscrowStatus.ps1'
$bitlocker = Get-CollectorSummary -Run $bitlockerRun
if ($null -eq $bitlocker) {
    Add-Control -Id 'ENC-01' -Question 'Is disk encryption enabled on all endpoints and laptops?' `
        -Status 'NotAssessed' -Finding "The BitLocker collector did not produce a summary. Status: $($bitlockerRun.Status). $($bitlockerRun.Note)" -Collector 'Export-BitLockerEscrowStatus.ps1'
    Add-Control -Id 'ENC-02' -Question 'Are disk encryption recovery keys escrowed where they can be retrieved?' `
        -Status 'NotAssessed' -Finding 'Not assessed because the BitLocker collector did not run.' -Collector 'Export-BitLockerEscrowStatus.ps1'
} else {
    $atRisk = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'AtRiskCount')
    $undetermined = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'UndeterminedCount')
    $protected = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'ProtectedCount')
    $partial = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'PartiallyProtectedCount')
    $notEncrypted = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'NotEncryptedCount')

    $encStatus = if ($undetermined -gt 0) { 'NotAssessed' } elseif ($notEncrypted -gt 0) { 'NotMet' } elseif ($partial -gt 0) { 'Partial' } elseif ($protected -gt 0) { 'Met' } else { 'NotAssessed' }
    Add-Control -Id 'ENC-01' -Question 'Is disk encryption enabled on all endpoints and laptops?' `
        -Status $encStatus `
        -Finding "Protected: $protected. Partially protected: $partial. Not encrypted: $notEncrypted. Undetermined: $undetermined." `
        -Evidence $bitlockerRun.RelativeOutputPath -Collector 'Export-BitLockerEscrowStatus.ps1'

    $noKey = [int](Get-OpsPropertyValue -InputObject $bitlocker -Name 'VolumesWithoutRecoveryKey')
    # Escrow is assessable wherever any volume is actually encrypted, including a
    # machine whose overall verdict is only PartiallyProtected.
    $escrowStatus = if ($undetermined -gt 0) { 'NotAssessed' } elseif ($atRisk -gt 0 -or $noKey -gt 0) { 'NotMet' } elseif (($protected + $partial) -gt 0) { 'Partial' } else { 'NotAssessed' }
    Add-Control -Id 'ENC-02' -Question 'Are disk encryption recovery keys escrowed where they can be retrieved?' `
        -Status $escrowStatus `
        -Finding "Volumes with no recovery key: $noKey. Machines at risk: $atRisk. Escrow was verified against a directory only where -VerifyAdEscrow was used; otherwise this reflects policy configuration." `
        -Evidence $bitlockerRun.RelativeOutputPath -Collector 'Export-BitLockerEscrowStatus.ps1'
}

# ---------------------------------------------------------------------------
# Privileged access on the endpoint.
# ---------------------------------------------------------------------------
$lapsRun = Invoke-Collector -Name 'local-admin' -RelativePath 'it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1'
$laps = Get-CollectorSummary -Run $lapsRun
if ($null -eq $laps) {
    Add-Control -Id 'PRIV-01' -Question 'Are local administrator passwords unique and managed?' `
        -Status 'NotAssessed' -Finding "The local admin collector did not produce a summary. Status: $($lapsRun.Status)." -Collector 'Export-LocalAdminAndLapsPosture.ps1'
} else {
    $unmanaged = [int](Get-OpsPropertyValue -InputObject $laps -Name 'UnmanagedCount')
    $needsAttention = [int](Get-OpsPropertyValue -InputObject $laps -Name 'NeedsAttentionCount')
    $managed = [int](Get-OpsPropertyValue -InputObject $laps -Name 'ManagedCount')
    $orphans = [int](Get-OpsPropertyValue -InputObject $laps -Name 'OrphanedSidTotal')

    $privStatus = if ($unmanaged -gt 0) { 'NotMet' } elseif ($needsAttention -gt 0) { 'Partial' } elseif ($managed -gt 0) { 'Met' } else { 'NotAssessed' }
    Add-Control -Id 'PRIV-01' -Question 'Are local administrator passwords unique and managed?' `
        -Status $privStatus `
        -Finding "LAPS managed: $managed. Needs attention: $needsAttention. Unmanaged: $unmanaged." `
        -Evidence $lapsRun.RelativeOutputPath -Collector 'Export-LocalAdminAndLapsPosture.ps1'

    Add-Control -Id 'PRIV-02' -Question 'Is local administrator group membership controlled and reviewed?' `
        -Status $(if ($orphans -gt 0) { 'NotMet' } else { 'Partial' }) `
        -Finding "Total local administrator members: $(Get-OpsPropertyValue -InputObject $laps -Name 'TotalAdminMembers'). Unresolvable SIDs holding admin: $orphans. Membership is reported, not approved; approval is a human review this cannot perform." `
        -Evidence $lapsRun.RelativeOutputPath -Collector 'Export-LocalAdminAndLapsPosture.ps1'
}

# ---------------------------------------------------------------------------
# Patching and supportability.
# ---------------------------------------------------------------------------
$updateRun = Invoke-Collector -Name 'update-health' -RelativePath 'it-operations\lifecycle\Export-WindowsUpdateHealth.ps1'
$update = Get-CollectorSummary -Run $updateRun
if ($null -eq $update) {
    Add-Control -Id 'PATCH-01' -Question 'Are security patches applied within a defined window?' `
        -Status 'NotAssessed' -Finding "The update health collector did not produce a summary. Status: $($updateRun.Status)." -Collector 'Export-WindowsUpdateHealth.ps1'
} else {
    $unhealthy = [int](Get-OpsPropertyValue -InputObject $update -Name 'UnhealthyCount')
    $degraded = [int](Get-OpsPropertyValue -InputObject $update -Name 'DegradedCount')
    $healthy = [int](Get-OpsPropertyValue -InputObject $update -Name 'HealthyCount')

    Add-Control -Id 'PATCH-01' -Question 'Are security patches applied within a defined window?' `
        -Status $(if ($unhealthy -gt 0) { 'NotMet' } elseif ($degraded -gt 0) { 'Partial' } elseif ($healthy -gt 0) { 'Met' } else { 'NotAssessed' }) `
        -Finding "Healthy: $healthy. Degraded: $degraded. Unhealthy: $unhealthy. Pending reboot on $(Get-OpsPropertyValue -InputObject $update -Name 'PendingRebootCount') machine(s)." `
        -Evidence $updateRun.RelativeOutputPath -Collector 'Export-WindowsUpdateHealth.ps1'
}

$lifecycleRun = Invoke-Collector -Name 'lifecycle' -RelativePath 'it-operations\lifecycle\Export-WindowsLifecycleInventory.ps1'
$lifecycle = Get-CollectorSummary -Run $lifecycleRun
if ($null -eq $lifecycle) {
    Add-Control -Id 'PATCH-02' -Question 'Are all operating systems still receiving security updates from the vendor?' `
        -Status 'NotAssessed' -Finding "The lifecycle collector did not produce a summary. Status: $($lifecycleRun.Status)." -Collector 'Export-WindowsLifecycleInventory.ps1'
} else {
    $outOfSupport = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'OutOfSupportCount')
    $endingSoon = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'EndingSoonCount')
    $unknown = [int](Get-OpsPropertyValue -InputObject $lifecycle -Name 'UnknownCount')

    Add-Control -Id 'PATCH-02' -Question 'Are all operating systems still receiving security updates from the vendor?' `
        -Status $(if ($outOfSupport -gt 0) { 'NotMet' } elseif ($unknown -gt 0) { 'Partial' } elseif ($endingSoon -gt 0) { 'Partial' } else { 'Met' }) `
        -Finding "Out of support: $outOfSupport. Support ending within the warning window: $endingSoon. Unrecognised build: $unknown." `
        -Evidence $lifecycleRun.RelativeOutputPath -Collector 'Export-WindowsLifecycleInventory.ps1'
}

# ---------------------------------------------------------------------------
# Transport security and hardening.
# ---------------------------------------------------------------------------
$hardeningRun = Invoke-Collector -Name 'hardening' -RelativePath 'windows-hardening\Test-WindowsHardeningState.ps1'
$hardening = Get-CollectorSummary -Run $hardeningRun
if ($null -eq $hardening) {
    Add-Control -Id 'CFG-01' -Question 'Are systems hardened to a documented configuration standard?' `
        -Status 'NotAssessed' -Finding "The hardening verifier did not produce a summary. Status: $($hardeningRun.Status)." -Collector 'Test-WindowsHardeningState.ps1'
} else {
    $drift = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'TotalDrift')
    $checked = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'ItemsChecked')
    $compliant = [int](Get-OpsPropertyValue -InputObject $hardening -Name 'CompliantCount')

    Add-Control -Id 'CFG-01' -Question 'Are systems hardened to a documented configuration standard?' `
        -Status $(if ($checked -eq 0) { 'NotAssessed' } elseif ($drift -eq 0) { 'Met' } elseif ($compliant -gt 0) { 'Partial' } else { 'NotMet' }) `
        -Finding "$compliant of $checked hardening items are in the desired state. Items not in the desired state: $drift." `
        -Evidence $hardeningRun.RelativeOutputPath -Collector 'Test-WindowsHardeningState.ps1'
}

$certRun = Invoke-Collector -Name 'certificates' -RelativePath 'certificates\Export-CertificateExpiryInventory.ps1'
$certificates = Get-CollectorSummary -Run $certRun
if ($null -eq $certificates) {
    Add-Control -Id 'CFG-02' -Question 'Are certificates tracked and renewed before expiry?' `
        -Status 'NotAssessed' -Finding "The certificate collector did not produce a summary. Status: $($certRun.Status)." -Collector 'Export-CertificateExpiryInventory.ps1'
} else {
    $expired = [int](Get-OpsPropertyValue -InputObject $certificates -Name 'ExpiredCount')
    $soon = [int](Get-OpsPropertyValue -InputObject $certificates -Name 'ExpiringSoonCount')

    Add-Control -Id 'CFG-02' -Question 'Are certificates tracked and renewed before expiry?' `
        -Status $(if ($expired -gt 0) { 'NotMet' } elseif ($soon -gt 0) { 'Partial' } else { 'Met' }) `
        -Finding "Expired: $expired. Expiring within the warning window: $soon. Weak signature: $(Get-OpsPropertyValue -InputObject $certificates -Name 'WeakSignatureCount')." `
        -Evidence $certRun.RelativeOutputPath -Collector 'Export-CertificateExpiryInventory.ps1'
}

# ---------------------------------------------------------------------------
# Identity. Off by default: needs a tenant and consented scopes.
# ---------------------------------------------------------------------------
if ($IncludeEntra) {
    $mfaRun = Invoke-Collector -Name 'entra-auth-methods' -RelativePath 'entra\Export-EntraAuthMethodReadiness.ps1' -Argument @('-Connect')
    $mfa = Get-CollectorSummary -Run $mfaRun
    if ($null -eq $mfa) {
        Add-Control -Id 'MFA-01' -Question 'Is multi-factor authentication enforced for all users?' `
            -Status 'NotAssessed' -Finding "The Entra authentication method collector did not produce a summary. Status: $($mfaRun.Status). $($mfaRun.Note)" -Collector 'Export-EntraAuthMethodReadiness.ps1'
    } else {
        $noMfa = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'NoMfaRegisteredCount')
        $adminNoMfa = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'AdminsWithoutMfa')
        $reported = [int](Get-OpsPropertyValue -InputObject $mfa -Name 'UsersReported')

        Add-Control -Id 'MFA-01' -Question 'Is multi-factor authentication enforced for all users?' `
            -Status $(if ($adminNoMfa -gt 0 -or $noMfa -gt 0) { 'NotMet' } elseif ($reported -gt 0) { 'Met' } else { 'NotAssessed' }) `
            -Finding "Users with no MFA method registered: $noMfa of $reported. Administrators with no MFA: $adminNoMfa. Registration is not the same as enforcement; see the Conditional Access control." `
            -Evidence $mfaRun.RelativeOutputPath -Collector 'Export-EntraAuthMethodReadiness.ps1'

        Add-Control -Id 'MFA-02' -Question 'Is MFA resistant to phishing and help desk social engineering?' `
            -Status $(if ([int](Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyCount') -gt 0) { 'NotMet' } elseif ([int](Get-OpsPropertyValue -InputObject $mfa -Name 'PhishingResistantCount') -gt 0) { 'Partial' } else { 'NotAssessed' }) `
            -Finding "Telephony-only users: $(Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyCount'), of which $(Get-OpsPropertyValue -InputObject $mfa -Name 'TelephonyOnlyAdminCount') are administrators. Phishing-resistant: $(Get-OpsPropertyValue -InputObject $mfa -Name 'PhishingResistantCount'). Microsoft-provided telephony delivery ends 1 February 2027." `
            -Evidence $mfaRun.RelativeOutputPath -Collector 'Export-EntraAuthMethodReadiness.ps1'
    }

    $caRun = Invoke-Collector -Name 'entra-conditional-access' -RelativePath 'entra\Export-EntraConditionalAccessBaseline.ps1' -Argument @('-Connect')
    $ca = Get-CollectorSummary -Run $caRun
    if ($null -eq $ca) {
        Add-Control -Id 'IAM-01' -Question 'Are access policies enforced, including a block on legacy authentication?' `
            -Status 'NotAssessed' -Finding "The Conditional Access collector did not produce a summary. Status: $($caRun.Status). $($caRun.Note)" -Collector 'Export-EntraConditionalAccessBaseline.ps1'
    } else {
        $criticalGaps = [int](Get-OpsPropertyValue -InputObject $ca -Name 'CriticalGapCount')
        $gaps = [int](Get-OpsPropertyValue -InputObject $ca -Name 'GapCount')

        Add-Control -Id 'IAM-01' -Question 'Are access policies enforced, including a block on legacy authentication?' `
            -Status $(if ($criticalGaps -gt 0) { 'NotMet' } elseif ($gaps -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Conditional Access policies: $(Get-OpsPropertyValue -InputObject $ca -Name 'PolicyCount') total, $(Get-OpsPropertyValue -InputObject $ca -Name 'EnabledCount') enforcing, $(Get-OpsPropertyValue -InputObject $ca -Name 'ReportOnlyCount') report-only. Missing baseline controls: $gaps, of which $criticalGaps are critical." `
            -Evidence $caRun.RelativeOutputPath -Collector 'Export-EntraConditionalAccessBaseline.ps1'
    }

    $credRun = Invoke-Collector -Name 'entra-app-credentials' -RelativePath 'entra\Export-EntraAppCredentialExpiry.ps1' -Argument @('-Connect', '-IncludeServicePrincipals')
    $credentials = Get-CollectorSummary -Run $credRun
    if ($null -eq $credentials) {
        Add-Control -Id 'IAM-02' -Question 'Are application credentials rotated before they expire?' `
            -Status 'NotAssessed' -Finding "The application credential collector did not produce a summary. Status: $($credRun.Status). $($credRun.Note)" -Collector 'Export-EntraAppCredentialExpiry.ps1'
    } else {
        $expiredCreds = [int](Get-OpsPropertyValue -InputObject $credentials -Name 'ExpiredCount')
        $expiringCreds = [int](Get-OpsPropertyValue -InputObject $credentials -Name 'ExpiringSoonCount')

        Add-Control -Id 'IAM-02' -Question 'Are application credentials rotated before they expire?' `
            -Status $(if ($expiredCreds -gt 0) { 'NotMet' } elseif ($expiringCreds -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Expired credentials still attached: $expiredCreds. Expiring within the warning window: $expiringCreds. Over-long secret lifetimes: $(Get-OpsPropertyValue -InputObject $credentials -Name 'ExceedsRecommendedLifetimeCount')." `
            -Evidence $credRun.RelativeOutputPath -Collector 'Export-EntraAppCredentialExpiry.ps1'
    }
} else {
    foreach ($pair in @(
            @('MFA-01', 'Is multi-factor authentication enforced for all users?'),
            @('MFA-02', 'Is MFA resistant to phishing and help desk social engineering?'),
            @('IAM-01', 'Are access policies enforced, including a block on legacy authentication?'),
            @('IAM-02', 'Are application credentials rotated before they expire?')
        )) {
        Add-Control -Id $pair[0] -Question $pair[1] -Status 'NotAssessed' `
            -Finding 'Not assessed. Re-run with -IncludeEntra and a Graph sign-in to cover the identity controls.' -Collector 'none'
    }
}

# ---------------------------------------------------------------------------
# Active Directory. Off by default: needs RSAT and a reachable domain.
# ---------------------------------------------------------------------------
if ($IncludeActiveDirectory) {
    $adArguments = @()
    if ($AdServer) { $adArguments = @('-Server', $AdServer) }

    $adRun = Invoke-Collector -Name 'ad-privileged-access' -RelativePath 'active-directory\Export-AdPrivilegedAccessAudit.ps1' -Argument $adArguments
    $ad = Get-CollectorSummary -Run $adRun
    if ($null -eq $ad) {
        Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
            -Status 'NotAssessed' -Finding "The Active Directory audit did not produce a summary. Status: $($adRun.Status). $($adRun.Note)" -Collector 'Export-AdPrivilegedAccessAudit.ps1'
    } else {
        $critical = [int](Get-OpsPropertyValue -InputObject $ad -Name 'CriticalCount')
        $high = [int](Get-OpsPropertyValue -InputObject $ad -Name 'HighCount')

        Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
            -Status $(if ($critical -gt 0) { 'NotMet' } elseif ($high -gt 0) { 'Partial' } else { 'Met' }) `
            -Finding "Critical findings: $critical. High findings: $high. Tier-0 members: $(Get-OpsPropertyValue -InputObject $ad -Name 'Tier0MemberCount')." `
            -Evidence $adRun.RelativeOutputPath -Collector 'Export-AdPrivilegedAccessAudit.ps1'
    }
} else {
    Add-Control -Id 'PRIV-03' -Question 'Is privileged directory access limited and free of known escalation paths?' `
        -Status 'NotAssessed' -Finding 'Not assessed. Re-run with -IncludeActiveDirectory on a machine with RSAT and a reachable domain.' -Collector 'none'
}

# ---------------------------------------------------------------------------
# Controls this repo genuinely cannot evidence. Stated, not silently omitted.
# ---------------------------------------------------------------------------
Add-Control -Id 'BCK-01' -Question 'Are backups taken, stored offline or immutably, and restore-tested?' `
    -Status 'NotAssessed' `
    -Finding 'No collector in this toolkit reads backup state. A restore test is an operational exercise, not a configuration read, and claiming it from configuration would be false. Attach the backup product report and the dated restore test record.' -Collector 'none'

Add-Control -Id 'IR-01' -Question 'Is there a documented and exercised incident response plan?' `
    -Status 'NotAssessed' `
    -Finding 'Not technically assessable. Attach the plan and the date of the last tabletop or live exercise.' -Collector 'none'

Add-Control -Id 'TRN-01' -Question 'Do staff receive security awareness training, including help desk verification procedures?' `
    -Status 'NotAssessed' `
    -Finding 'Not technically assessable. Attach training completion records. Help desk verification procedure is worth calling out separately: vishing was the second most common initial infection vector in 2025 and MFA reset requests are the specific step to control.' -Collector 'none'

# ---------------------------------------------------------------------------
# Assemble.
# ---------------------------------------------------------------------------
$assessment = @($controls) | Sort-Object -Property @{ Expression = { switch ($_.Status) { 'NotMet' { 0 } 'Partial' { 1 } 'NotAssessed' { 2 } default { 3 } } } }, ControlId

$statusRollup = foreach ($group in (@($assessment) | Group-Object -Property Status)) {
    [pscustomobject]@{ Status = $group.Name; Count = $group.Count; Controls = (@($group.Group | ForEach-Object { $_.ControlId }) -join ';') }
}

$exports = @(
    Export-OpsReport -Name 'control-assessment' -Record $assessment -Directory $packDirectory
    Export-OpsReport -Name 'status-rollup' -Record @($statusRollup) -Directory $packDirectory
    Export-OpsReport -Name 'collector-runs' -Record @($collectorRuns) -Directory $packDirectory
)

$notMet = @($assessment | Where-Object { $_.Status -eq 'NotMet' })
$partial = @($assessment | Where-Object { $_.Status -eq 'Partial' })
$notAssessed = @($assessment | Where-Object { $_.Status -eq 'NotAssessed' })
$met = @($assessment | Where-Object { $_.Status -eq 'Met' })

$markdown = [System.Collections.Generic.List[string]]::new()
$markdown.Add("# Security control evidence pack")
$markdown.Add('')
$markdown.Add("Organization: $Organization")
$markdown.Add("Generated: $($asOf.ToString('yyyy-MM-dd HH:mm:ss'))")
$markdown.Add("Machine: $env:COMPUTERNAME")
$markdown.Add("Elevated: $isElevated")
$markdown.Add("Endpoint scope: $scopeText")
$markdown.Add('')
$markdown.Add('This pack reports the state of this environment as read by automated collectors on the date above. Every control is answered from collector output or is marked NotAssessed. Nothing is inferred.')
$markdown.Add('')
$markdown.Add("## Summary")
$markdown.Add('')
$markdown.Add("| Status | Count |")
$markdown.Add("| ------ | ----- |")
$markdown.Add("| Met | $($met.Count) |")
$markdown.Add("| Partial | $($partial.Count) |")
$markdown.Add("| Not met | $($notMet.Count) |")
$markdown.Add("| Not assessed | $($notAssessed.Count) |")
$markdown.Add('')
$markdown.Add('Not assessed is not a pass. It means no collector produced evidence for that control in this run.')
$markdown.Add('')
$markdown.Add("## Controls")
$markdown.Add('')
$markdown.Add("| Control | Status | Question | Finding |")
$markdown.Add("| ------- | ------ | -------- | ------- |")
foreach ($control in $assessment) {
    $finding = ($control.Finding -replace '\|', '/') -replace '\s+', ' '
    $markdown.Add("| $($control.ControlId) | $($control.Status) | $($control.Question) | $finding |")
}
$markdown.Add('')
$markdown.Add("## Collector runs")
$markdown.Add('')
$markdown.Add("| Collector | Status | Scope | Seconds | Note |")
$markdown.Add("| --------- | ------ | ----- | ------- | ---- |")
foreach ($run in $collectorRuns) {
    $note = ($run.Note -replace '\|', '/') -replace '\s+', ' '
    $markdown.Add("| $($run.Collector) | $($run.Status) | $($run.Scope) | $($run.DurationSeconds) | $note |")
}
$markdown.Add('')
$markdown.Add('Raw collector output is under `collectors\`, one folder per collector.')

Set-Content -LiteralPath (Join-Path $packDirectory 'summary.md') -Value ($markdown -join [Environment]::NewLine) -Encoding utf8

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    Organization = $Organization
    ComputerName = $env:COMPUTERNAME
    Elevated = $isElevated
    EndpointScope = $scopeText
    TargetCount = $resolvedTargets.Count
    Targets = $resolvedTargets
    PackDirectory = $packDirectory
    IncludedEntra = [bool]$IncludeEntra
    IncludedActiveDirectory = [bool]$IncludeActiveDirectory
    ControlCount = $assessment.Count
    MetCount = $met.Count
    PartialCount = $partial.Count
    NotMetCount = $notMet.Count
    NotAssessedCount = $notAssessed.Count
    CollectorsRun = $collectorRuns.Count
    CollectorsCompleted = @($collectorRuns | Where-Object { $_.Status -eq 'Completed' }).Count
    CollectorsFailed = @($collectorRuns | Where-Object { $_.Status -in @('Failed', 'TimedOut', 'Missing') }).Count
    NotMetControls = @($notMet | ForEach-Object { $_.ControlId })
    NotAssessedControls = @($notAssessed | ForEach-Object { $_.ControlId })
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $packDirectory
