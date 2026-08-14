<#
.SYNOPSIS
Report local administrator membership, built-in Administrator account state, and whether LAPS manages the local admin password.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads local group membership and policy registry values, and writes
  reports. It adds, removes, and rotates nothing.
- Run elevated for complete results. Unelevated, local group membership usually
  still reads but LAPS state under HKLM policy may not.
- No password is ever read or written to a report. LAPS is reported by configuration
  and password age only, never by value.
- -ComputerName needs WinRM and local administrator rights on each target.
- Generated reports are written under reports\it-operations by default.

Purpose:
Attackers moved from stealing passwords to abusing the accounts that already have
them: shared local administrator passwords, stale members left in the group, and a
built-in Administrator that is enabled with a password nobody has rotated. Insurers
and CMMC assessors both ask who holds local admin and whether the password is
managed. This answers both per machine, and separates "LAPS is configured" from
"LAPS has actually rotated a password", which are not the same claim.

Required syntax:
pwsh -File .\scripts\it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1
pwsh -File .\scripts\it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1 -ComputerName pc01,pc02
pwsh -File .\scripts\it-operations\windows-hardening\Export-LocalAdminAndLapsPosture.ps1 -ExpectedMember 'CONTOSO\Workstation Admins'

.OUTPUTS
Writes local administrator membership, a per-machine posture verdict, and a run
summary as CSV and JSON under reports\it-operations by default. Returns a summary
object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ExpectedMember,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxPasswordAgeDays = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\..\reports\it-operations'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'local-admin-laps-posture'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\..\modules\OpsToolkit.Reporting') -Force

$posturePropbe = {
    function Get-RegValue {
        param($Path, $Name)
        try {
            return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        } catch {
            return $null
        }
    }

    $isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    # The Administrators group is resolved by well-known SID. It is renamed often
    # enough, and localized always, that the name is not an identity.
    $adminGroupName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

    $members = [System.Collections.Generic.List[object]]::new()
    $memberError = ''
    try {
        foreach ($member in Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop) {
            $members.Add([pscustomobject]@{
                    Name = [string]$member.Name
                    Sid = [string]$member.SID
                    ObjectClass = [string]$member.ObjectClass
                    PrincipalSource = [string]$member.PrincipalSource
                })
        }
    } catch {
        # Get-LocalGroupMember fails outright when the group contains an orphaned SID
        # from a deleted domain account, which is exactly the case worth reporting.
        $memberError = $_.Exception.Message
        try {
            $group = [ADSI]"WinNT://./$adminGroupName,group"
            foreach ($entry in @($group.Invoke('Members'))) {
                $path = $entry.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $entry, $null)
                $name = ($path -replace '^WinNT://', '') -replace '/', '\'
                $members.Add([pscustomobject]@{
                        Name = $name
                        Sid = ''
                        ObjectClass = 'unknown'
                        PrincipalSource = 'ADSI fallback'
                    })
            }
        } catch {
            $memberError = "$memberError | ADSI fallback also failed: $($_.Exception.Message)"
        }
    }

    # Built-in Administrator is RID 500 regardless of its current name.
    $builtIn = $null
    try {
        $builtIn = Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -match '-500$' } | Select-Object -First 1
    } catch {
        $builtIn = $null
    }

    # Windows LAPS (in-box) and the legacy Microsoft LAPS store state in different
    # places, and a machine can have the legacy client installed while policy points
    # at the new one.
    $lapsPolicy = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
    $lapsState = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    $legacyPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'

    $backupDirectory = Get-RegValue $lapsPolicy 'BackupDirectory'
    $lastPasswordSet = Get-RegValue $lapsState 'LastPasswordUpdateTime'
    $legacyEnabled = Get-RegValue $legacyPolicy 'AdmPwdEnabled'

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Elevated = $isElevated
        AdminGroupName = $adminGroupName
        MemberError = $memberError
        Members = @($members)
        BuiltInAdminName = if ($builtIn) { [string]$builtIn.Name } else { '' }
        BuiltInAdminEnabled = if ($builtIn) { [bool]$builtIn.Enabled } else { $null }
        BuiltInAdminPasswordLastSet = if ($builtIn) { $builtIn.PasswordLastSet } else { $null }
        BuiltInAdminRenamed = if ($builtIn) { [string]$builtIn.Name -ne 'Administrator' } else { $null }
        LapsBackupDirectory = $backupDirectory
        LapsAdministratorAccountName = Get-RegValue $lapsPolicy 'AdministratorAccountName'
        LapsPasswordAgeDays = Get-RegValue $lapsPolicy 'PasswordAgeDays'
        LapsLastPasswordUpdate = $lastPasswordSet
        LegacyLapsEnabled = $legacyEnabled
    }
}

$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$memberRecords = [System.Collections.Generic.List[object]]::new()
$postureRecords = [System.Collections.Generic.List[object]]::new()
$asOf = Get-Date

foreach ($target in $targets) {
    $probe = $null
    try {
        if ($target -eq $env:COMPUTERNAME) {
            $probe = & $posturePropbe
        } else {
            $probe = Invoke-Command -ComputerName $target -ScriptBlock $posturePropbe -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $postureRecords.Add([pscustomobject]@{
                ComputerName = $target
                Verdict = 'Unreachable'
                Note = $_.Exception.Message
            })
        continue
    }

    $members = @(Get-OpsPropertyValue -InputObject $probe -Name 'Members')
    foreach ($member in $members) {
        $unexpected = $false
        if ($ExpectedMember) {
            $unexpected = -not (@($ExpectedMember) | Where-Object { [string]$member.Name -like $_ -or [string]$member.Name -eq $_ })
        }

        $memberRecords.Add([pscustomobject]@{
                ComputerName = $probe.ComputerName
                MemberName = $member.Name
                Sid = $member.Sid
                ObjectClass = $member.ObjectClass
                PrincipalSource = $member.PrincipalSource
                Unexpected = $unexpected
                # A SID that never resolved to a name is an account deleted from its
                # source directory that still holds local administrator rights.
                OrphanedSid = [bool]([string]$member.Name -match '^S-1-[\d-]+$')
            })
    }

    $lapsDirectory = Get-OpsPropertyValue -InputObject $probe -Name 'LapsBackupDirectory'
    $lapsMode = switch ([int]($lapsDirectory ?? 0)) {
        1 { 'ActiveDirectory' }
        2 { 'EntraID' }
        default { 'NotConfigured' }
    }

    $legacyLaps = [bool](Get-OpsPropertyValue -InputObject $probe -Name 'LegacyLapsEnabled')
    $lapsLastUpdate = Get-OpsPropertyValue -InputObject $probe -Name 'LapsLastPasswordUpdate'
    $lapsAgeDays = Get-OpsAge -Timestamp $lapsLastUpdate -AsOf $asOf

    $builtInEnabled = Get-OpsPropertyValue -InputObject $probe -Name 'BuiltInAdminEnabled'
    $builtInPasswordAge = Get-OpsAge -Timestamp (Get-OpsPropertyValue -InputObject $probe -Name 'BuiltInAdminPasswordLastSet') -AsOf $asOf

    $issues = @()
    if ($lapsMode -eq 'NotConfigured' -and -not $legacyLaps) {
        $issues += 'LAPS not configured, local admin password is unmanaged'
    }
    if ($lapsMode -ne 'NotConfigured' -and $null -eq $lapsAgeDays) {
        $issues += 'LAPS configured but has never recorded a password update'
    }
    if ($null -ne $lapsAgeDays -and $lapsAgeDays -gt $MaxPasswordAgeDays) {
        $issues += "LAPS password is $lapsAgeDays days old"
    }
    if ($builtInEnabled -eq $true) {
        $issues += 'Built-in Administrator account is enabled'
    }
    if ($builtInEnabled -eq $true -and $null -ne $builtInPasswordAge -and $builtInPasswordAge -gt 365) {
        $issues += "Built-in Administrator password is $builtInPasswordAge days old"
    }
    $orphans = @($memberRecords | Where-Object { $_.ComputerName -eq $probe.ComputerName -and $_.OrphanedSid })
    if ($orphans.Count -gt 0) {
        $issues += "$($orphans.Count) unresolvable SID(s) hold local administrator rights"
    }
    $unexpectedMembers = @($memberRecords | Where-Object { $_.ComputerName -eq $probe.ComputerName -and $_.Unexpected })
    if ($unexpectedMembers.Count -gt 0) {
        $issues += "$($unexpectedMembers.Count) member(s) outside the expected list"
    }

    $verdict = if (-not $probe.Elevated -and $issues.Count -eq 0) {
        'Undetermined'
    } elseif ($issues.Count -eq 0) {
        'Managed'
    } elseif ($lapsMode -eq 'NotConfigured' -and -not $legacyLaps) {
        'Unmanaged'
    } else {
        'NeedsAttention'
    }

    $postureRecords.Add([pscustomobject]@{
            ComputerName = $probe.ComputerName
            Verdict = $verdict
            Elevated = $probe.Elevated
            AdminGroupName = $probe.AdminGroupName
            AdminMemberCount = $members.Count
            OrphanedSidCount = $orphans.Count
            UnexpectedMemberCount = $unexpectedMembers.Count
            LapsMode = $lapsMode
            LapsManagedAccount = Get-OpsPropertyValue -InputObject $probe -Name 'LapsAdministratorAccountName'
            LapsPasswordAgeDays = $lapsAgeDays
            LapsPolicyRotationDays = Get-OpsPropertyValue -InputObject $probe -Name 'LapsPasswordAgeDays'
            LegacyLapsEnabled = $legacyLaps
            BuiltInAdminName = Get-OpsPropertyValue -InputObject $probe -Name 'BuiltInAdminName'
            BuiltInAdminRenamed = Get-OpsPropertyValue -InputObject $probe -Name 'BuiltInAdminRenamed'
            BuiltInAdminEnabled = $builtInEnabled
            BuiltInAdminPasswordAgeDays = $builtInPasswordAge
            Issues = ($issues -join '; ')
            Note = [string](Get-OpsPropertyValue -InputObject $probe -Name 'MemberError')
        })
}

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'local-admin-members' -Record @($memberRecords) -Directory $runDirectory
    Export-OpsReport -Name 'admin-posture' -Record @($postureRecords) -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    ComputersQueried = @($targets).Count
    ManagedCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Managed' }).Count
    NeedsAttentionCount = @($postureRecords | Where-Object { $_.Verdict -eq 'NeedsAttention' }).Count
    UnmanagedCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Unmanaged' }).Count
    UndeterminedCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Undetermined' }).Count
    UnreachableCount = @($postureRecords | Where-Object { $_.Verdict -eq 'Unreachable' }).Count
    TotalAdminMembers = $memberRecords.Count
    OrphanedSidTotal = @($memberRecords | Where-Object { $_.OrphanedSid }).Count
    BuiltInAdminEnabledCount = @($postureRecords | Where-Object { $_.BuiltInAdminEnabled -eq $true }).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
