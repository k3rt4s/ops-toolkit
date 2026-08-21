<#
.SYNOPSIS
Reclaim disk space from developer and Windows caches with plan/state reports and -WhatIf.

.DESCRIPTION
Instructions:
- Read the root README.md and the IT operations README.md before running this script.
- Run with -WhatIf first and review the generated plan CSV/JSON.
- Run from an elevated shell to include ComponentStore (WinSxS) or WindowsUpdateCache targets.
- Use -Target to choose which caches to reclaim; omit it for the safe default set.
- The default set is unchanged from the original five targets, so existing callers and any
  scheduled task wrapping this script see no change in behaviour. Every target added later is
  selected explicitly.
- HuggingFaceCache, PlaywrightBrowsers, CodexRuntimeCache, DockerOldImageTags and
  DockerVhdxCompact are opt-in only. The first three force a large re-download or reinstall
  before the next run of the tool that owns them; the last two are described below.
- CodexRuntimeCache is expected to complete partially while Codex is running, because the
  runtime holds its own DLLs open. That is reported as a partial result, not a failure.
- DockerOldImageTags deletes tagged images, not just dangling ones. It keeps the newest
  -KeepTagsPerRepository tags per repository and records every tag it removed in the plan and
  state reports. Review a -WhatIf plan before running it on a machine whose tags you have not
  audited. Images with a container attached are skipped by Docker itself.
- DockerVhdxCompact stops Docker Desktop and runs "wsl --shutdown" before compacting, so every
  container and every WSL distro on the machine goes down for several minutes. It requires an
  elevated shell. It is the only target that returns space freed by the other Docker targets to
  the host volume, because pruning frees space inside the virtual disk without shrinking the file.
  Run it last, after the other Docker targets, or it compacts a disk that is still full.
- Generated reports are written under C:\Code_data\ops-toolkit\windows-file-cleanup by default,
  per the workspace data-hygiene rule (generated data lives under C:\Code_data, never in the repo).

Purpose:
This script reclaims space from reclaimable caches that the file/temp cleanup helper does not
cover: the pip, npm, torch, pre-commit, Codex runtime, NVIDIA shader and Playwright browser
caches, the Docker build cache, dangling images, stopped containers, unused volumes, superseded
image tags and the Docker virtual disk, the Recycle Bin, the Windows component store (WinSxS),
and optionally the Windows Update download cache. It complements Invoke-WindowsFileCleanup.ps1
(temp and stale files) and Invoke-DiskMaintenance.ps1 (chkdsk, defrag, cipher wipe). It never
touches source code, the live application database, audit_vault evidence, or the active model
cache unless explicitly opted in.

Required syntax:
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target PipCache,RecycleBin
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target ComponentStore  # elevated

The developer-workstation cache sweep verified on this machine on 2026-08-20, which reclaimed
18.3 GB. Run it elevated, and rehearse it with -WhatIf first:
pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target PipCache,NpmCache,TorchCache,PreCommitCache,CodexRuntimeCache,NvidiaShaderCache,PlaywrightBrowsers,HuggingFaceCache,DockerBuildCache,DockerDanglingImages,DockerStoppedContainers,DockerUnusedVolumes,DockerOldImageTags,DockerVhdxCompact

.OUTPUTS
Writes plan and state CSV/JSON files under the report directory. Returns a summary object with
report paths, per-target reclaimed bytes, and a free-space before/after delta for the system drive.

.NOTES
Status:
Active script in the ops-toolkit repo. Companion to Invoke-WindowsFileCleanup.ps1.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('PipCache', 'NpmCache', 'TorchCache', 'PreCommitCache', 'CodexRuntimeCache',
        'NvidiaShaderCache', 'PlaywrightBrowsers', 'HuggingFaceCache',
        'DockerBuildCache', 'DockerDanglingImages', 'DockerStoppedContainers', 'DockerUnusedVolumes',
        'DockerOldImageTags', 'DockerVhdxCompact',
        'RecycleBin', 'ComponentStore', 'WindowsUpdateCache')]
    [string[]]$Target = @('PipCache', 'DockerBuildCache', 'DockerDanglingImages', 'RecycleBin', 'ComponentStore'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PipExecutable = 'pip',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NpmExecutable = 'npm',

    # Applies to DockerOldImageTags only. Two keeps the shipped tag and the one before it, which
    # is what a rollback actually needs; one leaves nothing to roll back to.
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$KeepTagsPerRepository = 2,

    # Applies to DockerVhdxCompact only. Docker Desktop is asked to quit and then given this long
    # to release the virtual disk before the compaction is abandoned as unsafe.
    [Parameter()]
    [ValidateRange(30, 900)]
    [int]$DockerShutdownTimeoutSeconds = 180,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = 'C:\Code_data\ops-toolkit\windows-file-cleanup'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output @'
Reclaim disk space from developer and Windows caches.

Usage:
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -WhatIf
  pwsh -File .\scripts\it-operations\windows-file-cleanup\Invoke-DiskSpaceReclaim.ps1 -Target PipCache,RecycleBin

Options:
  -Target           One or more of:
                      Package/tool caches   PipCache, NpmCache, TorchCache, PreCommitCache,
                                            CodexRuntimeCache, NvidiaShaderCache,
                                            PlaywrightBrowsers, HuggingFaceCache
                      Docker                DockerBuildCache, DockerDanglingImages,
                                            DockerStoppedContainers, DockerUnusedVolumes,
                                            DockerOldImageTags, DockerVhdxCompact
                      Windows               RecycleBin, ComponentStore, WindowsUpdateCache
                    Default: PipCache, DockerBuildCache, DockerDanglingImages, RecycleBin,
                    ComponentStore. Opt-in only, never in the default set: HuggingFaceCache,
                    PlaywrightBrowsers, CodexRuntimeCache, DockerOldImageTags, DockerVhdxCompact.
  -PipExecutable    pip/pip3 path or name used for "pip cache" operations. Default: pip.
  -NpmExecutable    npm path or name used for "npm cache" operations. Default: npm.
  -KeepTagsPerRepository
                    DockerOldImageTags only. Newest tags kept per repository. Default: 2.
  -DockerShutdownTimeoutSeconds
                    DockerVhdxCompact only. Seconds to wait for Docker to release the virtual
                    disk before abandoning the compaction. Default: 180.
  -ReportDirectory  Plan and state output directory.
  -WhatIf           Write reports and preview reclaim actions without deleting anything.

Elevation:
  ComponentStore, WindowsUpdateCache and DockerVhdxCompact are skipped, and reported as
  skipped, when the shell is not elevated.

Ordering:
  DockerVhdxCompact runs last regardless of the order given, so it compacts a disk the other
  Docker targets have already emptied.
'@
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CommandPath {
    param([Parameter(Mandatory = $true)][string]$Name)
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    # Source is populated only for an external file, so a command resolved as a function
    # or an alias returns an empty string. Every caller here uses the result as a
    # presence check, and an empty string reads as "not installed" for something that
    # resolved perfectly well; fall back to the name so the check means what it says.
    if ($cmd.Source) { return $cmd.Source }
    $cmd.Name
}

function Get-FolderSize {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    try {
        [long]((Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum)
    } catch {
        0
    }
}

function Get-FreeBytesSystemDrive {
    # Prefer the Storage module; fall back to CIM on SKUs where Get-Volume is unavailable.
    $sys = ($env:SystemDrive).TrimEnd(':')
    try {
        (Get-Volume -DriveLetter $sys -ErrorAction Stop).SizeRemaining
    } catch {
        (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
    }
}

function Get-CacheDirectoryPath {
    <#
    .SYNOPSIS
    Resolve the on-disk location of one named tool cache, honouring its override variable.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    switch ($Name) {
        'NpmCache' {
            # npm_config_cache wins over the platform default, and npm on Windows uses
            # LOCALAPPDATA rather than the ~/.npm path it uses elsewhere.
            if ($env:npm_config_cache) { $env:npm_config_cache } else { Join-Path $env:LOCALAPPDATA 'npm-cache' }
        }
        'TorchCache' {
            if ($env:TORCH_HOME) { $env:TORCH_HOME } else { Join-Path $env:USERPROFILE '.cache\torch' }
        }
        'PreCommitCache' {
            if ($env:PRE_COMMIT_HOME) { $env:PRE_COMMIT_HOME } else { Join-Path $env:USERPROFILE '.cache\pre-commit' }
        }
        'CodexRuntimeCache' { Join-Path $env:USERPROFILE '.cache\codex-runtimes' }
        'PlaywrightBrowsers' {
            if ($env:PLAYWRIGHT_BROWSERS_PATH) { $env:PLAYWRIGHT_BROWSERS_PATH } else { Join-Path $env:LOCALAPPDATA 'ms-playwright' }
        }
        default { throw "No cache directory mapping for: $Name" }
    }
}

function Get-NvidiaShaderCachePath {
    <#
    .SYNOPSIS
    Return the NVIDIA shader cache directories that exist on this machine.
    #>
    # DXCache and GLCache are separate stores and either may be absent depending on which APIs
    # the machine has actually run. Filtering here keeps the planner estimate honest.
    @(
        (Join-Path $env:LOCALAPPDATA 'NVIDIA\DXCache')
        (Join-Path $env:LOCALAPPDATA 'NVIDIA\GLCache')
    ) | Where-Object { Test-Path -LiteralPath $_ }
}

function Get-DockerDataVhdxPath {
    <#
    .SYNOPSIS
    Return the Docker Desktop WSL data virtual disk path, or $null when it is not present.
    #>
    # Docker Desktop has moved this file between releases. Probe the known locations newest
    # first rather than assuming one, and return the largest match if several survive an
    # upgrade, because the stale one is the small leftover.
    $candidate = @(
        (Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx')
        (Join-Path $env:LOCALAPPDATA 'Docker\wsl\data\ext4.vhdx')
        (Join-Path $env:LOCALAPPDATA 'Docker\wsl\main\ext4.vhdx')
    ) | Where-Object { Test-Path -LiteralPath $_ }

    if (-not $candidate) { return $null }
    @($candidate | Sort-Object { (Get-Item -LiteralPath $_).Length } -Descending)[0]
}

function Get-DockerCreatedAtSortKey {
    <#
    .SYNOPSIS
    Turn one docker CreatedAt string into a value that sorts chronologically.

    .DESCRIPTION
    Docker prints CreatedAt as "2026-06-01 10:00:00 +0000 UTC", which [datetime]::TryParse
    rejects outright because of the trailing zone name. Falling back to a string sort on
    that happens to be chronological only while every row carries the same offset, and the
    cost of being wrong here is deleting the tag still in production rather than the one
    before it. The leading 19 characters are a fixed layout and locale-independent, so
    parse those exactly and let anything else sort last.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$CreatedAt)

    $parsed = [datetime]::MinValue
    $stamp = if ($CreatedAt.Length -ge 19) { $CreatedAt.Substring(0, 19) } else { '' }
    if ([datetime]::TryParseExact($stamp, 'yyyy-MM-dd HH:mm:ss',
            [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        return $parsed
    }

    # An unreadable date sorts oldest, so it lands outside the keep window and is offered
    # for removal rather than silently displacing a tag whose date did parse.
    [datetime]::MinValue
}

function Get-SupersededImageTag {
    <#
    .SYNOPSIS
    List Docker image tags beyond the newest -KeepCount in each repository.

    .DESCRIPTION
    Returns the tags that DockerOldImageTags would remove. Untagged (dangling) images and the
    <none> repository are left to DockerDanglingImages, which is the target that owns them.
    #>
    param([Parameter(Mandatory = $true)][int]$KeepCount)

    $raw = @(docker image ls --format '{{.Repository}}|{{.Tag}}|{{.CreatedAt}}|{{.Size}}' 2>$null)
    # An empty daemon reply and a daemon that is not running look the same here. Both mean
    # there is nothing to plan, so return an empty set rather than guessing.
    if (-not $raw) { return @() }

    $parsed = foreach ($line in ($raw | Where-Object { $_ })) {
        $field = $line -split '\|', 4
        if ($field.Count -lt 3) { continue }
        if ($field[0] -eq '<none>' -or $field[1] -eq '<none>') { continue }
        [pscustomobject]@{
            Repository = $field[0]
            Tag = $field[1]
            CreatedAt = $field[2]
            Reference = "$($field[0]):$($field[1])"
        }
    }

    # Strict mode: an empty result from the loop above is $null, not an empty array.
    $parsed = @($parsed | Where-Object { $_ })
    if ($parsed.Count -eq 0) { return @() }

    $superseded = foreach ($group in ($parsed | Group-Object Repository)) {
        @($group.Group | Sort-Object { Get-DockerCreatedAtSortKey -CreatedAt $_.CreatedAt } -Descending) |
            Select-Object -Skip $KeepCount
    }

    @($superseded | Where-Object { $_ })
}

# ---------------------------------------------------------------------------
# Per-target planners. Each returns a plan object describing what would run,
# the estimated reclaimable bytes (best effort, $null when not cheaply known),
# whether admin is required, and whether the tool is available on this box.
# ---------------------------------------------------------------------------

function Get-ReclaimPlanItem {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PipExecutable,
        [Parameter(Mandatory = $true)][string]$NpmExecutable,
        [Parameter(Mandatory = $true)][int]$KeepTagsPerRepository
    )

    switch ($Name) {
        'PipCache' {
            $pip = Get-CommandPath -Name $PipExecutable
            $bytes = $null
            if ($pip) {
                try {
                    $dir = (& $pip cache dir 2>$null | Select-Object -First 1)
                    if ($dir) { $bytes = Get-FolderSize -Path $dir.Trim() }
                } catch { $bytes = $null }
            }
            [pscustomobject]@{
                Target = 'PipCache'; Available = [bool]$pip; RequiresAdmin = $false
                EstimatedBytes = $bytes; Action = "$PipExecutable cache purge"
                Note = if ($pip) { 'Removes downloaded wheels and the HTTP index cache; pip re-fetches on demand.' } else { "pip not found ($PipExecutable)." }
            }
        }
        'NpmCache' {
            $npm = Get-CommandPath -Name $NpmExecutable
            $dir = Get-CacheDirectoryPath -Name 'NpmCache'
            [pscustomobject]@{
                Target = 'NpmCache'; Available = ([bool]$npm -or (Test-Path -LiteralPath $dir)); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $dir); Action = if ($npm) { "$NpmExecutable cache clean --force" } else { "Remove-Item $dir" }
                Note = 'Removes downloaded package tarballs and metadata; npm re-fetches on demand.'
            }
        }
        'TorchCache' {
            $dir = Get-CacheDirectoryPath -Name 'TorchCache'
            [pscustomobject]@{
                Target = 'TorchCache'; Available = (Test-Path -LiteralPath $dir); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $dir); Action = "Remove-Item $dir"
                Note = 'Torch hub checkpoints and downloaded weights; re-downloaded on the next run that needs them.'
            }
        }
        'PreCommitCache' {
            $dir = Get-CacheDirectoryPath -Name 'PreCommitCache'
            [pscustomobject]@{
                Target = 'PreCommitCache'; Available = (Test-Path -LiteralPath $dir); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $dir); Action = "Remove-Item $dir"
                Note = 'Hook environments; the next pre-commit run rebuilds them and is slower once.'
            }
        }
        'CodexRuntimeCache' {
            $dir = Get-CacheDirectoryPath -Name 'CodexRuntimeCache'
            [pscustomobject]@{
                Target = 'CodexRuntimeCache'; Available = (Test-Path -LiteralPath $dir); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $dir); Action = "Remove-Item $dir"
                Note = 'OPT-IN. Completes partially while Codex is running because the runtime holds its own DLLs open. Close Codex to clear it fully.'
            }
        }
        'NvidiaShaderCache' {
            $dir = @(Get-NvidiaShaderCachePath)
            $bytes = 0
            foreach ($d in $dir) { $bytes += Get-FolderSize -Path $d }
            [pscustomobject]@{
                Target = 'NvidiaShaderCache'; Available = ($dir.Count -gt 0); RequiresAdmin = $false
                EstimatedBytes = $bytes; Action = "Remove-Item $($dir -join ', ')"
                Note = 'Compiled DirectX/OpenGL shader caches; the driver rebuilds them and the first launch of a GPU application is slower.'
            }
        }
        'PlaywrightBrowsers' {
            $dir = Get-CacheDirectoryPath -Name 'PlaywrightBrowsers'
            [pscustomobject]@{
                Target = 'PlaywrightBrowsers'; Available = (Test-Path -LiteralPath $dir); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $dir); Action = "Remove-Item $dir"
                Note = 'OPT-IN. Downloaded browser binaries. Browser automation fails until "npx playwright install" is run again.'
            }
        }
        'DockerBuildCache' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerBuildCache'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker builder prune -f'
                Note = if ($docker) { 'Removes unused build cache only; tagged images and volumes are untouched.' } else { 'docker CLI not found.' }
            }
        }
        'DockerStoppedContainers' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerStoppedContainers'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker container prune -f'
                Note = if ($docker) { 'Removes stopped containers and their writable layers. Running containers are untouched; any state written inside a stopped container is lost.' } else { 'docker CLI not found.' }
            }
        }
        'DockerUnusedVolumes' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerUnusedVolumes'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker volume prune -f'
                Note = if ($docker) { 'Removes volumes no container references. A named volume holding data you still want counts as unused once its container is gone.' } else { 'docker CLI not found.' }
            }
        }
        'DockerOldImageTags' {
            $docker = Get-CommandPath -Name 'docker'
            $superseded = if ($docker) { @(Get-SupersededImageTag -KeepCount $KeepTagsPerRepository) } else { @() }

            # Built as a statement rather than an inline if, because an if used as an expression
            # emits down the pipeline and unrolls, which is how a note becomes a bare $null here.
            $note = 'docker CLI not found.'
            if ($docker -and $superseded.Count -eq 0) {
                $note = "OPT-IN. No repository has more than $KeepTagsPerRepository tags; nothing to remove."
            } elseif ($docker) {
                $note = "OPT-IN. Removes tagged images: $(($superseded.Reference | Sort-Object) -join ', ')"
            }

            [pscustomobject]@{
                Target = 'DockerOldImageTags'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null
                Action = "docker rmi <$($superseded.Count) superseded tag(s), keeping newest $KeepTagsPerRepository per repository>"
                Note = $note
            }
        }
        'DockerVhdxCompact' {
            $vhdx = Get-DockerDataVhdxPath
            [pscustomobject]@{
                Target = 'DockerVhdxCompact'; Available = [bool]$vhdx; RequiresAdmin = $true
                # The file size is what compaction acts on, but how much of it is recoverable is
                # only known after the fact, so this is an upper bound and not an estimate.
                EstimatedBytes = $null
                Action = if ($vhdx) { "Stop Docker Desktop, wsl --shutdown, diskpart compact vdisk on $vhdx" } else { 'Docker WSL virtual disk not found' }
                Note = if ($vhdx) { "OPT-IN. Requires elevation. Stops Docker Desktop and every WSL distro for several minutes. Current file size: $([math]::Round((Get-Item -LiteralPath $vhdx).Length / 1GB, 2)) GB." } else { 'No Docker WSL virtual disk on this machine.' }
            }
        }
        'DockerDanglingImages' {
            $docker = Get-CommandPath -Name 'docker'
            [pscustomobject]@{
                Target = 'DockerDanglingImages'; Available = [bool]$docker; RequiresAdmin = $false
                EstimatedBytes = $null; Action = 'docker image prune -f'
                Note = if ($docker) { 'Removes dangling (untagged) images only; in-use images are untouched.' } else { 'docker CLI not found.' }
            }
        }
        'RecycleBin' {
            $bytes = 0
            foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' })) {
                $rb = "$($v.DriveLetter):\`$Recycle.Bin"
                $bytes += Get-FolderSize -Path $rb
            }
            [pscustomobject]@{
                Target = 'RecycleBin'; Available = $true; RequiresAdmin = $false
                EstimatedBytes = $bytes; Action = 'Clear-RecycleBin (all fixed drives)'
                Note = 'Permanently empties the Recycle Bin on all fixed drives.'
            }
        }
        'ComponentStore' {
            [pscustomobject]@{
                Target = 'ComponentStore'; Available = $true; RequiresAdmin = $true
                EstimatedBytes = $null; Action = 'Dism /Online /Cleanup-Image /StartComponentCleanup'
                Note = 'Removes superseded WinSxS components. Requires an elevated shell. Estimate via /AnalyzeComponentStore.'
            }
        }
        'WindowsUpdateCache' {
            $dl = Join-Path $env:windir 'SoftwareDistribution\Download'
            [pscustomobject]@{
                Target = 'WindowsUpdateCache'; Available = (Test-Path -LiteralPath $dl); RequiresAdmin = $true
                EstimatedBytes = (Get-FolderSize -Path $dl); Action = 'Stop wuauserv + bits, clear SoftwareDistribution\Download, restart services'
                Note = 'Clears cached update downloads. Windows re-downloads pending updates as needed. Requires elevation.'
            }
        }
        'HuggingFaceCache' {
            $hf = if ($env:HF_HOME) { $env:HF_HOME } else { Join-Path $env:USERPROFILE '.cache\huggingface' }
            [pscustomobject]@{
                Target = 'HuggingFaceCache'; Available = (Test-Path -LiteralPath $hf); RequiresAdmin = $false
                EstimatedBytes = (Get-FolderSize -Path $hf); Action = "Remove-Item $hf"
                Note = 'OPT-IN. Active model cache; clearing forces large re-downloads on the next AI/transcription run.'
            }
        }
        default { throw "Unknown target: $Name" }
    }
}

function Invoke-DockerVhdxCompaction {
    <#
    .SYNOPSIS
    Stop Docker Desktop and WSL, compact the Docker data virtual disk, then restart Docker.

    .DESCRIPTION
    Pruning inside Docker frees space within the virtual disk without shrinking the file, so the
    host volume sees nothing back until the disk is compacted. Compaction requires exclusive
    access, which means Docker Desktop and every WSL distro must be down first.

    The disk is attached read-only for the compaction. That is deliberate: diskpart will compact
    a writable attachment too, but a read-only attach cannot modify the filesystem inside the
    image if the operation is interrupted.

    Throws when the virtual disk cannot be released, rather than compacting a disk that is still
    attached, because diskpart reports success on a no-op.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutSeconds)

    $vhdx = Get-DockerDataVhdxPath
    if (-not $vhdx) { throw 'Docker WSL virtual disk not found.' }

    $dockerDesktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    $wasRunning = [bool](Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)

    if ($wasRunning -and (Test-Path -LiteralPath $dockerDesktop)) {
        # Ask Docker Desktop to quit so it flushes and detaches the disk cleanly. Killing it
        # first can leave the vhdx attached, which makes the compaction a silent no-op.
        & $dockerDesktop -Quit *>$null
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Process -Name 'Docker Desktop', 'com.docker.backend' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
    }
    Get-Process -Name 'Docker Desktop', 'com.docker.backend', 'com.docker.build' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    wsl --shutdown *>$null
    Start-Sleep -Seconds 5

    # Prove the file is actually free before handing it to diskpart. An exclusive open is the
    # only reliable test; WSL reports "Stopped" before it has released the handle.
    $released = $false
    $releaseDeadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while (-not $released -and (Get-Date) -lt $releaseDeadline) {
        try {
            # Read access with FileShare.None: the share mode is what makes this a test of
            # exclusivity, and asking for write as well would fail on a read-only file for
            # a reason that has nothing to do with anyone else holding it.
            $stream = [System.IO.File]::Open($vhdx, 'Open', 'Read', 'None')
            $stream.Close()
            $released = $true
        } catch {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $released) {
        if ($wasRunning -and (Test-Path -LiteralPath $dockerDesktop)) { Start-Process -FilePath $dockerDesktop }
        throw "Docker virtual disk still locked after $TimeoutSeconds seconds; compaction abandoned."
    }

    $sizeBefore = (Get-Item -LiteralPath $vhdx).Length
    $scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) "compact-docker-$([guid]::NewGuid().ToString('N')).txt"
    try {
        # diskpart reads its script as ANSI, so this file must stay ASCII.
        Set-Content -LiteralPath $scriptPath -Encoding ascii -Value @(
            "select vdisk file=`"$vhdx`""
            'attach vdisk readonly'
            'compact vdisk'
            'detach vdisk'
            'exit'
        )
        diskpart.exe /s $scriptPath *>$null
    } finally {
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
        # Restart Docker only if this function stopped it, so a machine that had Docker closed
        # is left as it was found.
        if ($wasRunning -and (Test-Path -LiteralPath $dockerDesktop)) { Start-Process -FilePath $dockerDesktop }
    }

    $sizeAfter = (Get-Item -LiteralPath $vhdx).Length
    Write-Verbose ("Docker vhdx compacted: {0:N2} GB -> {1:N2} GB" -f ($sizeBefore / 1GB), ($sizeAfter / 1GB))
}

# ---------------------------------------------------------------------------
# Apply one target. Returns a result string and the bytes reclaimed (best
# effort). Every destructive action is gated through ShouldProcess.
# ---------------------------------------------------------------------------

function Invoke-ReclaimTarget {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][string]$PipExecutable,
        [Parameter(Mandatory = $true)][string]$NpmExecutable,
        [Parameter(Mandatory = $true)][int]$KeepTagsPerRepository,
        [Parameter(Mandatory = $true)][int]$DockerShutdownTimeoutSeconds
    )

    if (-not $Plan.Available) { return [pscustomobject]@{ Result = 'Skipped: unavailable'; ReclaimedBytes = 0 } }
    if ($Plan.RequiresAdmin -and -not (Test-IsAdministrator)) {
        return [pscustomobject]@{ Result = 'Skipped: requires elevation'; ReclaimedBytes = 0 }
    }
    if (-not $PSCmdlet.ShouldProcess($Plan.Target, $Plan.Action)) {
        return [pscustomobject]@{ Result = 'Previewed'; ReclaimedBytes = 0 }
    }

    $before = Get-FreeBytesSystemDrive
    # Set by a target that did part of what it promised, and folded into the result below.
    $partialNote = $null
    try {
        switch ($Plan.Target) {
            'PipCache' { & $PipExecutable cache purge *>$null }
            'NpmCache' {
                # Prefer the CLI so npm's own index stays consistent; fall back to deleting the
                # directory when npm is not installed but its cache was left behind.
                if (Get-CommandPath -Name $NpmExecutable) {
                    & $NpmExecutable cache clean --force *>$null
                } else {
                    Remove-Item -LiteralPath (Get-CacheDirectoryPath -Name 'NpmCache') -Recurse -Force -ErrorAction Stop
                }
            }
            'TorchCache' { Remove-Item -LiteralPath (Get-CacheDirectoryPath -Name 'TorchCache') -Recurse -Force -ErrorAction Stop }
            'PreCommitCache' { Remove-Item -LiteralPath (Get-CacheDirectoryPath -Name 'PreCommitCache') -Recurse -Force -ErrorAction Stop }
            'CodexRuntimeCache' {
                # A running Codex holds its own DLLs open, so a partial delete is the ordinary
                # outcome here and must not be reported as a failure. SilentlyContinue removes
                # everything that is not locked and leaves the rest; the caller sees the bytes
                # actually reclaimed, and the residue is reported below.
                Remove-Item -LiteralPath (Get-CacheDirectoryPath -Name 'CodexRuntimeCache') -Recurse -Force -ErrorAction SilentlyContinue
            }
            'NvidiaShaderCache' {
                foreach ($d in (Get-NvidiaShaderCachePath)) {
                    # The driver recreates these directories on demand, so removing the contents
                    # and the directory are equally safe; contents-only avoids a race with a
                    # running GPU application that already holds the directory handle.
                    Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            'PlaywrightBrowsers' { Remove-Item -LiteralPath (Get-CacheDirectoryPath -Name 'PlaywrightBrowsers') -Recurse -Force -ErrorAction Stop }
            'DockerBuildCache' { docker builder prune -f *>$null }
            'DockerDanglingImages' { docker image prune -f *>$null }
            'DockerStoppedContainers' { docker container prune -f *>$null }
            'DockerUnusedVolumes' { docker volume prune -f *>$null }
            'DockerOldImageTags' {
                $attempted = 0
                $refused = 0
                foreach ($image in (Get-SupersededImageTag -KeepCount $KeepTagsPerRepository)) {
                    # Docker refuses to remove an image a container still references. That is the
                    # correct outcome, not an error to abort the whole target on, but it is also
                    # not a removal and must not be reported as one.
                    $attempted++
                    # Reset first, or a stale code left by whatever ran before this loop reads
                    # as a refusal on the first image.
                    Set-Variable -Name LASTEXITCODE -Value 0 -Scope Global
                    docker rmi $image.Reference *>$null
                    if ($LASTEXITCODE -ne 0) { $refused++ }
                }
                if ($refused -gt 0) {
                    $partialNote = "$refused of $attempted superseded tag(s) still referenced and left in place"
                }
            }
            'DockerVhdxCompact' { Invoke-DockerVhdxCompaction -TimeoutSeconds $DockerShutdownTimeoutSeconds }
            'RecycleBin' {
                foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' })) {
                    Clear-RecycleBin -DriveLetter $v.DriveLetter -Force -ErrorAction SilentlyContinue
                }
            }
            'ComponentStore' { Dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null }
            'WindowsUpdateCache' {
                # Stop both the update and BITS services, clear the cache, and
                # guarantee the services restart even if deletion throws midway.
                $updateServices = @('wuauserv', 'bits')
                try {
                    foreach ($svc in $updateServices) { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
                    Get-ChildItem -LiteralPath (Join-Path $env:windir 'SoftwareDistribution\Download') -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } finally {
                    foreach ($svc in $updateServices) { Start-Service -Name $svc -ErrorAction SilentlyContinue }
                }
            }
            'HuggingFaceCache' {
                $hf = if ($env:HF_HOME) { $env:HF_HOME } else { Join-Path $env:USERPROFILE '.cache\huggingface' }
                Remove-Item -LiteralPath $hf -Recurse -Force -ErrorAction Stop
            }
        }
    } catch {
        return [pscustomobject]@{ Result = "Failed: $($_.Exception.Message)"; ReclaimedBytes = 0 }
    }
    $after = Get-FreeBytesSystemDrive

    # A path target that leaves bytes behind did not do what it said. Report that as Partial
    # rather than Reclaimed: a locked cache silently counted as cleared is how a disk that is
    # still full gets signed off as cleaned.
    $result = 'Reclaimed'
    if ($partialNote) {
        $result = "Partial: $partialNote"
    }
    if ($Plan.Target -in @('NpmCache', 'TorchCache', 'PreCommitCache', 'CodexRuntimeCache', 'PlaywrightBrowsers')) {
        $residualBytes = Get-FolderSize -Path (Get-CacheDirectoryPath -Name $Plan.Target)
        if ($residualBytes -gt 0) {
            $result = "Partial: $([math]::Round($residualBytes / 1MB)) MB still in use and left in place"
        }
    }

    # Some tools (Docker VM disk, component store) free space inside a VHDX or
    # over time, so a same-drive delta can read low; report it honestly.
    [pscustomobject]@{ Result = $result; ReclaimedBytes = [long][math]::Max(0, $after - $before) }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $ReportDirectory -Force -WhatIf:$false | Out-Null
$resolvedReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path

$freeBefore = Get-FreeBytesSystemDrive

# Compaction has to run after the Docker targets that empty the disk, whatever order the caller
# listed them in, or it compacts a disk that is still full and reports a successful no-op.
# Partitioned rather than sorted because Sort-Object is not documented as stable, and the
# caller's order among the remaining targets is meaningful.
$uniqueTarget = @($Target | Where-Object { $_ } | Select-Object -Unique)
$compactTarget = @($uniqueTarget | Where-Object { $_ -eq 'DockerVhdxCompact' })
$orderedTarget = @($uniqueTarget | Where-Object { $_ -ne 'DockerVhdxCompact' }) + $compactTarget

$plan = @(foreach ($t in $orderedTarget) {
        Get-ReclaimPlanItem -Name $t -PipExecutable $PipExecutable -NpmExecutable $NpmExecutable `
            -KeepTagsPerRepository $KeepTagsPerRepository
    })

$planPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-plan-$timestamp.csv"
$planJsonPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-plan-$timestamp.json"
$statePath = Join-Path $resolvedReportDirectory "disk-space-reclaim-state-$timestamp.csv"
$stateJsonPath = Join-Path $resolvedReportDirectory "disk-space-reclaim-state-$timestamp.json"

$plan | Export-Csv -Path $planPath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$planJson = if (@($plan).Count) { @($plan) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $planJsonPath -Value $planJson -Encoding utf8 -WhatIf:$false

$state = foreach ($item in $plan) {
    $outcome = Invoke-ReclaimTarget -Plan $item -PipExecutable $PipExecutable -NpmExecutable $NpmExecutable `
        -KeepTagsPerRepository $KeepTagsPerRepository -DockerShutdownTimeoutSeconds $DockerShutdownTimeoutSeconds `
        -WhatIf:$WhatIfPreference
    $item | Add-Member -NotePropertyName Result -NotePropertyValue $outcome.Result -Force
    $item | Add-Member -NotePropertyName ReclaimedBytes -NotePropertyValue $outcome.ReclaimedBytes -Force
    $item
}

$state | Export-Csv -Path $statePath -NoTypeInformation -Encoding utf8 -WhatIf:$false
$stateJson = if (@($state).Count) { @($state) | ConvertTo-Json -Depth 4 } else { '[]' }
Set-Content -LiteralPath $stateJsonPath -Value $stateJson -Encoding utf8 -WhatIf:$false

$freeAfter = Get-FreeBytesSystemDrive

[pscustomobject]@{
    Operation = 'DiskSpaceReclaim'
    Targets = @($orderedTarget)
    IsElevated = (Test-IsAdministrator)
    PlanCsvPath = (Resolve-Path -LiteralPath $planPath).Path
    PlanJsonPath = (Resolve-Path -LiteralPath $planJsonPath).Path
    StateCsvPath = (Resolve-Path -LiteralPath $statePath).Path
    StateJsonPath = (Resolve-Path -LiteralPath $stateJsonPath).Path
    ReclaimedTargets = @($state | Where-Object Result -eq 'Reclaimed').Count
    # Counted apart from Reclaimed on purpose. A target that left bytes behind is not a target
    # that ran; folding the two together is what turns a locked cache into a clean report.
    PartialTargets = @($state | Where-Object { $_.Result -like 'Partial:*' }).Count
    SkippedTargets = @($state | Where-Object { $_.Result -like 'Skipped:*' }).Count
    FailedTargets = @($state | Where-Object { $_.Result -like 'Failed:*' }).Count
    SystemDriveFreeBeforeGB = [math]::Round($freeBefore / 1GB, 2)
    SystemDriveFreeAfterGB = [math]::Round($freeAfter / 1GB, 2)
    SystemDriveReclaimedGB = [math]::Round(($freeAfter - $freeBefore) / 1GB, 2)
    Items = @($state)
}
