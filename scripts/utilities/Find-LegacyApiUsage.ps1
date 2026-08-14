<#
.SYNOPSIS
Scan a folder tree for Microsoft modules, cmdlets, and APIs that have a published retirement or cutoff date.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Read-only. It never changes a scanned file and needs no elevation or credentials.
- Point -Path at a script share, a repo, or any folder tree. Multiple paths are allowed.
- Findings are advisory. Open each hit before acting, because a pattern can match a
  comment, a doc example, or a string that only mentions the retired API.
- The cutoff dates in the rule table were current at the time of writing. Confirm a
  date against Microsoft's own announcement before you plan work around it.
- Generated reports are written under reports\utilities by default.

.PURPOSE
Use this script to find, in one pass, every place that still calls something
Microsoft has retired or scheduled for retirement, so the nearest cutoff can be
worked first instead of being discovered when an integration stops authenticating.
It covers the retired identity modules (MSOnline, AzureAD, AzureRM, ADAL), the
Exchange Online cutoffs (EWS for non-Microsoft apps, the -Credential parameter,
Application Impersonation, the original Get-MessageTrace), and Send-MailMessage.
Each finding carries the deadline, the reason, and the replacement.

.REQUIRED SYNTAX
pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts
pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path C:\Scripts,D:\Share -Severity Broken
pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path . -OutputDirectory .\reports\utilities

.OUTPUTS
Writes findings, a per-rule rollup, a per-deadline rollup, and a summary as CSV and
JSON under reports\utilities by default. Returns a summary object with output paths
and counts. Exits 2 when -Path is missing.

.STATUS
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Extension = @('.ps1', '.psm1', '.psd1', '.py', '.cs', '.js', '.ts', '.vbs', '.bat', '.cmd', '.txt', '.md', '.yml', '.yaml', '.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ExcludeDirectory = @('.git', 'node_modules', '.venv', 'venv', '__pycache__', 'bin', 'obj', 'dist', 'build'),

    [Parameter()]
    [ValidateSet('All', 'Broken', 'Deadline', 'Advisory')]
    [string]$Severity = 'All',

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxFileSizeMb = 10,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\utilities'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'legacy-api-usage',

    [Parameter()]
    [switch]$IncludeSelf
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if (-not $Path) {
    @(
        'Find-LegacyApiUsage.ps1 scans a folder tree for retired or soon-to-be-retired Microsoft APIs.'
        ''
        'Usage:'
        '  pwsh -File .\scripts\utilities\Find-LegacyApiUsage.ps1 -Path <folder> [-Path <folder2>]'
        '                                                        [-Severity All|Broken|Deadline|Advisory]'
        '                                                        [-Extension .ps1,.py] [-ExcludeDirectory .git]'
        '                                                        [-OutputDirectory <dir>] [-IncludeSelf]'
        ''
        '-Path is required.'
    ) | Write-Output
    exit 2
}

# Each rule states what to look for, when it stops working, and what replaces it.
# Severity: Broken is already retired, Deadline has a future cutoff, Advisory is
# deprecated with no hard date. Keep Pattern anchored enough that a rule cannot
# match its own replacement (see the Get-MessageTrace negative lookahead).
$rules = @(
    [pscustomobject]@{
        RuleId = 'MSOL-001'
        Category = 'Identity module'
        Pattern = '(?i)(Import-Module\s+MSOnline|Connect-MsolService|\b(Get|Set|New|Remove|Add|Redo|Confirm|Convert|Restore)-Msol[A-Za-z]+)'
        Severity = 'Broken'
        Deadline = '2025-05-31'
        DeadlineNote = 'MSOnline PowerShell retired through May 2025 and no longer works for any tenant or cloud.'
        Replacement = 'Microsoft Graph PowerShell SDK, or Microsoft Entra PowerShell.'
    }
    [pscustomobject]@{
        RuleId = 'AAD-001'
        Category = 'Identity module'
        Pattern = '(?i)(Import-Module\s+AzureADPreview|Import-Module\s+AzureAD\b|Connect-AzureAD|\b(Get|Set|New|Remove|Add|Enable|Disable|Select)-AzureAD[A-Za-z]+)'
        Severity = 'Broken'
        Deadline = '2025-07-01'
        DeadlineNote = 'AzureAD PowerShell unsupported after 30 March 2025 and retired after 1 July 2025.'
        Replacement = 'Microsoft Graph PowerShell SDK, or Microsoft Entra PowerShell (over 90 percent parity).'
    }
    [pscustomobject]@{
        RuleId = 'ARM-001'
        Category = 'Azure module'
        Pattern = '(?i)(Import-Module\s+AzureRM|\b(Get|Set|New|Remove|Add|Start|Stop|Restart|Select)-AzureRm[A-Za-z]+)'
        Severity = 'Broken'
        Deadline = '2024-02-29'
        DeadlineNote = 'AzureRM PowerShell retired 29 February 2024. This repo also forbids new AzureRM automation.'
        Replacement = 'The Az PowerShell module.'
    }
    [pscustomobject]@{
        RuleId = 'ADAL-001'
        Category = 'Auth library'
        Pattern = '(?i)(Microsoft\.IdentityModel\.Clients\.ActiveDirectory|AuthenticationContext\s*\(|\bADAL\b)'
        Severity = 'Broken'
        Deadline = '2023-06-30'
        DeadlineNote = 'Azure AD Authentication Library (ADAL) reached end of support 30 June 2023.'
        Replacement = 'Microsoft Authentication Library (MSAL).'
    }
    [pscustomobject]@{
        RuleId = 'EXO-001'
        Category = 'Exchange Online'
        Pattern = '(?i)Connect-ExchangeOnline[^\r\n]*-Credential'
        Severity = 'Deadline'
        Deadline = '2026-12-01'
        DeadlineNote = 'The -Credential parameter is removed from Exchange Online PowerShell versions released December 2026 or later. It relies on ROPC and cannot satisfy MFA or Conditional Access.'
        Replacement = 'Interactive sign-in, or certificate-based app-only authentication with -CertificateThumbprint and -AppId.'
    }
    [pscustomobject]@{
        RuleId = 'EWS-001'
        Category = 'Exchange Online'
        Pattern = '(?i)(Microsoft\.Exchange\.WebServices|\bExchangeService\b|ExchangeVersion\.Exchange|AutodiscoverUrl)'
        Severity = 'Deadline'
        Deadline = '2026-10-01'
        DeadlineNote = 'From 1 October 2026 Microsoft blocks non-Microsoft apps from using EWS to connect to Exchange Online.'
        Replacement = 'Microsoft Graph, which also supports RBAC for applications accessing mailboxes.'
    }
    [pscustomobject]@{
        RuleId = 'EXO-002'
        Category = 'Exchange Online'
        Pattern = '(?i)ApplicationImpersonation'
        Severity = 'Broken'
        Deadline = '2025-03-31'
        DeadlineNote = 'The ApplicationImpersonation RBAC role was retired in Exchange Online in March 2025.'
        Replacement = 'Graph application permissions scoped with RBAC for Applications, or delegated mailbox access.'
    }
    [pscustomobject]@{
        RuleId = 'EXO-003'
        Category = 'Exchange Online'
        Pattern = '(?i)\bGet-MessageTrace(?!V2)\b'
        Severity = 'Advisory'
        Deadline = ''
        DeadlineNote = 'The original Get-MessageTrace is superseded by Get-MessageTraceV2, which uses 10-day query windows and continuation keys.'
        Replacement = 'Get-MessageTraceV2. See scripts\microsoft-365\Export-M365DistributionGroupMessageTraceUsage.ps1 for the paging pattern.'
    }
    [pscustomobject]@{
        RuleId = 'SMTP-001'
        Category = 'Mail submission'
        Pattern = '(?i)(Send-MailMessage|System\.Net\.Mail\.SmtpClient|New-Object\s+Net\.Mail\.SmtpClient)'
        Severity = 'Advisory'
        Deadline = ''
        DeadlineNote = 'Send-MailMessage is obsolete and cannot do modern authentication. SMTP AUTH with a password is blocked wherever basic authentication is disabled.'
        Replacement = 'Microsoft Graph sendMail, or an SMTP client that supports OAuth 2.0.'
    }
)

$activeRules = if ($Severity -eq 'All') { $rules } else { @($rules | Where-Object { $_.Severity -eq $Severity }) }
if (-not $activeRules) {
    throw "No rules match -Severity $Severity."
}

function Resolve-OutputDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Export-Report {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Record,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory
    )

    $csvPath = Join-Path $Directory "$Name.csv"
    $jsonPath = Join-Path $Directory "$Name.json"
    $Record | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    Set-Content -LiteralPath $jsonPath -Value (@($Record) | ConvertTo-Json -Depth 8) -Encoding utf8

    [pscustomobject]@{
        Name = $Name
        Count = @($Record).Count
        CsvPath = (Resolve-Path -LiteralPath $csvPath).Path
        JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    }
}

function Test-CommentLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$FileExtension
    )

    $trimmed = $Line.TrimStart()
    if (-not $trimmed) {
        return $false
    }

    switch ($FileExtension.ToLowerInvariant()) {
        { $_ -in '.ps1', '.psm1', '.psd1', '.py', '.yml', '.yaml' } { return $trimmed.StartsWith('#') }
        { $_ -in '.cs', '.js', '.ts' } { return $trimmed.StartsWith('//') }
        '.vbs' { return $trimmed.StartsWith("'") }
        { $_ -in '.bat', '.cmd' } { return $trimmed -match '^(?i)(rem\b|::)' }
        '.md' { return $false }
        default { return $false }
    }
}

function Get-ScanFile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Root,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IncludeExtension,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$SkipDirectory,

        [Parameter(Mandatory = $true)]
        [int]$MaxBytes
    )

    $extensionSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $IncludeExtension) {
        $extensionSet.Add($item) | Out-Null
    }

    $skipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $SkipDirectory) {
        $skipSet.Add($item) | Out-Null
    }

    foreach ($rootPath in $Root) {
        if (-not (Test-Path -LiteralPath $rootPath)) {
            Write-Warning "Path not found, skipped: $rootPath"
            continue
        }

        $resolved = (Resolve-Path -LiteralPath $rootPath).Path
        foreach ($file in (Get-ChildItem -LiteralPath $resolved -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if (-not $extensionSet.Contains($file.Extension)) {
                continue
            }

            if ($file.Length -gt $MaxBytes) {
                Write-Verbose "Skipped oversize file: $($file.FullName)"
                continue
            }

            $segments = $file.DirectoryName -split '[\\/]'
            $skip = $false
            foreach ($segment in $segments) {
                if ($skipSet.Contains($segment)) {
                    $skip = $true
                    break
                }
            }

            if (-not $skip) {
                $file
            }
        }
    }
}

$resolvedOutputDirectory = Resolve-OutputDirectory -Path $OutputDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDirectory = Join-Path $resolvedOutputDirectory "$OutputPrefix-$timestamp"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

$selfPath = $MyInvocation.MyCommand.Path
$findings = [System.Collections.Generic.List[object]]::new()
$scannedCount = 0
$unreadableCount = 0

foreach ($file in (Get-ScanFile -Root $Path -IncludeExtension $Extension -SkipDirectory $ExcludeDirectory -MaxBytes ($MaxFileSizeMb * 1MB))) {
    # Without this the scanner reports its own rule table as findings.
    if (-not $IncludeSelf -and $selfPath -and $file.FullName -eq $selfPath) {
        Write-Verbose 'Skipped this scanner. Use -IncludeSelf to scan it too.'
        continue
    }

    $lines = $null
    try {
        $lines = [System.IO.File]::ReadAllLines($file.FullName)
    } catch {
        $unreadableCount++
        Write-Warning "Could not read $($file.FullName): $($_.Exception.Message)"
        continue
    }

    $scannedCount++

    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if (-not $line) {
            continue
        }

        foreach ($rule in $activeRules) {
            $matchResult = [regex]::Match($line, $rule.Pattern)
            if (-not $matchResult.Success) {
                continue
            }

            $findings.Add([pscustomobject]@{
                    RuleId = $rule.RuleId
                    Severity = $rule.Severity
                    Category = $rule.Category
                    Deadline = $rule.Deadline
                    File = $file.FullName
                    LineNumber = $index + 1
                    MatchedText = $matchResult.Value
                    LineText = $line.Trim()
                    InComment = Test-CommentLine -Line $line -FileExtension $file.Extension
                    DeadlineNote = $rule.DeadlineNote
                    Replacement = $rule.Replacement
                })
        }
    }
}

$allFindings = @($findings) | Sort-Object -Property @{ Expression = { if ($_.Deadline) { $_.Deadline } else { '9999-12-31' } } }, RuleId, File, LineNumber

$ruleRollup = foreach ($group in (@($allFindings) | Group-Object -Property RuleId)) {
    $rule = $activeRules | Where-Object { $_.RuleId -eq $group.Name } | Select-Object -First 1
    [pscustomobject]@{
        RuleId = $group.Name
        Severity = $rule.Severity
        Category = $rule.Category
        Deadline = $rule.Deadline
        FindingCount = $group.Count
        FileCount = @($group.Group | Select-Object -ExpandProperty File -Unique).Count
        CodeLineCount = @($group.Group | Where-Object { -not $_.InComment }).Count
        CommentLineCount = @($group.Group | Where-Object { $_.InComment }).Count
        Replacement = $rule.Replacement
    }
}

$deadlineRollup = foreach ($group in (@($allFindings) | Group-Object -Property Deadline)) {
    [pscustomobject]@{
        Deadline = if ($group.Name) { $group.Name } else { '(no fixed date)' }
        FindingCount = $group.Count
        FileCount = @($group.Group | Select-Object -ExpandProperty File -Unique).Count
        RuleIds = (@($group.Group | Select-Object -ExpandProperty RuleId -Unique) | Sort-Object) -join ';'
    }
}

$exports = @(
    Export-Report -Name 'findings' -Record $allFindings -Directory $runDirectory
    Export-Report -Name 'rule-rollup' -Record @($ruleRollup) -Directory $runDirectory
    Export-Report -Name 'deadline-rollup' -Record @($deadlineRollup) -Directory $runDirectory
)

$summaryPath = Join-Path $runDirectory 'summary.json'
$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    ScannedPaths = @($Path)
    OutputDirectory = (Resolve-Path -LiteralPath $runDirectory).Path
    SeverityFilter = $Severity
    RulesApplied = @($activeRules.RuleId)
    FilesScanned = $scannedCount
    FilesUnreadable = $unreadableCount
    FindingCount = @($allFindings).Count
    FindingsInCode = @($allFindings | Where-Object { -not $_.InComment }).Count
    FindingsInComments = @($allFindings | Where-Object { $_.InComment }).Count
    BrokenCount = @($allFindings | Where-Object { $_.Severity -eq 'Broken' }).Count
    DeadlineCount = @($allFindings | Where-Object { $_.Severity -eq 'Deadline' }).Count
    AdvisoryCount = @($allFindings | Where-Object { $_.Severity -eq 'Advisory' }).Count
    FilesWithFindings = @($allFindings | Select-Object -ExpandProperty File -Unique).Count
    Exports = @($exports)
}

Set-Content -LiteralPath $summaryPath -Value ($summary | ConvertTo-Json -Depth 8) -Encoding utf8
$summary | Add-Member -NotePropertyName SummaryPath -NotePropertyValue (Resolve-Path -LiteralPath $summaryPath).Path -Force
$summary
