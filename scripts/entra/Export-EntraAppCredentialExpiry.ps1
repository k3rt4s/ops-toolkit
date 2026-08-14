<#
.SYNOPSIS
Export Microsoft Entra ID app registration and service principal credential expiry with optional sign-in usage.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Requires Microsoft.Graph.Authentication and Microsoft.Graph.Applications. No
  extra module is needed for -IncludeSignInUsage: it calls the beta signIns
  endpoint directly through Invoke-MgGraphRequest, because the credential key ID
  and the app-only sign-in filter it depends on do not exist on the v1.0 signIn
  resource.
- Use -Connect when the shell is not already connected to Microsoft Graph.
  Delegated scopes requested: Application.Read.All, plus Directory.Read.All for
  -IncludeOwners and AuditLog.Read.All for -IncludeSignInUsage. Owners can be
  users, groups, or other service principals, which is why owner resolution asks
  for directory read rather than something narrower. Override the whole set with
  -GraphScope when your tenant grants something tighter.
- Sign-in log access through Graph requires Microsoft Entra ID P1 or P2. Without it
  the usage columns report Unavailable and the rest of the report still completes.
- This script never changes anything and never writes a secret value to a report.
  Only key IDs, certificate thumbprints, dates, and display names are exported.
- -RecommendedSecretLifetimeDays flags over-long client secrets only. Certificates
  legitimately run one to two years and are never flagged on lifetime.
- Generated reports are written under reports\entra by default.

Purpose:
Use this report-only script to find Entra ID client secrets and certificates that
have expired or are about to, and to say whether each one is actually still in use.
The portal has no native expiry alerting, so the usual discovery path is an
outage. Client secrets cut with the two-year maximum lifetime in 2024 are expiring
across tenants through 2026, which makes an expiry alert on its own ambiguous: the
question is not only what expires but whether anything still authenticates with it.
-IncludeSignInUsage answers that by matching each credential key ID against
service principal sign-ins in the retained log window.

Required syntax:
pwsh -File .\scripts\entra\Export-EntraAppCredentialExpiry.ps1 -Connect
pwsh -File .\scripts\entra\Export-EntraAppCredentialExpiry.ps1 -Connect -IncludeServicePrincipals -ExpiringWithinDays 90
pwsh -File .\scripts\entra\Export-EntraAppCredentialExpiry.ps1 -Connect -IncludeSignInUsage -IncludeOwners -TenantId "<tenant-id>"

.OUTPUTS
Writes CSV and JSON files under reports\entra by default: every credential, the
subset needing attention, an application rollup, and a run summary. Returns a
summary object with output paths and counts.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateRange(1, 730)]
    [int]$ExpiringWithinDays = 60,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$RecommendedSecretLifetimeDays = 180,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$SignInLookbackDays = 30,

    [Parameter()]
    [ValidateRange(100, 500000)]
    [int]$MaxSignInRecord = 50000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$GraphScope,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\entra'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'entra-app-credential-expiry',

    [Parameter()]
    [switch]$IncludeServicePrincipals,

    [Parameter()]
    [switch]$IncludeOwners,

    [Parameter()]
    [switch]$IncludeSignInUsage,

    [Parameter()]
    [switch]$Connect,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$DisconnectWhenFinished
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-OutputDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    (Resolve-Path -LiteralPath $Path).Path
}

function Assert-GraphCommand {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName
    )

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName is not available. Connect with -Connect or install the Microsoft Graph PowerShell module that provides it."
    }
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    $property.Value
}

function Join-ReportValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return (@($Value) | Where-Object { $null -ne $_ }) -join ';'
    }

    [string]$Value
}

function ConvertTo-ThumbprintString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    # customKeyIdentifier arrives as a byte array, but PowerShell unrolls an array
    # returned from a function, so this must accept any byte enumerable, not [byte[]].
    if ($Value -is [System.Collections.IEnumerable]) {
        $bytes = @($Value)
        if ($bytes.Count -eq 0) {
            return ''
        }

        return (($bytes | ForEach-Object { '{0:X2}' -f [byte]$_ }) -join '')
    }

    [string]$Value
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

function Get-OwnerSummary {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Owner
    )

    $names = foreach ($entry in @($Owner)) {
        $additional = Get-PropertyValue -InputObject $entry -Name 'AdditionalProperties'
        $displayName = $null
        if ($additional -is [System.Collections.IDictionary]) {
            foreach ($key in @('userPrincipalName', 'displayName', 'appId')) {
                if ($additional.Contains($key) -and $additional[$key]) {
                    $displayName = [string]$additional[$key]
                    break
                }
            }
        }

        if (-not $displayName) {
            $displayName = Join-ReportValue (Get-PropertyValue -InputObject $entry -Name 'Id')
        }

        $displayName
    }

    Join-ReportValue (@($names) | Where-Object { $_ })
}

function Get-HashtableValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Key)) {
        return $InputObject[$Key]
    }

    Get-PropertyValue -InputObject $InputObject -Name $Key
}

function Add-LatestSignIn {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Map,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [datetime]$Occurred
    )

    if (-not $Map.ContainsKey($Key) -or $Map[$Key] -lt $Occurred) {
        $Map[$Key] = $Occurred
    }
}

function Get-ServicePrincipalSignInUsage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 30)]
        [int]$LookbackDays,

        [Parameter(Mandatory = $true)]
        [ValidateRange(100, 500000)]
        [int]$MaxSignInRecord
    )

    $result = [pscustomobject]@{
        Available = $false
        Error = ''
        LookbackStart = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays)
        SignInCount = 0
        Truncated = $false
        ByCredential = @{}
        ByApplication = @{}
    }

    try {
        Assert-GraphCommand -CommandName 'Invoke-MgGraphRequest'

        # The credential-to-sign-in match needs servicePrincipalCredentialKeyId, and the
        # signInEventTypes filter that isolates app-only sign-ins. Neither exists on the
        # v1.0 signIn resource, so this goes straight at the beta endpoint rather than
        # through Get-MgAuditLogSignIn, which would silently return no key IDs at all
        # and report every live credential as unused.
        $filterStart = $result.LookbackStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge $filterStart"
        $select = 'id,createdDateTime,appId,appDisplayName,servicePrincipalId,servicePrincipalCredentialKeyId'
        $encodedFilter = [uri]::EscapeDataString($filter)
        $encodedSelect = [uri]::EscapeDataString($select)
        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$select=$encodedSelect&`$top=1000"

        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Hashtable -ErrorAction Stop
            $page = @(Get-HashtableValue -InputObject $response -Key 'value')

            foreach ($signIn in $page) {
                $rawCreated = Get-HashtableValue -InputObject $signIn -Key 'createdDateTime'
                if ($null -eq $rawCreated) {
                    continue
                }

                $occurred = ([datetime]$rawCreated).ToUniversalTime()
                $appId = Join-ReportValue (Get-HashtableValue -InputObject $signIn -Key 'appId')
                $keyId = Join-ReportValue (Get-HashtableValue -InputObject $signIn -Key 'servicePrincipalCredentialKeyId')

                if ($appId) {
                    Add-LatestSignIn -Map $result.ByApplication -Key $appId -Occurred $occurred
                }

                if ($appId -and $keyId) {
                    Add-LatestSignIn -Map $result.ByCredential -Key "$appId|$keyId" -Occurred $occurred
                }
            }

            $result.SignInCount += $page.Count

            if ($result.SignInCount -ge $MaxSignInRecord) {
                $result.Truncated = $true
                Write-Warning "Stopped reading sign-ins at the $MaxSignInRecord record cap. Usage columns may understate activity. Raise -MaxSignInRecord or shorten -SignInLookbackDays."
                break
            }

            $uri = Join-ReportValue (Get-HashtableValue -InputObject $response -Key '@odata.nextLink')
        }

        $result.Available = $true
    } catch {
        $result.Error = $_.Exception.Message
        Write-Warning "Sign-in usage lookup failed, usage columns will report Unavailable. $($_.Exception.Message)"
    }

    $result
}

function Get-CredentialRecord {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Application', 'ServicePrincipal')]
        [string]$ObjectType,

        [Parameter(Mandatory = $true)]
        [object]$DirectoryObject,

        [Parameter(Mandatory = $true)]
        [object]$KeyEntry,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ClientSecret', 'Certificate')]
        [string]$KeyEntryType,

        [Parameter(Mandatory = $true)]
        [datetime]$AsOfUtc,

        [Parameter(Mandatory = $true)]
        [int]$ExpiringWithinDays,

        [Parameter(Mandatory = $true)]
        [int]$RecommendedSecretLifetimeDays,

        [Parameter()]
        [AllowNull()]
        [object]$Usage,

        [Parameter()]
        [AllowEmptyString()]
        [string]$OwnerSummary = ''
    )

    $appId = Join-ReportValue (Get-PropertyValue -InputObject $DirectoryObject -Name 'AppId')
    $keyId = Join-ReportValue (Get-PropertyValue -InputObject $KeyEntry -Name 'KeyId')
    $startDateTime = Get-PropertyValue -InputObject $KeyEntry -Name 'StartDateTime'
    $endDateTime = Get-PropertyValue -InputObject $KeyEntry -Name 'EndDateTime'

    $daysToExpiry = $null
    $status = 'Unknown'
    if ($null -ne $endDateTime) {
        $daysToExpiry = [int][math]::Floor((([datetime]$endDateTime).ToUniversalTime() - $AsOfUtc).TotalDays)
        $status = if ($daysToExpiry -lt 0) {
            'Expired'
        } elseif ($daysToExpiry -le $ExpiringWithinDays) {
            'ExpiringSoon'
        } else {
            'Valid'
        }
    }

    $lifetimeDays = $null
    if ($null -ne $startDateTime -and $null -ne $endDateTime) {
        $lifetimeDays = [int][math]::Round((([datetime]$endDateTime) - ([datetime]$startDateTime)).TotalDays)
    }

    # The lifetime guidance is a client secret control. Certificates legitimately run
    # one to two years, so flagging them against the same threshold is pure noise.
    $exceedsRecommendedLifetime = $false
    if ($KeyEntryType -eq 'ClientSecret' -and $null -ne $lifetimeDays) {
        $exceedsRecommendedLifetime = $lifetimeDays -gt $RecommendedSecretLifetimeDays
    }

    $signInStatus = 'NotChecked'
    $lastSignIn = $null
    if ($null -ne $Usage) {
        if (-not $Usage.Available) {
            $signInStatus = 'Unavailable'
        } else {
            $credentialKey = "$appId|$keyId"
            if ($appId -and $keyId -and $Usage.ByCredential.ContainsKey($credentialKey)) {
                $signInStatus = 'InUse'
                $lastSignIn = $Usage.ByCredential[$credentialKey]
            } elseif ($appId -and $Usage.ByApplication.ContainsKey($appId)) {
                $signInStatus = 'AppActiveOnOtherCredential'
                $lastSignIn = $Usage.ByApplication[$appId]
            } else {
                $signInStatus = 'NoRecentSignIn'
            }
        }
    }

    [pscustomobject]@{
        ObjectType = $ObjectType
        DisplayName = Join-ReportValue (Get-PropertyValue -InputObject $DirectoryObject -Name 'DisplayName')
        AppId = $appId
        ObjectId = Join-ReportValue (Get-PropertyValue -InputObject $DirectoryObject -Name 'Id')
        CredentialType = $KeyEntryType
        CredentialDisplayName = Join-ReportValue (Get-PropertyValue -InputObject $KeyEntry -Name 'DisplayName')
        KeyId = $keyId
        Thumbprint = ConvertTo-ThumbprintString -Value (Get-PropertyValue -InputObject $KeyEntry -Name 'CustomKeyIdentifier')
        StartDateTime = $startDateTime
        EndDateTime = $endDateTime
        DaysToExpiry = $daysToExpiry
        LifetimeDays = $lifetimeDays
        Status = $status
        ExceedsRecommendedLifetime = $exceedsRecommendedLifetime
        SignInStatus = $signInStatus
        LastSignInDateTime = $lastSignIn
        SignInAudience = Join-ReportValue (Get-PropertyValue -InputObject $DirectoryObject -Name 'SignInAudience')
        ServicePrincipalType = Join-ReportValue (Get-PropertyValue -InputObject $DirectoryObject -Name 'ServicePrincipalType')
        AccountEnabled = Get-PropertyValue -InputObject $DirectoryObject -Name 'AccountEnabled'
        Owners = $OwnerSummary
    }
}

function Get-ApplicationRollup {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Record
    )

    $groups = @($Record) | Group-Object -Property ObjectType, ObjectId

    foreach ($group in $groups) {
        $rows = @($group.Group)
        $first = $rows[0]
        $dated = @($rows | Where-Object { $null -ne $_.DaysToExpiry })
        $earliest = if ($dated.Count -gt 0) { ($dated | Sort-Object DaysToExpiry | Select-Object -First 1) } else { $null }

        [pscustomobject]@{
            ObjectType = $first.ObjectType
            DisplayName = $first.DisplayName
            AppId = $first.AppId
            ObjectId = $first.ObjectId
            CredentialCount = $rows.Count
            SecretCount = @($rows | Where-Object { $_.CredentialType -eq 'ClientSecret' }).Count
            CertificateCount = @($rows | Where-Object { $_.CredentialType -eq 'Certificate' }).Count
            ExpiredCount = @($rows | Where-Object { $_.Status -eq 'Expired' }).Count
            ExpiringSoonCount = @($rows | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count
            InUseCount = @($rows | Where-Object { $_.SignInStatus -eq 'InUse' }).Count
            EarliestExpiryDateTime = if ($earliest) { $earliest.EndDateTime } else { $null }
            EarliestExpiryDays = if ($earliest) { $earliest.DaysToExpiry } else { $null }
            Owners = $first.Owners
        }
    }
}

if ($Connect) {
    Assert-GraphCommand -CommandName 'Connect-MgGraph'

    $scopes = [System.Collections.Generic.List[string]]::new()
    if ($GraphScope) {
        foreach ($scope in $GraphScope) {
            $scopes.Add($scope)
        }
    } else {
        $scopes.Add('Application.Read.All')
        if ($IncludeOwners) {
            $scopes.Add('Directory.Read.All')
        }
        if ($IncludeSignInUsage) {
            $scopes.Add('AuditLog.Read.All')
        }
    }

    $connectParameters = @{ Scopes = $scopes.ToArray() }
    if ($TenantId) {
        $connectParameters['TenantId'] = $TenantId
    }
    if ($UseDeviceCode) {
        $connectParameters['UseDeviceCode'] = $true
    }

    Connect-MgGraph @connectParameters | Out-Null
} elseif ($TenantId -or $UseDeviceCode -or $GraphScope) {
    throw 'TenantId, UseDeviceCode, and GraphScope apply only to a new connection. Add -Connect, or drop them and reuse the current Microsoft Graph session.'
}

Assert-GraphCommand -CommandName 'Get-MgApplication'
if (-not (Get-MgContext)) {
    throw 'No Microsoft Graph session. Run again with -Connect, or connect first with Connect-MgGraph.'
}

$resolvedOutputDirectory = Resolve-OutputDirectory -Path $OutputDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDirectory = Join-Path $resolvedOutputDirectory "$OutputPrefix-$timestamp"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

$asOfUtc = (Get-Date).ToUniversalTime()
$usage = $null
if ($IncludeSignInUsage) {
    Write-Verbose "Reading service principal sign-ins for the last $SignInLookbackDays days."
    $usage = Get-ServicePrincipalSignInUsage -LookbackDays $SignInLookbackDays -MaxSignInRecord $MaxSignInRecord
}

$credentialRecords = [System.Collections.Generic.List[object]]::new()
$objectsWithoutCredentials = [System.Collections.Generic.List[object]]::new()

if ($IncludeOwners) {
    Assert-GraphCommand -CommandName 'Get-MgApplicationOwner'
    if ($IncludeServicePrincipals) {
        Assert-GraphCommand -CommandName 'Get-MgServicePrincipalOwner'
    }
}

Write-Verbose 'Reading Entra ID app registrations.'
$applicationProperties = @('id', 'appId', 'displayName', 'createdDateTime', 'signInAudience', 'passwordCredentials', 'keyCredentials')
$applications = @(Get-MgApplication -All -Property $applicationProperties)

foreach ($application in $applications) {
    $ownerSummary = ''
    if ($IncludeOwners) {
        $ownerSummary = Get-OwnerSummary -Owner @(Get-MgApplicationOwner -ApplicationId $application.Id -All)
    }

    $passwordCredentials = @(Get-PropertyValue -InputObject $application -Name 'PasswordCredentials' | Where-Object { $null -ne $_ })
    $keyCredentials = @(Get-PropertyValue -InputObject $application -Name 'KeyCredentials' | Where-Object { $null -ne $_ })

    if ($passwordCredentials.Count -eq 0 -and $keyCredentials.Count -eq 0) {
        $objectsWithoutCredentials.Add([pscustomobject]@{
                ObjectType = 'Application'
                DisplayName = Join-ReportValue $application.DisplayName
                AppId = Join-ReportValue $application.AppId
                ObjectId = Join-ReportValue $application.Id
                CreatedDateTime = Get-PropertyValue -InputObject $application -Name 'CreatedDateTime'
                Owners = $ownerSummary
            })
        continue
    }

    foreach ($credential in $passwordCredentials) {
        $credentialRecords.Add((Get-CredentialRecord -ObjectType 'Application' -DirectoryObject $application -KeyEntry $credential -KeyEntryType 'ClientSecret' -AsOfUtc $asOfUtc -ExpiringWithinDays $ExpiringWithinDays -RecommendedSecretLifetimeDays $RecommendedSecretLifetimeDays -Usage $usage -OwnerSummary $ownerSummary))
    }

    foreach ($credential in $keyCredentials) {
        $credentialRecords.Add((Get-CredentialRecord -ObjectType 'Application' -DirectoryObject $application -KeyEntry $credential -KeyEntryType 'Certificate' -AsOfUtc $asOfUtc -ExpiringWithinDays $ExpiringWithinDays -RecommendedSecretLifetimeDays $RecommendedSecretLifetimeDays -Usage $usage -OwnerSummary $ownerSummary))
    }
}

$servicePrincipals = @()
if ($IncludeServicePrincipals) {
    Assert-GraphCommand -CommandName 'Get-MgServicePrincipal'
    Write-Verbose 'Reading Entra ID service principals.'
    $servicePrincipalProperties = @('id', 'appId', 'displayName', 'accountEnabled', 'servicePrincipalType', 'passwordCredentials', 'keyCredentials')
    $servicePrincipals = @(Get-MgServicePrincipal -All -Property $servicePrincipalProperties)

    foreach ($servicePrincipal in $servicePrincipals) {
        $passwordCredentials = @(Get-PropertyValue -InputObject $servicePrincipal -Name 'PasswordCredentials' | Where-Object { $null -ne $_ })
        $keyCredentials = @(Get-PropertyValue -InputObject $servicePrincipal -Name 'KeyCredentials' | Where-Object { $null -ne $_ })

        if ($passwordCredentials.Count -eq 0 -and $keyCredentials.Count -eq 0) {
            continue
        }

        $ownerSummary = ''
        if ($IncludeOwners) {
            $ownerSummary = Get-OwnerSummary -Owner @(Get-MgServicePrincipalOwner -ServicePrincipalId $servicePrincipal.Id -All)
        }

        foreach ($credential in $passwordCredentials) {
            $credentialRecords.Add((Get-CredentialRecord -ObjectType 'ServicePrincipal' -DirectoryObject $servicePrincipal -KeyEntry $credential -KeyEntryType 'ClientSecret' -AsOfUtc $asOfUtc -ExpiringWithinDays $ExpiringWithinDays -RecommendedSecretLifetimeDays $RecommendedSecretLifetimeDays -Usage $usage -OwnerSummary $ownerSummary))
        }

        foreach ($credential in $keyCredentials) {
            $credentialRecords.Add((Get-CredentialRecord -ObjectType 'ServicePrincipal' -DirectoryObject $servicePrincipal -KeyEntry $credential -KeyEntryType 'Certificate' -AsOfUtc $asOfUtc -ExpiringWithinDays $ExpiringWithinDays -RecommendedSecretLifetimeDays $RecommendedSecretLifetimeDays -Usage $usage -OwnerSummary $ownerSummary))
        }
    }
}

$allCredentials = @($credentialRecords) | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysToExpiry) { [int]::MaxValue } else { $_.DaysToExpiry } } }, DisplayName
$needsAttention = @($allCredentials | Where-Object { $_.Status -in @('Expired', 'ExpiringSoon') })
$rollup = @(Get-ApplicationRollup -Record $allCredentials) | Sort-Object -Property @{ Expression = { if ($null -eq $_.EarliestExpiryDays) { [int]::MaxValue } else { $_.EarliestExpiryDays } } }, DisplayName

$exports = @(
    Export-Report -Name 'credentials' -Record $allCredentials -Directory $runDirectory
    Export-Report -Name 'credentials-needing-attention' -Record $needsAttention -Directory $runDirectory
    Export-Report -Name 'application-rollup' -Record $rollup -Directory $runDirectory
    Export-Report -Name 'objects-without-credentials' -Record @($objectsWithoutCredentials) -Directory $runDirectory
)

$summaryPath = Join-Path $runDirectory 'summary.json'
$summary = [pscustomobject]@{
    GeneratedAt = Get-Date
    AsOfUtc = $asOfUtc
    TenantId = (Get-MgContext).TenantId
    OutputDirectory = (Resolve-Path -LiteralPath $runDirectory).Path
    ExpiringWithinDays = $ExpiringWithinDays
    RecommendedSecretLifetimeDays = $RecommendedSecretLifetimeDays
    ApplicationCount = @($applications).Count
    ServicePrincipalCount = @($servicePrincipals).Count
    CredentialCount = @($allCredentials).Count
    ExpiredCount = @($allCredentials | Where-Object { $_.Status -eq 'Expired' }).Count
    ExpiringSoonCount = @($allCredentials | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count
    ExceedsRecommendedLifetimeCount = @($allCredentials | Where-Object { $_.ExceedsRecommendedLifetime }).Count
    ObjectsWithoutCredentialsCount = @($objectsWithoutCredentials).Count
    SignInUsageChecked = [bool]$IncludeSignInUsage
    SignInUsageAvailable = if ($null -eq $usage) { $false } else { [bool]$usage.Available }
    SignInLookbackDays = if ($IncludeSignInUsage) { $SignInLookbackDays } else { $null }
    SignInRecordsRead = if ($null -eq $usage) { 0 } else { $usage.SignInCount }
    SignInRecordsTruncated = if ($null -eq $usage) { $false } else { [bool]$usage.Truncated }
    SignInUsageError = if ($null -eq $usage) { '' } else { $usage.Error }
    ExpiringAndInUseCount = @($needsAttention | Where-Object { $_.SignInStatus -eq 'InUse' }).Count
    ExpiringAndUnusedCount = @($needsAttention | Where-Object { $_.SignInStatus -eq 'NoRecentSignIn' }).Count
    Exports = @($exports)
}

Set-Content -LiteralPath $summaryPath -Value ($summary | ConvertTo-Json -Depth 8) -Encoding utf8
$summary | Add-Member -NotePropertyName SummaryPath -NotePropertyValue (Resolve-Path -LiteralPath $summaryPath).Path -Force

if ($DisconnectWhenFinished) {
    Disconnect-MgGraph | Out-Null
}

$summary
