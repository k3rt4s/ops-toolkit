<#
.SYNOPSIS
Inventory certificate expiry across local machine stores, IIS bindings, and remote TLS endpoints.

.DESCRIPTION
Instructions:
- Read the root README.md before running this script.
- Read-only. It reads certificate stores and opens TLS connections to read the
  presented certificate. It installs, renews, and removes nothing.
- Private keys are never read or exported. Only subject, issuer, thumbprint, dates,
  algorithm, and key size are reported.
- IIS binding enumeration needs the WebAdministration module and an elevated shell.
  It is skipped with a note when either is missing.
- -Endpoint probes remote hosts as host:port. The probe deliberately accepts any
  certificate so an already-expired or untrusted certificate is still reported
  rather than dropped as a connection failure. Nothing is trusted as a result of
  this; the certificate is read and discarded.
- Generated reports are written under reports\certificates by default.

Purpose:
Certificate expiry is the same failure as an Entra client secret expiring: nobody
notices until an outage, because the thing that expires is not the thing being
watched. This covers the three places a certificate hides on a Windows estate, the
machine store, an IIS binding, and whatever is actually being served on the wire,
and reports them on one timeline. The wire probe matters because a store can hold a
renewed certificate that no binding is using.

Required syntax:
pwsh -File .\scripts\certificates\Export-CertificateExpiryInventory.ps1
pwsh -File .\scripts\certificates\Export-CertificateExpiryInventory.ps1 -IncludeIisBindings -ExpiringWithinDays 90
pwsh -File .\scripts\certificates\Export-CertificateExpiryInventory.ps1 -Endpoint 'www.example.com:443','mail.example.com:993'

.OUTPUTS
Writes a certificate inventory, the subset needing attention, and a run summary as
CSV and JSON under reports\certificates by default. Returns a summary object.

.NOTES
Status:
Active script kept in the reorganized ops-toolkit repo.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$StorePath = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting', 'Cert:\LocalMachine\Remote Desktop'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Endpoint,

    [Parameter()]
    [switch]$IncludeIisBindings,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$ExpiringWithinDays = 60,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$ProbeTimeoutSeconds = 10,

    [Parameter()]
    [ValidateRange(0, 4096)]
    [int]$WeakKeySizeBits = 2048,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports\certificates'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPrefix = 'certificate-expiry-inventory'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\modules\OpsToolkit.Reporting') -Force

$asOf = Get-Date
$records = [System.Collections.Generic.List[object]]::new()

function Get-CertificateRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Note = '',

        # Passed rather than captured from script scope, so the dependency is visible
        # at every call site instead of being implied.
        [Parameter(Mandatory = $true)]
        [int]$MinimumKeySizeBits
    )

    $notAfter = [datetime]$Certificate.NotAfter
    $daysToExpiry = [int][math]::Floor(($notAfter - $asOf).TotalDays)
    $status = if ($daysToExpiry -lt 0) {
        'Expired'
    } elseif ($daysToExpiry -le $ExpiringWithinDays) {
        'ExpiringSoon'
    } else {
        'Valid'
    }

    $keySize = $null
    try {
        $keySize = $Certificate.PublicKey.Key.KeySize
    } catch {
        $keySize = $null
    }

    $signature = [string]$Certificate.SignatureAlgorithm.FriendlyName
    $weakSignature = $signature -match '(?i)(md5|sha1)'
    $weakKey = $null -ne $keySize -and $keySize -lt $MinimumKeySizeBits

    $sanEntries = ''
    try {
        $san = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($san) {
            $sanEntries = ($san.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ';')
        }
    } catch {
        $sanEntries = ''
    }

    [pscustomobject]@{
        Source = $Source
        Location = $Location
        Status = $status
        Subject = [string]$Certificate.Subject
        Issuer = [string]$Certificate.Issuer
        Thumbprint = [string]$Certificate.Thumbprint
        SerialNumber = [string]$Certificate.SerialNumber
        NotBefore = $Certificate.NotBefore
        NotAfter = $notAfter
        DaysToExpiry = $daysToExpiry
        SignatureAlgorithm = $signature
        KeySizeBits = $keySize
        WeakSignature = $weakSignature
        WeakKey = $weakKey
        HasPrivateKey = [bool]$Certificate.HasPrivateKey
        SubjectAlternativeNames = $sanEntries
        Note = $Note
    }
}

foreach ($store in $StorePath) {
    if (-not (Test-Path -LiteralPath $store)) {
        Write-Verbose "Store not present, skipped: $store"
        continue
    }

    try {
        foreach ($certificate in (Get-ChildItem -LiteralPath $store -ErrorAction Stop)) {
            $records.Add((Get-CertificateRecord -Certificate $certificate -Source 'CertificateStore' -Location $store -MinimumKeySizeBits $WeakKeySizeBits))
        }
    } catch {
        Write-Warning "Could not read $store : $($_.Exception.Message)"
    }
}

$iisChecked = $false
if ($IncludeIisBindings) {
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-Warning 'IIS bindings were requested but the WebAdministration module is not available. Skipped.'
    } else {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $iisChecked = $true
            foreach ($site in (Get-ChildItem -LiteralPath 'IIS:\Sites' -ErrorAction Stop)) {
                foreach ($binding in @($site.Bindings.Collection)) {
                    if ([string]$binding.protocol -ne 'https') {
                        continue
                    }

                    $thumbprint = ConvertTo-OpsHexString -Value $binding.certificateHash
                    if (-not $thumbprint) {
                        continue
                    }

                    $storeName = if ($binding.certificateStoreName) { $binding.certificateStoreName } else { 'My' }
                    $certPath = "Cert:\LocalMachine\$storeName\$thumbprint"
                    if (Test-Path -LiteralPath $certPath) {
                        $certificate = Get-Item -LiteralPath $certPath
                        $records.Add((Get-CertificateRecord -Certificate $certificate -Source 'IisBinding' `
                                    -Location "$($site.Name) $($binding.bindingInformation)" -Note "Store: $storeName" -MinimumKeySizeBits $WeakKeySizeBits))
                    } else {
                        # A binding pointing at a thumbprint that is not in the store
                        # serves nothing. This is a hard failure, not a missing record.
                        $records.Add([pscustomobject]@{
                                Source = 'IisBinding'
                                Location = "$($site.Name) $($binding.bindingInformation)"
                                Status = 'MissingCertificate'
                                Subject = ''
                                Issuer = ''
                                Thumbprint = $thumbprint
                                SerialNumber = ''
                                NotBefore = $null
                                NotAfter = $null
                                DaysToExpiry = $null
                                SignatureAlgorithm = ''
                                KeySizeBits = $null
                                WeakSignature = $false
                                WeakKey = $false
                                HasPrivateKey = $false
                                SubjectAlternativeNames = ''
                                Note = "Binding references a certificate that is not in Cert:\LocalMachine\$storeName."
                            })
                    }
                }
            }
        } catch {
            Write-Warning "Could not enumerate IIS bindings: $($_.Exception.Message)"
        }
    }
}

foreach ($target in @($Endpoint)) {
    if (-not $target) {
        continue
    }

    $parts = $target -split ':'
    $probeHost = $parts[0]
    $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }

    $client = $null
    $stream = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $connect = $client.ConnectAsync($probeHost, $port)
        if (-not $connect.Wait([timespan]::FromSeconds($ProbeTimeoutSeconds))) {
            throw "Connection timed out after $ProbeTimeoutSeconds seconds."
        }

        # Accept any certificate. The point is to read what is being served,
        # including a certificate that is expired or untrusted, which is precisely
        # the case a validating client would refuse and report as a bare failure.
        $stream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { $true })
        $stream.AuthenticateAsClient($probeHost)
        $remote = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        $records.Add((Get-CertificateRecord -Certificate $remote -Source 'TlsEndpoint' -Location $target `
                    -Note "Negotiated $($stream.SslProtocol), cipher $($stream.NegotiatedCipherSuite)" -MinimumKeySizeBits $WeakKeySizeBits))
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $records.Add([pscustomobject]@{
                Source = 'TlsEndpoint'
                Location = $target
                Status = 'ProbeFailed'
                Subject = ''
                Issuer = ''
                Thumbprint = ''
                SerialNumber = ''
                NotBefore = $null
                NotAfter = $null
                DaysToExpiry = $null
                SignatureAlgorithm = ''
                KeySizeBits = $null
                WeakSignature = $false
                WeakKey = $false
                HasPrivateKey = $false
                SubjectAlternativeNames = ''
                Note = $_.Exception.Message
            })
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

$inventory = @($records) | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysToExpiry) { [int]::MaxValue } else { $_.DaysToExpiry } } }, Location, Subject
$attention = @($inventory | Where-Object { $_.Status -in @('Expired', 'ExpiringSoon', 'MissingCertificate', 'ProbeFailed') -or $_.WeakSignature -or $_.WeakKey })

$runDirectory = Resolve-OpsRunDirectory -OutputDirectory $OutputDirectory -Prefix $OutputPrefix
$exports = @(
    Export-OpsReport -Name 'certificates' -Record $inventory -Directory $runDirectory
    Export-OpsReport -Name 'certificates-needing-attention' -Record $attention -Directory $runDirectory
)

$summary = [pscustomobject]@{
    GeneratedAt = $asOf
    OutputDirectory = $runDirectory
    StoresScanned = @($StorePath | Where-Object { Test-Path -LiteralPath $_ })
    IisBindingsChecked = $iisChecked
    EndpointsProbed = @($Endpoint).Count
    ExpiringWithinDays = $ExpiringWithinDays
    CertificateCount = @($inventory).Count
    ExpiredCount = @($inventory | Where-Object { $_.Status -eq 'Expired' }).Count
    ExpiringSoonCount = @($inventory | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count
    MissingCertificateCount = @($inventory | Where-Object { $_.Status -eq 'MissingCertificate' }).Count
    ProbeFailedCount = @($inventory | Where-Object { $_.Status -eq 'ProbeFailed' }).Count
    WeakSignatureCount = @($inventory | Where-Object { $_.WeakSignature }).Count
    WeakKeyCount = @($inventory | Where-Object { $_.WeakKey }).Count
    AttentionCount = @($attention).Count
    Exports = @($exports)
}

Export-OpsSummary -Summary $summary -Directory $runDirectory
