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
- -ComputerName reads certificate stores and IIS bindings on remote machines, which
  needs WinRM and local administrator rights on each. TLS endpoint probes always run
  from the machine this script was started on: what a certificate looks like on the
  wire is a property of the endpoint, not of the machine doing the asking, so
  probing the same endpoint from every target would return the same answer N times.
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
    [string[]]$ComputerName,

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
    <#
    .SYNOPSIS
    Turn a certificate fact into a reportable record with its expiry status.

    .DESCRIPTION
    Takes a plain fact object rather than an X509Certificate2 so that a certificate
    read on a remote machine and one read locally travel the same path. Certificate
    objects do not survive remoting intact.

    .PARAMETER Fact
    A certificate fact from the probe, or one built for a TLS endpoint.

    .PARAMETER MinimumKeySizeBits
    Key sizes below this are flagged weak. Passed rather than captured from script
    scope so the dependency is visible at every call site.

    .OUTPUTS
    PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Fact,

        [Parameter(Mandatory = $true)]
        [int]$MinimumKeySizeBits
    )

    $notAfter = Get-OpsPropertyValue -InputObject $Fact -Name 'NotAfter'
    $isMissing = [bool](Get-OpsPropertyValue -InputObject $Fact -Name 'Missing')

    $daysToExpiry = $null
    $status = 'MissingCertificate'
    if (-not $isMissing -and $null -ne $notAfter) {
        $daysToExpiry = [int][math]::Floor((([datetime]$notAfter) - $asOf).TotalDays)
        $status = if ($daysToExpiry -lt 0) {
            'Expired'
        } elseif ($daysToExpiry -le $ExpiringWithinDays) {
            'ExpiringSoon'
        } else {
            'Valid'
        }
    }

    $keySize = Get-OpsPropertyValue -InputObject $Fact -Name 'KeySizeBits'
    $signature = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'SignatureAlgorithm')

    [pscustomobject]@{
        ComputerName = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'ComputerName')
        Source = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Source')
        Location = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Location')
        Status = $status
        Subject = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Subject')
        Issuer = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Issuer')
        Thumbprint = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Thumbprint')
        SerialNumber = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'SerialNumber')
        NotBefore = Get-OpsPropertyValue -InputObject $Fact -Name 'NotBefore'
        NotAfter = $notAfter
        DaysToExpiry = $daysToExpiry
        SignatureAlgorithm = $signature
        KeySizeBits = $keySize
        WeakSignature = [bool]($signature -match '(?i)(md5|sha1)')
        WeakKey = ($null -ne $keySize -and [int]$keySize -lt $MinimumKeySizeBits)
        HasPrivateKey = [bool](Get-OpsPropertyValue -InputObject $Fact -Name 'HasPrivateKey')
        SubjectAlternativeNames = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'SubjectAlternativeNames')
        Note = Join-OpsValue (Get-OpsPropertyValue -InputObject $Fact -Name 'Note')
    }
}

function ConvertTo-CertificateFact {
    <#
    .SYNOPSIS
    Build a certificate fact from a live X509Certificate2, for the TLS endpoint probe.

    .PARAMETER Certificate
    The certificate presented by the endpoint.

    .PARAMETER Location
    The endpoint, as host:port.

    .PARAMETER Note
    Free text, used for the negotiated protocol and cipher.

    .OUTPUTS
    PSCustomObject shaped like the probe's facts.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Note = ''
    )

    $keySize = $null
    try { $keySize = $Certificate.PublicKey.Key.KeySize } catch { $keySize = $null }

    $sanEntries = ''
    try {
        $san = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($san) { $sanEntries = ($san.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ';') }
    } catch { $sanEntries = '' }

    [pscustomobject]@{
        # The probing machine, not a machine that owns the certificate. An endpoint
        # certificate belongs to the endpoint.
        ComputerName = $env:COMPUTERNAME
        Source = 'TlsEndpoint'
        Location = $Location
        Subject = [string]$Certificate.Subject
        Issuer = [string]$Certificate.Issuer
        Thumbprint = [string]$Certificate.Thumbprint
        SerialNumber = [string]$Certificate.SerialNumber
        NotBefore = $Certificate.NotBefore
        NotAfter = $Certificate.NotAfter
        SignatureAlgorithm = [string]$Certificate.SignatureAlgorithm.FriendlyName
        KeySizeBits = $keySize
        HasPrivateKey = [bool]$Certificate.HasPrivateKey
        SubjectAlternativeNames = $sanEntries
        Missing = $false
        Note = $Note
    }
}

# Certificate objects do not survive PowerShell remoting intact, so the probe reads
# the fields it needs on the machine that owns the store and returns plain data. The
# same block runs locally, which keeps one code path rather than two that drift.
$certificateProbe = {
    param($StorePathList, $IncludeIis)

    function ConvertTo-Hex {
        param($Value)
        if ($null -eq $Value) { return '' }
        if ($Value -is [string]) { return $Value }
        return ((@($Value) | ForEach-Object { '{0:X2}' -f [byte]$_ }) -join '')
    }

    function Get-Fact {
        param($Certificate, $Source, $Location, $Note = '')

        $keySize = $null
        try { $keySize = $Certificate.PublicKey.Key.KeySize } catch { $keySize = $null }

        $sanEntries = ''
        try {
            $san = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if ($san) { $sanEntries = ($san.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ';') }
        } catch { $sanEntries = '' }

        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Source = $Source
            Location = $Location
            Subject = [string]$Certificate.Subject
            Issuer = [string]$Certificate.Issuer
            Thumbprint = [string]$Certificate.Thumbprint
            SerialNumber = [string]$Certificate.SerialNumber
            NotBefore = $Certificate.NotBefore
            NotAfter = $Certificate.NotAfter
            SignatureAlgorithm = [string]$Certificate.SignatureAlgorithm.FriendlyName
            KeySizeBits = $keySize
            HasPrivateKey = [bool]$Certificate.HasPrivateKey
            SubjectAlternativeNames = $sanEntries
            Missing = $false
            Note = $Note
        }
    }

    $facts = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    foreach ($store in @($StorePathList)) {
        if (-not (Test-Path -LiteralPath $store)) {
            continue
        }

        try {
            foreach ($certificate in (Get-ChildItem -LiteralPath $store -ErrorAction Stop)) {
                $facts.Add((Get-Fact -Certificate $certificate -Source 'CertificateStore' -Location $store))
            }
        } catch {
            $warnings.Add("Could not read $store : $($_.Exception.Message)")
        }
    }

    $iisRead = $false
    if ($IncludeIis) {
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            $warnings.Add('IIS bindings were requested but the WebAdministration module is not available.')
        } else {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $iisRead = $true
                foreach ($site in (Get-ChildItem -LiteralPath 'IIS:\Sites' -ErrorAction Stop)) {
                    foreach ($binding in @($site.Bindings.Collection)) {
                        if ([string]$binding.protocol -ne 'https') { continue }

                        $thumbprint = ConvertTo-Hex -Value $binding.certificateHash
                        if (-not $thumbprint) { continue }

                        $storeName = if ($binding.certificateStoreName) { $binding.certificateStoreName } else { 'My' }
                        $certPath = "Cert:\LocalMachine\$storeName\$thumbprint"
                        $location = "$($site.Name) $($binding.bindingInformation)"

                        if (Test-Path -LiteralPath $certPath) {
                            $facts.Add((Get-Fact -Certificate (Get-Item -LiteralPath $certPath) -Source 'IisBinding' -Location $location -Note "Store: $storeName"))
                        } else {
                            # A binding pointing at a thumbprint that is not in the
                            # store serves nothing. That is a hard failure, not a
                            # missing record.
                            $facts.Add([pscustomobject]@{
                                    ComputerName = $env:COMPUTERNAME
                                    Source = 'IisBinding'
                                    Location = $location
                                    Subject = ''
                                    Issuer = ''
                                    Thumbprint = $thumbprint
                                    SerialNumber = ''
                                    NotBefore = $null
                                    NotAfter = $null
                                    SignatureAlgorithm = ''
                                    KeySizeBits = $null
                                    HasPrivateKey = $false
                                    SubjectAlternativeNames = ''
                                    Missing = $true
                                    Note = "Binding references a certificate that is not in Cert:\LocalMachine\$storeName."
                                })
                        }
                    }
                }
            } catch {
                $warnings.Add("Could not enumerate IIS bindings: $($_.Exception.Message)")
            }
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Facts = @($facts)
        Warnings = @($warnings)
        IisChecked = $iisRead
    }
}

$targets = if ($ComputerName) { $ComputerName } else { @($env:COMPUTERNAME) }
$iisChecked = $false
$unreachable = [System.Collections.Generic.List[string]]::new()

foreach ($machine in $targets) {
    $probe = $null
    try {
        if ($machine -eq $env:COMPUTERNAME) {
            $probe = & $certificateProbe $StorePath $IncludeIisBindings.IsPresent
        } else {
            $probe = Invoke-Command -ComputerName $machine -ScriptBlock $certificateProbe `
                -ArgumentList $StorePath, $IncludeIisBindings.IsPresent -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not probe $machine : $($_.Exception.Message)"
        $unreachable.Add($machine)
        continue
    }

    foreach ($warning in @(Get-OpsPropertyValue -InputObject $probe -Name 'Warnings')) {
        Write-Warning "$($probe.ComputerName): $warning"
    }

    if (Get-OpsPropertyValue -InputObject $probe -Name 'IisChecked') {
        $iisChecked = $true
    }

    foreach ($fact in @(Get-OpsPropertyValue -InputObject $probe -Name 'Facts')) {
        $records.Add((Get-CertificateRecord -Fact $fact -MinimumKeySizeBits $WeakKeySizeBits))
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
        $negotiated = "Negotiated $($stream.SslProtocol), cipher $($stream.NegotiatedCipherSuite)"
        $endpointFact = ConvertTo-CertificateFact -Certificate $remote -Location $target -Note $negotiated
        $records.Add((Get-CertificateRecord -Fact $endpointFact -MinimumKeySizeBits $WeakKeySizeBits))
    } catch {
        Write-Warning "Could not probe $target : $($_.Exception.Message)"
        $records.Add([pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
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
    ComputersQueried = @($targets).Count
    UnreachableComputers = @($unreachable)
    StoresRequested = @($StorePath)
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
