#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\certificates\Export-CertificateExpiryInventory.ps1' `
        -FunctionName @('Get-CertificateRecord')

    # The script reads these from its own scope. Set them so the extracted function
    # behaves as it does in a real run.
    $global:asOf = [datetime]::new(2026, 8, 15, 0, 0, 0, [DateTimeKind]::Utc)
    $global:ExpiringWithinDays = 60

    function New-Fact {
        param($NotAfter, $Missing = $false, $KeySize = 2048, $Signature = 'sha256RSA', $Computer = 'PC01')
        [pscustomobject]@{
            ComputerName = $Computer
            Source = 'CertificateStore'
            Location = 'Cert:\LocalMachine\My'
            Subject = 'CN=test'
            Issuer = 'CN=issuer'
            Thumbprint = 'ABC123'
            SerialNumber = '01'
            NotBefore = $global:asOf.AddDays(-30)
            NotAfter = $NotAfter
            SignatureAlgorithm = $Signature
            KeySizeBits = $KeySize
            HasPrivateKey = $true
            SubjectAlternativeNames = 'test.example.com'
            Missing = $Missing
            Note = ''
        }
    }
}

AfterAll {
    Remove-Variable -Name asOf, ExpiringWithinDays -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Get-CertificateRecord' {
    It 'reports an expired certificate with a negative day count' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(-10)) -MinimumKeySizeBits 2048
        $record.Status | Should -Be 'Expired'
        $record.DaysToExpiry | Should -BeLessThan 0
    }

    It 'reports a certificate inside the warning window as ExpiringSoon' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(30)) -MinimumKeySizeBits 2048
        $record.Status | Should -Be 'ExpiringSoon'
    }

    It 'reports a certificate beyond the window as Valid' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300)) -MinimumKeySizeBits 2048
        $record.Status | Should -Be 'Valid'
    }

    It 'carries the owning machine name through, so an estate report can be grouped' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -Computer 'SERVER42') -MinimumKeySizeBits 2048
        $record.ComputerName | Should -Be 'SERVER42'
    }

    It 'reports a binding whose certificate is absent as MissingCertificate, not as expired' {
        # An IIS binding pointing at a thumbprint that is not in the store serves
        # nothing. It has no dates, so it must not be forced into an expiry verdict.
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $null -Missing $true) -MinimumKeySizeBits 2048
        $record.Status | Should -Be 'MissingCertificate'
        $record.DaysToExpiry | Should -BeNullOrEmpty
    }

    It 'flags a weak key' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -KeySize 1024) -MinimumKeySizeBits 2048
        $record.WeakKey | Should -BeTrue
    }

    It 'does not flag a key at exactly the threshold' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -KeySize 2048) -MinimumKeySizeBits 2048
        $record.WeakKey | Should -BeFalse
    }

    It 'flags a SHA-1 signature' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -Signature 'sha1RSA') -MinimumKeySizeBits 2048
        $record.WeakSignature | Should -BeTrue
    }

    It 'does not flag a SHA-256 signature' {
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -Signature 'sha256RSA') -MinimumKeySizeBits 2048
        $record.WeakSignature | Should -BeFalse
    }

    It 'does not flag a weak key when the key size is unknown' {
        # An unreadable key size is not a small key. Guessing turns an unknown into a
        # finding somebody has to disprove.
        $record = Get-CertificateRecord -Fact (New-Fact -NotAfter $global:asOf.AddDays(300) -KeySize $null) -MinimumKeySizeBits 2048
        $record.WeakKey | Should -BeFalse
    }
}
