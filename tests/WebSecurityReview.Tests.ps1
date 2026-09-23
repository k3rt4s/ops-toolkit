#Requires -Modules Pester

# Offline tests for scripts/web. Nothing here touches the network: the host-list
# helpers are pure functions, and the risk-context pass reads fixture CSVs written
# to TestDrive. The fixtures reproduce the cases that produced wrong answers in the
# first version of the kit: a host that fails DNS appearing first in the evidence
# file, a login host that returns 401 at the root, a host whose HTTPS request
# failed, a dead host that is a CNAME to a third party, and an IP address.

BeforeAll {
    $script:WebDir = Join-Path $PSScriptRoot '..\scripts\web'
    . (Join-Path $script:WebDir 'OpsWebCommon.ps1')

    function New-EvidenceFixture {
        param([hashtable]$Values)
        $columns = @(
            'Host', 'IsIpAddress', 'ApexDomain', 'DnsResolved', 'CnameTarget', 'Port80', 'Http80Status', 'Http80Location'
            'Port443', 'HttpsOk', 'HttpsError', 'HttpsDirectStatus', 'HttpsDirectLocation', 'HeaderSource'
            'CertHostnameMatch', 'CertChainValid', 'CertSubjectAlternativeNames', 'CertNote'
            'Hsts', 'HstsMaxAge', 'HstsIncludeSubDomains', 'HstsPreloadDirective', 'ApexPreloadStatus'
            'Csp', 'CspUnsafeInline', 'CspUnsafeEval', 'CspUnsafeSources', 'FrameAncestors'
            'XFrameOptions', 'XContentTypeOptions', 'ServerHeader', 'ServerHeaderHasVersion', 'XPoweredBy'
            'WwwAuthenticate', 'AuthRequired', 'FinalUrl', 'FinalStatus', 'FinalContentType', 'FinalOnSameHost'
            'HasForm', 'HasPasswordField', 'LoginPathFound', 'LikelyDead', 'Port22', 'Port22Banner', 'Port25', 'Port25Banner'
            'IsMailHost', 'DmarcQueriedDomain', 'DmarcInherited', 'DmarcRecord', 'DmarcPolicy', 'DmarcSubdomainPolicy'
            'DmarcEffectivePolicy', 'DmarcPct', 'ApexDnssecEnabled', 'Note'
        )
        $row = [ordered]@{}
        foreach ($c in $columns) { $row[$c] = '' }
        foreach ($k in $Values.Keys) { $row[$k] = $Values[$k] }
        [pscustomobject]$row
    }
}

Describe 'ConvertTo-OpsWebHostName' {
    It 'strips <Entry> to <Expected>' -TestCases @(
        @{ Entry = 'https://www.example.com/path?q=1'; Expected = 'www.example.com' }
        @{ Entry = 'sftp://files.example.com'; Expected = 'files.example.com' }
        @{ Entry = 'Example.COM.'; Expected = 'example.com' }
        @{ Entry = 'api.example.com:8443'; Expected = 'api.example.com' }
        @{ Entry = 'www.example.com   # marketing'; Expected = 'www.example.com' }
        @{ Entry = '# a comment'; Expected = '' }
        @{ Entry = '   '; Expected = '' }
        @{ Entry = '192.0.2.10'; Expected = '192.0.2.10' }
    ) {
        ConvertTo-OpsWebHostName -Entry $Entry | Should -Be $Expected
    }
}

Describe 'Resolve-OpsWebHostList' {
    It 'reads a host file, normalizes entries, and removes duplicates' {
        $file = Join-Path $TestDrive 'hosts.txt'
        Set-Content -LiteralPath $file -Value @('# list', 'https://a.example.com/', 'A.example.com', '', 'b.example.com')
        $list = Resolve-OpsWebHostList -HostFile $file
        $list | Should -Be @('a.example.com', 'b.example.com')
    }

    It 'throws when nothing usable is supplied' {
        { Resolve-OpsWebHostList -HostName @('# only a comment') } | Should -Throw '*No hosts to check*'
    }
}

Describe 'Get-OpsWebApexDomain' {
    It 'returns the last two labels by default' {
        Get-OpsWebApexDomain -HostName 'em245.reviews.example.com' | Should -Be 'example.com'
    }
    It 'honors an explicit apex override for multi-part suffixes' {
        Get-OpsWebApexDomain -HostName 'www.example.co.uk' -Override 'example.co.uk' | Should -Be 'example.co.uk'
    }
    It 'returns empty for an IP address' {
        Get-OpsWebApexDomain -HostName '192.0.2.10' | Should -Be ''
    }
}

Describe 'New-SecurityFindingsRiskContext.ps1' {
    BeforeAll {
        $evidence = @(
            # A DNS failure first: the old sweep wrote a 3-column row here, which
            # collapsed the whole CSV and crashed this script under StrictMode.
            (New-EvidenceFixture @{ Host = 'gone.example.com'; DnsResolved = 'False'; Note = 'DNS lookup failed' })
            (New-EvidenceFixture @{ Host = 'login.example.com'; ApexDomain = 'example.com'; DnsResolved = 'True'; Port80 = 'Closed (refused)'
                    Port443 = 'Open'; HttpsOk = 'True'; FinalStatus = '401'; AuthRequired = 'True'; FinalContentType = 'text/html'; LikelyDead = 'False' })
            (New-EvidenceFixture @{ Host = 'videos.example.com'; ApexDomain = 'example.com'; DnsResolved = 'True'; CnameTarget = 'app.vendor.example.net'
                    Port80 = 'Open'; Http80Status = '404'; Port443 = 'Open'; HttpsOk = 'True'; FinalStatus = '404'; FinalContentType = 'text/plain'
                    CertHostnameMatch = 'False'; CertSubjectAlternativeNames = 'vendor.example.net'; LikelyDead = 'True' })
            (New-EvidenceFixture @{ Host = '192.0.2.10'; IsIpAddress = 'True'; DnsResolved = 'True'; Port443 = 'Open'; HttpsOk = 'True'
                    FinalStatus = '404'; ServerHeader = 'Microsoft-HTTPAPI/2.0'; ServerHeaderHasVersion = 'True'; LikelyDead = 'True' })
        )
        $findings = @(
            [pscustomobject]@{ Host = 'gone.example.com'; Severity = 'Medium'; Finding = 'CSP is not implemented'; Category = 'Content Security Policy'; Evidence = 'x'; Remediation = 'x' }
            [pscustomobject]@{ Host = 'login.example.com'; Severity = 'Medium'; Finding = 'X-Frame-Options is not deny or sameorigin'; Category = 'HTTP Security Headers'; Evidence = 'x'; Remediation = 'x' }
            [pscustomobject]@{ Host = 'login.example.com'; Severity = 'Medium'; Finding = 'HTTP Strict Transport Security (HSTS) not enforced'; Category = 'SSL/TLS'; Evidence = 'x'; Remediation = 'x' }
            [pscustomobject]@{ Host = 'videos.example.com'; Severity = 'High'; Finding = 'Hostname does not match SSL certificate'; Category = 'SSL/TLS'; Evidence = 'x'; Remediation = 'x' }
            [pscustomobject]@{ Host = '192.0.2.10'; Severity = 'Medium'; Finding = 'Server information header exposed'; Category = 'Information Disclosure'; Evidence = 'x'; Remediation = 'x' }
        )
        $findingsPath = Join-Path $TestDrive 'findings.csv'
        $evidencePath = Join-Path $TestDrive 'evidence.csv'
        $findings | Export-Csv -LiteralPath $findingsPath -NoTypeInformation
        $evidence | Export-Csv -LiteralPath $evidencePath -NoTypeInformation

        $priorOutputRendering = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = 'PlainText'
        try {
            $null = & (Join-Path $script:WebDir 'New-SecurityFindingsRiskContext.ps1') -FindingsPath $findingsPath -EvidencePath $evidencePath -OutputDirectory (Join-Path $TestDrive 'out') 6>$null
        }
        finally {
            $PSStyle.OutputRendering = $priorOutputRendering
        }
        $script:Result = @(Import-Csv -LiteralPath (Get-ChildItem -Path (Join-Path $TestDrive 'out') -Recurse -Filter '*.csv' | Select-Object -First 1).FullName)
    }

    It 'produces one row per finding without failing on a DNS-failed first row' {
        $script:Result.Count | Should -Be 5
    }

    It 'marks a host that does not resolve as likely stale' {
        $row = $script:Result | Where-Object { $_.Host -eq 'gone.example.com' }
        $row.Flags | Should -Match 'NoDns'
        $row.EvidenceForLowerRisk | Should -Match 'does not resolve'
    }

    It 'does not argue a 401 login host down for X-Frame-Options' {
        $row = $script:Result | Where-Object { $_.Host -eq 'login.example.com' -and $_.Finding -like 'X-Frame*' }
        $row.Flags | Should -Match 'AuthRequired'
        $row.EvidenceAgainstLowerRisk | Should -Match 'requires authentication'
        $row.EvidenceForLowerRisk | Should -Not -Match 'nothing on the page'
    }

    It 'credits a closed port 80 for HSTS' {
        $row = $script:Result | Where-Object { $_.Host -eq 'login.example.com' -and $_.Finding -like 'HTTP Strict*' }
        $row.EvidenceForLowerRisk | Should -Match 'no request can reach this server in clear text'
    }

    It 'warns about takeover risk for a dead third-party CNAME' {
        $row = $script:Result | Where-Object { $_.Host -eq 'videos.example.com' }
        $row.Flags | Should -Match 'Dead'
        $row.EvidenceAgainstLowerRisk | Should -Match 'subdomain takeover'
    }

    It 'recognizes the default HTTP.sys server header' {
        $row = $script:Result | Where-Object { $_.Host -eq '192.0.2.10' }
        $row.EvidenceForLowerRisk | Should -Match 'HTTP.sys'
    }
}
