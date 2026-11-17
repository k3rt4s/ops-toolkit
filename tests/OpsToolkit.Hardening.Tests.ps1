#Requires -Modules Pester

# OpsToolkit.Hardening: Get-OpsHostContext and Get-OpsPolicyOverrideNote.
#
# Nothing here reads the real machine. dsregcmd.exe is a stand-in .cmd file passed through
# -DsregcmdPath. The registry, service and CIM probes are either replaced through the module's
# documented OPSTOOLKIT_TEST_HOSTFACTS hook or, for the tests of the real probe code, mocked inside
# the module with Pester. Every guard that answers "undetermined" has a test that makes its probe
# fail and asserts the field is $null and listed in Unread, never a guessed value.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\modules\OpsToolkit.Hardening') -Force -Global

    $script:work = Join-Path ([System.IO.Path]::GetTempPath()) "ops-hosttest-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # A stand-in for dsregcmd.exe: prints the given lines and exits with the given code.
    function New-FakeDsregcmd {
        param([string]$Name, [string[]]$Line, [int]$ExitCode = 0)
        $text = Join-Path $script:work "$Name.txt"
        Set-Content -LiteralPath $text -Value $Line -Encoding ascii
        $cmd = Join-Path $script:work "$Name.cmd"
        Set-Content -LiteralPath $cmd -Encoding ascii -Value @('@echo off', "type `"$text`"", "exit /b $ExitCode")
        $cmd
    }

    function New-DsregOutput {
        param([string]$Azure, [string]$Domain, [string]$Workplace = 'NO')
        $lines = @('+----------------------------------------------------------------------+', '| Device State |', '+----------------------------------------------------------------------+', '')
        if ($Azure) { $lines += "             AzureAdJoined : $Azure" }
        $lines += '          EnterpriseJoined : NO'
        if ($Domain) { $lines += "              DomainJoined : $Domain" }
        if ($Workplace) { $lines += "           WorkplaceJoined : $Workplace" }
        $lines
    }

    # Physical, standalone facts for every probe except the one a test varies.
    function Set-HostFact {
        param([hashtable]$Fact = @{})
        $base = [ordered]@{ RdInfraAgentKey = 'absent'; RdAgentService = 'absent'; Enrollments = 'absent'; Manufacturer = 'Dell Inc.'; Model = 'Latitude 5540' }
        foreach ($k in $Fact.Keys) { $base[$k] = $Fact[$k] }
        $env:OPSTOOLKIT_TEST_HOSTFACTS = ($base | ConvertTo-Json -Compress)
    }

    $script:dsEntra = New-FakeDsregcmd -Name 'entra' -Line (New-DsregOutput -Azure 'YES' -Domain 'NO')
    $script:dsHybrid = New-FakeDsregcmd -Name 'hybrid' -Line (New-DsregOutput -Azure 'YES' -Domain 'YES')
    $script:dsDomain = New-FakeDsregcmd -Name 'domain' -Line (New-DsregOutput -Azure 'NO' -Domain 'YES')
    $script:dsWorkgroup = New-FakeDsregcmd -Name 'workgroup' -Line (New-DsregOutput -Azure 'NO' -Domain 'NO')
    $script:dsRegistered = New-FakeDsregcmd -Name 'registered' -Line (New-DsregOutput -Azure 'NO' -Domain 'NO' -Workplace 'YES')
    $script:dsNoAzure = New-FakeDsregcmd -Name 'noazure' -Line (New-DsregOutput -Azure '' -Domain 'YES')
    $script:dsGarbage = New-FakeDsregcmd -Name 'garbage' -Line @('this is not dsregcmd output', 'AzureAdJoined : MAYBE')
    $script:dsFails = New-FakeDsregcmd -Name 'fails' -Line @('AzureAdJoined : YES', 'DomainJoined : NO') -ExitCode 3
    $script:dsMissing = Join-Path $script:work 'does-not-exist.cmd'
}

AfterAll {
    Remove-Item Env:\OPSTOOLKIT_TEST_HOSTFACTS -ErrorAction SilentlyContinue
    Remove-Item Env:\OPSTOOLKIT_TEST_DSREGCMD_PATH -ErrorAction SilentlyContinue
    if ($script:work -and (Test-Path $script:work)) { Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Module OpsToolkit.Hardening -Force -ErrorAction SilentlyContinue
}

Describe 'OpsToolkit.Hardening module shape' {
    BeforeEach { Set-HostFact }
    It 'exports exactly the three documented functions' {
        $exported = @((Get-Module OpsToolkit.Hardening).ExportedFunctions.Keys | Sort-Object)
        $exported.Count | Should -Be 3
        $exported | Should -Be @('Get-OpsHostContext', 'Get-OpsOrgSettings', 'Get-OpsPolicyOverrideNote')
    }

    It 'gives every exported function comment-based help with a synopsis' {
        foreach ($name in 'Get-OpsHostContext', 'Get-OpsOrgSettings', 'Get-OpsPolicyOverrideNote') {
            (Get-Help $name).Synopsis.Trim() | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-OpsHostContext join type' {
    BeforeEach { Set-HostFact }
    It 'reads <Name> from dsregcmd output as <Join>' -ForEach @(
        @{ Name = 'entra'; Join = 'EntraJoined'; Azure = $true; Domain = $false }
        @{ Name = 'hybrid'; Join = 'HybridJoined'; Azure = $true; Domain = $true }
        @{ Name = 'domain'; Join = 'DomainJoined'; Azure = $false; Domain = $true }
        @{ Name = 'workgroup'; Join = 'Workgroup'; Azure = $false; Domain = $false }
    ) {
        $ctx = Get-OpsHostContext -DsregcmdPath (Join-Path $script:work "$Name.cmd")
        $ctx.JoinType | Should -Be $Join
        $ctx.AzureAdJoined | Should -Be $Azure
        $ctx.DomainJoined | Should -Be $Domain
        $ctx.Unread | Should -Not -Contain 'JoinType'
    }

    It 'keeps a workplace-registered device as Workgroup and exposes the raw WorkplaceJoined flag' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsRegistered
        $ctx.JoinType | Should -Be 'Workgroup'
        $ctx.WorkplaceJoined | Should -BeTrue
    }

    It 'reports Unknown, not Workgroup, when dsregcmd cannot be started' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsMissing
        $ctx.JoinType | Should -Be 'Unknown'
        $ctx.AzureAdJoined | Should -BeNullOrEmpty
        $ctx.DomainJoined | Should -BeNullOrEmpty
        $ctx.WorkplaceJoined | Should -BeNullOrEmpty
        $ctx.Unread | Should -Contain 'JoinType'
        @($ctx.Notes | Where-Object { $_ -like 'AzureAdJoined:*could not be run*' }).Count | Should -Be 1
    }

    It 'reports Unknown when dsregcmd exits non-zero even though its output looks valid' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsFails
        $ctx.JoinType | Should -Be 'Unknown'
        $ctx.AzureAdJoined | Should -BeNullOrEmpty
        @($ctx.Notes | Where-Object { $_ -like '*exited with code 3*' }).Count | Should -Be 3
    }

    It 'reports Unknown and names the field when one flag line is missing' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsNoAzure
        $ctx.JoinType | Should -Be 'Unknown'
        $ctx.AzureAdJoined | Should -BeNullOrEmpty
        $ctx.DomainJoined | Should -BeTrue
        $ctx.Unread | Should -Contain 'AzureAdJoined'
        $ctx.Unread | Should -Not -Contain 'DomainJoined'
    }

    It 'treats output with no YES or NO as unread for every flag' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsGarbage
        $ctx.JoinType | Should -Be 'Unknown'
        @($ctx.Unread | Where-Object { $_ -in 'AzureAdJoined', 'DomainJoined', 'WorkplaceJoined' }).Count | Should -Be 3
    }

    It 'takes the dsregcmd path from OPSTOOLKIT_TEST_DSREGCMD_PATH when no parameter is given' {
        $env:OPSTOOLKIT_TEST_DSREGCMD_PATH = $script:dsHybrid
        try { (Get-OpsHostContext).JoinType | Should -Be 'HybridJoined' }
        finally { Remove-Item Env:\OPSTOOLKIT_TEST_DSREGCMD_PATH -ErrorAction SilentlyContinue }
    }
}

Describe 'Get-OpsHostContext AVD session host' {
    BeforeEach { Set-HostFact }
    It 'is true when only the RDInfraAgent key exists' {
        Set-HostFact @{ RdInfraAgentKey = 'present' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeTrue
        $ctx.Platform | Should -Be 'VDI'
    }

    It 'is true when only the RDAgentBootLoader service exists' {
        Set-HostFact @{ RdAgentService = 'present' }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsAvdSessionHost | Should -BeTrue
    }

    It 'is false, and the platform Physical, only when both markers were read and are absent' {
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeFalse
        $ctx.Platform | Should -Be 'Physical'
        $ctx.Unread | Should -Not -Contain 'IsAvdSessionHost'
    }

    It 'is $null, never false, when the key probe fails and the service is absent' {
        Set-HostFact @{ RdInfraAgentKey = 'error' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeNullOrEmpty
        $ctx.IsAvdSessionHost -eq $false | Should -BeFalse
        $ctx.Unread | Should -Contain 'IsAvdSessionHost'
        $ctx.Platform | Should -Be 'Unknown'
        @($ctx.Notes | Where-Object { $_ -like 'IsAvdSessionHost:*' }).Count | Should -Be 1
    }

    It 'is $null when the service probe fails and the key is absent' {
        Set-HostFact @{ RdAgentService = 'error' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeNullOrEmpty
        $ctx.Unread | Should -Contain 'IsAvdSessionHost'
    }

    It 'is still true when one probe failed and the other found the marker' {
        Set-HostFact @{ RdInfraAgentKey = 'error'; RdAgentService = 'present' }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsAvdSessionHost | Should -BeTrue
    }

    It 'reads a missing key through the real probe as absent and an access failure as unread' {
        Remove-Item Env:\OPSTOOLKIT_TEST_HOSTFACTS
        # The real service and CIM probes still run here, so mock every real probe the module has.
        Mock -ModuleName OpsToolkit.Hardening Get-Service { @() }
        Mock -ModuleName OpsToolkit.Hardening Get-ChildItem { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-CimInstance { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5540' } }
        Mock -ModuleName OpsToolkit.Hardening Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsAvdSessionHost | Should -BeFalse

        Mock -ModuleName OpsToolkit.Hardening Get-Item { throw [System.UnauthorizedAccessException]::new('denied') }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeNullOrEmpty
        $ctx.Unread | Should -Contain 'IsAvdSessionHost'
    }

    It 'reads a failing service listing through the real probe as unread' {
        Remove-Item Env:\OPSTOOLKIT_TEST_HOSTFACTS
        Mock -ModuleName OpsToolkit.Hardening Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-Service { throw 'service control manager unavailable' }
        Mock -ModuleName OpsToolkit.Hardening Get-ChildItem { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-CimInstance { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5540' } }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsAvdSessionHost | Should -BeNullOrEmpty
        @($ctx.Notes | Where-Object { $_ -like '*could not list services*' }).Count | Should -Be 1
    }
}

Describe 'Get-OpsHostContext MDM management' {
    BeforeEach { Set-HostFact }
    It 'is true when an enrollment names the MS DM Server provider' {
        Set-HostFact @{ Enrollments = @('Other Provider', 'MS DM Server') }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsMdmManaged | Should -BeTrue
    }

    It 'is false when enrollments exist but none is the MS DM Server provider' {
        Set-HostFact @{ Enrollments = @('Other Provider') }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsMdmManaged | Should -BeFalse
    }

    It 'is false when the Enrollments key is absent' {
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsMdmManaged | Should -BeFalse
    }

    It 'is $null and unread when the Enrollments key cannot be read' {
        Set-HostFact @{ Enrollments = 'error' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsMdmManaged | Should -BeNullOrEmpty
        $ctx.Unread | Should -Contain 'IsMdmManaged'
    }

    It 'reads enrollment subkeys through the real probe, and an unreadable subkey with no match is unread' {
        Remove-Item Env:\OPSTOOLKIT_TEST_HOSTFACTS
        Mock -ModuleName OpsToolkit.Hardening Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-Service { @() }
        Mock -ModuleName OpsToolkit.Hardening Get-CimInstance { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5540' } }
        Mock -ModuleName OpsToolkit.Hardening Get-ChildItem {
            @([pscustomobject]@{ PSPath = 'good'; PSChildName = 'good' }, [pscustomobject]@{ PSPath = 'bad'; PSChildName = 'bad' })
        }
        Mock -ModuleName OpsToolkit.Hardening Get-ItemProperty {
            if ($LiteralPath -eq 'bad') { throw 'denied' }
            [pscustomobject]@{ ProviderID = 'Other Provider' }
        }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsMdmManaged | Should -BeNullOrEmpty
        $ctx.Unread | Should -Contain 'IsMdmManaged'

        Mock -ModuleName OpsToolkit.Hardening Get-ItemProperty {
            if ($LiteralPath -eq 'bad') { throw 'denied' }
            [pscustomobject]@{ ProviderID = 'MS DM Server' }
        }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsMdmManaged | Should -BeTrue
        @($ctx.Notes | Where-Object { $_ -like 'IsMdmManaged:*' }).Count | Should -Be 1
    }
}

Describe 'Get-OpsHostContext virtual machine and platform' {
    BeforeEach { Set-HostFact }
    It 'reads a Hyper-V guest as a virtual machine that is not VDI' {
        Set-HostFact @{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsVirtualMachine | Should -BeTrue
        $ctx.Platform | Should -Be 'VirtualMachine'
    }

    It 'reads a Dell laptop as not a virtual machine' {
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).IsVirtualMachine | Should -BeFalse
    }

    It 'leaves IsVirtualMachine $null and Platform Unknown when Win32_ComputerSystem cannot be read' {
        Set-HostFact @{ ComputerSystem = 'error' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsVirtualMachine | Should -BeNullOrEmpty
        $ctx.Platform | Should -Be 'Unknown'
        $ctx.Unread | Should -Contain 'IsVirtualMachine'
        $ctx.Unread | Should -Contain 'Platform'
    }

    It 'still reports VDI when only the virtual machine probe failed' {
        Set-HostFact @{ ComputerSystem = 'error'; RdInfraAgentKey = 'present' }
        (Get-OpsHostContext -DsregcmdPath $script:dsEntra).Platform | Should -Be 'VDI'
    }

    It 'leaves the platform Unknown when a read of Win32_ComputerSystem through the real probe fails' {
        Remove-Item Env:\OPSTOOLKIT_TEST_HOSTFACTS
        Mock -ModuleName OpsToolkit.Hardening Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-Service { @() }
        Mock -ModuleName OpsToolkit.Hardening Get-ChildItem { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
        Mock -ModuleName OpsToolkit.Hardening Get-CimInstance { throw 'WMI repository is busy' }
        $ctx = Get-OpsHostContext -DsregcmdPath $script:dsEntra
        $ctx.IsVirtualMachine | Should -BeNullOrEmpty
        $ctx.Platform | Should -Be 'Unknown'
    }
}

Describe 'Get-OpsPolicyOverrideNote' {
    BeforeEach { Set-HostFact }
    BeforeAll {
        function New-Context {
            param([string]$JoinType, $Mdm)
            [pscustomobject]@{ JoinType = $JoinType; IsMdmManaged = $Mdm }
        }
    }

    It 'warns about Group Policy on a domain joined host' {
        Get-OpsPolicyOverrideNote -HostContext (New-Context 'DomainJoined' $false) | Should -BeLike '*Group Policy (DomainJoined)*override*'
    }

    It 'warns about both sources on a hybrid joined, MDM managed host' {
        $note = Get-OpsPolicyOverrideNote -HostContext (New-Context 'HybridJoined' $true)
        $note | Should -BeLike '*Group Policy (HybridJoined) and MDM policy*'
    }

    It 'warns about MDM policy on an Entra joined, enrolled host' {
        $note = Get-OpsPolicyOverrideNote -HostContext (New-Context 'EntraJoined' $true)
        $note | Should -BeLike '*MDM policy (enrolled)*'
        $note | Should -Not -BeLike '*Group Policy*'
    }

    It 'returns nothing for a workgroup host and an Entra host that were both read as not managed' {
        Get-OpsPolicyOverrideNote -HostContext (New-Context 'Workgroup' $false) | Should -BeNullOrEmpty
        Get-OpsPolicyOverrideNote -HostContext (New-Context 'EntraJoined' $false) | Should -BeNullOrEmpty
    }

    It 'says it could not tell, rather than staying silent, when the join type is Unknown' {
        Get-OpsPolicyOverrideNote -HostContext (New-Context 'Unknown' $false) | Should -BeLike 'Could not determine*'
    }

    It 'says it could not tell when MDM state is unread on a workgroup host' {
        Get-OpsPolicyOverrideNote -HostContext (New-Context 'Workgroup' $null) | Should -BeLike 'Could not determine*'
    }
}

Describe 'Get-OpsOrgSettings' {
    # Every file here lives under a temp directory and is passed with -Path or the documented
    # OPSTOOLKIT_TEST_ORGSETTINGS_PATH hook. The real %ProgramData% file is never read.
    BeforeAll {
        $script:orgDir = Join-Path $script:work 'org'
        New-Item -ItemType Directory -Path $script:orgDir -Force | Out-Null
        function New-OrgFile {
            param([string]$Name, [string]$Text)
            $p = Join-Path $script:orgDir "$Name.json"
            Set-Content -LiteralPath $p -Value $Text -Encoding ascii -NoNewline
            $p
        }
        $script:wefText = 'Server=http://wec.example.com:5985/wsman/SubscriptionManager/WEC,Refresh=60'
    }
    AfterEach { Remove-Item Env:\OPSTOOLKIT_TEST_ORGSETTINGS_PATH -ErrorAction SilentlyContinue }

    It 'reports a missing file as Missing with both sections NotConfigured and a reason' {
        $r = Get-OpsOrgSettings -Path (Join-Path $script:orgDir 'nope.json')
        $r.FileState | Should -Be 'Missing'
        foreach ($s in $r.EventDestination, $r.BitLockerKeyBackup) {
            $s.Status | Should -Be 'NotConfigured'
            $s.Reason | Should -BeLike 'not configured: *'
        }
    }

    It 'reports an empty file as Invalid, not as NotConfigured' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'empty' '   ')
        $r.FileState | Should -Be 'Invalid'
        $r.EventDestination.Status | Should -Be 'Invalid'
        $r.BitLockerKeyBackup.Status | Should -Be 'Invalid'
        $r.EventDestination.Reason | Should -BeLike '*empty*'
    }

    It 'reports malformed JSON as Invalid without throwing' {
        { Get-OpsOrgSettings -Path (New-OrgFile 'bad' '{ "SchemaVersion": 1, ') } | Should -Not -Throw
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'bad2' '{ "SchemaVersion": 1, ')
        $r.FileState | Should -Be 'Invalid'
        $r.EventDestination.Reason | Should -BeLike '*not valid JSON*'
    }

    It 'reports a JSON array root as Invalid' {
        (Get-OpsOrgSettings -Path (New-OrgFile 'arr' '[1,2]')).FileState | Should -Be 'Invalid'
    }

    It 'reports a directory in place of the file as Missing, never throws' {
        (Get-OpsOrgSettings -Path $script:orgDir).FileState | Should -Be 'Missing'
    }

    It 'reports a wrong or missing SchemaVersion as Invalid for both sections' -ForEach @(
        @{ Name = 'v2'; Text = '{ "SchemaVersion": 2, "EventDestination": { "Type": "AzureMonitorAgent" } }' }
        @{ Name = 'vstr'; Text = '{ "SchemaVersion": "1", "EventDestination": { "Type": "AzureMonitorAgent" } }' }
        @{ Name = 'vnone'; Text = '{ "EventDestination": { "Type": "AzureMonitorAgent" } }' }
        @{ Name = 'vtrue'; Text = '{ "SchemaVersion": true, "EventDestination": { "Type": "AzureMonitorAgent" } }' }
    ) {
        $r = Get-OpsOrgSettings -Path (New-OrgFile $Name $Text)
        $r.FileState | Should -Be 'Invalid'
        $r.EventDestination.Status | Should -Be 'Invalid'
        $r.BitLockerKeyBackup.Status | Should -Be 'Invalid'
        $r.EventDestination.Reason | Should -BeLike 'SchemaVersion*'
    }

    It 'reads a WEF destination with its subscription manager string' {
        $text = '{ "SchemaVersion": 1, "EventDestination": { "Type": "WEF", "SubscriptionManager": "' + $script:wefText + '" } }'
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'wef' $text)
        $r.FileState | Should -Be 'Present'
        $r.EventDestination.Status | Should -Be 'Configured'
        $r.EventDestination.Type | Should -Be 'WEF'
        $r.EventDestination.SubscriptionManager | Should -Be $script:wefText
        $r.EventDestination.SharePath | Should -BeNullOrEmpty
        $r.BitLockerKeyBackup.Status | Should -Be 'NotConfigured'
        $r.BitLockerKeyBackup.Reason | Should -Be 'not configured: BitLockerKeyBackup section is missing'
    }

    It 'reads AzureMonitorAgent with no extra field' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'ama' '{ "SchemaVersion": 1, "EventDestination": { "Type": "AzureMonitorAgent" } }')
        $r.EventDestination.Status | Should -Be 'Configured'
        $r.EventDestination.Type | Should -Be 'AzureMonitorAgent'
    }

    It 'reads a Share destination with its UNC path' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'share' '{ "SchemaVersion": 1, "EventDestination": { "Type": "Share", "SharePath": "\\\\server.example.com\\logs" } }')
        $r.EventDestination.Status | Should -Be 'Configured'
        $r.EventDestination.SharePath | Should -Be '\\server.example.com\logs'
    }

    It 'reads each BitLocker key backup type' -ForEach @(
        @{ Name = 'k1'; Json = '{ "Type": "EntraId" }'; Type = 'EntraId'; Folder = $null }
        @{ Name = 'k2'; Json = '{ "Type": "ActiveDirectory" }'; Type = 'ActiveDirectory'; Folder = $null }
        @{ Name = 'k3'; Json = '{ "Type": "Folder", "FolderPath": "\\\\server.example.com\\keys" }'; Type = 'Folder'; Folder = '\\server.example.com\keys' }
    ) {
        $r = Get-OpsOrgSettings -Path (New-OrgFile $Name ('{ "SchemaVersion": 1, "BitLockerKeyBackup": ' + $Json + ' }'))
        $r.BitLockerKeyBackup.Status | Should -Be 'Configured'
        $r.BitLockerKeyBackup.Type | Should -Be $Type
        $r.BitLockerKeyBackup.FolderPath | Should -Be $Folder
        $r.EventDestination.Status | Should -Be 'NotConfigured'
    }

    It 'reports an unknown Type as Invalid and never repeats the value from the file' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'unk' '{ "SchemaVersion": 1, "EventDestination": { "Type": "Splunk-Token-abc123" }, "BitLockerKeyBackup": { "Type": "Usb" } }')
        $r.EventDestination.Status | Should -Be 'Invalid'
        $r.BitLockerKeyBackup.Status | Should -Be 'Invalid'
        ($r | ConvertTo-Json -Depth 4) | Should -Not -BeLike '*abc123*'
        $r.EventDestination.Type | Should -BeNullOrEmpty
    }

    It 'does not guess a near-miss Type spelling' {
        (Get-OpsOrgSettings -Path (New-OrgFile 'case' '{ "SchemaVersion": 1, "EventDestination": { "Type": "wef", "SubscriptionManager": "Server=http://a.example.com" } }')).EventDestination.Status | Should -Be 'Invalid'
    }

    It 'reports a missing required field for the Type as Invalid' -ForEach @(
        @{ Name = 'f1'; Section = 'EventDestination'; Json = '{ "Type": "WEF" }' }
        @{ Name = 'f2'; Section = 'EventDestination'; Json = '{ "Type": "Share" }' }
        @{ Name = 'f3'; Section = 'BitLockerKeyBackup'; Json = '{ "Type": "Folder" }' }
        @{ Name = 'f4'; Section = 'EventDestination'; Json = '{ "Type": "WEF", "SubscriptionManager": "" }' }
        @{ Name = 'f5'; Section = 'EventDestination'; Json = '{ "Type": "WEF", "SubscriptionManager": "http://wec.example.com" }' }
        @{ Name = 'f6'; Section = 'EventDestination'; Json = '{ "Type": "Share", "SharePath": "C:\\local" }' }
        @{ Name = 'f7'; Section = 'BitLockerKeyBackup'; Json = '{ "Type": "Folder", "FolderPath": "relative\\dir" }' }
        @{ Name = 'f8'; Section = 'EventDestination'; Json = '{ "SubscriptionManager": "Server=http://a.example.com" }' }
        @{ Name = 'f9'; Section = 'EventDestination'; Json = '"just a string"' }
    ) {
        $r = Get-OpsOrgSettings -Path (New-OrgFile $Name ('{ "SchemaVersion": 1, "' + $Section + '": ' + $Json + ' }'))
        $r.$Section.Status | Should -Be 'Invalid'
        $r.$Section.Reason | Should -Not -BeNullOrEmpty
        $r.FileState | Should -Be 'Present'
    }

    It 'reads one section when only that section is present and leaves the other NotConfigured' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'one' '{ "SchemaVersion": 1, "BitLockerKeyBackup": { "Type": "EntraId" } }')
        $r.BitLockerKeyBackup.Status | Should -Be 'Configured'
        $r.EventDestination.Status | Should -Be 'NotConfigured'
    }

    It 'treats a null section as NotConfigured' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'nullsec' '{ "SchemaVersion": 1, "EventDestination": null }')
        $r.EventDestination.Status | Should -Be 'NotConfigured'
    }

    It 'keeps one section valid when the other is Invalid' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'mix' '{ "SchemaVersion": 1, "EventDestination": { "Type": "WEF" }, "BitLockerKeyBackup": { "Type": "EntraId" } }')
        $r.EventDestination.Status | Should -Be 'Invalid'
        $r.BitLockerKeyBackup.Status | Should -Be 'Configured'
    }

    It 'never copies a stray property, such as a secret, into the result' {
        $r = Get-OpsOrgSettings -Path (New-OrgFile 'secret' '{ "SchemaVersion": 1, "ApiKey": "s3cr3t-value", "EventDestination": { "Type": "AzureMonitorAgent", "WorkspaceKey": "s3cr3t-value" } }')
        $r.EventDestination.Status | Should -Be 'Configured'
        ($r | ConvertTo-Json -Depth 4) | Should -Not -BeLike '*s3cr3t*'
    }

    It 'uses the OPSTOOLKIT_TEST_ORGSETTINGS_PATH hook when -Path is not bound, and -Path wins over it' {
        $env:OPSTOOLKIT_TEST_ORGSETTINGS_PATH = New-OrgFile 'hook' '{ "SchemaVersion": 1, "EventDestination": { "Type": "AzureMonitorAgent" } }'
        $viaHook = Get-OpsOrgSettings
        $viaHook.Path | Should -Be $env:OPSTOOLKIT_TEST_ORGSETTINGS_PATH
        $viaHook.EventDestination.Status | Should -Be 'Configured'
        $explicit = Get-OpsOrgSettings -Path (Join-Path $script:orgDir 'absent.json')
        $explicit.FileState | Should -Be 'Missing'
    }

    It 'defaults to the ProgramData settings path when nothing is set, without reading it in this test' {
        Mock -ModuleName OpsToolkit.Hardening Test-Path { $false }
        $r = Get-OpsOrgSettings
        $r.Path | Should -BeLike '*OpsToolkit\settings.json'
        $r.FileState | Should -Be 'Missing'
    }
}
