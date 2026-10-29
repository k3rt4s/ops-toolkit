#Requires -Modules Pester

# The mutation stubs are functions injected into the script's runspace, so a stub called from a
# script running under -WhatIf inherits that script's $WhatIfPreference. If the recorder's own
# write honoured it, an unguarded mutation under -WhatIf would record nothing and every
# "nothing changed under -WhatIf" assertion would pass vacuously. Each case runs in a child
# process so the stubs never shadow real cmdlets in this session.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ops-recorder-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $script:pwsh = (Get-Process -Id $PID).Path

    function Invoke-UnguardedMutationUnderWhatIf {
        param([string]$Name)
        $log = Join-Path $script:workRoot "$Name.log"
        $body = Join-Path $script:workRoot "$Name.ps1"
        $stub = Get-WindowsMutationStubText -MutationLogPath $log
        # A script that mutates without consulting ShouldProcess: the defect the log must catch.
        Set-Content -LiteralPath $body -Encoding utf8 -Value ($stub + @'

function Invoke-Unguarded {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpsToolkitTest' -Name 'Probe' -Value 1
}
Invoke-Unguarded -WhatIf
'@)
        & $script:pwsh -NoProfile -NonInteractive -File $body | Out-Null
        if (Test-Path -LiteralPath $log) { @(Get-OpsMutationRecord -Path $log) } else { @() }
    }
}

AfterAll {
    if ($script:workRoot -and (Test-Path -LiteralPath $script:workRoot)) {
        Remove-Item -LiteralPath $script:workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-WindowsMutationStubText recorder' {
    It 'records a mutation made under -WhatIf without ShouldProcess' {
        $records = Invoke-UnguardedMutationUnderWhatIf -Name 'unguarded'
        @($records | Where-Object { $_.Command -eq 'Set-ItemProperty' }).Count | Should -Be 1
    }
}
