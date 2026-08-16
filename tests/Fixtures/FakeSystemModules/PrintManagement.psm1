<#
.SYNOPSIS
Stand-in for the PrintManagement module so printer scripts never reach the real spooler.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Set OPSTOOLKIT_TEST_PRINTERS to a semicolon-separated list of "<Name>|<Type>" entries
  describing the printers that already exist.
- Set OPSTOOLKIT_TEST_MUTATION_LOG to record attempted changes.

Purpose:
A same-named function in the caller's scope did not shadow Add-Printer, so a test run
reached the real cmdlet and only failed because the spooler happened to be unreachable.
That is luck, not isolation. Staging this module means the real one is never loaded.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Write-FakePrinterMutation {
    param([string]$Command, [string]$Target)
    $path = $env:OPSTOOLKIT_TEST_MUTATION_LOG
    if (-not $path) { return }
    Add-Content -LiteralPath $path -Encoding utf8 -Value ([pscustomobject]@{
            Command = $Command; Target = $Target; Detail = '' } | ConvertTo-Json -Compress)
}

function Get-Printer {
    [CmdletBinding()]
    param([Parameter()]$Name)

    foreach ($entry in @(($env:OPSTOOLKIT_TEST_PRINTERS -split ';') | Where-Object { $_ })) {
        $parts = $entry -split '\|'
        if ($parts.Count -lt 2) { continue }
        if ($Name -and [string]$Name -ne $parts[0]) { continue }
        [pscustomobject]@{
            Name = $parts[0]; Type = $parts[1]
            DriverName = 'Fake Driver'; PortName = 'FAKE:'
        }
    }
}

function Add-Printer {
    [CmdletBinding()]
    param([Parameter()]$Name, [Parameter()]$ConnectionName)
    Write-FakePrinterMutation -Command 'Add-Printer' -Target ([string]$ConnectionName)
}

function Remove-Printer {
    [CmdletBinding()]
    param([Parameter()]$Name)
    Write-FakePrinterMutation -Command 'Remove-Printer' -Target ([string]$Name)
}

Export-ModuleMember -Function 'Get-Printer', 'Add-Printer', 'Remove-Printer'
