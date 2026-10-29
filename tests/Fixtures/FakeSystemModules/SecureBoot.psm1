<#
.SYNOPSIS
Stand-in for the SecureBoot module so scripts that read Secure Boot state answer from a fixture.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Confirm-SecureBootUEFI returns false by default, which no script should treat as compliant.
  Set OPSTOOLKIT_TEST_SECUREBOOT to 'true' to report it on, or to 'error' to throw the way a
  legacy-BIOS or unelevated session does.

Purpose:
Confirm-SecureBootUEFI is a read, but the answer would otherwise be the development machine's
firmware state and would make a test depend on the hardware it runs on.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Confirm-SecureBootUEFI {
    [CmdletBinding()]
    param()

    if ($env:OPSTOOLKIT_TEST_SECUREBOOT -eq 'error') {
        throw 'Cmdlet not supported on this platform (fake Secure Boot read error).'
    }
    $env:OPSTOOLKIT_TEST_SECUREBOOT -eq 'true'
}

Export-ModuleMember -Function 'Confirm-SecureBootUEFI'
