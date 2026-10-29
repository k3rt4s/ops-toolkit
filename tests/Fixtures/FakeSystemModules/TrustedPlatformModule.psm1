<#
.SYNOPSIS
Stand-in for the TrustedPlatformModule module so scripts that read TPM state answer from a fixture.

.DESCRIPTION
Instructions:
- Do not import this by hand. `Use-FakeSystemModule` in TestHelpers.psm1 stages it on
  PSModulePath ahead of the real module.
- Get-Tpm reports no TPM by default, which no script should treat as compliant. Set
  OPSTOOLKIT_TEST_TPM_PRESENT, OPSTOOLKIT_TEST_TPM_READY, OPSTOOLKIT_TEST_TPM_ENABLED and
  OPSTOOLKIT_TEST_TPM_ACTIVATED to '1' to report each as true.
- Set OPSTOOLKIT_TEST_TPM_READERROR to any value to make Get-Tpm throw, the way an unelevated
  session does.

Purpose:
Get-Tpm is a read, but a script that reads it on a development machine would otherwise take
that machine's real state into its plan and make the result depend on the hardware.

.NOTES
Status:
Active test fixture kept in the reorganized ops-toolkit repo.
#>

Set-StrictMode -Version 3.0

function Get-Tpm {
    [CmdletBinding()]
    param()

    if ($env:OPSTOOLKIT_TEST_TPM_READERROR) { throw 'Access is denied (fake TPM read error).' }

    [pscustomobject]@{
        TpmPresent = ($env:OPSTOOLKIT_TEST_TPM_PRESENT -eq '1')
        TpmReady = ($env:OPSTOOLKIT_TEST_TPM_READY -eq '1')
        TpmEnabled = ($env:OPSTOOLKIT_TEST_TPM_ENABLED -eq '1')
        TpmActivated = ($env:OPSTOOLKIT_TEST_TPM_ACTIVATED -eq '1')
        ManagedAuthLevel = 'Full'
    }
}

Export-ModuleMember -Function 'Get-Tpm'
