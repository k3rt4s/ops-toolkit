<#
.SYNOPSIS
Disable Windows dark mode for the current user.

.INSTRUCTIONS
- Read the root README.md before running this script.
- Review parameters with Get-Help .\Disable-WindowsDarkMode.ps1 -Full or by opening the script.
- Run from an elevated shell when the target system, tenant, or server requires admin rights.
- If this script supports -WhatIf, run with -WhatIf first before making live changes.
- Write generated output under the repo reports\ folder unless a different path is required.

.STATUS
Active script kept in the reorganized SecOps repo.
#>
Write-Information "Disabling Dark Mode" -InformationAction Continue
$Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Set-ItemProperty $Theme AppsUseLightTheme -Value 1
Start-Sleep 1
Write-Information "Disabled" -InformationAction Continue

