<#
.SYNOPSIS
Switches the Windows apps and system theme to light mode (or dark) and applies it live without signing out.

.DESCRIPTION
Sets AppsUseLightTheme and SystemUsesLightTheme under the current user's
Personalize key, then broadcasts WM_SETTINGCHANGE so open apps, the taskbar,
and Start pick up the new appearance immediately. Per-user and non-elevated;
touches only HKCU.

.PARAMETER Mode
Light (default) or Dark.

.EXAMPLE
.\Set-WindowsLightMode.ps1
Sets light mode.

.EXAMPLE
.\Set-WindowsLightMode.ps1 -Mode Dark -WhatIf
Previews switching to dark mode without changing anything.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
    [ValidateSet('Light', 'Dark')]
    [string]$Mode = 'Light'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$value = if ($Mode -eq 'Light') { 1 } else { 0 }
$key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'

if (-not (Test-Path $key)) {
    if ($PSCmdlet.ShouldProcess($key, 'Create Personalize key')) {
        New-Item -Path $key -Force | Out-Null
    }
}

foreach ($name in 'AppsUseLightTheme', 'SystemUsesLightTheme') {
    if ($PSCmdlet.ShouldProcess("$key\$name", "Set to $value ($Mode)")) {
        Set-ItemProperty -Path $key -Name $name -Value $value -Type DWord
    }
}

if ($PSCmdlet.ShouldProcess('Desktop shell', 'Broadcast WM_SETTINGCHANGE')) {
    if (-not ('Win32.NativeMethods' -as [type])) {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(
    System.IntPtr hWnd, uint Msg, System.UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@
    }

    $HWND_BROADCAST = [System.IntPtr]0xffff
    $WM_SETTINGCHANGE = 0x1a
    $result = [System.UIntPtr]::Zero
    [void][Win32.NativeMethods]::SendMessageTimeout(
        $HWND_BROADCAST, $WM_SETTINGCHANGE, [System.UIntPtr]::Zero,
        'ImmersiveColorSet', 2, 100, [ref]$result)

    Write-Host "Windows theme set to $Mode mode."
}
