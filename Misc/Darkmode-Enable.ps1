##enable dark mode
Write-Host "Enabling Dark Mode"
$Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Set-ItemProperty $Theme AppsUseLightTheme -Value 0
Start-Sleep 1
Write-Host "Enabled"