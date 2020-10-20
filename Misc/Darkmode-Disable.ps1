Write-Host "Disabling Dark Mode"
$Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Set-ItemProperty $Theme AppsUseLightTheme -Value 1
Start-Sleep 1
Write-Host "Disabled"