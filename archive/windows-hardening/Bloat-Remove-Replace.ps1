# === AI REVIEWER - READ BEFORE EDITING ==============================
# Before changing this file, read the master workspace README at
#   d:\Proton Drive\My files\Code\README.md   ("AI Session Rules" section)
# and the README(s) for this project and sub-product. Those documents
# are the single source of truth for venvs, path conventions,
# archive/backup rules, markdown conventions, and every repo-wide rule.
# Do not guess - reference the READMEs first.
# =====================================================================

#remove MS installed Junk

$junk = Import-Csv -path C:\scripts\Bloat.csv
$ComPack = Import-Csv -path C:\scripts\Safe.csv



foreach ($line in $junk) {
    Write-Output $line.name
    Get-AppxPackage $line.appxpkg | Remove-AppxPackage -Verbose

}

#Install Items

foreach ($line in $ComPack) {
    Write-Output $line.name
       Get-AppxPackage $line.appxpkg | add-AppxPackage -Verbose

}
