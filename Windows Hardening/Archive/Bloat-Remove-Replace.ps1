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
