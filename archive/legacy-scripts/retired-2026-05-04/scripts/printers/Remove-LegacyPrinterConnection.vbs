' Archive Notes:
' - Retired on 2026-05-04 during the SecOps repo modernization.
' - Kept for historical reference only; use ITOps\scripts\printers\Set-WindowsPrinterConnections.ps1 instead.
' - Removes printer connections broadly and should not be run as-is.
'
On error resume next

Set WshNetwork = WScript.CreateObject("WScript.Network")
Set oPrinters = WshNetwork.EnumPrinterConnections
For i = 0 to oPrinters.Count - 1 Step 2

WshNetwork.RemovePrinterConnection oPrinters.Item(i+1)

Next
