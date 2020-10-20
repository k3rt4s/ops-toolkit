On error resume next

Set WshNetwork = WScript.CreateObject("WScript.Network")
Set oPrinters = WshNetwork.EnumPrinterConnections
For i = 0 to oPrinters.Count - 1 Step 2

WshNetwork.RemovePrinterConnection oPrinters.Item(i+1)

Next