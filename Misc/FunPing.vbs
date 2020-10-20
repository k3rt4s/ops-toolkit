' Mark's VNCSchool Script
' Read the commentary in this script to get a feel for how to write your own VBScripts


'Take out the comment for the next line to ignore any errors and continue processing
'On Error Resume Next
' Set a Constant for the file operation type
CONST ForReading = 1

' Functions

' Convert a decimal value to a binary string
Function DecToBin(ByVal decVal, decMaxPassed)
stringBin = ""
decMax = decMaxPassed
Do While decVal > 0 OR decMax >= 1
	If decVal Mod 2 > 0 Then
		stringBin = "1" & stringBin
	Else
		stringBin = "0" & stringBin
	End If
	decVal = Int(decVal / 2)
	decMax = decMax / 2
Loop
DecToBin = stringBin
End Function 

' Convert a binary string to a long decimal value
Function BinToDec(BinVal)
maxBits = Len(BinVal)
numBit = maxBits - 1
bitLoop = 1
Do While bitLoop <= maxBits
	getBit = mid(BinVal,bitLoop,1)
	If getBit = "1" Then
		decResult = decResult + 2^numBit
	End If	
	bitLoop = bitLoop + 1
	numBit = numBit - 1
Loop
BinToDec = Cstr(decResult)
End Function

Function Alive(strHost)
  Const SYSTEM_FOLDER = 1, TEMP_FOLDER = 2  ' FileSystemObject constants
  Dim objFSO, objTS
  Dim strTempFile, strCmdLine
  Dim objRE

  Set objFSO = CreateObject("Scripting.FileSystemObject")

  With objFSO
    ' Construct a temporary filename.
    Do
      strTempFile = .BuildPath(.GetSpecialFolder(TEMP_FOLDER), .GetTempName)
    Loop While .FileExists(strTempFile)

    ' Construct the command line using cmd.exe;
    ' redirect the ping.exe output to the temporary file.
    strCmdLine = .BuildPath(.GetSpecialFolder(SYSTEM_FOLDER), "cmd.exe") _
      & " /c " & .BuildPath(.GetSpecialFolder(SYSTEM_FOLDER), "ping.exe") _
      & " -w 100 -l 1 " & strHost & " > " & strTempFile
  End With

  ' Execute the command line in a hidden window.
  ' Wait for it to complete before continuing.
  CreateObject("Wscript.Shell").Run strCmdLine, 0, True

  ' Open the temporary file.
  Set objTS = objFSO.OpenTextFile(strTempFile, 1)

  ' Function result will be True if the pattern
  ' was found in the temporary file's contents.
  Alive = objTS.ReadAll

  ' Close and delete the temporary file.
  objTS.Close
  objFSO.DeleteFile strTempFile
End Function

' Create an object for operating system Shell commands
Set objShell = WScript.CreateObject("WScript.Shell")

' Get the data file names as input from the command-line or shortcut
If WScript.Arguments.Count < 1 Then 
clientIP = "192.168.0.1"
GetButton = objShell.Popup ("You didn't type an IP Address at the command line.  Would you like to see an example using 192.168.0.1?", , "Fun Ping", vbQuestion+vbOKCancel)
If GetButton = vbCancel Then
	objShell.Popup "Ping Cancelled", 10, "Fun Ping", vbInformation
	wscript.quit
End If
Else 
	clientIP = Wscript.Arguments.Item(0)
End If	

' Now split the IP address into four parts using the period as a delimeter
IPOctets = split(clientIP, ".")
bitString = decToBin(int(IPOctets(0)),255) & decToBin(int(IPOctets(1)),255) & decToBin(int(IPOctets(2)),255) & decToBin(int(IPOctets(3)),255)
bigDecimalIP = binToDec(bitString)

wscript.echo "Decimal IP: " & clientIP
wscript.echo "Here is the full 32 bit binary IP:  " & bitString
wscript.echo "Now, this is the big decimal value of the IP Address:  " & bigDecimalIP
wscript.echo "Ping " & bigDecimalIP & Alive(bigDecimalIP)
wscript.echo "Now try the big decimal value with the normal Ping command yourself:   Ping " & bigDecimalIP

' See ya!	
Wscript.Quit

