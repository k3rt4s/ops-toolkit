'***********************************************************
'Any line that says "if (DEBUG)" will display the status message
'following that line.  Used when the script is called "whoami.js debug"
'************************************************************
Option Explicit
'On Error Resume Next

Dim ScriptVer, logDir, Shell, netSys, fileSys

ScriptVer = "1.6"
logDir = "C:\PROGRAM FILES\BANK OF AMERICA\LOG\"

Const OpenFileForReading = 1
Const OpenFileForWriting = 2
Const OpenFileForAppending = 8

'**************************************************************
'*
'*	Main Program
'*
'**************************************************************


Set Shell = WScript.CreateObject("WScript.Shell")
Set netSys = WScript.CreateObject("WScript.Network")
Set fileSys = WScript.CreateObject("Scripting.FileSystemObject")

Dim  d, ErrorTxt, StatusTxt, bError, strUsrDomain
Dim oInfo, LDAPUsr, DEBUG, oArgs, colIPs
Set colIPs = CreateObject("Scripting.Dictionary")

strUsrDomain=netSys.UserDomain

ErrorTxt=" "
StatusTxt=" "

'Writes a line to the event log telling when the whoami script started
StatusTxt=StatusTxt & VBCRLF & "Beginning Whoami Script at: " & Now() & VBCRLF

' Some machines have had problems accessing Active Directory information so these section
' captures any errors and stops the script if there are any
Set oInfo = WScript.createObject("ADSystemInfo")
If err.number <> 0 Then
	shell.popup("Error creating oInfo object " & e.description)
	WScript.quit(1)
End If

Set LDAPUsr = GetObject("LDAP://" & oInfo.UserName)
If err.number <> 0 Then
	shell.popup("Error creating LDAPUsr object " & e.description)
	WScript.quit(1)
End If


DEBUG=0

' Assigns the arguments from calling the script to oArgs for use later.
' Only acceptable argument is DEBUG
Set oArgs=WScript.Arguments


' Checks if "debug" was an argument and turns on status messages if so.
If oArgs.count>0 Then
	If UCase(oArgs(0))="DEBUG" Then
		DEBUG=1
		WScript.echo("Debug turned on")
	End If
End If

' All procedures branch from this section
startUp()
UserGreeting()
Drive_Map()
After_Script()


'**************************************************************
'*
'*	End of Main Program
'*
'**************************************************************/

function startUp()
	' Checks of the C:\Program Files\Bank of America\log directory
	' exists of creates it if not
	Dim infoStream, errStream

	If not fileSys.FolderExists(logDir) Then
		' Start at the beginning of the logDir variable and
		' create each directory in the path if it doesn't exist
		Dim tempdir, i
		tempdir=""
		For i=1 to Len(logDir)
			If (Mid(logDir,i,1)="\") AND (not fileSys.FolderExists(tempdir)) Then
				fileSys.CreateFolder(tempdir)
			End If
			tempdir=tempdir & Mid(logDir,i,1)
		Next
	End If

	'Initializes the information and error logs.

	 Set infoStream = fileSys.OpenTextFile(logDir & "Whoami" & UCase(netSys.UserName) & ".log", OpenFileForWriting, true)

	infoStream.Writeline("Whoami Script Version " & ScriptVer)
	infoStream.WriteBlankLines(1)
	infoStream.Close()
End Function


Function UserGreeting()
	'**************************************************************
	'* Collects and displays information for the user.  Usually the
	'* first thing the user sees
	'***************************************************************/
	On Error Resume Next

	Dim env, strGreeting, lastChange, passExpire, strBuildVer, strBuildBuild
	Dim icount, IPItems
	If DEBUG Then
		WScript.echo("Displaying User Greeting")
		WScript.echo("")
	End If
	Set env=shell.environment("Process")
	strGreeting=""
	lastChange=LDAPUsr.PasswordLastChanged
	passExpire=DateSerial(Year(lastChange), Month(lastChange), Day(lastChange)+90)
	strBuildVer = Shell.regread("HKEY_LOCAL_MACHINE\SOFTWARE\Bank of America\OS Build\CD Version")
	If err.number<> 0 Then
		strBuildVer=""
		err.clear
	Else
		strBuildBuild = Shell.regread("HKEY_LOCAL_MACHINE\SOFTWARE\Bank of America\OS Build\CD Build")
	End If
	On Error GoTo 0
	strGreeting = "Hello " & LDAPUsr.FirstName & " " & LDAPUsr.LastName
	strGreeting = strGreeting & VBCRLF & "Today is " & strDayName(Weekday(Now())) & " " & strMonthName(Month(Now())) & " " & Day(Now()) & ", " & Year(Now())
	strGreeting = strGreeting & VBCRLF & "You are logged into the " & netSys.UserDomain & " Domain"
	strGreeting = strGreeting & VBCRLF & "In the " & oInfo.SiteName & " site"
	strGreeting = strGreeting & VBCRLF & "From server " & Mid(env("LOGONSERVER"),3)
	strGreeting = strGreeting & VBCRLF & "Using the ID " & UCase(netSys.UserName)
	strGreeting = strGreeting & VBCRLF & "From Computer " & netSys.ComputerName
	strGreeting = strGreeting & VBCRLF & "Using IP Address(es) "
	On Error Resume Next
	GetIP()
	IPItems=colIPs.items
	icount=0
	If colIPs.count>1 Then
		For icount=0 to colIPs.count -1
			If icount=0 Then
				strGreeting = strGreeting & IPItems(icount)
			Else
				strGreeting = strGreeting & VBCRLF & Space(34) & IPItems(icount)
			End If
		Next
	Else
		strGreeting = strGreeting & IPItems(icount)
	End if

	If strBuildVer<>"" Then
		strGreeting = strGreeting & VBCRLF & "Build Version " & strBuildVer & " b" & strBuildBuild
	End If
	strGreeting = strGreeting & VBCRLF & "Your password will expire on "
	strGreeting = strGreeting & VBCRLF & "     " & strDayName(Weekday(passExpire)) & " " & strMonthName(Month(passExpire)) & " " & Day(passExpire) & ", " & Year(passExpire)

	shell.popup strGreeting, 30, "WhoAmI Greeting " & ScriptVer, 64
	ErrorTxt=ErrorTxt & VBCRLF & strGreeting & VBCRLF
	StatusTxt=StatusTxt & VBCRLF & strGreeting & VBCRLF
	strGreeting=null
	On Error GoTo 0
End Function



function Drive_Map()
	'**************************************************************************
	'	Runs Groupmap to map drives as specified in group membership
	'**************************************************************************/

	Dim intRetCode, strScriptPath

	If DEBUG Then
		WScript.echo("Mapping drives")
	End If


	' Retrieves the directory the script is being run from and run Groupmap.exe
	' from that same directory.  Groupmap reads the users group membership and maps
	' drives if the user is part of specific groups with certain information in the
	' description line of the group
	strScriptPath=Mid(WScript.ScriptFullName,1,(Len(WScript.ScriptFullName)-14))
	if fileSys.FileExists(strScriptPath & "GROUPMAP.EXE") Then
		intRetCode=shell.run(chr(34) & strScriptPath & "GROUPMAP.exe" & chr(34), 0, false)
	End If


	if DEBUG Then
		WScript.echo ""
	End If
End Function


Function After_Script()
	'**************************************************************************
	'* This function writes any errors to the error and status logs.
	'**************************************************************************/
	If DEBUG Then
		WScript.echo "Running After script"
		WScript.echo ""
	End If
	StatusTxt=StatusTxt & VBCRLF & "Ending Whoami Script at: "  & Now()
	logInfo(StatusTxt)
End Function



'*********************************************************************
'*
'* Function strDayName()
'* Purpose: Returns the name of the weekday
'* Input:   strDate		Date to find the day from
'* Output:  strDayName		Name of the weekday
'*
'*********************************************************************

function strDayName(intDay)
	Select Case intDay
		case 1	strDayName="Sunday"
		case 2	strDayName="Monday"
		case 3	strDayName="Tuesday"
		case 4	strDayName="Wednesday"
		case 5	strDayName="Thursday"
		case 6	strDayName="Friday"
		case 7	strDayName="Saturday"
		Case Else strDayName=" "
	End Select
End Function


'********************************************************************
'*
'* Function strMonthName()
'* Purpose: Returns the name of the Month
'* Input:   strDate		Date to find the month from
'* Output:  MonthName		Name of the month
'*
'********************************************************************/
function strMonthName(intMonth)
	Select Case intMonth
		case 1 strMonthName="January"
		case 2 strMonthName="February"
		case 3 strMonthName="March"
		case 4 strMonthName="April"
		case 5 strMonthName="May"
		case 6 strMonthName="June"
		case 7 strMonthName="July"
		case 8 strMonthName="August"
		case 9 strMonthName="September"
		case 10 strMonthName="October"
		case 11 strMonthName="November"
		case 12 strMonthName="December"
		Case Else strMonthName=" "
	End Select
End Function


function logInfo(linein)
	'**************************************************************************
	'* This function takes a string to be written to the information log, creates
	'* the log if it doesn't exist, writes the date/time stamp then the string
	'* and closes the file.
	'***************************************************************************/
	Dim tempwritestring, infoStream
	Set infoStream = fileSys.OpenTextFile(logDir & "Whoami" & UCase(netSys.UserName) & ".log", OpenFileForAppending, true)
	infoStream.Write(Now() & "  " )
	infoStream.WriteBlankLines(1)

	'Since the string to be written can be long with many carriage returns
	'   and line feeds and those characters don't write well to a text file
	'   this code finds those characters and pulls them out and writes
	'   the lines in an orderly fashon.
	If not linein = "" Then
		infoStream.WriteLine(linein)
	End If
	infoStream.WriteBlankLines(1)
	infoStream.Close()

	If err.number<>0 Then
		WScript.Echo("error opening log file " & err.description)
		err.clear
	End If
	tempwritestring=null
End Function


Sub getIP()
	On Error GoTo 0
	Dim strComputer, objWMIService, colItems, objItem, icount, icount2
	Dim bDuplicatefound, IPItems
	strComputer = "."
	Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
	Set colItems = objWMIService.ExecQuery("Select * from Win32_NetworkAdapterConfiguration",,48)
	icount=0
	For Each objItem in colItems
		If IsArray(objItem.IPAddress) Then
			If InStr(UCase(objItem.Caption), "WIRELESS") Then
				If objItem.IPAddress(0) <> "0.0.0.0" Then
					colIPs.add icount,objItem.IPAddress(0) & " Wireless"
				End If
			Else
				If objItem.IPAddress(0) <> "0.0.0.0" Then
					colIPs.add icount,objItem.IPAddress(0)
				End If
			End If
			icount=icount+1
		End if
	Next

	IPItems=colIPs.items
	If colIPs.count>1 Then
		For icount=0 to colIPs.count-1
			For icount2=0 to colips.count-1
				If icount2<>icount Then
					If IPItems(icount)=IPItems(icount2) Then
						colIPs.remove(icount2)
						bDuplicatefound=true
						Exit For
					End If
				End If
			Next
			If bDuplicatefound Then
				Exit For
			End If
		Next
	End If

	'On Error Resume Next
End Sub
