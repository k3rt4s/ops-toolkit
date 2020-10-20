On Error Resume Next

'Check if OK to run script
Set objShell = WScript.CreateObject("WScript.Shell")
GetButton = objShell.Popup ("About to run cleanup (OK in 5 seconds)", 5, "Cleanup", vbQuestion+vbOKCancel)
If GetButton = vbCancel Then
	objShell.Popup "Cleanup Canceled", 5, "Cleanup", vbInformation
	wscript.quit
Else

'Get environment variables
Set objUserEnv 	= objShell.Environment("USER")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strEnvVarPath 	= objShell.ExpandEnvironmentStrings(objUserEnv("TEMP"))
'Wscript.Echo (strEnvVarPath)

'Delete the subfolders in temp
Set objFolder = objFSO.GetFolder(strEnvVarPath)
Set colSubfolders = objFolder.Subfolders

For Each objSubfolder in colSubfolders
objFSO.DeleteFolder (strEnvVarPath & "\" & objSubfolder.Name), true
Next

'Delete the files in temp
Set objFolder = objFSO.GetFolder(strEnvVarPath)
Set colFiles = objFolder.Files

For Each objFile in colFiles
objFSO.DeleteFile (strEnvVarPath & "\" & objFile.Name), true
Next

objFSO.DeleteFolder("c:\temp\*.*")
objFSO.DeleteFile("c:\temp\*.*")

objFSO.DeleteFolder("d:\temp\*.*")
objFSO.DeleteFile("d:\temp\*.*")

objFSO.DeleteFolder("e:\temp\*.*")
objFSO.DeleteFile("e:\temp\*.*")

objFSO.DeleteFolder("i:\temp\*.*")
objFSO.DeleteFile("i:\temp\*.*")


End If