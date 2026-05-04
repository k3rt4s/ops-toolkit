' Objective: To delete old files from a given folder and all subfolders below
'
' Format: cscript deloldfiles.vbs {DriveLetter:\FolderName} {#ofDays}
'     or: cscript deloldfiles.vbs {\\servername\FolderName} {#ofDays}
' Example: cscript deloldfiles.vbs c:\dba\log 3
'    (deletes files older than 3 days from the \dba\log file on drive C:)
Set objArgs = WScript.Arguments
FolderName =objArgs(0)
Days=objArgs(1)

set fso = createobject("scripting.filesystemobject")
set folders = fso.getfolder(FolderName)
datetoday = now()
newdate = dateadd("d", Days*-1, datetoday)
wscript.echo "Today:" & now()
wscript.echo "Started deleting files older than :" & newdate 
wscript.echo "________________________________________________"
wscript.echo ""
recurse folders 
wscript.echo ""
wscript.echo "Completed deleting files older than :" & newdate 
wscript.echo "________________________________________________"

sub recurse( byref folders)
  set subfolders = folders.subfolders
  set files = folders.files
  wscript.echo ""
  wscript.echo "Deleting Files under the Folder:" & folders.path
  wscript.echo "__________________________________________________________________________"
  for each file in files
    if file.datelastmodified < newdate then
      wscript.echo "Deleting " & folders.path & "\" & file.name & " last modified: " & file.datelastmodified
      on error resume next
' === to test this script but not actually delete files, comment out the next line ===
    file.delete
    end if
    
  next  

  for each folder in subfolders
    recurse folder
  next  

  set subfolders = nothing
  set files = nothing

end sub

