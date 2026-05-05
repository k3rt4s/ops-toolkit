' Archive Notes:
' - Retired on 2026-05-04 during the SecOps repo modernization.
' - Kept for historical reference only after the duplicate active utility was removed.
' - Do not run in production; use supported Windows activation tooling instead.
'
' 
' WMI Script - ChangeVLKey.vbs
'
' This script changes the product key on the computer
'
'***************************************************************************

ON ERROR RESUME NEXT


if Wscript.arguments.count<1 then
   Wscript.echo "Script can't run without VolumeProductKey argument"
   Wscript.echo "Correct usage: Cscript ChangeVLKey.vbs ABCDE-FGHIJ-KLMNO-PRSTU-WYQZX"
   Wscript.quit
end if

Dim VOL_PROD_KEY
VOL_PROD_KEY = Wscript.arguments.Item(0)
VOL_PROD_KEY = Replace(VOL_PROD_KEY,"-","") 'remove hyphens if any

for each Obj in GetObject("winmgmts:{impersonationLevel=impersonate}").InstancesOf ("win32_WindowsProductActivation")

   result = Obj.SetProductKey (VOL_PROD_KEY)

   if err <> 0 then
      WScript.Echo Err.Description, "0x" & Hex(Err.Number)
      Err.Clear
   end if

Next
