@echo off
REM Archive Notes:
REM - Retired on 2026-05-04 during the SecOps repo modernization.
REM - Kept for historical reference only after the duplicate active BGInfo utility was removed.
REM - References legacy BGInfo paths and should not be run as-is.
setlocal
cls

if exist c:\programdata goto Run2008

echo Running BGInfo for Pre Windows Server 2008
echo.
"c:\Documents and Settings\All Users\bginfo.exe" "c:\Documents and Settings\All Users\default.bgi" /timer:0 /nolicprompt /silent
goto End

:Run2008
echo Running BGInfo for Windows Server 2008
echo.
c:\programdata\bginfo.exe c:\programdata\default.bgi /timer:0 /nolicprompt /silent

:End
