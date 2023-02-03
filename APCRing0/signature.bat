set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd /d "%projectpath%"
set "SignFullPath=%Projectpath%/x64/debug/APCRing0.sys"

set "d=%date:~0,10%"
set "path=%path%;D:/DSignTool/"

date 2013/8/15
CsignTool.exe sign /r landong /f %SignFullPath% /ac
date %d%