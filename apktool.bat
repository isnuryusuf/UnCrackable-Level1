@echo off
setlocal
set APKTOL_HOME=%~dp0
java -jar "%APKTOL_HOME%build-tools\apktool.jar" %*
endlocal
