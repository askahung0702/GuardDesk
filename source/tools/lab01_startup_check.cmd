@echo off
setlocal EnableExtensions DisableDelayedExpansion
title GuardDesk LAB01 read-only startup check
if /I not "%COMPUTERNAME%"=="LAB01" (
  echo This check is for LAB01 only. No check was performed.
  exit /b 2
)
set "GD_CHECK_SYS=%SystemRoot%\System32"
"%GD_CHECK_SYS%\fltmc.exe" >nul 2>&1
if errorlevel 1 (
  echo Please right-click this CMD file and choose Run as administrator.
  pause
  exit /b 3
)
set "GD_CHECK_REPORT=%~dp0LAB01-Startup-Report-%RANDOM%-%RANDOM%.txt"
if exist "%GD_CHECK_REPORT%" (
  echo Report name already exists. Please run this check again.
  exit /b 4
)
echo Collecting a read-only report. No Agent process or task will be started or stopped.
call :collect >"%GD_CHECK_REPORT%" 2>&1
if errorlevel 1 (
  echo Report creation failed. No Agent files were changed.
  pause
  exit /b 1
)
echo Result=READ_ONLY_REPORT_CREATED
echo This result does not mean that Agent installation passed.
echo Report="%GD_CHECK_REPORT%"
echo Send the report back for review. Do not send config.json.
pause
exit /b 0

:collect
echo GuardDesk LAB01 read-only startup check / revision 001 / internal trial
echo CheckedAt=%DATE% %TIME%
echo ExpectedDeviceID=ee71b588f7254c73d4adbbc5
echo AgentChanged=false
echo NetworkRequests=false
echo TaskOrProcessStartedOrStopped=false
echo.
echo === GuardDesk task names and states ===
"%GD_CHECK_SYS%\schtasks.exe" /Query /FO CSV /NH | "%GD_CHECK_SYS%\findstr.exe" /I /C:"GuardDesk-"
echo QueryExitCode=%ERRORLEVEL%
echo.
echo === Exact task detail ===
"%GD_CHECK_SYS%\schtasks.exe" /Query /TN "GuardDesk-USBControl-ee71b588f7254c73d4adbbc5" /V /FO LIST
echo QueryExitCode=%ERRORLEVEL%
echo.
echo === Current GuardDesk.exe processes; no command lines or owners ===
"%GD_CHECK_SYS%\tasklist.exe" /FI "IMAGENAME eq GuardDesk.exe" /FO CSV /NH
echo QueryExitCode=%ERRORLEVEL%
echo.
echo === Fixed program root directory names; no recursion ===
dir /a:d /b "C:\Program Files\GuardDeskPilot"
echo.
echo === Native executable metadata; not executed ===
dir /a:-d "C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe"
echo.
echo === Fixed new identity directory filenames; no recursion or config contents ===
dir /a /b "C:\ProgramData\GuardDeskPilot\USBControl\ee71b588f7254c73d4adbbc5"
echo.
echo === Native health file metadata only ===
dir /a:-d "C:\ProgramData\GuardDeskPilot\USBControl\ee71b588f7254c73d4adbbc5\native-health.json"
echo.
echo === Last 12 matching task events within two hours; channel is not enabled or changed ===
"%GD_CHECK_SYS%\wevtutil.exe" qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System[TimeCreated[timediff(@SystemTime) <= 7200000]] and EventData[Data[@Name='TaskName']='\GuardDesk-USBControl-ee71b588f7254c73d4adbbc5']]" /c:12 /rd:true /f:text
echo QueryExitCode=%ERRORLEVEL%
echo.
echo === Last four GuardDesk.exe application errors within two hours ===
"%GD_CHECK_SYS%\wevtutil.exe" qe Application /q:"*[System[EventID=1000 and TimeCreated[timediff(@SystemTime) <= 7200000]] and EventData[Data[@Name='AppName']='GuardDesk.exe']]" /c:4 /rd:true /f:text
echo QueryExitCode=%ERRORLEVEL%
echo.
echo Result=READ_ONLY_COLLECTION_FINISHED
echo Missing logs or files are observations, not a confirmed cause.
exit /b 0
