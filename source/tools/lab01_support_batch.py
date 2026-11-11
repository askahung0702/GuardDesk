"""One bounded read-only field collection; no Agent executable is invoked."""
DID='eea0d7f81091fe91372a924c'
DATA=rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}'
EXE=r'C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe'
SMALL=[DATA+'\\'+name for name in ('install-transaction.json','native-health.json','installation.json')]
ACL=[r'C:\Program Files\GuardDeskPilot',r'C:\Program Files\GuardDeskPilot\USBControl',
     r'C:\ProgramData\GuardDeskPilot',r'C:\ProgramData\GuardDeskPilot\USBControl',DATA,EXE,DATA+r'\config.json']
QUERIES=[
 ('tasks','Microsoft-Windows-TaskScheduler/Operational',f"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='TaskName']='\\GuardDesk-USBControl-{DID}']]",48),
 ('crashes','Application',"*[System[EventID=1000 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='AppName']='GuardDesk.exe' or Data[@Name='AppName']='GuardDeskAgent.exe']]",12),
 ('defender','Microsoft-Windows-Windows Defender/Operational',"*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119) and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='Threat Name']='Behavior:Win32/Execution.A!ml' or Data[@Name='Threat Name']='Trojan:Win32/Bearfoos.A!ml']]",32),
]

def batch():
    text=r'''@echo off
setlocal EnableExtensions DisableDelayedExpansion
title GuardDesk LAB01 - one read-only support report
if /I not "%COMPUTERNAME%"=="LAB01" goto wrong_host
set "sys=%SystemRoot%\System32"
"%sys%\fltmc.exe" >nul 2>&1
if errorlevel 1 goto need_admin
set "report=%~dp0LAB01-Support-%RANDOM%-%RANDOM%"
if exist "%report%" goto collision
mkdir "%report%"
if errorlevel 1 goto write_failed
echo [1/5] Reading current task and process state.
echo Report="%report%"
call :state > "%report%\state.txt" 2>&1
echo [2/5] Reading fixed folder permissions.
call :acl > "%report%\acl.txt" 2>&1
echo [3/5] Reading bounded startup and protection events.
'''
    for label,channel,query,count in QUERIES:
        text+=f'echo Checking {label} events...\n"%sys%\\wevtutil.exe" qe "{channel}" /q:"{query}" /c:{count} /rd:true /f:xml /e:Events > "%report%\\{label}.xml" 2> "%report%\\{label}-error.txt"\n'
        text+=f'>> "%report%\\query-results.txt" echo {label}ExitCode=%errorlevel%\n'
    text+=r'''echo [4/5] Reading task definition only; not running it.
"%sys%\schtasks.exe" /Query /TN "GuardDesk-USBControl-DID" /XML > "%report%\task.xml" 2> "%report%\task-error.txt"
>> "%report%\query-results.txt" echo TaskXmlExitCode=%errorlevel%
echo [5/5] Reading health again to preserve changes during collection.
call :health > "%report%\health-after.txt" 2>&1
> "%report%\README-result.txt" echo Result=REPORT_CREATED_NOT_INSTALL_ACCEPTANCE
>> "%report%\README-result.txt" echo Check query-results.txt and state.txt; failures are not treated as missing.
echo Result=REPORT_CREATED_NOT_INSTALL_ACCEPTANCE
echo Report="%report%"
echo No install, cleanup, ACL changes or Defender changes performed.
echo Return this report folder. Do not rerun installation until reviewed.
pause
exit /b 0
:state
echo GuardDesk LAB01 consolidated support 001
echo CheckedAt=%DATE% %TIME%
echo ExpectedDevice=DID
echo ExpectedVersion=0.4.86
echo SettingsChanged=false
echo AgentExecuted=false
"%sys%\schtasks.exe" /Query /TN "GuardDesk-USBControl-DID" /V /FO LIST
echo TaskQueryExitCode=%errorlevel%
"%sys%\tasklist.exe" /FI "IMAGENAME eq GuardDesk.exe" /FO CSV /NH
echo ProcessQueryExitCode=%errorlevel%
dir /a:d /b "C:\Program Files\GuardDeskPilot"
echo ProgramNamesExitCode=%errorlevel%
dir /a:d /b "C:\ProgramData\GuardDeskPilot\USBControl"
echo IdentityNamesExitCode=%errorlevel%
"%sys%\certutil.exe" -hashfile "EXE" SHA256
echo ImageHashExitCode=%errorlevel%
'''.replace('DID',DID).replace('EXE',EXE)
    for path in SMALL:
        text+='set "target='+path+'"\ncall :small_file\n'
    text+='exit /b 0\n:health\necho CheckedAt=%DATE% %TIME%\nset "target='+SMALL[1]+'"\ncall :small_file\nexit /b 0\n:acl\n'
    for path in ACL:
        text+='"%sys%\\icacls.exe" "'+path+'" /L\necho AclQueryExitCode=%errorlevel%\n'
    text+=r'''exit /b 0
:small_file
echo File="%target%"
dir /a:-d "%target%"
echo FileMetadataExitCode=%errorlevel%
if not exist "%target%" exit /b 0
for %%Z in ("%target%") do if %%~zZ GTR 65536 goto oversized
for %%Z in ("%target%") do set "attrs=%%~aZ"
if /I not "%attrs:l=%"=="%attrs%" goto linked
type "%target%"
echo.
echo FileReadExitCode=%errorlevel%
exit /b 0
:oversized
echo FileRead=SKIPPED_SIZE_LIMIT
exit /b 0
:linked
echo FileRead=SKIPPED_REPARSE
exit /b 0
:wrong_host
echo WRONG_HOST_NO_QUERIES
pause
exit /b 2
:need_admin
echo Right-click Start-Check.cmd and choose Run as administrator.
pause
exit /b 3
:collision
echo REPORT_NAME_COLLISION_NO_OVERWRITE
pause
exit /b 4
:write_failed
echo REPORT_DIRECTORY_WRITE_FAILED
pause
exit /b 5
'''
    return text.replace('\n','\r\n').encode('ascii')
