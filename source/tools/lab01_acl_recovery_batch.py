"""Generate one operator-approved, exact four-directory ACL repair workflow.

Reuses the already reviewed recovery executable, without rebuilding Agent.
"""
TARGETS = [
    r'C:\ProgramData\GuardDeskPilot',
    r'C:\ProgramData\GuardDeskPilot\USBControl',
    r'C:\ProgramData\GuardDeskPilot\USBControl\eea0d7f81091fe91372a924c',
    r'C:\Program Files\GuardDeskPilot\USBControl',
]
ANCESTORS = ['C:/', r'C:\ProgramData', r'C:\Program Files', r'C:\Program Files\GuardDeskPilot']
EXE_HASH = '5d38864f8739830e8255351243dd4fe0534bfbd40e5e14515c6d494094a2a8e7'


def batch():
    text = r'''@echo off
setlocal EnableExtensions DisableDelayedExpansion
title GuardDesk LAB01 - repair four ACL grants and prepare interrupted install
if /I not "%COMPUTERNAME%"=="LAB01" goto wrong_host
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 goto admin
if not exist "%~dp0GuardDeskInstallRecovery.exe" goto missing
"%SystemRoot%\System32\certutil.exe" -hashfile "%~dp0GuardDeskInstallRecovery.exe" SHA256 | "%SystemRoot%\System32\findstr.exe" /i /x "EXE_HASH" >nul
if errorlevel 1 goto hash
echo Repair only EXAMPLE\labuser grants on four fixed GuardDesk directories.
echo Save all four DACLs before modifying any. Do not change Defender or owner.
'''.replace('EXE_HASH',EXE_HASH)
    for path in ANCESTORS + TARGETS:
        text += 'set "target='+path+'"\ncall :plain_directory\nif errorlevel 1 goto path_error\n'
    text += r'''set "report=%~dp0ACL-Recovery-%RANDOM%-%RANDOM%"
if exist "%report%" goto collision
mkdir "%report%"
if errorlevel 1 goto write_failed
> "%report%\result.txt" echo Result=BACKUP_STARTED_NO_ACL_CHANGES_YET
echo Report="%report%"
'''
    for i,path in enumerate(TARGETS,1):
        text += 'echo [Backup '+str(i)+'/4]\n'
        text += '"%SystemRoot%\\System32\\icacls.exe" "'+path+'" /save "%report%\\acl-'+str(i)+'.txt" /L > "%report%\\backup-'+str(i)+'.log" 2>&1\n'
        text += 'if errorlevel 1 goto backup_failed\nif not exist "%report%\\acl-'+str(i)+'.txt" goto backup_failed\n'
    text += '> "%report%\\result.txt" echo Result=ACL_REPAIR_STARTED\n'
    for i,path in enumerate(TARGETS,1):
        text += 'echo [Repair '+str(i)+'/4]\nset "target='+path+'"\ncall :plain_directory\nif errorlevel 1 goto repair_failed\n'
        text += '"%SystemRoot%\\System32\\icacls.exe" "'+path+'" /remove:g "EXAMPLE\\labuser" /L > "%report%\\repair-'+str(i)+'.log" 2>&1\n'
        text += 'if errorlevel 1 goto repair_failed\n'
        text += '>> "%report%\\result.txt" echo ChangedPath="'+path+'"\n'
        text += '"%SystemRoot%\\System32\\icacls.exe" "'+path+'" /L > "%report%\\after-'+str(i)+'.txt" 2>&1\n'
        text += 'if errorlevel 1 goto repair_failed\n'
    text += r'''echo [Recovery] Verify all original safeguards and archive interrupted state.
"%~dp0GuardDeskInstallRecovery.exe" --prepare > "%report%\Recovery-Result.json" 2>&1
set "result=%errorlevel%"
type "%report%\Recovery-Result.json"
>> "%report%\result.txt" echo RecoveryExitCode=%result%
echo Report="%report%"
echo ExitCode=%result%
echo Return this report folder. This does not install or start Agent.
pause
exit /b %result%
:plain_directory
set "attributes="
for %%P in ("%target%") do set "attributes=%%~aP"
if not defined attributes exit /b 1
if /I not "%attributes:~0,1%"=="d" exit /b 1
if /I not "%attributes:l=%"=="%attributes%" exit /b 1
exit /b 0
:backup_failed
>> "%report%\result.txt" echo Result=BACKUP_FAILED_NO_ACL_CHANGES
echo BACKUP_FAILED. No permission changes performed.
goto failed
:repair_failed
>> "%report%\result.txt" echo Result=ACL_REPAIR_INCOMPLETE_REVIEW_REQUIRED
echo ACL_REPAIR_INCOMPLETE. Keep all reports. Do not restore broad grants automatically.
goto failed
:failed
echo Report="%report%"
pause
exit /b 1
:wrong_host
echo WRONG_HOST_NO_CHANGES
pause
exit /b 2
:admin
echo ADMIN_REQUIRED: Right-click Repair-Permissions-And-Prepare.bat and run as administrator.
pause
exit /b 3
:missing
echo HELPER_MISSING: Extract the complete ZIP.
pause
exit /b 4
:hash
echo HELPER_HASH_MISMATCH: No changes performed.
pause
exit /b 5
:path_error
echo INVALID_OR_REPARSE_DIRECTORY: No changes performed.
pause
exit /b 6
:collision
echo REPORT_DIRECTORY_EXISTS: No changes performed.
pause
exit /b 7
:write_failed
echo REPORT_WRITE_FAILED: No changes performed.
pause
exit /b 8
'''
    return text.replace('\n','\r\n').encode('ascii')
