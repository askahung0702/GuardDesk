"""Bounded read-only CMD DACL snapshots for the three installed checker roots.

No /T: an owned probe showed icacls /T /L still descends NTFS junctions.
Names and queues are data, never interpolated into CALL or child CMD source.
"""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]
DID='ee1e1e17c6c8730a37603b1e'


def render(fixture=None):
    cfg=dict(HOST='LAB01',TOOLS=r'C:\Windows\System32',
        DATA=rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}',
        UPDATER=r'C:\Program Files\GuardDeskPilot\Updater',
        NATIVE=r'C:\Program Files\GuardDeskPilot\USBControl',MAX_NODES='4096',MAX_DIRS='512')
    if fixture:cfg.update(fixture)
    template=r'''@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
title GuardDesk LAB01 read-only ACL audit
set "GD_HOST=@HOST@"
set "GD_TOOLS=@TOOLS@"
set "GD_DATA=@DATA@"
set "GD_UPDATER=@UPDATER@"
set "GD_NATIVE=@NATIVE@"
set "GD_MAX_NODES=@MAX_NODES@"
set "GD_MAX_DIRS=@MAX_DIRS@"
set "GD_NODES=0"
set "GD_DIRS=0"
set "GD_NEXT=1"
set "GD_PARTIAL=0"
set "GD_OUT="
if /i not "%COMPUTERNAME%"=="%GD_HOST%" goto wrong_host
"%GD_TOOLS%\fltmc.exe" >nul 2>&1
if errorlevel 1 goto not_admin
echo READ ONLY. Three fixed Agent trees; no content read, ACL repair, task or Agent execution.
echo At most %GD_MAX_NODES% DACLs, %GD_MAX_DIRS% directories, depth 32 and 16 MiB DACL output.
echo Reparse paths are skipped; skips/errors/limits mean PARTIAL, never a trusted-tree verdict.
echo Extract this BAT to a private MIS writable folder. Keep reports private.
"%GD_TOOLS%\choice.exe" /c YN /n /m "Audit the three fixed paths into this private MIS folder? [Y/N]: "
if not errorlevel 1 goto cancelled
if errorlevel 2 goto cancelled
set "GD_OUT=%~dp0LAB01-ACL-Audit-%RANDOM%-%RANDOM%"
if exist "%GD_OUT%" goto output_error
md "%GD_OUT%" >nul 2>&1
if errorlevel 1 goto output_error
set "GD_REPORT=%GD_OUT%\Audit.txt"
set "GD_DACLS=%GD_OUT%\DACLs.txt"
> "%GD_REPORT%" echo GuardDesk LAB01 READ ONLY DACL collection / internal trial / 20261029
if errorlevel 1 goto output_error
> "%GD_DACLS%" type nul
if errorlevel 1 goto output_error
set "GD_SCOPE=1"
set "GD_NODE=%GD_DATA%"
call :node
if errorlevel 1 goto limit
set "GD_SCOPE=2"
set "GD_NODE=%GD_UPDATER%"
call :node
if errorlevel 1 goto limit
set "GD_SCOPE=3"
set "GD_NODE=%GD_NATIVE%"
call :node
if errorlevel 1 goto limit
:walk
if %GD_NEXT% GTR %GD_DIRS% goto done
set "GD_DIR="
set "GD_SCOPE="
for /f "usebackq tokens=1,* delims=|" %%S in ("%GD_OUT%\Queue-%GD_NEXT%.txt") do (
 set "GD_SCOPE=%%S"
 set "GD_DIR=%%T"
)
set /a GD_NEXT+=1 >nul
if not defined GD_DIR goto limit
set "GD_NODE=%GD_DIR%"
call :plain_ancestors
if errorlevel 1 goto walk
dir /b /a "%GD_DIR%" > "%GD_OUT%\names.tmp" 2>> "%GD_REPORT%"
if errorlevel 1 goto list_error
for %%S in ("%GD_OUT%\names.tmp") do if %%~zS GTR 262144 goto limit
for /f "usebackq delims= eol=|" %%N in ("%GD_OUT%\names.tmp") do (
 set "GD_LEAF=%%N"
 call :child
 if errorlevel 1 goto limit
)
goto walk
:list_error
set "GD_PARTIAL=1"
>> "%GD_REPORT%" echo ListingError="%GD_DIR%"
goto walk
:child
if "%GD_LEAF%"=="." exit /b 0
if "%GD_LEAF%"==".." exit /b 0
if not "%GD_LEAF:\=%"=="%GD_LEAF%" exit /b 1
if not "%GD_LEAF:/=%"=="%GD_LEAF%" exit /b 1
if not "%GD_LEAF::=%"=="%GD_LEAF%" exit /b 1
set "GD_NODE=%GD_DIR%\%GD_LEAF%"
call :node
exit /b %ERRORLEVEL%
:node
if %GD_NODES% GEQ %GD_MAX_NODES% exit /b 1
call :plain_ancestors
if errorlevel 1 exit /b 0
set /a GD_NODES+=1 >nul
>> "%GD_REPORT%" echo Node=%GD_NODES% Scope=%GD_SCOPE% Path="%GD_NODE%"
set "GD_SAVED_ATTR=%GD_ATTR%"
"%GD_TOOLS%\icacls.exe" "%GD_NODE%" /save "%GD_OUT%\node.tmp" /l /q >> "%GD_REPORT%" 2>&1
set "GD_TOOL_CODE=%ERRORLEVEL%"
if not "%GD_TOOL_CODE%"=="0" goto node_error
if not exist "%GD_OUT%\node.tmp" goto node_error
for %%S in ("%GD_OUT%\node.tmp") do if %%~zS LSS 2 goto node_error
for %%S in ("%GD_OUT%\node.tmp") do if %%~zS GTR 1048576 exit /b 1
type "%GD_OUT%\node.tmp" >> "%GD_DACLS%"
if errorlevel 1 exit /b 1
>> "%GD_REPORT%" echo SavedNode=%GD_NODES% Scope=%GD_SCOPE% Path="%GD_NODE%"
for %%S in ("%GD_DACLS%") do if %%~zS GTR 16777216 exit /b 1
if /i not "%GD_SAVED_ATTR:~0,1%"=="d" exit /b 0
if %GD_DIRS% GEQ %GD_MAX_DIRS% exit /b 1
set /a GD_DIRS+=1 >nul
setlocal EnableDelayedExpansion
> "!GD_OUT!\Queue-!GD_DIRS!.txt" echo !GD_SCOPE!^|!GD_NODE!
endlocal
if errorlevel 1 exit /b 1
exit /b 0
:node_error
set "GD_PARTIAL=1"
>> "%GD_REPORT%" echo SnapshotError="%GD_NODE%" ToolExitCode=%GD_TOOL_CODE%
exit /b 0
:plain_ancestors
set "GD_CHECK=%GD_NODE%"
set "GD_DEPTH=0"
:ancestor
set /a GD_DEPTH+=1 >nul
if %GD_DEPTH% GTR 32 goto path_error
set "GD_ATTR="
for %%P in ("%GD_CHECK%") do set "GD_ATTR=%%~aP"
if not defined GD_ATTR goto path_error
if not "%GD_ATTR:l=%"=="%GD_ATTR%" goto path_error
if not "%GD_ATTR:L=%"=="%GD_ATTR%" goto path_error
for %%P in ("%GD_CHECK%\..") do set "GD_PARENT=%%~fP"
if /i "%GD_PARENT%"=="%GD_CHECK%" goto path_ok
set "GD_CHECK=%GD_PARENT%"
goto ancestor
:path_ok
for %%P in ("%GD_NODE%") do set "GD_ATTR=%%~aP"
exit /b 0
:path_error
set "GD_PARTIAL=1"
>> "%GD_REPORT%" echo SkippedUnavailableOrReparse="%GD_NODE%" Check="%GD_CHECK%" Attributes="%GD_ATTR%"
exit /b 1
:limit
set "GD_PARTIAL=1"
>> "%GD_REPORT%" echo LimitOrQueueOrOutputFailure=stop_no_additional_traversal
:done
set "GD_CODE=0"
set "GD_RESULT=READ_ONLY_COLLECTION_COMPLETE_NOT_A_TRUST_VALIDATION"
if "%GD_PARTIAL%"=="1" set "GD_RESULT=READ_ONLY_COLLECTION_PARTIAL_NOT_A_TRUST_VALIDATION"
if "%GD_PARTIAL%"=="1" set "GD_CODE=2"
>> "%GD_REPORT%" echo Nodes=%GD_NODES% Directories=%GD_DIRS%
>> "%GD_REPORT%" echo Result=%GD_RESULT%
>> "%GD_REPORT%" echo ExitCode=%GD_CODE%
echo Result: %GD_RESULT%
echo Send ONLY these two metadata reports to MIS:
echo "%GD_REPORT%"
echo "%GD_DACLS%"
echo No permissions/files/tasks were changed in the three source trees. Do not redeploy yet.
pause
exit /b %GD_CODE%
:wrong_host
echo STOP: this BAT is restricted to LAB01. No tools or output were used.
pause
exit /b 1
:not_admin
echo STOP: run as administrator on LAB01. Do not bypass company policy.
pause
exit /b 1
:cancelled
echo Cancelled. No report or source change.
pause
exit /b 2
:output_error
echo STOP: output collision/write failure. Preserve any partial reports. No source changes.
pause
exit /b 1
'''
    for key,value in cfg.items():template=template.replace('@'+key+'@',str(value).replace('%','%%'))
    return template.replace('\n','\r\n').encode('utf-8')


README='''LAB01 唯讀 ACL 定位（未簽章內部維護工具）
根目錄user1額外授權已移除，但原updater-check仍拒絕。這次只取得實際逐項DACL，不能當成又一次修復。
在LAB01將包解壓到MIS私人資料夾，右鍵Audit-LAB01-ACL.bat以系統管理員執行，確認範圍後按Y。
只檢查三個固定來源：該端點ProgramData資料根、現用Program Files\\GuardDeskPilot\\Updater、USBControl。
只讀取路徑／屬性及DACL，不讀公司文件、設定內容、token或私鑰；不執行Agent、啟停工作、變更ACL、改owner、刪檔或封存。
沒有/T遞迴。逐層列出（含隱藏／系統項）、逐物件檢查祖先reparse，略過junction／symlink及無法讀取者。
最多4096份DACL、512目錄、32層祖先；單層列名256KiB、單份DACL 1MiB、合計16MiB，超標停止並標PARTIAL。
列目錄由Windows DIR列一次該層，完成後才檢查列名大小；沒有宣稱每個OS呼叫都有硬逾時或可抵抗所有並行替換。
這是MIS前景的一次維護，不新增常駐或全磁碟掃描。請在沒有同時手動更名／安裝更新的維護時段執行。
遇到錯誤、reparse、上限或中斷，結果是部分快照，不代表其餘物件安全。收集完成也不是權限驗證通過。
提供新資料夾中的 Audit.txt 和 DACLs.txt 即可；Queue-*.txt、names.tmp及node.tmp為工具自己的中間檔，不用提供。
這兩份只含內部路徑／SID／DACL，仍限MIS保留；不把診斷輸出放到員工共用可寫位置。
來源不會被修改；自身新輸出資料夾內的中間檔會覆寫，原維護包、修復包及ACL Before備份請保留。
若被公司App Control擋住，停止交MIS核准，不改政策、不換格式繞過。實際LAB01定位、修復及更新仍未驗收。
Windows icacls /save /l語意：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
'''


def main():
    folder=ROOT/'dist/lab01-acl-audit-20261029';folder.mkdir(exist_ok=True)
    members={'Audit-LAB01-ACL.bat':render(),'README.txt':README.encode('utf-8-sig')}
    for name,body in members.items():(folder/name).write_bytes(body)
    hashes={n:hashlib.sha256(b).hexdigest() for n,b in members.items()}
    (folder/'MANIFEST-SHA256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='ascii')
    archive=ROOT/'dist/GuardDesk-LAB01-ACL-Audit-20261029.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for name in [*members,'MANIFEST-SHA256.json']:z.write(folder/name,name)
    print(json.dumps({'artifact':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}))


if __name__=='__main__':main()
