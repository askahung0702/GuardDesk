"""Build a fixed, operator-assisted CMD maintenance runbook, not an Agent update.

No runtime path/device overrides. Fixture substitution is build-time only and is
never exposed by the delivered BAT. Original journals are compared by digest,
not interpreted by fragile locale-dependent CMD JSON parsing.
"""
from pathlib import Path, PureWindowsPath
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DID = 'ee1e1e17c6c8730a37603b1e'
STAGE = 'USBControl.stage-264626046385d80b133c831738b747ae'
JOBS = ['264626046385d80b133c831738b747ae', '62f0fa075ac160ce37231d9a79350d05',
        '660a1644e7c0412616c3341062ce96f6', '82fcee146799c0834eff6bbb876a8ba9']
REVISION = 'v2'
PINS = {
    'install-transaction.json': '950521221d286ae88959a31247dddba40bc67f9d054f9b59bcee22353c565839',
    'updates\\transaction-native.json': 'ebb14aacf6084717de674055fc124de1f7de8704536a0204275d31b63450056c',
    'updates\\updater-refresh.json': '1489006f5a13cce0e8f057048fa7105742f5ecd03a5bb07d06f9c331a3915edc',
}
ZIP_HASH = '182a51cbd86eabedf31d62793160867ed80ce5e65368345973adee88b656eb09'


def render(fixture=None):
    if len(JOBS) != 4 or len(set(JOBS)) != 4 or any(not re.fullmatch(r'[0-9a-f]{32}', j) for j in JOBS):
        raise ValueError('Maintenance job allowlist must contain four unique 32-hex IDs')
    # Tests render a separate BAT into an owned tree. Production has literal C:
    # roots; ProgramFiles/ProgramData/PATH environment substitutions are avoided.
    cfg = dict(host='LAB01', program=r'C:\Program Files\GuardDeskPilot',
               data=rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}',
               archive=rf'C:\ProgramData\GuardDeskPilot\RepairArchive\{DID}',
               tools=r'C:\Windows\System32', pins=PINS, zip_hash=ZIP_HASH)
    if fixture:
        cfg.update(fixture)
    def lit(s):
        return str(s).replace('%', '%%')
    lines = [
        '@echo off', 'setlocal DisableDelayedExpansion', 'chcp 65001 >nul',
        'title GuardDesk LAB01 controlled archive - internal maintenance',
        f'set "GD_HOST={lit(cfg["host"])}"', f'set "GD_PROGRAM={lit(cfg["program"])}"',
        f'set "GD_DATA={lit(cfg["data"])}"', f'set "GD_ARCHIVE_PARENT={lit(cfg["archive"])}"',
        f'set "GD_TOOLS={lit(cfg["tools"])}"', f'set "GD_DID={DID}"',
        'set "GD_STOPPED=0"', 'set "GD_CODE=1"', 'set "GD_REASON=NOT_STARTED"',
        'set "GD_REPORT="', 'set "GD_HASHLOG="',
        'if /i not "%COMPUTERNAME%"=="%GD_HOST%" goto wrong_host',
        '"%GD_TOOLS%\\fltmc.exe" >nul 2>&1', 'if errorlevel 1 goto not_admin',
        'set "GD_TAG=%RANDOM%-%RANDOM%"',
        'set "GD_REPORT=%~dp0LAB01-Maintenance-%GD_TAG%.txt"',
        'set "GD_HASHLOG=%~dp0LAB01-Hash-%GD_TAG%.txt"',
        'set "GD_DIGESTLOG=%~dp0LAB01-Digest-%GD_TAG%.txt"',
        'if exist "%GD_REPORT%" goto output_error',
        'if exist "%GD_HASHLOG%" goto output_error',
        'if exist "%GD_DIGESTLOG%" goto output_error',
        '> "%GD_REPORT%" echo GuardDesk LAB01 fixed maintenance / internal trial / 20261029 / v2',
        'if errorlevel 1 goto output_error',
        '>> "%GD_REPORT%" echo DeviceID=%GD_DID%',
        'echo This tool is ONLY for LAB01, reviewed state 0.4.59 to 0.4.64.',
        'echo No deletion, JSON editing, re-enrollment, policy changes or forced process kill.',
        'echo [C] Check only  [A] Guided archive  [Q] Quit',
        '"%GD_TOOLS%\\choice.exe" /c CAQ /n /m "Choose C, A or Q: "',
        'if errorlevel 3 goto cancelled', 'if errorlevel 2 goto apply_mode',
        'if errorlevel 1 goto check_mode', 'goto cancelled',
        ':check_mode', 'set "GD_APPLY=0"', 'goto preflight',
        ':apply_mode', 'set "GD_APPLY=1"',
        ':preflight', 'set "GD_REASON=PREFLIGHT_FAILED"',
    ]
    # Check each existing ancestor from the drive down before invoking any
    # installed executable. This checks root reparse attributes, not subtree ACL.
    ancestors = set()
    for key in ('program', 'data', 'archive'):
        p = PureWindowsPath(cfg[key])
        ancestors.update(str(x) for x in p.parents)
        if key != 'archive':
            ancestors.add(str(p))
    for p in sorted(ancestors, key=lambda s: (len(s), s)):
        # Some archive ancestors are new; if present they must be plain dirs.
        lines += [f'set "GD_PATH={lit(p)}"', 'call :optional_plain',
                  'if errorlevel 1 goto failed']
    for p in ['%GD_PROGRAM%\\Updater', '%GD_PROGRAM%\\USBControl', '%GD_DATA%\\updates'] + [
        '%GD_PROGRAM%\\' + STAGE] + ['%GD_DATA%\\updates\\' + j for j in JOBS]:
        lines += [f'set "GD_PATH={p}"', 'call :plain', 'if errorlevel 1 goto failed']
    lines += [
        'call :state', 'if errorlevel 1 goto failed',
        'set "GD_REASON=PACKAGE_HASH_CHANGED_OR_UNREADABLE"',
        rf'set "GD_PATH=%GD_DATA%\updates\{JOBS[1]}\package.zip"',
        f'set "GD_EXPECT={cfg["zip_hash"]}"', 'call :hash', 'if errorlevel 1 goto failed',
        'set "GD_REASON=TASK_QUERY_FAILED"',
        'echo Expected updater task action:', 'echo "%GD_PROGRAM%\\Updater\\GuardDesk.exe"',
        'echo update-service --config "%GD_DATA%\\config.json"',
        'echo Expected principal SYSTEM, highest privileges, enabled and RUNNING.',
        '"%GD_TOOLS%\\schtasks.exe" /query /tn "GuardDesk-AgentUpdater-%GD_DID%" /xml >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        'set "GD_REASON=SOURCE_ACL_QUERY_FAILED"',
        '"%GD_TOOLS%\\icacls.exe" "%GD_PROGRAM%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        '"%GD_TOOLS%\\icacls.exe" "%GD_DATA%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        'echo.', 'echo Initial checks passed. Report:', 'echo "%GD_REPORT%"',
        'echo This does NOT verify live center status, process exit or all archive ACLs.',
        'if "%GD_APPLY%"=="0" goto checked',
        'echo.',
        'echo MANUAL GATE 1 - MIS must verify all of the following BEFORE answering Y:',
        'echo 1. All four listed old jobs ended in center; no new job/installer/repair is active.',
        'echo 2. Task Scheduler: EXACT action above, SYSTEM/highest, enabled and running.',
        'echo 3. Program/data/archive parents: trusted owner; only administrators/SYSTEM can write.',
        'echo 4. The five source trees have no reparse links and are no longer recovery inputs.',
        'echo Inspect existing RepairArchive parents too. If unsure, choose N and stop.',
        '"%GD_TOOLS%\\choice.exe" /c YN /n /m "All four verified by MIS? [Y/N]: "',
        'if not errorlevel 1 goto cancelled', 'if errorlevel 2 goto cancelled',
        '>> "%GD_REPORT%" echo ManualGate1=operator_attested_center_task_owner_ACL_reparse_references',
        'set "GD_REASON=INSTALLED_CHECK_FAILED"',
        '"%GD_PROGRAM%\\Updater\\GuardDesk.exe" updater-check --device-id "%GD_DID%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        'set "GD_REASON=STOP_TASK_FAILED"',
        'set "GD_STOPPED=1"',
        '"%GD_TOOLS%\\schtasks.exe" /end /tn "GuardDesk-AgentUpdater-%GD_DID%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        'echo MANUAL GATE 2 - Task Manager / Details / Image path name:',
        'echo Verify no process uses the exact Updater image above or the old stage:',
        f'echo "%GD_PROGRAM%\\{STAGE}"',
        'echo Also check no scheduled action or Native Host references that old stage.',
        'echo Do not kill by name/PID. Do not stop the USBControl protection task.',
        '"%GD_TOOLS%\\choice.exe" /c YN /n /m "Exact paths exited and stage unused? [Y/N]: "',
        'if not errorlevel 1 goto cancelled', 'if errorlevel 2 goto cancelled',
        '>> "%GD_REPORT%" echo ManualGate2=operator_attested_exact_images_exited_and_stage_unused',
        'call :state', 'if errorlevel 1 goto failed',
        'set "GD_REASON=ARCHIVE_CREATE_FAILED"',
    ]
    # Create/protect only new empty parents. Existing directories are never
    # given different permissions by this tool; their ACL is a manual gate.
    archive_parents = [str(PureWindowsPath(cfg['archive']).parent), str(cfg['archive'])]
    for p in archive_parents:
        lines += [f'set "GD_PATH={lit(p)}"', 'call :parent', 'if errorlevel 1 goto failed']
    lines += [
        'set "GD_ARCHIVE=%GD_ARCHIVE_PARENT%\\20261029-%GD_TAG%"',
        'if exist "%GD_ARCHIVE%" goto failed',
        'set "GD_PATH=%GD_ARCHIVE%"', 'call :new_protected', 'if errorlevel 1 goto failed',
        'md "%GD_ARCHIVE%\\Programs" "%GD_ARCHIVE%\\Packages" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        '>> "%GD_REPORT%" echo Archive="%GD_ARCHIVE%"',
        'echo Archive: "%GD_ARCHIVE%"',
    ]
    for i, (parent, leaf, dest) in enumerate(
        [('%GD_PROGRAM%', STAGE, 'Programs')] + [('%GD_DATA%\\updates', j, 'Packages') for j in JOBS], 1
    ):
        lines += [f'set "GD_FROM={parent}"', f'set "GD_LEAF={leaf}"',
                  f'set "GD_TO=%GD_ARCHIVE%\\{dest}"', f'set "GD_INDEX={i}"',
                  'call :move_one', 'if errorlevel 1 goto failed']
    lines += [
        'call :state', 'if errorlevel 1 goto failed',
        'set "GD_REASON=POST_ARCHIVE_MANUAL_REVIEW_REQUIRED"',
        'echo.', 'echo Only the five allowlisted folders were moved. Originals of all JSONs remain.',
        'echo Verify the report and original/archived folder owner and ACL.',
        'echo Run these READ-ONLY commands in administrator CMD and inspect ALL errors/totals:',
        'echo dir /s /a /-c "%GD_PROGRAM%"',
        'echo dir /a "%GD_DATA%\\updates"',
        'echo Required: program total at most 387973120 bytes / 370 MiB, at most 20000 files.',
        'echo updates: ONLY transaction-native.json and updater-refresh.json; no other files/dirs.',
        'echo Traversal access errors or missing totals mean NOT VERIFIED. Do not retry yet.',
        '"%GD_TOOLS%\\choice.exe" /c YN /n /m "Totals, inventory and archive owner/ACL all verified? [Y/N]: "',
        'if not errorlevel 1 goto failed', 'if errorlevel 2 goto failed',
        '>> "%GD_REPORT%" echo ManualGate3=operator_attested_capacity_inventory_and_archive_owner_ACL',
        '"%GD_PROGRAM%\\Updater\\GuardDesk.exe" updater-check --device-id "%GD_DID%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto failed',
        'set "GD_REASON=ARCHIVED_WAIT_FOR_FRESH_HEALTH"', 'set "GD_CODE=0"', 'goto finish',
        ':checked', 'set "GD_REASON=READ_ONLY_CHECK_COMPLETE_NO_ARCHIVE"', 'set "GD_CODE=0"', 'goto finish',
        ':cancelled', 'set "GD_REASON=CANCELLED"', 'set "GD_CODE=2"', 'goto finish',
        ':failed', 'set "GD_CODE=1"', 'goto finish',
        ':finish',
        'if not "%GD_STOPPED%"=="1" goto report_result',
        'echo Restoring ONLY the verified, originally-running updater task...',
        '"%GD_TOOLS%\\schtasks.exe" /run /tn "GuardDesk-AgentUpdater-%GD_DID%" >> "%GD_REPORT%" 2>&1',
        'if not errorlevel 1 goto restored',
        'set "GD_REASON=UPDATER_RESTART_FAILED_MANUAL_ACTION_REQUIRED"', 'set "GD_CODE=1"',
        'echo ERROR: restart failed. Use Task Scheduler to restore the EXACT updater task.',
        'goto report_result', ':restored',
        '>> "%GD_REPORT%" echo UpdaterTaskRunRequest=accepted_NOT_fresh_health_proof',
        ':report_result',
        'if not defined GD_REPORT goto console_result',
        '>> "%GD_REPORT%" echo Result=%GD_REASON%', '>> "%GD_REPORT%" echo ExitCode=%GD_CODE%',
        ':console_result', 'echo.', 'echo Result: %GD_REASON%', 'echo ExitCode: %GD_CODE%',
        'echo Report: "%GD_REPORT%"',
        'echo Do not delete an archive, edit JSON or repeat a partial run.',
        'echo After archive SUCCESS: verify FRESH 0.4.59 broker health, then ONE NEW',
        'echo LAB01-only 0.4.64 main+native job in center. Archive is NOT update success.',
        'echo On error/cancel: preserve report, archive and sources. Do not redeploy yet.',
        'echo If interrupted/closed after task END: manually restore that updater task.',
        'pause', 'exit /b %GD_CODE%',
        ':wrong_host', 'echo STOP: this BAT is restricted to LAB01. No check or change was made.',
        'pause', 'exit /b 1',
        ':not_admin', 'echo STOP: right-click this BAT and Run as administrator on LAB01.',
        'echo If company policy blocks execution, stop and contact MIS. Do not bypass policy.',
        'pause', 'exit /b 1',
        ':output_error', 'echo STOP: use a private MIS writable folder; output collision or write failure.',
        'pause', 'exit /b 1',
        ':optional_plain', 'if not exist "%GD_PATH%" exit /b 0',
        'call :plain', 'exit /b %ERRORLEVEL%',
        ':plain', 'set "GD_ATTR="',
        '>> "%GD_REPORT%" echo CheckingDirectory="%GD_PATH%"',
        'for %%G in ("%GD_PATH%") do set "GD_ATTR=%%~aG"',
        'if not exist "%GD_PATH%" goto path_not_visible',
        'if not defined GD_ATTR goto path_attributes_unavailable',
        'if not "%GD_ATTR:l=%"=="%GD_ATTR%" goto path_reparse',
        'if not "%GD_ATTR:L=%"=="%GD_ATTR%" goto path_reparse',
        'if /i not "%GD_ATTR:~0,1%"=="d" goto path_not_directory',
        'if not exist "%GD_PATH%\\" goto path_not_visible',
        'exit /b 0',
        ':path_not_visible', 'set "GD_REASON=PATH_NOT_VISIBLE"',
        'set "GD_DETAIL=Absent_or_not_accessible_not_distinguished_by_CMD"', 'goto path_failed',
        ':path_attributes_unavailable', 'set "GD_REASON=PATH_ATTRIBUTES_UNAVAILABLE"',
        'set "GD_DETAIL=Cannot_read_directory_attributes"', 'goto path_failed',
        ':path_reparse', 'set "GD_REASON=PATH_REPARSE_POINT_REFUSED"',
        'set "GD_DETAIL=Reparse_attribute_detected_no_target_traversal"', 'goto path_failed',
        ':path_not_directory', 'set "GD_REASON=PATH_NOT_DIRECTORY"',
        'set "GD_DETAIL=Expected_directory_but_other_attributes_observed"',
        ':path_failed',
        '>> "%GD_REPORT%" echo FailedPath="%GD_PATH%"',
        '>> "%GD_REPORT%" echo Attributes="%GD_ATTR%"',
        '>> "%GD_REPORT%" echo CheckDetail=%GD_DETAIL%',
        'echo STOP: %GD_REASON% at "%GD_PATH%"', 'exit /b 1',
        ':hash', 'set "GD_DETAIL=HASH_SOURCE_NOT_VISIBLE"',
        'set "GD_HASH_CODE=not_run"', 'if not exist "%GD_PATH%" goto hash_failed',
        'set "GD_ATTR="',
        'for %%G in ("%GD_PATH%") do set "GD_ATTR=%%~aG"',
        'set "GD_DETAIL=HASH_SOURCE_REPARSE_REFUSED"',
        'if not "%GD_ATTR:l=%"=="%GD_ATTR%" goto hash_failed',
        'if not "%GD_ATTR:L=%"=="%GD_ATTR%" goto hash_failed',
        '"%GD_TOOLS%\\certutil.exe" -hashfile "%GD_PATH%" SHA256 > "%GD_HASHLOG%" 2>&1',
        'set "GD_HASH_CODE=%ERRORLEVEL%"', 'set "GD_DETAIL=HASH_TOOL_FAILED"',
        'if not "%GD_HASH_CODE%"=="0" goto hash_failed',
        '"%GD_TOOLS%\\findstr.exe" /i /x /c:"%GD_EXPECT%" "%GD_HASHLOG%" >nul',
        'set "GD_HASH_CODE=%ERRORLEVEL%"', 'set "GD_DETAIL=HASH_COMPARISON_TOOL_FAILED"',
        'if %GD_HASH_CODE% GTR 1 goto hash_failed',
        'set "GD_DETAIL=HASH_MISMATCH"',
        'if not "%GD_HASH_CODE%"=="0" goto hash_failed', 'exit /b 0',
        ':hash_failed', '>> "%GD_REPORT%" echo FailedPath="%GD_PATH%"',
        '>> "%GD_REPORT%" echo CheckDetail=%GD_DETAIL%',
        '>> "%GD_REPORT%" echo HashToolExitCode=%GD_HASH_CODE%',
        'echo STOP: %GD_DETAIL% at "%GD_PATH%"', 'exit /b 1',
        ':state', 'set "GD_REASON=REVIEWED_JSON_STATE_CHANGED_OR_UNREADABLE"',
    ]
    for name, digest in cfg['pins'].items():
        lines += [f'set "GD_PATH=%GD_DATA%\\{name}"', f'set "GD_EXPECT={digest}"',
                  'call :hash', 'if errorlevel 1 exit /b 1']
    lines += [
        'exit /b 0',
        ':parent', 'if exist "%GD_PATH%" goto parent_exists',
        'call :new_protected', 'exit /b %ERRORLEVEL%',
        ':parent_exists', 'call :plain', 'exit /b %ERRORLEVEL%',
        ':new_protected', 'if exist "%GD_PATH%" exit /b 1',
        'md "%GD_PATH%" >> "%GD_REPORT%" 2>&1', 'if errorlevel 1 exit /b 1',
        '"%GD_TOOLS%\\icacls.exe" "%GD_PATH%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 exit /b 1',
        '"%GD_TOOLS%\\icacls.exe" "%GD_PATH%" /setowner "*S-1-5-32-544" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 exit /b 1', 'call :plain', 'exit /b %ERRORLEVEL%',
        ':move_one', 'call :state', 'if errorlevel 1 exit /b 1',
        'set "GD_REASON=ARCHIVE_MOVE_OR_DACL_CHECK_FAILED"',
        'set "GD_PATH=%GD_FROM%\\%GD_LEAF%"', 'call :plain', 'if errorlevel 1 exit /b 1',
        'set "GD_PATH=%GD_TO%"', 'call :plain', 'if errorlevel 1 exit /b 1',
        'if exist "%GD_TO%\\%GD_LEAF%" exit /b 1',
        'pushd "%GD_FROM%"', 'if errorlevel 1 exit /b 1',
        '"%GD_TOOLS%\\icacls.exe" "%GD_LEAF%" /save "%GD_ARCHIVE%\\DACL-%GD_INDEX%-before.txt" /t /q >> "%GD_REPORT%" 2>&1',
        'set "GD_SAVE_CODE=%ERRORLEVEL%"', 'popd',
        'if not "%GD_SAVE_CODE%"=="0" exit /b 1',
        'if not exist "%GD_ARCHIVE%\\DACL-%GD_INDEX%-before.txt" exit /b 1',
        'for %%G in ("%GD_ARCHIVE%\\DACL-%GD_INDEX%-before.txt") do if %%~zG LSS 2 exit /b 1',
        'call :state', 'if errorlevel 1 exit /b 1',
        'set "GD_REASON=ARCHIVE_MOVE_OR_DACL_CHECK_FAILED"',
        'if exist "%GD_TO%\\%GD_LEAF%" exit /b 1',
        '>> "%GD_REPORT%" echo Moving="%GD_FROM%\\%GD_LEAF%"',
        'move /-Y "%GD_FROM%\\%GD_LEAF%" "%GD_TO%\\%GD_LEAF%" <nul >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 exit /b 1',
        '>> "%GD_REPORT%" echo Moved="%GD_TO%\\%GD_LEAF%"',
        'if exist "%GD_FROM%\\%GD_LEAF%" exit /b 1',
        'set "GD_PATH=%GD_TO%\\%GD_LEAF%"', 'call :plain', 'if errorlevel 1 exit /b 1',
        'pushd "%GD_TO%"', 'if errorlevel 1 exit /b 1',
        '"%GD_TOOLS%\\icacls.exe" "%GD_LEAF%" /save "%GD_ARCHIVE%\\DACL-%GD_INDEX%-after.txt" /t /q >> "%GD_REPORT%" 2>&1',
        'set "GD_SAVE_CODE=%ERRORLEVEL%"', 'popd',
        'if not "%GD_SAVE_CODE%"=="0" exit /b 1',
        'if not exist "%GD_ARCHIVE%\\DACL-%GD_INDEX%-after.txt" exit /b 1',
        'for %%G in ("%GD_ARCHIVE%\\DACL-%GD_INDEX%-after.txt") do if %%~zG LSS 2 exit /b 1',
        '"%GD_TOOLS%\\certutil.exe" -hashfile "%GD_ARCHIVE%\\DACL-%GD_INDEX%-before.txt" SHA256 > "%GD_HASHLOG%" 2>&1',
        'if errorlevel 1 exit /b 1',
        '"%GD_TOOLS%\\findstr.exe" /i /r /x "[0-9a-f][0-9a-f]*" "%GD_HASHLOG%" > "%GD_DIGESTLOG%"',
        'if errorlevel 1 exit /b 1',
        'set "GD_EXPECT="',
        'for /f "usebackq delims=" %%H in ("%GD_DIGESTLOG%") do set "GD_EXPECT=%%H"',
        'if not defined GD_EXPECT exit /b 1',
        'if "%GD_EXPECT:~63,1%"=="" exit /b 1',
        'if not "%GD_EXPECT:~64,1%"=="" exit /b 1',
        'set "GD_PATH=%GD_ARCHIVE%\\DACL-%GD_INDEX%-after.txt"',
        'call :hash',
        'if errorlevel 1 exit /b 1',
        '>> "%GD_REPORT%" echo DACL-%GD_INDEX%=identical_owner_still_requires_MIS_review',
        'exit /b 0', '',
    ]
    return '\r\n'.join(lines).encode('utf-8')


README = '''LAB01 受控封存 BAT v2（未簽章內部維護工具，2026-10-29）

v1有一個job目錄ID轉錄成31碼；v2依原目錄畫面更正為32碼，新增建置檢查與失敗路徑。
現場四行PREFLIGHT_FAILED不足以確認實際停在哪一個路徑，請先選C並保留新報告。
這次先不要選A。若C有失敗，提供報告中的Result、FailedPath、Attributes、CheckDetail；
若C通過，提供通過結果，再核對是否進入A。不要在端點替資料夾改名以配合BAT。

只適用電腦 LAB01 / 端點ee1e1e17c6c8730a37603b1e，以及已提供的0.4.59狀態。
完整解壓到 MIS 私人可寫資料夾，右鍵 Archive-LAB01-v2.bat「以系統管理員身分執行」。
本次先選 C 唯讀檢查並回傳結果；Q 離開。以下A流程供確認現場後使用，不要直接選A。
畫面使用英文，避免端點中文字碼造成操作失敗。本說明對應三個人工核對關卡：

關卡1：中心四個舊job已結束且沒有新工作／安裝／修復；工作排程器固定updater的動作、
SYSTEM／最高權限、已啟用且正在執行均正確。所有來源、封存父目錄owner可信，
僅管理員／SYSTEM可寫；來源樹無junction／符號連結，舊stage無其他交易回復引用。
如果 RepairArchive 或其端點子目錄已存在也要核對；無法確認請選N。
這些檢查不是BAT自動驗證，報告明記operator_attested。

BAT才會結束固定的AgentUpdater排程，不碰USBControl保護排程。
關卡2：在工作管理員詳細資料加入「映像路徑名稱」，確認固定Updater映像及舊stage
都沒有程序使用；確認沒有排程或Native Host引用舊stage。看不到／仍在使用就選N。
排程停止不等於程序退出；不強制殺程序、不使用之前提供過的PID。

接著僅同C磁碟搬移一個舊stage與四個快取資料夾（完整清單見runbook）。
目的位於C:\\ProgramData\\GuardDeskPilot\\RepairArchive\\ee1e1e17c6c8730a37603b1e\\20261029-隨機碼，
不在原本容量掃描範圍；新空資料夾設定管理員／SYSTEM ACL及管理員owner。
既有目錄權限不改。搬前／搬後保存並以SHA256核對DACL檔案完整性；owner另由MIS核對。
同NTFS磁碟目錄move保留安全描述元，不允許跨磁碟、合併、覆蓋或刪除。
封存仍占硬碟，不是釋放磁碟空間；原JSON、公鑰、設定、身分、佇列、兩組rollback／
install-failed及現用程式全部保留。只核對狀態檔hash，不輸出JSON內容或config。

關卡3：依畫面兩個dir命令，另開管理員CMD確認完整程式總量<=387973120 bytes（370MiB）、
<=20000檔，沒有存取錯誤；updates只剩transaction-native.json與updater-refresh.json。
核對封存owner／ACL與清單後才選Y。BAT不把人工總量確認冒稱自動完整盤點。

結果ARCHIVED_WAIT_FOR_FRESH_HEALTH：BAT只已提出恢復更新器排程的要求。
再確認新鮮0.4.59健康回報，才從中心新建一筆「只對LAB01」的0.4.64一般+原生工作。
封存完成不是更新完成；實際三元件版本、端點ID與佇列仍須驗收。

錯誤／取消會嘗試恢復本來正在執行的固定更新器；重新啟動失敗會明記。
部分搬移不自動回搬、不刪目錄；保留報告與封存，不直接再跑A或重派。
Ctrl+C、關閉視窗、斷電無法保證收尾，請MIS手動確認固定updater排程已恢復。
回復必須先停固定更新器並確認程序退出／沒有新工作及原位置無同名新檔，再照
報告將各資料夾原路搬回；不得覆蓋。參閱runbook.txt。

腳本固定電腦／身分／C磁碟與清單，無任意路徑參數；狀態JSON或既有ZIP的hash不同
便停止，不能改BAT內的hash勉強執行。這是一次性現場方案，不是通用自動清理器。
正常C模式不停止工作或建立封存；只核對雜湊、路徑與固定工作XML／根目錄ACL並寫報告。
A模式關卡1核對既有程式目錄可信後才呼叫已安裝的updater-check，避免以管理員執行
尚未核對信任的程式。此CLI不是本包提供的替代程式。
原有updater-check仍需管理員且可能受公司App Control限制。
只使用CMD內建命令、Windows工具及已安裝CLI，不呼叫PowerShell／JS／VBS或替代EXE。
若BAT或既有EXE也被政策阻擋，停止交MIS核准，不解除政策或改名繞過。
本工具尚未在LAB01執行／驗收，不影響封存0.4.64產品包，不含永久容量治理修正。
報告及DACL檔含內部路徑／SID，限MIS保留，勿公開上傳。不要提供config或完整JSON。
'''


def main():
    folder = ROOT / f'dist/lab01-controlled-archive-20261029-{REVISION}'
    folder.mkdir(exist_ok=True)
    members = {
        f'Archive-LAB01-{REVISION}.bat': render(),
        'README.txt': README.encode('utf-8-sig'),
        'runbook.txt': (ROOT / 'doc/88-lab01-controlled-archive-and-retry.md').read_bytes(),
    }
    for name, body in members.items():
        (folder / name).write_bytes(body)
    manifest = {n: hashlib.sha256(b).hexdigest() for n, b in members.items()}
    (folder / 'MANIFEST-SHA256.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='ascii')
    archive = ROOT / f'dist/GuardDesk-LAB01-Controlled-Archive-20261029-{REVISION}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in [*members, 'MANIFEST-SHA256.json']:
            z.write(folder / name, name)
    print(json.dumps({'archive': str(archive), 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
