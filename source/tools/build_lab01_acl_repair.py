"""Fixed, operator-assisted root DACL repair for the reported LAB01 grant.

Not part of the Agent or updater. No SYSTEM task runs this file, no PowerShell,
no blanket tree reset, no content/owner edits. Inheritance propagation is an
explicit part of the operator preview and the owned Windows acceptance test.
"""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DID = 'ee1e1e17c6c8730a37603b1e'


def render(fixture=None):
    cfg = dict(host='LAB01', parent=r'C:\ProgramData\GuardDeskPilot\USBControl',
               exe=r'C:\Program Files\GuardDeskPilot\Updater\GuardDesk.exe',
               tools=r'C:\Windows\System32', trustee=r'EXAMPLE\user1')
    if fixture: cfg.update(fixture)
    def lit(s): return str(s).replace('%', '%%')
    lines = [
        '@echo off', 'setlocal DisableDelayedExpansion', 'chcp 65001 >nul',
        'title GuardDesk LAB01 scoped data ACL repair - internal maintenance',
        f'set "GD_HOST={lit(cfg["host"])}"', f'set "GD_PARENT={lit(cfg["parent"])}"',
        f'set "GD_EXE={lit(cfg["exe"])}"', f'set "GD_TOOLS={lit(cfg["tools"])}"',
        f'set "GD_TRUSTEE={lit(cfg["trustee"])}"', f'set "GD_DID={DID}"',
        'set "GD_ROOT=%GD_PARENT%\\%GD_DID%"',
        'set "GD_REPORT="', 'set "GD_CODE=1"', 'set "GD_REASON=NOT_STARTED"',
        'if /i not "%COMPUTERNAME%"=="%GD_HOST%" goto wrong_host',
        '"%GD_TOOLS%\\fltmc.exe" >nul 2>&1', 'if errorlevel 1 goto not_admin',
        'set "GD_TAG=%RANDOM%-%RANDOM%"',
        'set "GD_REPORT=%~dp0LAB01-ACL-Repair-%GD_TAG%.txt"',
        'set "GD_BACKUP=%~dp0LAB01-ACL-Before-%GD_TAG%.txt"',
        'set "GD_AFTER=%~dp0LAB01-ACL-After-%GD_TAG%.txt"',
        'set "GD_BACKUP_HASH=%~dp0LAB01-ACL-Backup-Hash-%GD_TAG%.txt"',
        'set "GD_PRIVS=%~dp0LAB01-ACL-Privilege-Check-%GD_TAG%.txt"',
        'if exist "%GD_REPORT%" goto output_error',
        'if exist "%GD_BACKUP%" goto output_error',
        'if exist "%GD_AFTER%" goto output_error',
        'if exist "%GD_BACKUP_HASH%" goto output_error',
        'if exist "%GD_PRIVS%" goto output_error',
        '> "%GD_REPORT%" echo GuardDesk LAB01 scoped root DACL repair / internal trial / 20261029',
        'if errorlevel 1 goto output_error',
        '>> "%GD_REPORT%" echo DeviceID=%GD_DID%',
        'set "GD_REASON=PATH_PREFLIGHT_FAILED"',
    ]
    # All ancestors must be plain directories before touching the named object.
    from pathlib import PureWindowsPath
    paths = list(reversed(list(PureWindowsPath(cfg['parent']).parents))) + [PureWindowsPath(cfg['parent'])]
    for p in paths:
        lines += [f'set "GD_PATH={lit(p)}"', 'call :plain', 'if errorlevel 1 goto finish']
    lines += [
        'set "GD_PATH=%GD_ROOT%"', 'call :plain', 'if errorlevel 1 goto finish',
        'echo Target directory: "%GD_ROOT%"', 'echo Named grant to remove: "%GD_TRUSTEE%"',
        'echo [C] Read-only ACL report  [R] Backup and remove this root grant  [Q] Quit',
        '"%GD_TOOLS%\\choice.exe" /c CRQ /n /m "Choose C, R or Q: "',
        'if errorlevel 3 goto cancelled', 'if errorlevel 2 goto repair_preview',
        'if errorlevel 1 goto check_only', 'goto cancelled',
        ':check_only', 'set "GD_REASON=ACL_QUERY_FAILED"',
        '"%GD_TOOLS%\\icacls.exe" "%GD_ROOT%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto finish',
        'set "GD_REASON=READ_ONLY_ACL_REPORT_COMPLETE_NOT_A_TRUST_VALIDATION"',
        'set "GD_CODE=0"', 'goto finish',
        ':repair_preview',
        'echo This changes ONLY the named allow grant on the root directory above.',
        'echo Windows can propagate removal to children that inherit this grant.',
        'echo No /T, /reset, /setowner, new grant, task stop/start, archive or file content edit.',
        'echo MIS MUST VERIFY before answering Y:',
        'echo 1. This is LAB01; no new install/update/repair is active.',
        'echo 2. Directory owner is SYSTEM or Administrators; their full-control grants remain.',
        r'echo 3. EXAMPLE\user1 is the extra explicit root allow grant reported; no child reparse links.',
        'echo 4. This BAT and its output folder are private trusted MIS files, not a shared writable folder.',
        'echo 5. The fixed installed Updater executable tree is trusted before its read-only check.',
        'echo Owner, other ACEs, inheritance settings, config, identity and queues will be preserved.',
        'set "GD_REASON=ACL_QUERY_FAILED_NO_REMOVE_ATTEMPT"',
        '"%GD_TOOLS%\\icacls.exe" "%GD_ROOT%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto finish',
        '"%GD_TOOLS%\\choice.exe" /c YN /n /m "All five verified; backup then remove ONLY this root grant? [Y/N]: "',
        'if not errorlevel 1 goto cancelled', 'if errorlevel 2 goto cancelled',
        '>> "%GD_REPORT%" echo ManualGate=operator_attested_exact_scope_owner_ACE_quiescence_reparse_and_trusted_paths',
        'set "GD_REASON=RESTORE_PRIVILEGE_UNAVAILABLE_NO_REMOVE_ATTEMPT"',
        '"%GD_TOOLS%\\whoami.exe" /priv > "%GD_PRIVS%" 2>&1',
        'if errorlevel 1 goto finish',
        '"%GD_TOOLS%\\findstr.exe" /l /c:"SeRestorePrivilege" "%GD_PRIVS%" >nul',
        'if errorlevel 1 goto finish',
        '>> "%GD_REPORT%" echo RestorePrivilege=present_NOT_proof_of_successful_restore',
        'set "GD_REASON=BACKUP_FAILED_NO_REMOVE_ATTEMPT"',
        'pushd "%GD_PARENT%"', 'if errorlevel 1 goto finish',
        '"%GD_TOOLS%\\icacls.exe" "%GD_DID%" /save "%GD_BACKUP%" /l /q >> "%GD_REPORT%" 2>&1',
        'set "GD_TOOL_CODE=%ERRORLEVEL%"', 'popd',
        'if not "%GD_TOOL_CODE%"=="0" goto finish',
        'if not exist "%GD_BACKUP%" goto finish',
        'for %%G in ("%GD_BACKUP%") do if %%~zG LSS 2 goto finish',
        '"%GD_TOOLS%\\certutil.exe" -hashfile "%GD_BACKUP%" SHA256 > "%GD_BACKUP_HASH%" 2>&1',
        'if errorlevel 1 goto finish',
        '>> "%GD_REPORT%" echo RootDACLBackup="%GD_BACKUP%"',
        '>> "%GD_REPORT%" echo RootDACLBackupSHA256File="%GD_BACKUP_HASH%"',
        'set "GD_PATH=%GD_ROOT%"', 'call :plain', 'if errorlevel 1 goto finish',
        'set "GD_REASON=GRANT_REMOVE_FAILED_OR_PARTIAL_INSPECT_BEFORE_RETRY"',
        '>> "%GD_REPORT%" echo AttemptingRootGrantRemoval="%GD_TRUSTEE%"',
        '"%GD_TOOLS%\\icacls.exe" "%GD_ROOT%" /remove:g "%GD_TRUSTEE%" /l >> "%GD_REPORT%" 2>&1',
        'set "GD_TOOL_CODE=%ERRORLEVEL%"',
        '>> "%GD_REPORT%" echo GrantRemoveExitCode=%GD_TOOL_CODE%',
        'if not "%GD_TOOL_CODE%"=="0" goto finish',
        'set "GD_REASON=POST_REPAIR_DACL_CAPTURE_FAILED"',
        'pushd "%GD_PARENT%"', 'if errorlevel 1 goto finish',
        '"%GD_TOOLS%\\icacls.exe" "%GD_DID%" /save "%GD_AFTER%" /l /q >> "%GD_REPORT%" 2>&1',
        'set "GD_TOOL_CODE=%ERRORLEVEL%"', 'popd',
        'if not "%GD_TOOL_CODE%"=="0" goto finish',
        'if not exist "%GD_AFTER%" goto finish',
        'for %%G in ("%GD_AFTER%") do if %%~zG LSS 2 goto finish',
        '"%GD_TOOLS%\\icacls.exe" "%GD_ROOT%" >> "%GD_REPORT%" 2>&1',
        'if errorlevel 1 goto finish',
        'set "GD_REASON=ACL_COMMAND_COMPLETED_INSTALLED_CHECK_FAILED_KEEP_BACKUP"',
        'if not exist "%GD_EXE%" goto finish',
        '"%GD_EXE%" updater-check --device-id "%GD_DID%" >> "%GD_REPORT%" 2>&1',
        'set "GD_TOOL_CODE=%ERRORLEVEL%"',
        '>> "%GD_REPORT%" echo InstalledCheckExitCode=%GD_TOOL_CODE%',
        'if not "%GD_TOOL_CODE%"=="0" goto finish',
        'set "GD_REASON=INSTALLED_CHECK_PASSED_CAPACITY_ARCHIVE_STILL_PENDING"',
        'set "GD_CODE=0"', 'goto finish',
        ':cancelled', 'set "GD_REASON=CANCELLED_NO_REMOVE_ATTEMPT"', 'set "GD_CODE=2"',
        ':finish', 'if not defined GD_REPORT goto console_result',
        '>> "%GD_REPORT%" echo Result=%GD_REASON%', '>> "%GD_REPORT%" echo ExitCode=%GD_CODE%',
        ':console_result', 'echo.', 'echo Result: %GD_REASON%', 'echo ExitCode: %GD_CODE%',
        'echo Report: "%GD_REPORT%"',
        'echo Preserve the report and ACL backup/hash. Do not edit original JSON or rename directories.',
        'echo If installed check fails, STOP. Do not remove more grants or use a recursive reset.',
        'echo If installed check passes, capacity is NOT fixed: resume the reviewed v2 archive workflow.',
        'echo Manual DACL rollback, ONLY after verifying private backup and no concurrent work:',
        'echo "%GD_TOOLS%\\icacls.exe" "%GD_PARENT%" /restore "%GD_BACKUP%" /l',
        'echo Rollback restores the insecure grant too; MIS must evaluate before applying. No automatic rollback.',
        'pause', 'exit /b %GD_CODE%',
        ':wrong_host', 'echo STOP: this BAT is restricted to LAB01. No tool/check/change was run.',
        'pause', 'exit /b 1',
        ':not_admin', 'echo STOP: right-click Run as administrator on LAB01. Do not bypass company policy.',
        'pause', 'exit /b 1',
        ':output_error', 'echo STOP: output collision/write failure. Use a private MIS writable folder.',
        'pause', 'exit /b 1',
        ':plain', 'set "GD_ATTR="',
        'for %%G in ("%GD_PATH%") do set "GD_ATTR=%%~aG"',
        'if not exist "%GD_PATH%\\" goto path_failed',
        'if not defined GD_ATTR goto path_failed',
        'if not "%GD_ATTR:l=%"=="%GD_ATTR%" goto path_failed',
        'if not "%GD_ATTR:L=%"=="%GD_ATTR%" goto path_failed', 'exit /b 0',
        ':path_failed', 'set "GD_REASON=PATH_UNAVAILABLE_OR_REPARSE_REFUSED"',
        '>> "%GD_REPORT%" echo FailedPath="%GD_PATH%"',
        '>> "%GD_REPORT%" echo Attributes="%GD_ATTR%"', 'exit /b 1', '',
    ]
    # These are CMD literal lines, not interpreted Python escapes.
    return '\r\n'.join(lines).encode('utf-8')


README = '''LAB01 指定資料目錄額外授權修復（未簽章內部維護工具）

用途：依使用者最新報告，固定端點資料根目錄含 EXAMPLE\\user1:(OI)(CI)(F)，
已安裝updater-check回「更新目錄可由非信任帳戶改寫」。不是放寬更新器檢查。
固定根目錄：C:\\ProgramData\\GuardDeskPilot\\USBControl\\ee1e1e17c6c8730a37603b1e
固定移除對象：EXAMPLE\\user1 的allow授權。沒有任意路徑／帳戶參數。

1. 在LAB01完整解壓到MIS私人可寫資料夾，右鍵Repair-LAB01-Data-ACL.bat以系統管理員執行。
2. C只列根目錄ACL，不驗證整棵樹。R會顯示具體修改內容，需完成畫面五項人工核對。
   核對root owner為SYSTEM/Administrators，這兩者完整控制仍在；user1是額外明確allow項，
   子樹沒有reparse／junction、沒有新更新安裝，安裝的Updater程式樹與本工具／備份位置可信。
   無法核對選N；不要以「user1也是管理員」視為符合SYSTEM受保護路徑的直接SID規則。
3. R先用icacls保存根DACL與SHA256，再對固定根執行 /remove:g EXAMPLE\\user1 /l。
   修改前另查目前token有SeRestorePrivilege；缺少或讀取失敗即停止，不新增／啟用系統權利。
   權利存在只是前置條件，不代表公司環境實際還原已驗收。
   沒有/T，不對每一子項強制移除／重設；Windows可能把父授權移除傳播至繼承它的子項。
   不改owner、其他ACE、繼承設定、SYSTEM/Administrators權限、檔案內容／名稱、端點身分與佇列。
   備份是「根DACL」，不含owner／SACL，也不是整樹完整安全描述元備份；由父繼承的變更
   可由還原根DACL再次傳播。子項自己的明確user1授權／不受信任owner不會由此工具全面修復。
4. 保存修後根DACL，再執行原已安裝Updater的updater-check --device-id固定ID。
   成功：INSTALLED_CHECK_PASSED_CAPACITY_ARCHIVE_STILL_PENDING。
   失敗：ACL_COMMAND_COMPLETED_INSTALLED_CHECK_FAILED_KEEP_BACKUP 或其他明確結果，停止並貼回
   原CLI錯誤與Result；不繼續/T、/reset、setowner，不自動還原不安全授權或另找帳戶硬移除。
5. 檢查成功才回原Archive-LAB01-v2.bat走A封存流程；其人工中心／排程／程序退出等關卡仍要核對。
   本工具沒有封存或更新；容量問題及真正0.4.64更新成功另行驗收，不直接重派。

本工具不停止／啟動工作、不讀config內容、不啟動更新、不用PowerShell、不改Defender或公司政策。
若公司政策擋住BAT或既有EXE，停止交MIS正式處理，不能繞過。未在LAB01執行修復或驗收。
修改前後報告與ACL檔只含內部路徑／SID，限MIS保留。不要將備份放共享可寫位置。
手動回復命令顯示於畫面：icacls 固定父目錄 /restore 這次根DACL備份 /l；須先核對備份
SHA256、目標、原物件及沒有新工作，回復也會恢復不安全的user1授權，只有MIS判斷需要時執行。
目前非管理員自建測試對icacls /restore回1300；其管理員／公司權利驗收尚未完成。
備份內容另外透過自建目錄的Win32 WRITE_DAC還原驗證，但不冒稱正式還原命令已通過。
若現場回復也遇到1300／存取拒絕，保留備份交MIS處理，不增加系統權利、不重設整樹。
保存／回復DACL及remove:g語意參照Microsoft：
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls

此前唯讀check曾passed，最新ACL如何加入仍未知；不把此次ACL阻擋倒推為原歷史失敗唯一根因。
原v1/v2維護包與0.4.64產品包不變。實際owner／SYSTEM／公司Defender與完整更新仍待現場驗收。
'''


def main():
    folder=ROOT/'dist/lab01-data-acl-repair-20261029'; folder.mkdir(exist_ok=True)
    members={'Repair-LAB01-Data-ACL.bat':render(), 'README.txt':README.encode('utf-8-sig')}
    for n,b in members.items(): (folder/n).write_bytes(b)
    hashes={n:hashlib.sha256(b).hexdigest() for n,b in members.items()}
    (folder/'MANIFEST-SHA256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='ascii')
    archive=ROOT/'dist/GuardDesk-LAB01-Data-ACL-Repair-20261029.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for n in [*members,'MANIFEST-SHA256.json']: z.write(folder/n,n)
    print(json.dumps({'artifact':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}))


if __name__=='__main__': main()
