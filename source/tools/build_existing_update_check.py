"""Use only the installed GuardDesk read-only CLI; no PowerShell invocation."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def collector(program=None,data=None):
    # Optional paths are for owned fixture tests only; the shipped CMD uses the
    # existing Windows ProgramFiles/ProgramData locations, never bundled code.
    exe=str(program).replace('%','%%') if program else r'%ProgramFiles%\GuardDeskPilot\Updater\GuardDesk.exe'
    data_path=str(data).replace('%','%%') if data else r'%ProgramData%\GuardDeskPilot\USBControl'
    pattern='[0-9a-f]*'
    return '\r\n'.join([
        '@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
        f'set "GUARDDESK_CHECK_EXE={exe}"',f'set "GUARDDESK_CHECK_DATA={data_path}"',
        'set "GUARDDESK_CHECK_OUT=%~dp0GuardDesk-Installed-Update-Check.txt"',
        'set "GUARDDESK_CHECK_IDS=%~dp0GuardDesk-Update-IDs.txt"',
        'if exist "%GUARDDESK_CHECK_OUT%\\" goto output_error',
        'if exist "%GUARDDESK_CHECK_IDS%\\" goto output_error',
        'copy /y NUL "%GUARDDESK_CHECK_OUT%" >nul 2>&1','if errorlevel 1 goto output_error',
        '> "%GUARDDESK_CHECK_OUT%" echo GuardDesk installed updater read-only check',
        'if not exist "%GUARDDESK_CHECK_EXE%" goto exe_missing',
        'if not exist "%GUARDDESK_CHECK_DATA%\\" goto data_missing',
        'copy /y NUL "%GUARDDESK_CHECK_IDS%" >nul 2>&1','if errorlevel 1 goto output_error',
        rf'dir /b /ad "%GUARDDESK_CHECK_DATA%" 2>nul | "%SystemRoot%\System32\findstr.exe" /r /x "{pattern}" > "%GUARDDESK_CHECK_IDS%"',
        'set "GUARDDESK_CHECK_COUNT=0"',
        'for /f "usebackq delims=" %%D in ("%GUARDDESK_CHECK_IDS%") do call :check_one "%%D"',
        'if "%GUARDDESK_CHECK_COUNT%"=="0" goto no_id',
        'goto show_result',
        ':check_one','set "GUARDDESK_CHECK_ID=%~1"',
        'if "%GUARDDESK_CHECK_ID:~23,1%"=="" exit /b 0',
        'if not "%GUARDDESK_CHECK_ID:~24,1%"=="" exit /b 0',
        'if %GUARDDESK_CHECK_COUNT% GEQ 8 exit /b 0',
        'set /a GUARDDESK_CHECK_COUNT+=1 >nul',
        'echo Checking existing endpoint %~1 ...',
        '>> "%GUARDDESK_CHECK_OUT%" echo DeviceID=%~1',
        '"%GUARDDESK_CHECK_EXE%" updater-check --device-id "%~1" >> "%GUARDDESK_CHECK_OUT%" 2>&1',
        'set "GUARDDESK_CHECK_RESULT=%ERRORLEVEL%"',
        '>> "%GUARDDESK_CHECK_OUT%" echo CheckExitCode=%GUARDDESK_CHECK_RESULT%',
        'exit /b 0',
        ':exe_missing','>> "%GUARDDESK_CHECK_OUT%" echo ERROR: Installed Updater GuardDesk.exe was not found. No alternate program was run.','goto show_result',
        ':data_missing','>> "%GUARDDESK_CHECK_OUT%" echo ERROR: Existing protected native-data folder was not found.','goto show_result',
        ':no_id','>> "%GUARDDESK_CHECK_OUT%" echo ERROR: No readable 24-hex endpoint folder. MIS administrator read access may be required.','goto show_result',
        ':show_result','type "%GUARDDESK_CHECK_OUT%"','echo.',
        'echo Report: "%GUARDDESK_CHECK_OUT%"',
        'echo A running task or a passed check does not prove a later update succeeded.',
        'exit /b 0',
        ':output_error','echo ERROR: Cannot write diagnostic output in this folder. Use a private writable MIS folder.','exit /b 1',''
    ]).encode('utf-8')


def main():
    folder=ROOT/'dist/installed-update-check';folder.mkdir(exist_ok=True)
    (folder/'Collect-Installed-Update-Check.cmd').write_bytes(collector())
    entry='\r\n'.join(['@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
        'echo Existing GuardDesk read-only check. No PowerShell script or update will run.',
        r'"%SystemRoot%\System32\cmd.exe" /d /v:off /k call "%~dp0Collect-Installed-Update-Check.cmd"','exit /b',''])
    (folder/'Diagnose-Installed-Updater.cmd').write_bytes(entry.encode('ascii'))
    text=('GuardDesk 已安裝更新器唯讀檢查（內部試用）\n'
          '由 MIS 在 user1 登入自己的管理帳戶，將 ZIP 解壓到 MIS 的私人資料夾，執行 Diagnose-Installed-Updater.cmd。\n'
          '會呼叫已安裝於 Program Files\\GuardDeskPilot\\Updater 的 GuardDesk.exe updater-check --device-id。\n'
          '該命令需要管理員權限以讀取受保護設定；沒有安裝、更新、重新註冊或啟動／停止工作的動作。\n'
          '不呼叫 PowerShell、不讀取原本被阻擋的 .ps1，也不變更公司執行／簽章政策。\n'
          '若此 CMD 或原有 EXE 也遭公司政策阻擋，保留訊息交由 MIS，不更換格式或解除政策。\n'
          '提供 GuardDesk-Installed-Update-Check.txt 即可，不提供 config.json、金鑰或完整交易紀錄。\n'
          '另有 GuardDesk-Update-IDs.txt 僅含篩選後端點ID；最多呼叫8個ID。文字檔每次覆寫。\n'
          '此檢查只驗證既有目錄、信任公鑰格式、固定工作身分及目前原生程式版本，未必能識別先前更新健康失敗。\n'
          '若沒有原有 Updater EXE，此工具停止，不會執行 ZIP 內替代 EXE或腳本。\n'
          '完成後輸入 EXIT 關閉視窗。\n')
    (folder/'README.txt').write_text(text,encoding='utf-8-sig')
    manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir() if p.is_file() and p.name!='MANIFEST-SHA256.json'}
    (folder/'MANIFEST-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    archive=ROOT/'dist/GuardDesk-Installed-Updater-Check.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.iterdir()):
            if p.is_file():z.write(p,p.name)
    print(json.dumps({'file':str(archive.relative_to(ROOT)),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size}))


if __name__=='__main__':main()
