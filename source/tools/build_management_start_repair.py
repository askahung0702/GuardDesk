"""Build a small existing-config launcher; does not run the company Server."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def launcher(candidates=None):
    candidates=candidates or [r'C:\GuardDesk\GuardDesk\GuardDesk.exe',r'C:\GuardDesk\GuardDesk.exe']
    def literal(path):return str(path).replace('%','%%')
    select=[f'set "GUARDDESK_EXE={literal(candidates[0])}"']
    select += [f'if not exist "%GUARDDESK_EXE%" set "GUARDDESK_EXE={literal(p)}"' for p in candidates[1:]]
    lines=['@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
        'set "GUARDDESK_CONFIG=%~dp0server.json"',
        'set "GUARDDESK_LOG=%~dp0Management-Startup.txt"',
        *select,
        'if exist "%GUARDDESK_LOG%\\" goto log_error',
        'copy /y NUL "%GUARDDESK_LOG%" >nul 2>&1',
        'if errorlevel 1 goto log_error',
        '> "%GUARDDESK_LOG%" echo GuardDesk existing-config startup diagnostic v2',
        '>> "%GUARDDESK_LOG%" echo Config="%GUARDDESK_CONFIG%"',
        '>> "%GUARDDESK_LOG%" echo Executable="%GUARDDESK_EXE%"',
        'if not exist "%GUARDDESK_CONFIG%" goto missing_config',
        'if not exist "%GUARDDESK_EXE%" goto missing_exe',
        '>> "%GUARDDESK_LOG%" echo Runtime version check:',
        '"%GUARDDESK_EXE%" component-info >> "%GUARDDESK_LOG%" 2>&1',
        'set "GUARDDESK_RESULT=%ERRORLEVEL%"',
        '>> "%GUARDDESK_LOG%" echo RuntimeCheckExitCode=%GUARDDESK_RESULT%',
        'if not "%GUARDDESK_RESULT%"=="0" goto runtime_error',
        'type "%GUARDDESK_LOG%"',
        'echo.',
        'echo Starting the existing management center. No setup wizard is used.',
        'echo If startup fails, the error remains in this command window.',
        'echo Keep this window open while the Server is running.',
        'echo Type EXIT only after the Server has stopped.',
        'echo.',
        r'"%SystemRoot%\System32\cmd.exe" /d /v:off /k call "%GUARDDESK_EXE%" serve --config "%GUARDDESK_CONFIG%" --open-console',
        'set "GUARDDESK_RESULT=%ERRORLEVEL%"',
        '>> "%GUARDDESK_LOG%" echo ConsoleExitCode=%GUARDDESK_RESULT%',
        'exit /b %GUARDDESK_RESULT%',
        ':missing_config',
        '>> "%GUARDDESK_LOG%" echo ERROR: server.json is missing. Put this CMD in the original DATA folder.',
        'goto show_error',
        ':missing_exe',
        r'>> "%GUARDDESK_LOG%" echo ERROR: GuardDesk.exe was not found in the known C:\GuardDesk layouts.',
        'goto show_error',
        ':runtime_error',
        '>> "%GUARDDESK_LOG%" echo ERROR: GuardDesk.exe could not complete its runtime version check.',
        'goto show_error',
        ':log_error',
        'echo ERROR: Cannot write Management-Startup.txt in this folder.',
        'echo Check the DATA folder location and write permissions. No Server was launched.',
        'goto keep_error_console',
        ':show_error',
        'type "%GUARDDESK_LOG%"',
        ':keep_error_console',
        'echo.',
        'echo Startup stopped. Keep the message above and report the error.',
        'echo No setup wizard was invoked. Type EXIT to close this window.',
        r'"%SystemRoot%\System32\cmd.exe" /d /v:off /k',
        'exit /b 1','']
    # Actual payload is deliberately ASCII for older cmd.exe/code-page behavior.
    return '\r\n'.join(lines).encode('ascii')


def main():
    folder=ROOT/'dist/management-start-repair-v2';folder.mkdir(exist_ok=True)
    (folder/'Start-Management.cmd').write_bytes(launcher())
    text=('GuardDesk 啟動修正 v2（內部試用；不是新的 Server/Agent 版本）\r\n'
          '將 Start-Management.cmd 放在原資料目錄，例如 C:\\GuardDeskData，與原 server.json 同層。\r\n'
          '保留原檔備份後再替換；不要重跑 Setup-Management.cmd。\r\n'
          '支援 C:\\GuardDesk\\GuardDesk\\GuardDesk.exe 或 C:\\GuardDesk\\GuardDesk.exe。\r\n'
          '啟動失敗時命令視窗會保留；請提供最後幾行錯誤。\r\n'
          '同目錄 Management-Startup.txt 每次覆寫，僅記錄路徑、版本檢查及退出碼。\r\n'
          'Server 執行期間的錯誤顯示在視窗，不會無上限寫入此檔。\r\n'
          '正常運行時保留視窗；停止 Server 後輸入 EXIT 才關閉診斷命令視窗。\r\n'
          '此檔不呼叫初始化，不改設定、防火牆、Defender 或啟動工作。\r\n')
    (folder/'README.txt').write_bytes(text.encode('utf-8-sig'))
    manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir() if p.is_file() and p.name!='MANIFEST-SHA256.json'}
    (folder/'MANIFEST-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    archive=ROOT/'dist/GuardDesk-Management-Start-Repair-v2.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.iterdir()):
            if p.is_file():z.write(p,p.name)
    print(json.dumps({'path':str(archive.relative_to(ROOT)),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size}))


if __name__=='__main__':main()
