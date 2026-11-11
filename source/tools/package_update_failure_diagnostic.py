"""Separate maintenance package; never rewrites a sealed product release."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    script=(ROOT/'tools/collect_update_failure.ps1').read_bytes()
    proof=json.loads((ROOT/'evidence/maintenance/update-failure-metadata-smoke-20261029.json').read_text(encoding='utf-8'))
    assert proof['passed'] and proof['script_sha256']==hashlib.sha256(script).hexdigest()
    wrapper='\r\n'.join([
        '@echo off','setlocal DisableDelayedExpansion',
        'echo LAB01 GuardDesk update metadata - read only. Run as MIS administrator.',
        r'"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -File "%~dp0collect_update_failure.ps1" -DeviceId ee1e1e17c6c8730a37603b1e -OutputPath "%~dp0GuardDesk-Update-Failure.json"',
        'set "GUARDDESK_DIAG_EXIT=%ERRORLEVEL%"',
        'echo ExitCode=%GUARDDESK_DIAG_EXIT%',
        'echo If blocked by policy, keep the error for MIS. Do not bypass policy.',
        'echo Successful output: "%~dp0GuardDesk-Update-Failure.json"',
        'pause','exit /b %GUARDDESK_DIAG_EXIT%','']).encode('ascii')
    readme=('LAB01 更新失敗唯讀診斷（未簽章內部維護工具）\r\n'
        '僅供 LAB01（ee1e1e17c6c8730a37603b1e）。請完整解壓至 MIS 私人可寫資料夾，\r\n'
        '右鍵 Diagnose-LAB01-Update.cmd，以系統管理員身分執行。\r\n'
        '只讀固定 GuardDesk 原生交易、健康／錯誤狀態、版本 metadata 與至多64筆快取目錄／package檔長。\r\n'
        '不執行 GuardDesk、不讀 config.json、不讀文件內容、不列程序命令列、不連網。\r\n'
        '不停止／啟動排程、不安裝／更新／刪除交易或備份、不修改 Defender／腳本原則。\r\n'
        '成功只需提供 GuardDesk-Update-Failure.json。不要提供 config.json 或完整原始交易。\r\n'
        '輸出只含格式驗證後欄位；現場讀取不足會記錄 read_error，不自動提權。\r\n'
        '報告已存在時停止，保留前次報告後再由MIS重新選擇資料夾執行。\r\n'
        '腳本沒有 Authenticode 簽章，仍受公司執行原則／App Control 限制；\r\n'
        '若被阻擋，保留錯誤交 MIS 正式核准／簽章，不使用 Bypass 或更換格式規避。\r\n'
        '這是一次 metadata 快照，不證明占用程序、完整快取用量、下載完整性或升級成功。\r\n'
        '自有合成 metadata／真 PowerShell 測試通過，LAB01 尚未驗收。\r\n').encode('utf-8-sig')
    files={'collect_update_failure.ps1':script,'Diagnose-LAB01-Update.cmd':wrapper,'README.txt':readme}
    manifest={n:hashlib.sha256(b).hexdigest() for n,b in files.items()}
    files['MANIFEST-SHA256.json']=(json.dumps(manifest,indent=2)+'\n').encode('ascii')
    assert b'\\WindowsPowerShell\\v1.0\\powershell.exe' in wrapper
    assert all(c >= 32 or c in (10,13) for c in wrapper)
    archive=ROOT/'dist/GuardDesk-LAB01-Update-Diagnosis-20261029-v2.zip'
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for n,b in files.items():z.writestr(n,b)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in manifest.items())
    evidence={'artifact':str(archive.relative_to(ROOT)).replace('\\','/'),
        'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'files':manifest,
        'read_only':True,'unsigned':True,'product_release_changed':False,'lab01_inspected':False,
        'test':'evidence/maintenance/update-failure-metadata-smoke-20261029.json',
        'requirements':['GD-008','GD-009','GD-020','GD-021','GD-022','SEC-03','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04']}
    (ROOT/'evidence/maintenance/lab01-diagnostic-package-20261029-v2.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(evidence))


if __name__=='__main__':main()
