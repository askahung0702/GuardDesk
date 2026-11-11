"""Complete revised setup, with byte-identical 094 Agent/MIS/core runtime."""
from pathlib import Path
import argparse,hashlib,json,zipfile
S=Path(__file__).resolve().parents[1];R=S.parents[1];E=R/'runtime/center-source-permissions-094-001'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def body_sha(raw):return hashlib.sha256(raw).hexdigest()
def launcher():
    lines=['@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
        'title GuardDesk management center setup - internal trial',
        'if not "%~1"=="" if /i not "%~1"=="--check-program-only" exit /b 2',
        'if not exist "%~dp0GuardDesk\\GuardDesk.exe" goto missing',
        'if not exist "%~dp0GuardDeskCenterPrepare.exe" goto missing',
        'echo Verifying the complete package and preparing its program folder. Please wait.',
        '"%~dp0GuardDeskCenterPrepare.exe" --prepare "%~dp0."',
        'set "GD_RESULT=%ERRORLEVEL%"','if not "%GD_RESULT%"=="0" goto stopped',
        'if /i "%~1"=="--check-program-only" goto checked',
        '"%~dp0GuardDesk\\GuardDesk.exe" server-setup',
        'set "GD_RESULT=%ERRORLEVEL%"','echo ExitCode=%GD_RESULT%','pause','exit /b %GD_RESULT%',
        ':checked','"%~dp0GuardDesk\\GuardDesk.exe" component-info','exit /b %ERRORLEVEL%',
        ':missing','echo Required files are missing. Extract the complete management ZIP first.','set "GD_RESULT=2"',
        ':stopped','echo Setup did not start. No center data was created or removed.',
        'echo Keep the error and report shown above. For access denied, run this entry as administrator.',
        'echo Keep Defender and company security policies enabled.','if /i "%~1"=="--check-program-only" exit /b %GD_RESULT%',
        'pause','exit /b %GD_RESULT%','']
    # CMD command text must remain ASCII regardless of the original console CP.
    # The actual setup wizard remains localized inside the frozen application.
    return '\r\n'.join(lines).encode('ascii')
def main():
    global E
    parser=argparse.ArgumentParser();parser.add_argument('--helper-root',type=Path,required=True);parser.add_argument('--revision',choices=['002','003','004','005'],required=True);args=parser.parse_args()
    E=args.helper_root.resolve(strict=True)
    if not E.is_relative_to(R/'runtime') or not E.name.startswith('center-source-permissions-094-'):raise ValueError('Owned helper build required')
    revision=args.revision
    old=R/'dist/GuardDesk-Management-0.4.94-internal.zip'
    assert sha(old)=='61371e4ebb04d472eb106f4dea868a4fae33a84276ec3c65bec102c525da1f70'
    receipt=json.loads((E/'build-receipt.json').read_text());tests=json.loads((E/'owned-tests.json').read_text())
    assert receipt['passed'] and tests['passed'] and tests['original_payload_bytes_unchanged']
    if revision in ('003','004'):assert json.loads((E/'replacement-rights-negative.json').read_text())['passed']
    if revision=='004':assert json.loads((E/'large-file-negative.json').read_text())['passed']
    if revision=='005':
        assert tests['inherited_CI_WD_AD_reproduced_on_delivered_004']
        assert tests['inherited_CI_WD_AD_fixed_on_real_NTFS']
        assert tests['no_center_started']
    helper=E/'GuardDeskCenterPrepare.exe';assert sha(helper)==receipt['helper_sha256']
    assert sha(S/'tools/center_source_prepare.cs')==receipt['source_sha256']
    target=R/('dist/GuardDesk-Management-0.4.94-internal-'+revision+'.zip');assert not target.exists()
    with zipfile.ZipFile(old) as original:
        info=json.loads(original.read('BUILD-INFO.json'));info.update(packaging_revision=revision,
            preparation_helper_sha256=sha(helper),original_094_zip_sha256=sha(old),
            program_payload_unchanged=True,setup_prepares_private_program_source=True)
        readme=original.read('README-Management.txt').decode('utf-8')
        readme=readme.replace('新管理中心完整安裝包（未簽章內部試用）','新管理中心完整安裝包・安裝流程修訂'+revision+'（未簽章內部試用）',1)
        readme=readme.replace('1. 雙擊 Setup-Management.cmd。','1. 雙擊 Setup-Management.cmd。入口會先核對完整程式，並收緊此專用程式目錄中\n   一般 Users 的寫入權限；保留原擁有者與原 Server 帳號權限。不需另套修復包。\n   若有額外檔案、內容不符、junction 或其他帳戶寫入權限，會在設定前停止。\n   檢查完成後，',1)
        readme+='\n本修訂僅整合新機解壓目錄中 Users 建立檔案／資料夾權限的準備；Agent、MIS、\n服務與原生元件位元組和原0.4.94完全一致，沒有新增端點功能或變更公司防護。\n僅對已核對的完整管理中心目錄生效，不操作資料目錄／資料庫／憑證，也不改\n磁碟根目錄。其他可替換檔案／修改權限的授權不會擅自移除，會先停止並報告。\n報告位置會顯示在視窗；存取被拒時，由同一 Server 帳號以管理員執行入口。\n若資料目錄尚未建立，可依精靈設定；若已建立中心，保留原資料與帳號，\n使用原資料目錄，程式不會重新初始化已完成的中心。\n'
        if revision=='005':
            readme+='\n修訂005：修正繼承型 Users CI WD/AD 的讀回失敗。先持久化繼承保護再讀回\n明確ACE，僅收緊原先允許處理的Users建立權；原owner及其他授權保留。\n外層CMD改為純ASCII，避免不同主控台碼頁把提示當指令；中心精靈維持中文。\n這是全新Server用的完整包，無須安裝舊中心或先套任何修復包。\n請完整解壓到新的專用程式資料夾，資料另放D:\\GuardDeskData等專用資料夾。\n開發機僅檢查實包、NTFS權限與入口；未啟動本機中心，實際Server啟動／\n登入／下載Agent與MIS仍須在新Server驗收。未簽章，僅限內部試用。\n'
        overrides={'Setup-Management.cmd':launcher(),'GuardDeskCenterPrepare.exe':helper.read_bytes(),
            'BUILD-INFO.json':json.dumps(info,ensure_ascii=False,indent=2).encode('utf-8'),
            'README-Management.txt':readme.encode('utf-8')}
        hashes={}
        with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as output:
            for name in original.namelist():
                if name=='SHA256SUMS.txt':continue
                raw=overrides.pop(name,None)
                if raw is None:raw=original.read(name)
                hashes[name]=body_sha(raw);output.writestr(name,raw)
            for name,raw in overrides.items():hashes[name]=body_sha(raw);output.writestr(name,raw)
            raw=''.join(h+'  '+n+'\n' for n,h in sorted(hashes.items())).encode('utf-8')
            output.writestr('SHA256SUMS.txt',raw);hashes['SHA256SUMS.txt']=body_sha(raw)
        with zipfile.ZipFile(target) as z:
            assert z.testzip() is None and set(z.namelist())==set(hashes)
            for name,h in hashes.items():assert body_sha(z.read(name))==h
            for name in original.namelist():
                if name.startswith('GuardDesk/'):assert body_sha(z.read(name))==body_sha(original.read(name))
    record={'passed':True,'version':'0.4.94','packaging_revision':revision,'archive':str(target),'sha256':sha(target),
        'bytes':target.stat().st_size,'file_hashes':hashes,'helper_sha256':sha(helper),
        'original_zip_unchanged':sha(old),'all_Agent_MIS_and_service_payload_unchanged':True,
        'installed_center_or_endpoint_changed':False,'signed':False,'deployable':False}
    (E/'complete-package.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    target.with_suffix('.zip.sha256').write_text(record['sha256']+'  '+target.name+'\n',encoding='ascii')
    print(json.dumps({k:v for k,v in record.items() if k!='file_hashes'}))
if __name__=='__main__':main()
