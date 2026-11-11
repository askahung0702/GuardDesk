"""Package an exact passing build; no installation, network or baseline promotion."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,shutil,subprocess,zipfile
from worktree import digest,contained

def write(path,body):
    with Path(path).open('x',encoding='utf-8') as stream:json.dump(body,stream,ensure_ascii=False,indent=2);stream.write('\n')

def verify_zip(path,expected):
    with zipfile.ZipFile(path) as archive:
        names=archive.namelist()
        if len(names)!=len(set(n.casefold() for n in names)):raise ValueError('Duplicate ZIP entry')
        for name in names:
            p=PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:raise ValueError('Unsafe ZIP entry')
        if set(names)!=set(expected)|{'SHA256SUMS.txt'}:raise ValueError('ZIP inventory differs')
        for name,wanted in expected.items():
            with archive.open(name) as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
            if actual!=wanted:raise ValueError('ZIP content changed: '+name)
        wanted=''.join(h+'  '+n+'\n' for n,h in sorted(expected.items())).encode('utf-8')
        if archive.read('SHA256SUMS.txt')!=wanted or archive.testzip():raise ValueError('ZIP checksum list or CRC differs')

def package(root,stage,run,receipt,version,revision,env):
    root=Path(root).resolve();run=contained(root,run);receipt=contained(root,receipt)
    build=json.loads(receipt.read_text(encoding='utf-8'));product=receipt.parent/'product/GuardDesk'
    if not build.get('passed') or not build.get('source_stable') or build.get('version')!=version:
        raise ValueError('Exact stable passing build required')
    if not build.get('files'):raise ValueError('Empty build inventory')
    for name,row in build['files'].items():
        path=contained(product,product/name)
        if digest(path)!=row['sha256']:raise ValueError('Product hash changed: '+name)
    manifest=run/'center-files.txt'
    manifest.write_text(''.join(row['sha256']+' '+name+'\n' for name,row in sorted(build['files'].items())),encoding='utf-8')
    lock=json.loads((root/'dependencies/management-package.lock.json').read_text())
    compiler=Path(lock['compiler']);helper=run/'GuardDeskCenterPrepare.exe';source=stage/'tools/center_source_prepare.cs'
    if digest(compiler)!=lock['compiler_sha256']:raise ValueError('Reviewed compiler hash differs')
    with (run/'helper-build.log').open('x',encoding='utf-8') as log:
        subprocess.run([str(compiler),'/nologo','/target:exe','/platform:x64','/optimize+',
            '/out:'+str(helper),'/resource:'+str(manifest)+',center-files',str(source)],
            stdout=log,stderr=subprocess.STDOUT,check=True,timeout=90,env=env)
    # Import only the reviewed version-independent launcher, never a historical main.
    import importlib.util
    spec=importlib.util.spec_from_file_location('management_cmd_template',stage/'tools/package_management_094_002.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    info={'format':1,'version':version,'packaging_revision':revision,'cohort':build['cohort'],
        'internal_trial':True,'signed':False,'deployable':False,'accepted_baseline':'0.4.105/001',
        'paired_Agent_and_MIS_required':True,'automatic_installation_performed':False,
        'local_center_started':False,'source_build_receipt_sha256':digest(receipt),
        'preparation_source_sha256':digest(source),'preparation_helper_sha256':digest(helper)}
    readme=f'''GuardDesk {version} / {revision} 完整管理中心內部試用包

包含中心、標準全機Agent產包內容、MIS及匹配原生元件，不需拼湊修復包。
完整解壓至專用程式資料夾後，執行 Setup-Management.cmd。
全新Server依中文精靈設定資料目錄、Server位址及管理帳號；不帶真實憑證或帳密。
既有中心升級須停止原中心、依維護流程保留資料及設定，完整更新程式目錄，
沿用原資料目錄的 Start-Management.cmd。不要重新初始化資料或端點身分。
Server更新後，從該中心下載配套Agent及MIS；Server本身不會更新已安裝的端點。
原生遠端、服務、授權與cohort必須整套匹配，不能單換DLL。

沿用0.4.105/001內部功能基準；本次建置驗證詳見開發收據。
本候選包尚未經使用者現場驗收，也不會自動取代目前訂版。
未簽章，只供內部試用。離線測試及正常Defender掃描不代表公司端點永不告警。
公司防護阻擋時停止擴大部署、保留證據，不還原隔離或新增排除。
不改Defender、EDR、UAC、App Control、PowerShell政策或防火牆。
正式發布仍需簽章、公司防護與Windows10/11安裝、更新、移除、UAC和效能驗收。
本建置流程未啟動中心、未安裝Agent、未進行跨機遠端或現場資料變更。
'''
    extra={'Setup-Management.cmd':module.launcher(),'GuardDeskCenterPrepare.exe':helper.read_bytes(),
        'BUILD-INFO.json':json.dumps(info,ensure_ascii=False,indent=2).encode('utf-8'),
        'README-Management.txt':readme.replace('\n','\r\n').encode('utf-8-sig')}
    hashes={'GuardDesk/'+n:row['sha256'] for n,row in build['files'].items()}
    hashes.update({n:hashlib.sha256(raw).hexdigest() for n,raw in extra.items()})
    candidate=run/f'GuardDesk-Management-{version}-internal-{revision}.zip'
    with zipfile.ZipFile(candidate,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for name in sorted(build['files']):archive.write(product/name,'GuardDesk/'+name)
        for name,raw in extra.items():archive.writestr(name,raw)
        archive.writestr('SHA256SUMS.txt',''.join(h+'  '+n+'\n' for n,h in sorted(hashes.items())).encode('utf-8'))
    verify_zip(candidate,hashes)
    proof={'passed':True,'candidate':str(candidate),'sha256':digest(candidate),'file_hashes':hashes,
        'build_receipt_sha256':digest(receipt),'helper_source_sha256':digest(source),
        'compiler_sha256':digest(compiler),'signed':False,'deployable':False}
    write(run/'package.json',proof)
    return candidate,proof

def clean_scan(code,raw):
    # Exit 0 can also mean a detection was remediated. Require explicit clean output.
    # Unknown/localized output fails for review, never silently becomes a clean scan.
    return code==0 and b'found no threats.' in raw.lower()

def scan(run,targets,env):
    defender=Path(os.environ.get('ProgramData','C:/ProgramData'))/'Microsoft/Windows Defender/Platform/CurrentVersion/MpCmdRun.exe'
    if not defender.is_file():raise ValueError('Normal Defender scanner unavailable; no final package')
    rows=[]
    for number,target in enumerate(targets,1):
        log=run/f'defender-{number}.log';print(f'Defender scan {number}/{len(targets)}: {target.name}',flush=True)
        with log.open('xb') as stream:
            result=subprocess.run([str(defender),'-Scan','-ScanType','3','-File',str(target)],
                stdout=stream,stderr=subprocess.STDOUT,env=env,timeout=900)
        raw=log.read_bytes()
        rows.append({'target':str(target),'exit_code':result.returncode,'log':log.name,'log_sha256':digest(log)})
        if not clean_scan(result.returncode,raw):raise ValueError('Defender clean verdict unconfirmed; preserve isolation and logs')
    body={'passed':True,'scans':rows,'exclusion_scope_verified':False,'company_EDR_acceptance':False,
        'settings_changed':False,'manual_submission':False,'deployable':False}
    write(run/'defender.json',body);return body

def publish(candidate,dest,expected_hash):
    dest=Path(dest);dest.parent.mkdir(exist_ok=True)
    if dest.exists() or dest.with_suffix('.zip.sha256').exists():raise ValueError('Output exists; never overwrite')
    if digest(candidate)!=expected_hash:raise ValueError('Candidate changed before publication')
    # Exclusive create reserves the exact destination; failures remove only our partial copy.
    created=False
    try:
        with dest.open('xb') as out:
            created=True
            with candidate.open('rb') as stream:shutil.copyfileobj(stream,out,1024*1024)
        if digest(dest)!=expected_hash:raise ValueError('Published copy differs')
    except Exception:
        if created and dest.exists():dest.unlink()
        raise
    with dest.with_suffix('.zip.sha256').open('x',encoding='ascii') as stream:stream.write(expected_hash+'  '+dest.name+'\n')
