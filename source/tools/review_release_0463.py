"""MIS single EXE internal-release byte/proof review, never rollout approval."""
import hashlib,json,marshal,re,zipfile
from importlib.metadata import version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from run_mis_regression_0463 import snapshot
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.63'
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def passing(pattern):
    paths=[p for p in (ROOT/'evidence').glob(pattern) if read(p).get('passed') and read(p).get('version')==VERSION]
    assert paths,pattern
    p=max(paths,key=lambda p:p.stat().st_mtime_ns);return p,read(p)
def main():
    regression_path,regression=passing('mis-regression-*.json');assert regression['tests']==142 and not regression['skipped']
    assert regression['source_unchanged_during_run'] and regression['source_sha256']==snapshot()
    frozen_path,frozen=passing('mis-onefile-frozen-*.json');assert frozen['actual_onefile_lifecycle']['hide_restore_cycles']==3
    app=ROOT/'dist/GuardDesk';files={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke-0.4.63.json');assert smoke['passed'] and smoke['application_files']==files
    assert frozen['exe_sha256']==files['GuardDesk.exe']
    meta=read(app/'_internal/agent-release.json');assert meta['version']==VERSION and meta['files']=={k:v for k,v in files.items() if k!='_internal/agent-release.json'}
    template=app/'_internal/GuardDeskMIS.exe';generic=read(ROOT/'evidence/mis-executable-0.4.63.json')
    assert files['_internal/GuardDeskMIS.exe']==generic['sha256']==sha(ROOT/'dist'/generic['artifact'])
    compiled={}
    for label,exe in (('server',app/'GuardDesk.exe'),('onefile',template)):
        reader=CArchiveReader(str(exe));pyz=reader.open_embedded_archive('PYZ.pyz');compiled[label]=[]
        for p in (ROOT/'guarddesk').glob('*.py'):
            name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
            if name in pyz.toc:assert pyz.extract(name)==compile(p.read_bytes(),str(p),'exec'),(label,name);compiled[label].append(name)
        assert {'guarddesk.remote_viewer','guarddesk.mis_onefile','guarddesk.remote_tray','guarddesk.remote_client'}<=set(compiled[label])
        if label=='onefile':assert marshal.loads(reader.extract('mis_remote_app'))==compile((ROOT/'mis_remote_app.py').read_bytes(),str(ROOT/'mis_remote_app.py'),'exec')
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for p in area.rglob('*'):
            if p.is_file():assert files[target+'/'+p.relative_to(area).as_posix()]==sha(p)
    previous=read(ROOT/'evidence/release-0.4.62-final.json');old={a['name']:a['sha256'] for a in previous['artifacts']}
    assert all(sha(ROOT/'dist'/n)==h for n,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.62-source.zip') as z:manifest=json.loads(z.read('MANIFEST-SHA256.json'))
    unchanged=['guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/server_config.py','guarddesk/server_setup.py','guarddesk/endpoint_package.py','guarddesk/source_permissions.py','guarddesk/native_handoff_runtime.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
    assert all(sha(ROOT/n)==manifest[n] for n in unchanged)
    signatures=read(ROOT/'evidence/authenticode-0.4.63.json');assert all(r['Status']=='NotSigned' for r in signatures)
    docs=['README.md','AGENTS.md','doc/README.md','doc/85-mis-single-exe-and-tray-0.4.63.md','doc/60-engineering-lessons-and-regression-rules.md'];links=0
    for rel in docs:
        p=ROOT/rel
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (p.parent/target.split('#',1)[0]).exists(),(rel,target);links+=1
    pem=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{100,}')
    field=re.compile(rb'"(?:password|client_secret|access_token|refresh_token)"\s*:\s*"[^"\r\n]+"');scanned=0
    for area in ('doc','evidence','browser-extension'):
        for p in (ROOT/area).rglob('*'):
            if p.is_file() and p.suffix in ('.json','.txt','.md','.js','.html','.csv','.pem','.key'):
                blob=p.read_bytes();scanned+=1;assert not pem.search(blob) and not (p.suffix=='.json' and field.search(blob)),str(p)
    source={p.relative_to(ROOT).as_posix():sha(p) for area in ('guarddesk','native','browser-extension','tests','tools') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.cpp','.h','.json','.dll','.spec') and '__pycache__' not in p.parts}
    for name in ('app.py','mis_remote_app.py','Start-MIS-Remote.cmd'):source[name]=sha(ROOT/name)
    proofs={'regression':{'path':str(regression_path.relative_to(ROOT)),'sha256':sha(regression_path)},'frozen_onefile':{'path':str(frozen_path.relative_to(ROOT)),'sha256':sha(frozen_path)}}
    review={'version':VERSION,'status':'unsigned_internal_trial','internal_checks_passed':True,'formal_release_ready':False,'self_review_only':True,'company_changed':False,
      'proofs':proofs,'application_files':files,'final_source_sha256':source,'compiled_modules_verified':compiled,'generic_executable':generic,'source_tests':142,
      'separate_executable_api_test':{'command':'python -m unittest test_mis_executable_api','tests':1,'observed_exit_code':0,'log':'runtime/mis-executable-api-0463-final.txt','source_sha256':sha(ROOT/'tests/test_mis_executable_api.py')},
      'sealed_0462_verified':old,'unchanged_boundaries':unchanged,'documentation_links_checked':links,'limited_literal_secret_scan_files':scanned,
      'limited_scan_scope':'literal private PEM payloads and selected nonempty JSON credential fields, not comprehensive',
      'dependencies':{n:version(n) for n in ('cryptography','cffi','Pillow','pyinstaller','pyreadline3')},'signatures':'evidence/authenticode-0.4.63.json',
      'requirements':['MIS-REMOTE-02','MIS-REMOTE-03','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
      'gd':['GD-001','GD-002','GD-003','GD-004','GD-005','GD-006','GD-007','GD-008','GD-019','GD-020','GD-021','GD-022','GD-023','GD-024'],
      'remaining':['Company Server/Agent unchanged; actual MIS-to-employee two-PC and real protected SYSTEM/update/ACL lifecycle pending',
       'Unsigned trial; adding public EXE configuration changes its hash; future signing must occur after configuration',
       'Win10/11 company Defender/EDR, independent review, full SBOM/vulnerability/secret scan, formal approval and 8/24h whole-endpoint performance pending',
       'Preexisting Pillow declaration 13.0.0 versus actual build 11.3.0 remains unresolved',
       'Arbitrary host-glob native blocking and Edge production native drop remain incomplete']}
    folder=ROOT/'evidence/security/0.4.63';folder.mkdir(parents=True,exist_ok=True);p=folder/'requirements-review.json';assert not p.exists();p.write_text(json.dumps(review,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'internal_checks_passed':True,'version':VERSION,'files':len(files),'compiled':{k:len(v) for k,v in compiled.items()},'formal_release_ready':False},ensure_ascii=False))
if __name__=='__main__':main()
