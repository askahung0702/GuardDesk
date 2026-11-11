"""Exact internal MIS release self-review; never company rollout approval."""
import hashlib,json,re,shutil,zipfile
from pathlib import Path
from importlib.metadata import version
from PyInstaller.archive.readers import CArchiveReader
from run_mis_regression import snapshot
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.61'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def passing(pattern):
    paths=[p for p in (ROOT/'evidence').glob(pattern) if read(p).get('passed')]
    assert paths,pattern
    p=max(paths,key=lambda x:x.stat().st_mtime_ns);return p,read(p)
def main():
    regression_path,regression=passing('mis-regression-*.json');assert regression['tests']==132 and not regression['skipped']
    assert regression['source_unchanged_during_run'] and regression['source_sha256']==snapshot()
    frozen_path,frozen=passing('mis-frozen-*.json');assert frozen['version']==VERSION
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke-0.4.61.json');assert smoke['passed'] and smoke['application_files']==actual
    assert frozen['exe_sha256']==actual['GuardDesk.exe'] and frozen['viewer_sha256']==actual['_internal/GuardDeskRemote.exe']
    meta=read(app/'_internal/agent-release.json');assert meta['version']==VERSION and meta['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    compiled=[];pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name;compiled.append(name)
    assert {'guarddesk.mis_support','guarddesk.remote_client','guarddesk.remote_viewer','guarddesk.server','guarddesk.desktop_agent'}<=set(compiled)
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path)
    generic=read(ROOT/'evidence/mis-package-0.4.61.json');generic_path=ROOT/'dist'/generic['artifact'];assert sha(generic_path)==generic['sha256'] and generic['viewer_sha256']==frozen['viewer_sha256']
    with zipfile.ZipFile(generic_path) as z:
        manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert set(z.namelist())==set(manifest)|{'MANIFEST-SHA256.json'}
        for name,value in manifest.items():
            assert hashlib.sha256(z.read(name)).hexdigest()==value
            if name.startswith('Runtime/'):assert actual['_internal/'+name.removeprefix('Runtime/')]==value
        assert 'mis-connection.json' not in manifest and not any(n.endswith(('.key','.sqlite3')) for n in manifest)
    signature=read(ROOT/'evidence/authenticode-0.4.61.json');assert all(x['Status']=='NotSigned' for x in signature)
    old=read(ROOT/'evidence/release-0.4.60-final.json')['artifacts'];oldhashes={a['name']:a['sha256'] for a in old}
    assert all(sha(ROOT/'dist'/name)==value for name,value in oldhashes.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.60-source.zip') as z:previous=json.loads(z.read('MANIFEST-SHA256.json'))
    unchanged=['guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/server_config.py','guarddesk/server_setup.py','guarddesk/endpoint_package.py','guarddesk/source_permissions.py','guarddesk/native_handoff_runtime.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
    assert all(sha(ROOT/name)==previous[name] for name in unchanged)
    for p in (ROOT/'browser-extension').rglob('*'):
        if p.is_file():assert sha(p)==previous[p.relative_to(ROOT).as_posix()]
    docs=['README.md','AGENTS.md','doc/README.md','doc/82-mis-workstation-remote-0.4.61.md','doc/60-engineering-lessons-and-regression-rules.md'];links=0
    for name in docs:
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (p.parent/target.split('#',1)[0]).exists(),(name,target);links+=1
    pem=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{100,}')
    field=re.compile(rb'"(?:password|client_secret|access_token|refresh_token)"\s*:\s*"[^"\r\n]+"');scanned=0
    for area in ('doc','evidence','browser-extension'):
        for p in (ROOT/area).rglob('*'):
            if not p.is_file() or p.suffix not in ('.json','.txt','.md','.js','.html','.csv','.pem','.key'):continue
            blob=p.read_bytes();scanned+=1;assert not pem.search(blob) and not (p.suffix=='.json' and field.search(blob)),str(p)
    folder=ROOT/'evidence/security/0.4.61';folder.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/regression['log'],folder/'mis-regression.log')
    source={str(p.relative_to(ROOT)):sha(p) for area in ('guarddesk','native','browser-extension','tests') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.cpp','.h','.json','.dll') and '__pycache__' not in p.parts}
    source['app.py']=sha(ROOT/'app.py');source['Start-MIS-Remote.cmd']=sha(ROOT/'Start-MIS-Remote.cmd')
    proofs={'regression':{'path':str(regression_path.relative_to(ROOT)),'sha256':sha(regression_path)},'frozen_mis':{'path':str(frozen_path.relative_to(ROOT)),'sha256':sha(frozen_path)}}
    review={'version':VERSION,'status':'unsigned_internal_trial','internal_checks_passed':True,'formal_release_ready':False,'self_review_only':True,
      'company_changed':False,'candidate_deployed_to_office':False,'application_files':actual,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],'viewer_sha256':actual['_internal/GuardDeskRemote.exe'],
      'proofs':proofs,'compiled_modules_verified':compiled,'final_source_sha256':source,'sealed_0460_verified':oldhashes,'unchanged_boundaries_verified':unchanged,
      'generic_mis':generic,'packaged_smoke':'evidence/packaged-smoke-0.4.61.json','signatures':'evidence/authenticode-0.4.61.json','documentation_links_checked':links,
      'limited_literal_secret_scan_files':scanned,'limited_secret_scan_scope':'literal private PEM payloads and selected nonempty JSON credential fields, not comprehensive',
      'dependencies':{n:version(n) for n in ('cryptography','cffi','Pillow','pyinstaller','pyreadline3')},
      'validation_scope':'132 MIS and adjacent tests with zero skips; separate one-test own installed launcher check; frozen smoke; actual frozen admin UI download and portable viewer startup; exact compiled GUI with synthetic consent/frame/revocation over TLS. No actual employee capture/input.',
      'standalone_launcher_test':{'command':'python -m unittest discover -s tests -p test_mis_agent_launcher.py -v','tests':1,'observed_exit_code':0,'recording':'tool-run observed result, separate from 132-test runner','source_sha256':sha(ROOT/'tests/test_mis_agent_launcher.py')},
      'requirements':['MIS-REMOTE-01','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
      'gd':['GD-005','GD-007','GD-008','GD-019','GD-020','GD-021','GD-022','GD-024'],
      'remaining':['Actual company Server upgrade, authorized MIS-to-user two-PC lifecycle and network/TLS acceptance pending',
        'No actual installed old SYSTEM updater or protected native deployment test in this feature; source updater unchanged and new user-Agent entry repair tested with owned marker fixture',
        'Win10/Win11 company Defender/EDR, signing, independent review, full SBOM/vulnerability/secret scan, formal approval and 8/24h whole-endpoint/browser/helper performance pending',
        'Preexisting requirements Pillow 13.0.0 versus actual 11.3.0 remains disclosed; dependency reconciliation not completed',
        'Edge extensionless native drop and production source still incomplete; native runtime default None unchanged']}
    (folder/'requirements-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'internal_checks_passed':True,'version':VERSION,'proofs':proofs,'files':len(actual),'compiled_modules':len(compiled),'formal_release_ready':False}))
if __name__=='__main__':main()
