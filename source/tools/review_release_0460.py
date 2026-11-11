"""Exact internal candidate review. Not independent audit or rollout approval."""
import hashlib,json,re,shutil,zipfile
from importlib.metadata import version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.60'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def latest_passed(pattern):
    matches=[p for p in (ROOT/'evidence').glob(pattern) if read(p).get('passed')]
    assert matches,'No passing evidence: '+pattern
    path=max(matches,key=lambda p:p.stat().st_mtime_ns);return path,read(path)

def main():
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke-0.4.60.json');assert smoke['passed'] and smoke['application_files']==actual
    proofs={}
    for key,pattern in [('category','category-regression-*.json'),('deployment','deployment-regression-0460-*.json'),('frozen_ui','category-frozen-0460-*.json'),('upgrade','server-upgrade-0460-*.json')]:
        path,proof=latest_passed(pattern);proofs[key]={'path':str(path.relative_to(ROOT)),'sha256':sha(path)}
        if 'source_sha256' in proof:assert all((ROOT/name).is_file() and sha(ROOT/name)==value for name,value in proof['source_sha256'].items()),key+' source changed'
        if 'exe_sha256' in proof:assert proof['exe_sha256']==actual['GuardDesk.exe'],key
    assert read(ROOT/proofs['category']['path'])['tests']==204
    assert read(ROOT/proofs['deployment']['path'])['tests']==76
    assert not read(ROOT/proofs['category']['path'])['skipped'] and not read(ROOT/proofs['deployment']['path'])['skipped']
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name;compiled.append(name)
    assert {'guarddesk.category_library','guarddesk.category_rules','guarddesk.website_control','guarddesk.native_handoff_runtime'}<=set(compiled)
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path),str(path)
    assert not any('OwnedBrowser' in name or 'FileHandoff' in name for name in actual)
    signature=read(ROOT/'evidence/authenticode-0.4.60.json');assert all(s['Status']=='NotSigned' for s in signature)
    old={'dist/GuardDesk-0.4.59-windows-x64.zip':'08611476cc584e780fafab8f38d68bf12e4a3aadc7edb2ae524b7ab26d59dc0b',
         'dist/GuardDesk-0.4.59-source.zip':'cc06883e812260a402553b0209349a3304314be76cfc508f1b7d8470f81d0783'}
    assert all(sha(ROOT/name)==value for name,value in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.59-source.zip') as z:previous=json.loads(z.read('MANIFEST-SHA256.json'))
    unchanged=['guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/server_config.py','guarddesk/server_setup.py','guarddesk/endpoint_package.py','guarddesk/source_permissions.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
    assert all(sha(ROOT/name)==previous[name] for name in unchanged)
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.59-windows-x64.zip') as z:olddeps=json.loads(z.read('build-info.json'))
    deps={n:version(n) for n in ('cryptography','cffi','pyinstaller','Pillow','pyreadline3')}
    assert all(deps[n]==olddeps[n] for n in deps)
    # Limited literal secrets check, not a full secret scanner or vulnerability audit.
    private_key=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{100,}')
    secret_field=re.compile(rb'"(?:password|client_secret|access_token|refresh_token)"\s*:\s*"[^"\r\n]+"')
    scanned=0;findings=[]
    for area in ('doc','evidence','browser-extension'):
        for path in (ROOT/area).rglob('*'):
            if not path.is_file() or path.suffix.lower() not in ('.json','.txt','.md','.js','.html','.csv','.pem','.key'):continue
            scanned+=1;blob=path.read_bytes()
            if private_key.search(blob) or path.suffix=='.json' and secret_field.search(blob):findings.append(str(path.relative_to(ROOT)))
    assert not findings,findings
    docs=['README.md','AGENTS.md','doc/README.md','doc/80-category-policy-website-blocking-and-edge-plan.md','doc/81-server-deployment-0.4.60.md','doc/60-engineering-lessons-and-regression-rules.md'];links=0
    for name in docs:
        path=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (path.parent/target.split('#',1)[0]).exists(),(name,target);links+=1
    folder=ROOT/'evidence/security/0.4.60';folder.mkdir(parents=True,exist_ok=True)
    for key in ('category','deployment'):
        log=read(ROOT/proofs[key]['path'])['log'];shutil.copyfile(ROOT/log,folder/(key+'-regression.log'))
    source={str(p.relative_to(ROOT)):sha(p) for area in ('guarddesk','native','browser-extension','tests') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.json','.cpp','.h','.dll') and '__pycache__' not in p.parts}
    source['app.py']=sha(ROOT/'app.py')
    result={'version':VERSION,'status':'unsigned_internal_trial','internal_checks_passed':True,'formal_release_ready':False,'self_review_only':True,
       'company_changed':False,'candidate_deployed_to_office':False,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],
       'application_files':actual,'final_source_sha256':source,'compiled_modules_verified':compiled,'proofs':proofs,
       'packaged_smoke':'evidence/packaged-smoke-0.4.60.json','signatures':'evidence/authenticode-0.4.60.json',
       'unchanged_boundaries_verified':unchanged,'sealed_0459_verified':old,'dependency_versions_unchanged_from_0459':deps,
       'limited_literal_secret_scan':{'files':scanned,'findings':findings,'scope':'literal private PEM payloads and nonempty password/client_secret/access_token/refresh_token JSON fields; not comprehensive'},
       'documentation_links_checked':links,'deployment_guide':'doc/81-server-deployment-0.4.60.md',
       'gd':['GD-001','GD-005','GD-007','GD-008','GD-013','GD-018','GD-019','GD-020','GD-021','GD-022','GD-024'],
       'requirements':['CAT-01','CAT-02','APP-01','WEB-01','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
       'validation_scope':'204 category and adjacent tests plus 76 deployment tests, no skips; frozen smoke; frozen category UI; actual owned frozen 0.4.59-to-0.4.60 same-config upgrade and authenticated endpoint ZIP download. Not full project suite or field acceptance.',
       'remaining':['Edge extensionless native drop positive and production source missing; source_factory remains None',
          'Actual company browser navigation blocking, AppLocker execution, protected SYSTEM/ACL and installed Agent receipt pending',
          'No company Server/Agent deployment; real old installed updater and actual user-downloaded package acceptance pending',
          'Full endpoint/browser/helper 8/24h performance, Win10/Win11 company Defender/EDR matrix pending',
          'Unsigned; independent security review, full SBOM/vulnerability/secret scanning and formal approval pending',
          'Preexisting dependency mismatch: requirements.txt pins Pillow 13.0.0, actual build uses 11.3.0 exactly as sealed 0.4.59. Full reproducible dependency reconciliation pending; actual versions disclosed, no compliance claim',
          'URL match simulator not implemented; compiled rules/diff preview available']}
    (folder/'requirements-review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'version':VERSION,'internal_checks_passed':True,'proofs':proofs,'compiled_modules':len(compiled),'files':len(actual),'limited_secret_scan_files':scanned,'formal_release_ready':False}))
if __name__=='__main__':main()
