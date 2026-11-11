"""Exact source/build/deployment proof for an unsigned internal Server ZIP."""
import hashlib,json,re,zipfile
from importlib.metadata import version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.62'
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    app=ROOT/'dist/GuardDesk';files={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    paths={'category_source':'evidence/category-regression-7ed666f68f1f4b13bda5aff2685a9856.json',
           'registry':'evidence/category-wildcard-registry-af4b72a0748241b0aee86aa5dc74b73f.json',
           'deployment':'evidence/deployment-regression-0462-96cc0bcb2170492ba5b034bc7fcf21b9.json',
           'upgrade':'evidence/server-upgrade-0462-158a06dd60b045249e9697c52c6f9d55.json',
           'frozen_ui':'evidence/category-wildcard-frozen-0462-76d1b450793544e6a27baab191fd08ef.json',
           'smoke':'evidence/packaged-smoke-0.4.62.json'}
    proofs={}
    for label,rel in paths.items():
        p=ROOT/rel;r=read(p);assert r['passed'],label
        for name,digest in r.get('source_sha256',{}).items():assert sha(ROOT/name)==digest,name
        proofs[label]={'path':rel,'sha256':sha(p)}
    assert read(ROOT/paths['category_source'])['tests']==214
    assert read(ROOT/paths['deployment'])['tests']==76
    smoke=read(ROOT/paths['smoke']);assert smoke['application_files']==files
    upgrade=read(ROOT/paths['upgrade']);assert upgrade['exe_sha256']==files['GuardDesk.exe'] and upgrade['original_config_unchanged'] and upgrade['prior_version']=='0.4.61'
    ui=read(ROOT/paths['frozen_ui']);assert ui['exe_sha256']==files['GuardDesk.exe']
    assert sha(ROOT/ui['ui_evidence'])==ui['ui_evidence_sha256']
    meta=read(app/'_internal/agent-release.json');assert meta['version']==VERSION and meta['files']=={k:v for k,v in files.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in pyz.toc:assert pyz.extract(name)==compile(p.read_bytes(),str(p),'exec'),name;compiled.append(name)
    assert {'guarddesk.category_rules','guarddesk.category_library','guarddesk.server','guarddesk.mis_support'}<=set(compiled)
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for p in area.rglob('*'):
            if p.is_file():assert files[target+'/'+p.relative_to(area).as_posix()]==sha(p)
    old=read(ROOT/'evidence/release-0.4.61-final.json');sealed={a['name']:a['sha256'] for a in old['artifacts']}
    assert all(sha(ROOT/'dist'/name)==digest for name,digest in sealed.items())
    allowed={'guarddesk/category_rules.py','guarddesk/category_library.py','guarddesk/static/category_library_ui.js','guarddesk/__init__.py','guarddesk/static/index.html'}
    checked=[];changed=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.61-source.zip') as z:
        manifest=read_manifest=json.loads(z.read('MANIFEST-SHA256.json'))
        for name,digest in manifest.items():
            if name.startswith(('guarddesk/','native/','browser-extension/')) or name in ('app.py','requirements.txt','requirements-build.txt','Start-Remote.cmd','Start-MIS-Remote.cmd'):
                if sha(ROOT/name)!=digest:changed.append(name)
                else:checked.append(name)
    assert set(changed)==allowed,changed
    signatures=read(ROOT/'evidence/authenticode-0.4.62.json');assert len(signatures)==4 and all(s['Status'] in (2,'NotSigned') for s in signatures)
    docs=['README.md','AGENTS.md','doc/README.md','doc/83-website-category-wildcards-0.4.62.md','doc/84-server-deployment-0.4.62.md','doc/60-engineering-lessons-and-regression-rules.md'];links=0
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
            data=p.read_bytes();scanned+=1;assert not pem.search(data) and not (p.suffix=='.json' and field.search(data)),str(p)
    source={p.relative_to(ROOT).as_posix():sha(p) for area in ('guarddesk','native','browser-extension','tests','tools') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.cpp','.h','.json','.dll','.spec') and '__pycache__' not in p.parts}
    source['app.py']=sha(ROOT/'app.py')
    report={'version':VERSION,'status':'unsigned_internal_trial','internal_checks_passed':True,'self_review_only':True,'formal_release_ready':False,
      'company_changed':False,'candidate_deployed_to_office':False,'application_files':files,'final_source_sha256':source,'compiled_modules_verified':compiled,
      'proofs':proofs,'category_source_tests':214,'deployment_tests':76,'separate_owned_registry_tests':1,'prior_archives_verified':sealed,
      'unchanged_source_files_verified':checked,'changed_guarddesk_files':changed,'documentation_links_checked':links,'limited_literal_secret_scan_files':scanned,
      'limited_secret_scan_scope':'actual private PEM payloads and selected JSON credential fields, not full SBOM/vulnerability/secret scan',
      'dependencies':{n:version(n) for n in ('cryptography','cffi','Pillow','pyinstaller','pyreadline3')},'signatures':'evidence/authenticode-0.4.62.json',
      'requirements':['CAT-03','CAT-01','CAT-02','WEB-01','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
      'gd':['GD-001','GD-002','GD-003','GD-004','GD-005','GD-006','GD-007','GD-008','GD-019','GD-020','GD-021','GD-022','GD-023','GD-024'],
      'remaining':['Unsigned internal trial; company signing/Win10/11 Defender/EDR, independent review, full SBOM and vulnerability/secret scans pending',
       'Company Server not updated and no company endpoint deployment; real SYSTEM/ACL, actual installed updater and 8/24h full endpoint performance pending',
       'Arbitrary host globs require explicit finite native domains; no complete arbitrary-glob native blocking or automatic TLD enumeration',
       'Edge extensionless native drop and production handoff source incomplete; no fix claimed for ChatGPT upload collection',
       'Preexisting Pillow declaration 13.0.0 versus actual build 11.3.0 remains unresolved',
       'Downgrade before host_glob use or convert/remove new typed categories in new Server before old version rollback']}
    p=ROOT/'evidence/security/0.4.62/requirements-review.json';assert not p.exists();p.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'internal_checks_passed':True,'compiled_modules':len(compiled),'application_files':len(files),'formal_release_ready':False,'review':str(p)},ensure_ascii=False))
if __name__=='__main__':main()
