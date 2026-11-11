"""Exact source, frozen runtime, release scope and old updater boundary gates."""
import hashlib,json,re,subprocess,sys,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.build-deps/remote'))
from tools.build_dependencies import verify
verify(Path(__file__).resolve().parents[1])
from PyInstaller.archive.readers import CArchiveReader
from tools.run_update_release_regression import snapshot
from tools.check_deployment_scope import check
ROOT=Path(__file__).resolve().parents[1]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))

def main():
    from tools.build_dependencies import verify
    dependency=verify(ROOT)
    target=ROOT/'evidence/security/0.4.69/requirements-review.json';assert not target.exists()
    regression=read(ROOT/sys.argv[1]);assert regression['passed'] and not regression['skipped'] and not regression['errors'] and not regression['failures']
    assert regression['source_sha256']==snapshot()
    app=ROOT/'dist/GuardDesk';exe=app/'GuardDesk.exe'
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke-0.4.69-final.json');assert smoke['passed'] and smoke['exe_sha256']==sha(exe) and smoke['application_files']==actual
    meta=read(app/'_internal/agent-release.json');assert meta['version']=='0.4.69' and meta['files']=={n:h for n,h in actual.items() if n!='_internal/agent-release.json'}
    scope=read(app/'_internal/deployment-scope.json');assert scope['scope']=='endpoint' and scope['version']=='0.4.69' and scope['required_updater']=='0.4.69'
    boundary=read(ROOT/'evidence/update-boundary-frozen-0.4.69.json');browser=read(ROOT/'evidence/release-scope-browser-0.4.69.json')
    for proof in (boundary,browser):assert proof['passed'] and proof['exe_sha256']==sha(exe) and not proof['company_changed']
    assert boundary['candidate_runtime']['files']==len(actual)
    compiled={};pillow_compiled={};pillow_embedded={}
    for label,path in [('server',exe),('agent',app/'GuardDeskAgent.exe'),('remote',app/'_internal/GuardDeskRemote.exe'),('mis',app/'_internal/GuardDeskMIS.exe')]:
        container=CArchiveReader(str(path));archive=container.open_embedded_archive('PYZ.pyz');names=[]
        for source in (ROOT/'guarddesk').glob('*.py'):
            name='guarddesk' if source.stem=='__init__' else 'guarddesk.'+source.stem
            if name in archive.toc:
                assert archive.extract(name)==compile(source.read_bytes(),str(source),'exec'),(label,name)
                names.append(name)
        compiled[label]=names
        pillow_compiled[label]=[]
        for name in archive.toc:
            if name=='PIL' or name.startswith('PIL.'):
                source=ROOT/'.build-deps/remote'/Path(name.replace('.','/'))
                source=source/'__init__.py' if source.is_dir() else source.with_suffix('.py')
                assert archive.extract(name)==compile(source.read_bytes(),str(source),'exec'),(label,name,'dependency source mismatch')
                pillow_compiled[label].append(name)
        assert 'PIL._version' in pillow_compiled[label]
        pillow_embedded[label]=[]
        for n in container.toc:
            normalized=n.replace('\\','/')
            if normalized.startswith('PIL/') and normalized.endswith('.pyd'):
                assert hashlib.sha256(container.extract(n)).hexdigest()==sha(ROOT/'.build-deps/remote'/normalized),(label,n)
                pillow_embedded[label].append(n)
    assert {'guarddesk.update_preflight','guarddesk.update_storage','guarddesk.release_scope','guarddesk.update_cache','guarddesk.updates','guarddesk.machine_agent'}<=set(compiled['server'])
    for source,dest in [('guarddesk/static','_internal/guarddesk/static'),('guarddesk/windows','_internal/guarddesk/windows'),('browser-extension','_internal/browser-extension')]:
        for p in (ROOT/source).rglob('*'):
            if p.is_file():assert actual[dest+'/'+p.relative_to(ROOT/source).as_posix()]==sha(p)
    assert not any(p.suffix.lower() in ('.sqlite3','.pem','.key') for p in app.rglob('*') if p.is_file())
    for p in (app/'_internal/PIL').glob('*.pyd'):assert sha(p)==sha(ROOT/'.build-deps/remote/PIL'/p.name),p.name
    prior={}
    for version in ('0.4.66','0.4.67','0.4.68'):
        for item in read(ROOT/f'evidence/release-{version}-final.json')['artifacts']:
            name=item.get('name',item.get('artifact'));assert sha(ROOT/'dist'/name)==item['sha256'];prior[name]=item['sha256']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.68-source.zip') as old:
        for n in ('requirements.txt','requirements-build.txt'):assert old.read(n)==(ROOT/n).read_bytes()
    result=subprocess.run(['node','--check',str(ROOT/'guarddesk/static/updates_ui.js')],capture_output=True);assert result.returncode==0
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/94-release-scope-and-update-working-set-0.4.69.md'):
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if link.startswith(('https:','http:','#','mailto:')):continue
            assert (path.parent/link.split('#')[0]).exists(),(name,link)
            links+=1
    report={'version':'0.4.69','status':'unsigned_internal_trial','internal_checks_passed':True,'formal_release_ready':False,
        'company_changed':False,'source_tests':regression['tests'],'source_proof':sys.argv[1],'source_sha256':snapshot(),
        'application_files':actual,'compiled_modules_verified':compiled,'deployment_analysis':check(),'deployment_metadata':scope,
        'documentation_links_checked':links,'prior_sealed_archives_verified':prior,'dependency_files_unchanged':True,
        'isolated_dependency':dependency,'pillow_compiled_modules':pillow_compiled,'pillow_embedded_binaries':pillow_embedded,
        'frozen_boundary':'evidence/update-boundary-frozen-0.4.69.json','frozen_browser':'evidence/release-scope-browser-0.4.69.json',
        'frozen_smoke':'evidence/packaged-smoke-0.4.69-final.json',
        'requirements':['UPDATE-SCOPE-01','UPDATE-RELIABILITY-01','GD-005','GD-006','GD-007','GD-008','GD-009','GD-010','GD-017','GD-020','GD-021','GD-022','GD-023','GD-026','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'],
        'intermediate_failures':'evidence/update-release-0.4.69-attempts.json',
        'remaining':['Actual DEV/user1/LAB01 controlled first upgrade and SYSTEM task/ACL/account-switch/reboot acceptance pending; no installed cache or program modified',
            'Old updater 66 remains constrained until an individually checked bridge; Server-only deployment cannot replace installed budget code',
            'user1 root cause not field confirmed; DEV original raw exception unavailable, actual frozen budget reproduction uses measured field values',
            'Owned test config replacement WinError5 occurred once; isolated and final suite results are recorded, transient handle owner not identified',
            'Unsigned; company Win10/11 Defender/EDR/ASR/App Control, full SBOM/vulnerability/independent review and long-duration performance acceptance pending',
            'No guarantee of zero future failures; each endpoint release must test the actual old updater against its own exact candidate']}
    assert (ROOT/report['intermediate_failures']).exists()
    target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'passed':True,'tests':regression['tests'],'compiled':{k:len(v) for k,v in compiled.items()},'files':len(actual),'formal_release_ready':False}))

if __name__=='__main__':main()
