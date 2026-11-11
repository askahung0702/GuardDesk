"""Exact trial build/source/proof checks; not SYSTEM/Defender acceptance."""
import hashlib,json,re,subprocess,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from run_machine_agent_regression import snapshot
ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def main():
    app=ROOT/'dist/GuardDesk';exe=app/'GuardDesk.exe'
    regression=read(ROOT/'evidence/machine-agent-regression-1d8ed851fdd4414cbb76db18a1101cfe.json')
    assert regression['passed'] and regression['tests']==236 and not regression['skipped']
    assert regression['source_sha256']==snapshot()
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['exe_sha256']==sha(exe)
    files={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['application_files']==files
    meta=read(app/'_internal/agent-release.json');assert meta['version']=='0.4.64'
    assert meta['files']=={n:h for n,h in files.items() if n!='_internal/agent-release.json'}
    compiled={}
    for label,path in [('server',exe),('mis',app/'_internal/GuardDeskMIS.exe')]:
        archive=CArchiveReader(str(path)).open_embedded_archive('PYZ.pyz');modules=[]
        for source in (ROOT/'guarddesk').glob('*.py'):
            name='guarddesk' if source.stem=='__init__' else 'guarddesk.'+source.stem
            if name in archive.toc:
                assert archive.extract(name)==compile(source.read_bytes(),str(source),'exec'),(label,name)
                modules.append(name)
        compiled[label]=modules
    assert {'guarddesk.machine_agent','guarddesk.machine_agent_session','guarddesk.machine_agent_windows','guarddesk.native_usb','guarddesk.updates'}<=set(compiled['server'])
    for area,target in [('guarddesk/static','_internal/guarddesk/static'),('guarddesk/windows','_internal/guarddesk/windows'),('browser-extension','_internal/browser-extension')]:
        for p in (ROOT/area).rglob('*'):
            if p.is_file():assert files[target+'/'+p.relative_to(ROOT/area).as_posix()]==sha(p)
    for version in ('0.4.62','0.4.63'):
        sealed=read(ROOT/'evidence'/f'release-{version}-final.json')
        for item in sealed['artifacts']:assert sha(ROOT/'dist'/item.get('name',item.get('artifact')))==item['sha256']
    result=subprocess.run([str(exe),'machine-session','--parent',str(__import__('os').getpid())],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode!=0 and b'Installed machine session entry required' in result.stderr
    docs=['README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/86-machine-agent-all-users.md'];links=0
    for rel in docs:
        p=ROOT/rel
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if target.startswith(('https:','http:','#','mailto:')):continue
            assert (p.parent/target.split('#')[0]).exists(),(rel,target);links+=1
    assert read(ROOT/'evidence/machine-agent-ui-ed2f3db264414e118a9b744992ca7094.json')['passed']
    proof={'version':'0.4.64','status':'unsigned_internal_trial','internal_checks_passed':True,
        'formal_release_ready':False,'company_changed':False,'requirements':['MACHINE-01','SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'gd':['GD-001','GD-004','GD-005','GD-007','GD-008','GD-009','GD-011','GD-012','GD-013','GD-017','GD-020','GD-021','GD-022','GD-023','GD-024','GD-026'],
        'source_tests':236,'source_proof':'evidence/machine-agent-regression-1d8ed851fdd4414cbb76db18a1101cfe.json','source_sha256':snapshot(),
        'application_files':files,'compiled_modules_verified':compiled,'documentation_links_checked':links,
        'frozen_smoke':'evidence/packaged-smoke-0.4.64-final.json','ui':'evidence/machine-agent-ui-ed2f3db264414e118a9b744992ca7094.json',
        'unprotected_machine_entry_rejected':True,'prior_sealed_archives_unchanged':True,
        'remaining':['Actual installed SYSTEM/WTS A-to-B, reboot, old updater and rollback ACL lifecycle not field accepted',
            'Same SID simultaneous RDP browser history deduplication needs field verification; ambiguous remote desktops fail closed',
            'Unsigned; company Windows10/11 Defender/EDR, independent review, full SBOM/vulnerability/secret scanning and 8/24h total performance pending',
            'Legacy A private credential backup retained, not rotated; no machine token distributed to B',
            'Existing Edge production native drag/drop provider and complete arbitrary host-glob native coverage remain incomplete']}
    folder=ROOT/'evidence/security/0.4.64';folder.mkdir(parents=True,exist_ok=True);target=folder/'requirements-review.json';assert not target.exists()
    target.write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'passed':True,'compiled':{k:len(v) for k,v in compiled.items()},'files':len(files),'formal_release_ready':False}))
if __name__=='__main__':main()
