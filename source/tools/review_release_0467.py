"""Exact 0.4.67 trial source/frozen gates; no field or formal acceptance claim."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import zipfile
from PyInstaller.archive.readers import CArchiveReader
from tools.run_machine_agent_regression import snapshot

ROOT=Path(__file__).resolve().parents[1]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))


def main():
    proof=ROOT/'evidence/security/0.4.67/requirements-review.json'
    assert not proof.exists(),'Do not overwrite a release review'
    regression=read(ROOT/__import__('sys').argv[1])
    assert regression['passed'] and regression['tests']==272 and not regression['skipped']
    assert regression['source_sha256']==snapshot()
    app=ROOT/'dist/GuardDesk';exe=app/'GuardDesk.exe'
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['exe_sha256']==sha(exe)
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['application_files']==actual
    meta=read(app/'_internal/agent-release.json')
    assert meta['version']=='0.4.67' and meta['files']=={n:h for n,h in actual.items() if n!='_internal/agent-release.json'}
    frozen=read(ROOT/'evidence/frozen-machine-remote-0.4.67-v2.json')
    assert frozen['passed'] and frozen['candidate_exe_sha256']==sha(exe)
    compiled={}
    for label,path in [('server',exe),('agent',app/'GuardDeskAgent.exe'),('remote',app/'_internal/GuardDeskRemote.exe'),('mis',app/'_internal/GuardDeskMIS.exe')]:
        archive=CArchiveReader(str(path)).open_embedded_archive('PYZ.pyz');names=[]
        for source in (ROOT/'guarddesk').glob('*.py'):
            name='guarddesk' if source.stem=='__init__' else 'guarddesk.'+source.stem
            if name in archive.toc:
                assert archive.extract(name)==compile(source.read_bytes(),str(source),'exec'),(label,name)
                names.append(name)
        compiled[label]=names
    assert 'guarddesk.remote_readiness' in compiled['mis']
    assert {'guarddesk.native_installer','guarddesk.machine_agent','guarddesk.machine_agent_windows','guarddesk.updates','guarddesk.machine_agent_session','guarddesk.remote_readiness'}<=set(compiled['server'])
    for source,dest in [('guarddesk/static','_internal/guarddesk/static'),('guarddesk/windows','_internal/guarddesk/windows'),('browser-extension','_internal/browser-extension')]:
        for p in (ROOT/source).rglob('*'):
            if p.is_file():assert actual[dest+'/'+p.relative_to(ROOT/source).as_posix()]==sha(p)
    for p in app.rglob('*'):
        if p.is_file():assert p.suffix.lower() not in ('.sqlite3','.pem','.key'),p
    prior_archives={}
    for version in ('0.4.66',):
        previous=read(ROOT/'evidence'/f'release-{version}-final.json')
        for item in previous['artifacts']:
            name=item.get('name',item.get('artifact'))
            assert sha(ROOT/'dist'/name)==item['sha256']
            prior_archives[name]=item['sha256']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.66-source.zip') as z:
        for n in ['requirements.txt','requirements-build.txt']:assert z.read(n)==(ROOT/n).read_bytes()
    result=subprocess.run([str(exe),'machine-session','--parent',str(__import__('os').getpid())],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode!=0 and b'Installed machine session entry required' in result.stderr
    links=0
    for rel in ['README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/92-machine-remote-all-users-0.4.67.md']:
        p=ROOT/rel
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if target.startswith(('https:','http:','#','mailto:')):continue
            assert (p.parent/target.split('#')[0]).exists(),(rel,target)
            links+=1
    out=dict(version='0.4.67',status='unsigned_internal_trial',internal_checks_passed=True,formal_release_ready=False,
        company_changed=False,source_tests=272,source_proof=__import__('sys').argv[1],
        source_sha256=snapshot(),application_files=actual,compiled_modules_verified=compiled,documentation_links_checked=links,
        frozen_smoke='evidence/packaged-smoke-0.4.67-final.json',frozen_remote='evidence/frozen-machine-remote-0.4.67-v2.json',
        prior_sealed_archives_verified=prior_archives,dependency_files_unchanged=True,unprotected_machine_entry_rejected=True,
        requirements=['MACHINE-01','GD-005','GD-006','GD-007','GD-008','GD-009','GD-017','GD-020','GD-021','GD-022','GD-025','GD-026',
                      'SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'],
        remaining=['LAB01 user confirms native/main/updater 0.4.66 healthy, ordinary unlocked desktop; actual runtime root cause and new field acceptance unconfirmed',
                   'Actual protected SYSTEM updater to 0.4.67, WTS A/B, reboot, removal and rollback still need field acceptance; owned pipe and frozen tests are not field tests',
                   'Unsigned; company Win10/11 Defender/EDR/ASR/App Control, independent review, full SBOM/vulnerability checks and long-duration performance pending',
                   'Existing update aggregate 512MiB capacity/cache retention and native Edge drag/drop remain separate gaps',
                   'Old 0.4.64/65 archives unavailable; only available 0.4.66 sealed archives reverified, not reconstructed'])
    proof.parent.mkdir(parents=True,exist_ok=True)
    proof.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests':272,'compiled':{k:len(v) for k,v in compiled.items()},'files':len(actual),'formal_release_ready':False}))


if __name__=='__main__':main()
