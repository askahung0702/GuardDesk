"""Exact 0.4.68 trial source/frozen gates; no field or formal acceptance claim."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import zipfile
from PyInstaller.archive.readers import CArchiveReader
from tools.run_fleet_network_regression import snapshot

ROOT=Path(__file__).resolve().parents[1]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))


def main():
    proof=ROOT/'evidence/security/0.4.68/requirements-review.json'
    assert not proof.exists(),'Do not overwrite a release review'
    regression=read(ROOT/__import__('sys').argv[1])
    assert regression['passed'] and regression['tests']==30 and not regression['skipped']
    assert regression['source_sha256']==snapshot()
    app=ROOT/'dist/GuardDesk';exe=app/'GuardDesk.exe'
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['exe_sha256']==sha(exe)
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['application_files']==actual
    meta=read(app/'_internal/agent-release.json')
    assert meta['version']=='0.4.68' and meta['files']=={n:h for n,h in actual.items() if n!='_internal/agent-release.json'}
    frozen=read(ROOT/'evidence/fleet-network-frozen-0.4.68.json')
    assert frozen['passed'] and frozen['exe_sha256']==sha(exe)
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
    assert {'guarddesk.native_installer','guarddesk.machine_agent','guarddesk.machine_agent_windows','guarddesk.updates','guarddesk.machine_agent_session','guarddesk.remote_readiness','guarddesk.fleet'}<=set(compiled['server'])
    for source,dest in [('guarddesk/static','_internal/guarddesk/static'),('guarddesk/windows','_internal/guarddesk/windows'),('browser-extension','_internal/browser-extension')]:
        for p in (ROOT/source).rglob('*'):
            if p.is_file():assert actual[dest+'/'+p.relative_to(ROOT/source).as_posix()]==sha(p)
    for p in app.rglob('*'):
        if p.is_file():assert p.suffix.lower() not in ('.sqlite3','.pem','.key'),p
    prior_archives={}
    for version in ('0.4.67',):
        previous=read(ROOT/'evidence'/f'release-{version}-final.json')
        for item in previous['artifacts']:
            name=item.get('name',item.get('artifact'))
            assert sha(ROOT/'dist'/name)==item['sha256']
            prior_archives[name]=item['sha256']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.67-source.zip') as z:
        for n in ['requirements.txt','requirements-build.txt']:assert z.read(n)==(ROOT/n).read_bytes()
        changes=[]
        for p in (ROOT/'guarddesk').rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:
                n=p.relative_to(ROOT).as_posix()
                if n not in z.namelist() or z.read(n)!=p.read_bytes():changes.append(n)
        assert set(changes)=={'guarddesk/__init__.py','guarddesk/fleet.py','guarddesk/static/index.html','guarddesk/static/management.js'},changes
    result=subprocess.run([str(exe),'machine-session','--parent',str(__import__('os').getpid())],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode!=0 and b'Installed machine session entry required' in result.stderr
    links=0
    for rel in ['README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/93-fleet-ip-mac-search-0.4.68.md']:
        p=ROOT/rel
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if target.startswith(('https:','http:','#','mailto:')):continue
            assert (p.parent/target.split('#')[0]).exists(),(rel,target)
            links+=1
    out=dict(version='0.4.68',status='unsigned_internal_trial',internal_checks_passed=True,formal_release_ready=False,
        company_changed=False,product_changes_from_0_4_67=changes,source_tests=30,source_proof=__import__('sys').argv[1],
        source_sha256=snapshot(),application_files=actual,compiled_modules_verified=compiled,documentation_links_checked=links,
        frozen_smoke='evidence/packaged-smoke-0.4.68-final.json',frozen_fleet_browser='evidence/fleet-network-frozen-0.4.68.json',
        prior_sealed_archives_verified=prior_archives,dependency_files_unchanged=True,unprotected_machine_entry_rejected=True,
        requirements=['FLEET-SEARCH-01','GD-005','GD-007','GD-014','GD-015','GD-017','GD-020','GD-021','GD-023','GD-025',
                      'SEC-01','SEC-04','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04'],
        remaining=['Company Server not updated; actual endpoint latest inventory accuracy/coverage not field accepted',
                   'Search uses latest reported IP/MAC plus center source IP; no new NIC discovery, historical addresses or Agent requirement',
                   'Unsigned; company Win10/11 Defender/EDR/ASR/App Control, independent review, full SBOM/vulnerability checks and long-duration performance pending',
                   'Native remote account switching, existing 512MiB update capacity/cache retention and native Edge drag/drop field gaps unchanged'])
    proof.parent.mkdir(parents=True,exist_ok=True)
    proof.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests':30,'compiled':{k:len(v) for k,v in compiled.items()},'files':len(actual),'formal_release_ready':False}))


if __name__=='__main__':main()
