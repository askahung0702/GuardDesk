"""Developer review of the exact updater-fix trial build; no office deployment."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.34'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))


def main():
    regression=read(f'evidence/server-deployment-check-{VERSION}.json')
    frozen=read('evidence/packaged-smoke.json')
    assert regression['passed'] and regression['tests_run']>=320 and not regression['cleanup_error']
    app=ROOT/'dist/GuardDesk'
    assert frozen['passed'] and frozen['exe_sha256']==sha(app/'GuardDesk.exe')
    assert frozen['application_files']=={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    previous={'GuardDesk-0.4.33-windows-x64.zip':'68f5428aabfb69a721dc24fabb267b3f810351d1e12269771a7d4f73ea02d140',
              'GuardDesk-0.4.33-source.zip':'549df3242f91596e801e936302e078e5b59ba7bd72e9f3a5f21bb45dd8ea4eb9'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.33-source.zip') as prior:
        changed=[n for n in prior.namelist() if n.startswith('guarddesk/') and (ROOT/n).is_file() and prior.read(n)!=(ROOT/n).read_bytes()]
        assert set(changed)=={'guarddesk/__init__.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py','guarddesk/static/index.html'}
        added=[p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*.py') if p.relative_to(ROOT).as_posix() not in prior.namelist()]
        assert added==['guarddesk/update_windows.py']
        for name in prior.namelist():
            if (name.startswith(('guarddesk/windows/','guarddesk/static/','browser-extension/')) and name!='guarddesk/static/index.html') or name in ('requirements.txt','requirements-build.txt'):
                assert prior.read(name)==(ROOT/name).read_bytes(),name
    # Read the actual PyInstaller archive rather than assuming the new lazy
    # import was collected. Code objects compare their nested constants too.
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    compiled=[]
    for name in ('guarddesk.update_windows','guarddesk.update_native','guarddesk.update_client','guarddesk.updater_refresh'):
        source=ROOT/(name.replace('.','/')+'.py')
        assert archive.extract(name)==compile(source.read_bytes(),str(source),'exec'),name
        compiled.append(name)
    links=0
    for name in ('README.md','doc/README.md','doc/50-updater-directory-switch-0.4.34.md','doc/49-existing-updater-check-with-signature-policy.md'):
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-02','SEC-03','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'Existing authenticated signed update transaction -> fixed protected directories and validated tasks -> bounded read-only process image handles -> exit wait and guarded directory rename -> existing health/rollback and safe numeric status',
        'controls':[
            'Only validated existing scheduled tasks are ended; no arbitrary process termination, elevated debug privilege, new startup task or remote shell',
            'Exact full executable path checked on retained process handles; same-name processes at other paths excluded; handles closed on all paths',
            'Snapshot at most 16384 processes and 64 matching handles; 30-second shared stop deadline',
            'Same-parent protected rename; existing destination refused; ACL/reparse roots rechecked; retry Windows 5/32/33 only for <=5 seconds and <=21 attempts',
            'Original complete stage integrity/deep ACL checks and health/version/PID validation retained; no force success or Defender/policy changes',
            'Only fixed failure stage/type and bounded numeric Windows/errno codes persisted and reported; raw exception messages excluded',
            'Rollback failure remains nonterminal with independent diagnostic; diagnostic write failure does not prevent rollback',
            'No new collection, network destinations, dependencies, credential changes or event deletion'],
        'tests_run':regression['tests_run'],'new_test_count':12,
        'document_links_checked':links,'compiled_modules_equal_source':compiled,
        'changed_existing_product_files':changed,'added_product_files':added,
        'signatures':signatures,'prior_archives_unchanged':previous,
        'evidence':{'regression':f'evidence/server-deployment-check-{VERSION}.json','frozen':'evidence/packaged-smoke.json'},
        'limits':[
            'user1 exact original switch error remains unknown; no repair or update performed on user1',
            'Old 0.4.19 updater needs one controlled trusted bootstrap upgrade before benefiting; Agent-only update does not guarantee it',
            'Process/rename positive tests use disposable owned Windows fixtures with privileged ACL guards mocked for that fixture only',
            'Unsigned; company Authenticode/full SBOM and vulnerability gates, independent review, Windows10/Server/Defender EDR/fleet acceptance incomplete',
            'A persistent exact-image browser host or inaccessible same-name process can safely defer an update; it is not killed']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests_run':report['tests_run'],'links_checked':links,'release_status':report['release_status']}))


if __name__=='__main__':main()
