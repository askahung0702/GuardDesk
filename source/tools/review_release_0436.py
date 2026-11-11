"""Developer self-review: explicit, once-only default exclusion publication."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.36'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    regression=read(f'evidence/server-deployment-check-{VERSION}.json')
    browser=read(f'evidence/default-audit-exclusions-{VERSION}.json')
    frozen=read(f'evidence/packaged-smoke-{VERSION}.json')
    assert regression['passed'] and regression['tests_run']>=328 and not regression['cleanup_error']
    assert browser['passed'] and browser['frozen_server_used'] and browser['page_errors']==[]
    app=ROOT/'dist/GuardDesk'
    assert frozen['passed'] and frozen['exe_sha256']==sha(app/'GuardDesk.exe')
    assert frozen['application_files']=={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    previous={'GuardDesk-0.4.35-windows-x64.zip':'e908b925ba6a972be8e2b05913955d37eeea37ed2325e86dc455aaa78b7b4279',
              'GuardDesk-0.4.35-source.zip':'d8a34d9561f09f097efb919995acfcf674e6c4fdf404cc9b5f8819258682eeba'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.35-source.zip') as prior:
        changed=[n for n in prior.namelist() if n.startswith('guarddesk/') and (ROOT/n).is_file() and prior.read(n)!=(ROOT/n).read_bytes()]
        assert set(changed)=={'guarddesk/__init__.py','guarddesk/store.py','guarddesk/static/index.html'}
        added=[p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*.py') if p.relative_to(ROOT).as_posix() not in prior.namelist()]
        assert added==['guarddesk/policy_defaults.py']
        for name in prior.namelist():
            if name.startswith(('guarddesk/windows/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','guarddesk/policy.py','guarddesk/server.py','guarddesk/agent.py','guarddesk/file_exclusions.py','guarddesk/application_exclusions.py','guarddesk/update_windows.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py'):
                assert prior.read(name)==(ROOT/name).read_bytes(),name
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for name in ('guarddesk.store','guarddesk.policy_defaults'):
        p=ROOT/(name.replace('.','/')+'.py');assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec')
    for p in (ROOT/'guarddesk/static').rglob('*'):
        if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk/static'/p.relative_to(ROOT/'guarddesk/static')).read_bytes()
    links=0
    for name in ('README.md','doc/README.md','doc/52-default-audit-exclusions-0.4.36.md'):
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'authorization':'User explicitly requested default C:\\Users\\{user}\\AppData\\Roaming file-operation exclusion and conhost.exe/docker.exe ordinary process exclusions',
        'data_flow':'Server startup -> explicit fresh baseline or once-only transactional merge -> durable revision/generation/audit -> existing authenticated policy wire -> existing source/ingress filters',
        'controls':[
            'Only requested defaults are added; custom rules and historical policies/events remain unchanged',
            'Persistent marker prevents defaults from being re-added after MIS removal; generic legacy normalization/endpoint cache defaults unchanged',
            'BEGIN IMMEDIATE serializes initialization; savepoint restores candidate baseline on incompatible active endpoint or empty-group combinations',
            '100-item bounds retained; no truncation, new remote command or unauthenticated policy endpoint; scoped explicit overrides preserved',
            'Original application filters retain blocked/warning/critical events; original file-kind/path semantics and cross-boundary retention unchanged',
            'No Defender exclusions, OS audit policy changes, startup jobs, new rights, dependencies or destinations',
            'Existing MIS edits retain CSRF, generation/revision checks and preview; old wire format remains unchanged'],
        'tests_run':regression['tests_run'],'new_tests':7,'frozen_browser':browser,
        'document_links_checked':links,'compiled_modules_equal_source':True,'static_files_equal_source':True,
        'changed_product_files':changed,'added_product_files':added,'signatures':signatures,'prior_archives_unchanged':previous,
        'evidence':{'regression':f'evidence/server-deployment-check-{VERSION}.json','browser':f'evidence/default-audit-exclusions-{VERSION}.json','frozen':f'evidence/packaged-smoke-{VERSION}.json'},
        'limits':[
            'Roaming business-file operations and same-name programs at all paths can be excluded; MIS can remove or narrow defaults',
            'Existing explicit scoped replacements override global defaults; rule limits/incompatible combinations preserve prior configuration and produce a warning audit record',
            'Server filters on arrival; source reduction requires compatible Agent and received effective policy; offline/older endpoints may still produce/transfer events',
            'No office Server/endpoint policy changes or user1 repair performed',
            'Unsigned internal trial; company Authenticode/full SBOM and vulnerability gates, independent review, Windows10/Server/Defender EDR/fleet acceptance incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests_run':report['tests_run'],'links_checked':links,'release_status':report['release_status']}))


if __name__=='__main__':main()
