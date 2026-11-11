"""Exact-build developer review for the bounded device-detail change."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.35'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))


def main():
    regression=read(f'evidence/server-deployment-check-{VERSION}.json')
    browser=read(f'evidence/device-detail-{VERSION}.json')
    frozen=read('evidence/packaged-smoke.json')
    assert regression['passed'] and regression['tests_run']>=321 and not regression['cleanup_error']
    assert browser['passed'] and browser['page_errors']==[] and browser['audit_reads_denied_and_detail_succeeded']
    app=ROOT/'dist/GuardDesk'
    assert frozen['passed'] and frozen['exe_sha256']==sha(app/'GuardDesk.exe')
    assert frozen['application_files']=={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    previous={'GuardDesk-0.4.34-windows-x64.zip':'88a23f08f0448a233f7395cabf9edc0298d8df3b15eda9439f78880a6331e432',
              'GuardDesk-0.4.34-source.zip':'ef1af7309907c2148528cf9e21d5094f508198585723b6963278ccd39ed7e6a6'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.34-source.zip') as prior:
        changed=[n for n in prior.namelist() if n.startswith('guarddesk/') and (ROOT/n).is_file() and prior.read(n)!=(ROOT/n).read_bytes()]
        assert set(changed)=={'guarddesk/__init__.py','guarddesk/server.py','guarddesk/static/index.html','guarddesk/static/management.js','guarddesk/static/audit_ui.js'}
        added=[p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*.py') if p.relative_to(ROOT).as_posix() not in prior.namelist()]
        assert not added
        for name in prior.namelist():
            if name.startswith(('guarddesk/windows/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','guarddesk/update_windows.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py'):
                assert prior.read(name)==(ROOT/name).read_bytes(),name
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    source=ROOT/'guarddesk/server.py'
    assert archive.extract('guarddesk.server')==compile(source.read_bytes(),str(source),'exec')
    for p in (ROOT/'guarddesk/static').rglob('*'):
        if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk/static'/p.relative_to(ROOT/'guarddesk/static')).read_bytes()
    links=0
    for name in ('README.md','doc/README.md','doc/51-device-detail-without-audit-0.4.35.md'):
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-09','SEC-10','SEC-11','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'Authenticated MIS/auditor -> device-detail -> device/diagnostic/policy tables only; audit data reads and aggregate response fields removed; standalone authorized audit remains',
        'controls':[
            'Existing session/role/device-token redaction and parameterized device lookup retained',
            'Removed history queries for every detail open/principal preview, not only hidden UI tabs',
            'SQLite authorizer denies events and event payload functions in legacy/daily fixture detail requests',
            'Detail UI accepts only basic/effective tabs; normal output escaping preserved',
            'No event deletion, ingestion change, schema change, Agent rollout requirement or policy mutation',
            'Updater security fix from 0.4.34 and all Windows/browser extension/dependency sources unchanged',
            'No new rights, collection, startup jobs, destinations, dependencies or Defender changes'],
        'tests_run':regression['tests_run'],'new_integration_tests':1,
        'browser':browser,'document_links_checked':links,
        'compiled_server_equals_source':True,'static_files_equal_source':True,
        'changed_product_files':changed,'signatures':signatures,'prior_archives_unchanged':previous,
        'evidence':{'regression':f'evidence/server-deployment-check-{VERSION}.json','browser':f'evidence/device-detail-{VERSION}.json','frozen':f'evidence/packaged-smoke-{VERSION}.json'},
        'limits':[
            'Synthetic 6000-event localhost benchmark is not office Server latency or 250 endpoints',
            'Device inventory/policy complexity, contention and other query screens still affect latency',
            'Detail API drops history fields; refresh the browser after updating Server',
            'No office Server update or user1 endpoint repair performed',
            'Unsigned internal trial; company Authenticode/full SBOM and vulnerability gates, independent review, Windows10/Server/Defender EDR/fleet acceptance incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests_run':report['tests_run'],'links_checked':links,'release_status':report['release_status']}))


if __name__=='__main__':main()
