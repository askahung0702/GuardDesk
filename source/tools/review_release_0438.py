"""Developer self-review of exact 0.4.38 frozen/source artifact and evidence."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile
from PyInstaller.archive.readers import CArchiveReader

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.38'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    logs={}
    for name,expected in [('mail-reports-regression.txt',395),('mail-reports-unit-final.txt',28)]:
        path=ROOT/'runtime'/name
        text=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',text)
        assert match and int(match[1])==expected and '\nOK\n' in text and 'FAILED (' not in text
        logs[name]={'passed':True,'tests':int(match[1]),'seconds':float(match[2]),'log_sha256':sha(path)}
    app=ROOT/'dist/GuardDesk';smoke=read(ROOT/'evidence/packaged-smoke.json')
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['passed'] and smoke['application_files']==actual
    assert smoke['exe_sha256']==sha(app/'GuardDesk.exe') and smoke['gui_sha256']==sha(app/'GuardDeskAgent.exe')
    browsers={}
    for name in [f'mail-reports-browser-{VERSION}.json',f'custom-settings-browser-smoke-{VERSION}.json']:
        value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['frozen_server_used'] and value['exe_sha256']==sha(app/'GuardDesk.exe') and value['page_errors']==[]
        browsers[name]=value
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert 'guarddesk.mail_reports' in compiled
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes()
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    prior={'GuardDesk-0.4.37-windows-x64.zip':'c34cc14f75561aaa9b6466a6d88ff6a9154e94ee3c6d41b323d5fdfb2eb1aa37','GuardDesk-0.4.37-source.zip':'3dadeb3a1097f77bacfc6be70e7bc4ebd4879cae05228ee3c7f71ff5382f1219'}
    for name,value in prior.items():assert sha(ROOT/'dist'/name)==value
    critical=['guarddesk/agent.py','guarddesk/policy.py','guarddesk/policy_defaults.py','guarddesk/native_usb.py','guarddesk/application_control.py','guarddesk/remote.py','guarddesk/removal.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/updater_maintenance.py','guarddesk/updates.py','guarddesk/event_storage.py','guarddesk/audit_reports.py','guarddesk/audit_archive.py','guarddesk/custom_settings.py','guarddesk/custom_client.py','guarddesk/custom_network.py','guarddesk/custom_software.py','guarddesk/custom_windows.py','requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.37-source.zip') as z:
        critical += [n for n in z.namelist() if n.startswith(('browser-extension/','guarddesk/windows/'))]
        for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(exist_ok=True)
    signatures=read(folder/'signatures.json')
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    regression={'passed':True,'full_regression':logs['mail-reports-regression.txt'],'final_targeted':logs['mail-reports-unit-final.txt'],'note':'Full regression includes 25 new mail tests; final 28 mail tests also validate final retention hardening and three additional boundary cases. Frozen browser validates final draft-revision protection. No live mail or company endpoint changes.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial','review_type':'developer_self_review_not_independent','requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],'authorization':'Requested daily prior-day file-mutation reports via M365 to configurable MIS mail group, computer-name charts and top20. No actual company credential or send used.','regression':regression,'compiled_modules_equal_source':compiled,'application_files':len(actual),'static_windows_equal_source':True,'prior_archives_unchanged':prior,'critical_sources_unchanged':critical,'frozen_browsers':browsers,'signatures':signatures,'performance':read(ROOT/'evidence/mail-reports-250-performance.json'),'supply_chain':'No new dependencies; pinned requirements and browser extension unchanged from 0.4.37','controls':['Admin-only configuration, preview and sends; CSRF, request/revision validation and draft conflicts','Fixed Microsoft global hosts, normal TLS verification, no redirects, bounded timeout/response/request size','DPAPI CurrentUser or server environment; no plaintext fallback or credential response/audit; local or TLS secret entry','Daily rollup snapshot, exact Taipei prior day, zero devices and same-name ID separation, no raw path/account/document in mail','Bounded background worker and preview slots; Graph calls outside DB transactions; all computer charts and top20','Persistent daily dedupe and manual request idempotence; final revision recheck; ambiguous sends never automatically retried','Default disabled, no new endpoint collection/privilege/startup job, no Defender/OS policy changes; only server upgrade needed'],'limits':['Actual tenant Mail.Send scoping, secret lifetime and rotation, sender/group permissions, Outlook inline rendering and message trace require MIS acceptance','202 is accepted, not delivered; ambiguous outcome needs operator review; no exactly-once delivery promise','DPAPI encrypted credentials tied to server Windows identity/profile; moving account/machine requires reconfiguration','Late/offline logs may be absent at cutoff; no automatic historical resend or multiday backfill','1000-device/1.8MB image/2.8MB JSON caps fail explicitly; synthetic 250-device timing is not full concurrent fleet acceptance','All own executables/scripts unsigned; independent review, company signing, full SBOM/vulnerability and actual Windows/Defender acceptance outstanding']}
    path=folder/'requirements-review.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ['README.md','doc/README.md','doc/56-daily-mail-reports-0.4.38.md']:
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report['document_links_checked']=links
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':395,'final_mail_tests':28,'compiled_modules':len(compiled),'application_files':len(actual),'document_links':links,'live_mail_sent':False,'status':'unsigned_internal_trial'}))


if __name__=='__main__':main()
