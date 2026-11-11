"""Reproducible developer self-review of the sealed 0.4.39 internal trial."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile
from PyInstaller.archive.readers import CArchiveReader

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.39'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    logs={}
    for name,count in [('library-regression.txt',425),('library-custom-sealed.txt',76)]:
        path=ROOT/'runtime'/name;text=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',text)
        assert match and int(match[1])==count and '\nOK\n' in text and 'FAILED (' not in text
        logs[name]={'passed':True,'tests':count,'seconds':float(match[2]),'log_sha256':sha(path)}
    app=ROOT/'dist/GuardDesk';smoke=read(ROOT/'evidence/packaged-smoke.json')
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==sha(app/'GuardDesk.exe') and smoke['gui_sha256']==sha(app/'GuardDeskAgent.exe')
    browsers={}
    for name in (f'custom-library-browser-{VERSION}.json',f'mail-reports-browser-{VERSION}.json'):
        value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['frozen_server_used'] and value['exe_sha256']==sha(app/'GuardDesk.exe') and value['page_errors']==[]
        browsers[name]=value
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert all('guarddesk.'+name in compiled for name in ('custom_library','custom_settings','custom_client','custom_windows','mail_reports'))
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes()
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    prior={'GuardDesk-0.4.38-windows-x64.zip':'60052250ed180512dce858ff897f04d30c7cdd0cffedb265d62c96fb6cf2878c','GuardDesk-0.4.38-source.zip':'310ea56d7196cdf12ceeaf7eeb485aff1948c1f3bcd3e1b80a6bc1ec5ee5ec1f'}
    for name,value in prior.items():assert sha(ROOT/'dist'/name)==value,name
    critical=['guarddesk/agent.py','guarddesk/policy.py','guarddesk/policy_defaults.py','guarddesk/native_usb.py','guarddesk/application_control.py','guarddesk/remote.py','guarddesk/removal.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/updater_maintenance.py','guarddesk/updates.py','guarddesk/event_storage.py','guarddesk/audit_reports.py','guarddesk/audit_archive.py','guarddesk/custom_network.py','guarddesk/custom_software.py','guarddesk/mail_reports.py','requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.38-source.zip') as z:
        critical += [n for n in z.namelist() if n.startswith(('browser-extension/','guarddesk/windows/'))]
        for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(exist_ok=True)
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    regression={'passed':True,'full_regression':logs['library-regression.txt'],'final_targeted_custom':logs['library-custom-sealed.txt'],'new_library_and_repeat_tests':34,'legacy_custom_tests':42,'note':'Full 425-test regression followed by final 76 custom tests after strict protocol validation and rollback/rollforward migration protection. Final frozen browser and packaged smoke match exact compiled/static bytes. No live office actions or email.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial','review_type':'developer_self_review_not_independent','requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],'authorization':'User requested repeat notices and a fully redesigned reusable custom settings center. User confirmed interval/cutoff configurable by MIS, no forced closing of documents, and personal assignment means the colleagues endpoint computer rather than roaming Windows accounts.','regression':regression,'compiled_modules_equal_source':compiled,'application_files':len(actual),'static_windows_equal_source':True,'critical_sources_unchanged':critical,'prior_archives_unchanged':prior,'frozen_browsers':browsers,'signatures':signatures,'performance':read(ROOT/'evidence/custom-library-250-performance.json'),'supply_chain':'No new dependency; pinned requirements, browser extension and Windows scripts unchanged from sealed 0.4.38','controls':['Admin+CSRF writes; auditor read, support denied; scoped typed items/bindings, strict revisions and both custom/management generation checks','Single-category named templates; group tree, explicit per-item excludes/restore, stable schedule identity, active-source and shadowed-source explanation','Atomic legacy import preserves replacement and empty-list semantics; original profiles/history/hashes retained; edited-library conflicts cannot be overwritten by old console','Rollback/rollforward legacy conflict preserves complete newer library, retains old profiles/history, shows migration warning and does not prevent startup','Resolved network ties and power-window overlap fail explicitly, including future groups and atomic device/group moves','Protocol 1 preserved; protocol 2 separately validates schema/identity/body hash and server-side expiring/deduplicated action authorization','Repeat yes/no/cancel/timeout mapping tested; wall+monotonic clock, exact Taipei cutoff, capped prompt threads and rechecked logon/session/busy/offline conditions','Protected native executable, update/remote/removal leases, network baseline recovery and software maintenance protection retained; no forced document closure','Bounded library/rules/bindings/pages and metadata-only queries; no raw audit scans or new AD/employee data/destination/startup job; no Defender changes'],'limits':['New named items/repeat control require Server, general Agent and native component 0.4.39; old components keep protocol-1 profiles, not new library assignments','Human assignment is endpoint computer only, not a Windows account roaming or per-user isolation','Repeated notifications run within configurable Taipei cutoff, at most 24 hours; cutoff stops rather than forces a final action; process restart/lock/offline/busy changes can cancel an occurrence','WTS prompts are standard deadline messages, not animated per-second countdowns; multi-session abandoned notices may delay a new prompt until old wait ends','Actual cross-session notification, power actions, IPv6 recovery/reboot, LINE/Brave enforcement and Defender/Windows fleet acceptance remain controlled MIS validation','250-device/500-report measurement is synthetic metadata cost, not concurrent physical fleet acceptance','All own binaries/scripts remain unsigned internal trial; formal signing, full SBOM/vulnerability and independent/company review incomplete','No company Server, DEV, user1 settings were changed and no actual company mail was sent']}
    path=folder/'requirements-review.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ['README.md','doc/README.md','doc/57-custom-settings-library-0.4.39.md','doc/07-ui-reference-and-policy-model.md']:
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report['document_links_checked']=links;path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':425,'final_custom_tests':76,'new_tests':34,'compiled_modules':len(compiled),'application_files':len(actual),'document_links':links,'live_controls_changed':False,'status':'unsigned_internal_trial'}))


if __name__=='__main__':main()
