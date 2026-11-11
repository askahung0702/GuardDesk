"""Reproducible developer self-review for the 0.4.40 internal trial."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.40'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(exist_ok=True)
    logs={}
    for name,count in [('installer-regression.txt',443),('installer-targeted-final.txt',14),('installer-endpoint-final.txt',10)]:
        path=ROOT/'runtime'/name;text=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',text)
        assert match and int(match[1])==count and '\nOK\n' in text and 'FAILED (' not in text,(name,text[-1000:])
        logs[name]={'passed':True,'tests':count,'seconds':float(match[2]),'log_sha256':sha(path)}
    app=ROOT/'dist/GuardDesk';smoke=read(ROOT/'evidence/packaged-smoke.json')
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==sha(app/'GuardDesk.exe') and smoke['gui_sha256']==sha(app/'GuardDeskAgent.exe')
    browsers={}
    for name in (f'custom-library-browser-{VERSION}.json',f'mail-reports-browser-{VERSION}.json'):
        value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['frozen_server_used'] and value['exe_sha256']==sha(app/'GuardDesk.exe') and value['page_errors']==[]
        browsers[name]=value
    compiled=[];archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert all('guarddesk.'+name in compiled for name in ('endpoint_setup','endpoint_package','usb_install','installer_channel','custom_library','mail_reports'))
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    prior={'GuardDesk-0.4.39-windows-x64.zip':'936d81b2f3bd99791332db2f9b16dd6454ca39e338348a7caafe3e04c111cfed','GuardDesk-0.4.39-source.zip':'30db6c2194033b91303bca0af869c77df34af26fe0af3ddb34f1ba4a5d80d251'}
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest
    critical=['guarddesk/agent.py','guarddesk/policy.py','guarddesk/policy_defaults.py','guarddesk/native_usb.py','guarddesk/application_control.py','guarddesk/remote.py','guarddesk/removal.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/updater_maintenance.py','guarddesk/updates.py','guarddesk/event_storage.py','guarddesk/audit_reports.py','guarddesk/audit_archive.py','guarddesk/custom_network.py','guarddesk/custom_software.py','guarddesk/custom_library.py','guarddesk/custom_settings.py','guarddesk/custom_client.py','guarddesk/custom_windows.py','guarddesk/mail_reports.py','requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.39-source.zip') as z:
        critical += [n for n in z.namelist() if n.startswith(('browser-extension/','guarddesk/windows/')) and n!='guarddesk/windows/install-usb.ps1']
        for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    regression={'passed':True,'logs':logs,'note':'Full 443-test regression followed by final 24 installer tests, including two additional cases. Final source has 445 unique cases. Final frozen executable and all bundled bytes verified; no real UAC or SYSTEM install performed.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    requirements={'version':VERSION,'passed_with_gaps':True,'release_status':'unsigned_internal_trial','review_type':'developer_self_review_not_independent',
        'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'authorization':'User requested robust single-entry installation and assessment of the management-generated endpoint ZIP. User reports only PowerShell appeared, with no observed UAC approval. Actual endpoint failure cause remains unconfirmed.',
        'controls':['Mandatory native scripts, exact version/manifest/hash tree and private Server source checks before providing ZIP; per-stream hash check prevents publishing changed source','Mandatory valid update public key before enrollment; preserve existing device identity, queues and CA/update pin','Fixed-action GuardDesk UAC helper, protected SYSTEM paths/task identities and existing script policy retained','Diagnostic-only local first-instance random pipe, reject remote clients, explicit current-user/Admin/SYSTEM DACL, bounded JSON and exit-code validation','No privileged writes to caller result paths; ordinary parent writes redacted private diagnostic; 64 KiB ring/16 KiB packet/5000-char detail','PowerShell pre-start policy failure captured with system-codepage fallback; no nonexistent-script instructions','Repair retains running user Agent during native failures, gracefully switches after success, attempts last-ready Agent on launch failure','Native and updater startup health checks require current version, fresh time and exact protected worker PID; first-install task cleanup on failure','Parent/helper single-instance guards and bounded parent wait; no forced termination mid-install','Admin/CSRF download authorization and cleanup retained; no office install, mail, GPO/Defender/EDR changes or new collection/startup/dependencies'],
        'gaps':['Target-machine original failure not diagnosed; new result required for final attribution','Unsigned EXE/PS1 may be blocked by company signing/App Control policy. Company-trusted signing and actual policy acceptance required; no bypass','Actual Windows 10/11 UAC approval/cancellation/alternate MIS credentials, protected install/reboot/update/uninstall and Defender/EDR matrix not run','Interrupted in-place native binary copy is not a full disk transaction; existing work/backups preserved, MIS repair may be needed after power loss','Formal independent review, complete SBOM/vulnerability scan, company security mapping and fleet resource acceptance incomplete'],
        'regression':regression,'compiled_modules_equal_source':compiled,'application_files':len(actual),'static_windows_equal_source':True,'critical_sources_unchanged':critical,'prior_archives_unchanged':prior,'frozen_browsers':browsers,'signatures':signatures,'supply_chain':'No new dependency; pinned requirements and critical collection/control/update/storage modules unchanged from 0.4.39.'}
    (folder/'requirements-review.json').write_text(json.dumps(requirements,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ['README.md','doc/README.md','doc/58-endpoint-installer-0.4.40.md']:
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    requirements['document_links_checked']=links
    (folder/'requirements-review.json').write_text(json.dumps(requirements,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':443,'final_installer_tests':24,'compiled_modules':len(compiled),'application_files':len(actual),'document_links':links,'live_controls_changed':False,'status':'unsigned_internal_trial'}))
if __name__=='__main__':main()
