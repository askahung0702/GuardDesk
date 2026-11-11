"""Reproducible developer review of the exact 0.4.37 internal trial artifact."""
import hashlib
import json
import platform
from pathlib import Path
import re
import shutil
import zipfile
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.37'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))

def main():
 log=(ROOT/'runtime/custom-settings-regression-sealed.txt').read_text(encoding='utf-8-sig')
 match=re.search(r'Ran (\d+) tests in ([\d.]+)s',log)
 assert match and int(match[1])>=369 and '\nOK\n' in log.replace('\r\n','\n') and 'FAILED (' not in log
 regression={'validation_note':'Full regression passed; final packet-validation and removal-lease hardening also reran all custom and removal/backup tests', 'passed':True,'tests_run':int(match[1]),'seconds':float(match[2]),'new_custom_tests':42,'cleanup_error':False,'live_company_endpoint_controls_modified':False}
 for logname,count in [('custom-settings-unit-identity.txt',42),('custom-settings-removal-release.txt',6)]:
  extra=(ROOT/'runtime'/logname).read_text(encoding='utf-8-sig').replace('\r\n','\n')
  assert ('Ran '+str(count)+' tests') in extra and '\nOK\n' in extra
 regression['final_targeted_checks']={'custom_tests':42,'removal_and_backup_tests':6}
 folder=ROOT/'evidence/security'/VERSION;folder.mkdir(exist_ok=True)
 (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
 app=ROOT/'dist/GuardDesk';frozen=read(ROOT/'evidence/packaged-smoke.json');browser=read(ROOT/f'evidence/custom-settings-browser-smoke-{VERSION}.json')
 assert frozen['passed'] and frozen['exe_sha256']==sha(app/'GuardDesk.exe') and frozen['gui_sha256']==sha(app/'GuardDeskAgent.exe')
 actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
 assert frozen['application_files']==actual
 assert browser['passed'] and browser['frozen_server_used'] and browser['exe_sha256']==sha(app/'GuardDesk.exe') and browser['page_errors']==[]
 shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
 archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
 for p in (ROOT/'guarddesk').glob('*.py'):
  name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
  if name in archive.toc:
   assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name
   compiled.append(name)
 for name in ('custom_settings','custom_client','custom_windows','custom_network','custom_software'):
  assert 'guarddesk.'+name in compiled
 for area in ('static','windows'):
  for p in (ROOT/'guarddesk'/area).rglob('*'):
   if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes()
 manifest=read(app/'_internal/agent-release.json')
 assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
 prior={'GuardDesk-0.4.36-windows-x64.zip':'2cbe6699cd31ddcfc8a5c9fef9d680b25861e52b8150e926fbc6b8d6a0871d49','GuardDesk-0.4.36-source.zip':'54b236efd0017da718bc0a67e1017f855853da0cfc3fb001d2e864d5ff34d962'}
 for name,value in prior.items():assert sha(ROOT/'dist'/name)==value,name
 with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.36-source.zip') as z:
  changed=[n for n in z.namelist() if n.startswith('guarddesk/') and (ROOT/n).is_file() and z.read(n)!=(ROOT/n).read_bytes()]
  added=[p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.relative_to(ROOT).as_posix() not in z.namelist()]
  critical=['guarddesk/policy.py','guarddesk/policy_defaults.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/event_storage.py','guarddesk/windows/install-usb.ps1','guarddesk/application_exclusions.py','requirements.txt','requirements-build.txt']
  critical += [n for n in z.namelist() if n.startswith('browser-extension/')]
  for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
 signatures=read(folder/'signatures.json')
 for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
 links=0
 for name in ('README.md','doc/README.md','doc/55-custom-settings-center-0.4.37.md','doc/07-ui-reference-and-policy-model.md'):
  source=ROOT/name
  for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8-sig')):
   if target.startswith(('http:','https:','#','mailto:')):continue
   assert (source.parent/target.split('#')[0]).exists(),(name,target)
   links+=1
 report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial','review_type':'developer_self_review_not_independent','applicable':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],'authorization':'User requested full assessment and implementation of a custom settings center while preserving existing features; no live control deployment requested','regression':regression,'compiled_modules_equal_source':compiled,'application_files':len(actual),'static_windows_files_equal_source':True,'old_policy_wire_and_update_protocol_preserved':True,'prior_archives_unchanged':prior,'critical_sources_unchanged':critical,'changed_product_files':changed,'added_product_files':added,'frozen_browser':browser,'metadata_performance':read(ROOT/'evidence/custom-settings-250-metadata-performance.json'),'document_links_checked':links,'signatures':signatures,'supply_chain_check':'Pinned dependencies and browser extension bytes unchanged from sealed 0.4.36; no new dependency','controls':['Dedicated typed API and scoped/revisioned schema; existing legacy policy body unchanged','Admin/CSRF/role and endpoint credential/revocation checks; no arbitrary shell/script/path','Fixed protected executable/configuration for native controls; guarded owner/ACL/reparse and exact recovery state','Bounded visible session prompts, cancel/defer/dedup/final authorization and update/remote action leases','Network baseline journal and five-minute recovery lease; external/company changes preserved','Expiring own-source pauses retain Security-clear alerts and AppLocker block logs; no Defender/App Control weakening','Publisher product rules merge with enabled base policy; disabled latent allowlist remains disabled; maintenance identities checked','Default-disabled queries/status throttled; no file-content collection or new startup tasks/destinations'],'limits':['No live office Server/DEV/user1 setting changed','Destructive shutdown/restart/suspend/logoff, cross-session WTS/UI/helper, real IPv6/reboot/recovery and actual LINE/Brave blocking require controlled Windows acceptance','Read-only registry query passed; tool session had no verified interactive idle query','All own executables/scripts are unsigned; full company signing/SBOM/vulnerability gates, independent review, Defender/EDR/Windows10/Server/fleet acceptance incomplete','Software identities must be obtained from actual signed binaries and packages; no fabricated universal LINE/Brave publisher identity','Rollback to older Agent must first restore network and custom software with 0.4.37','250-device result is synthetic local metadata cost, not concurrency or whole-fleet acceptance']}
 (folder/'requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'passed':True,'tests_run':regression['tests_run'],'new_tests':42,'compiled_modules':len(compiled),'application_files':len(actual),'links_checked':links,'release_status':report['release_status']}))

if __name__=='__main__':main()
