# Dedicated internal endpoint artifact. No center, viewer or script data tree.
from pathlib import Path
import hashlib,json,os
root=Path(SPECPATH).parent
from tools.build_dependencies import verify
verify(root)
from guarddesk import remote_trial,__version__
if not remote_trial.enabled():raise ValueError('Frozen compiled remote-only source required')
if not (root/'ENDPOINT-SOURCE.json').is_file():raise ValueError('Reviewed endpoint source receipt required')
from tools.remote_notices import verify as verify_notices
notices,notice_hash=verify_notices(root)
from tools.remote_endpoint_artifact import FORBIDDEN_MODULES,RUNTIME_FORBIDDEN,check_inventory,deployment_scope
from guarddesk.remote_components import read_cohort,ENDPOINT_REMOTE_FILES,COHORT_MANIFEST,validate_layout
cohort=Path(os.environ['GUARDDESK_REMOTE_COHORT_ROOT']).resolve(strict=True)
if not cohort.is_relative_to(root.parents[1]/'runtime'):raise ValueError('Cohort escaped workspace runtime')
pins=read_cohort(cohort)
remote=cohort/'_internal/remote'
a=Analysis([str(root/'app_remote_endpoint.py')],pathex=[str(root)],binaries=[],
    datas=[(str(notices),'remote-notices'),
           *((str(remote/name),'remote') for name in (*ENDPOINT_REMOTE_FILES,COHORT_MANIFEST))],
    hiddenimports=[],hookspath=[],hooksconfig={},runtime_hooks=[],
    excludes=['numpy',*sorted(FORBIDDEN_MODULES|RUNTIME_FORBIDDEN)],noarchive=False)
check_inventory([name for name,_,_ in a.pure],[name for name,_,_ in a.datas])
b=Analysis([str(root/'app_remote_installer.py')],pathex=[str(root)],binaries=[],datas=[],
    hiddenimports=[],hookspath=[],hooksconfig={},runtime_hooks=[],
    excludes=['numpy',*sorted(FORBIDDEN_MODULES)],noarchive=False)
check_inventory([name for name,_,_ in b.pure],[name for name,_,_ in b.datas],installer=True)
pyz=PYZ(a.pure)
console=EXE(pyz,a.scripts,[],exclude_binaries=True,name='GuardDesk',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=True)
agent=EXE(pyz,a.scripts,[],exclude_binaries=True,name='GuardDeskAgent',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=False,disable_windowed_traceback=True)
installer=EXE(PYZ(b.pure),b.scripts,[],exclude_binaries=True,name='GuardDeskInstaller',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=True)
coll=COLLECT(console,agent,installer,a.binaries,a.datas,b.binaries,b.datas,strip=False,upx=False,name='GuardDesk')
application=Path(coll.name)
import shutil
service=Path(os.environ['GUARDDESK_REMOTE_SERVICE_ROOT'])
service_receipt=json.loads((service/'receipt.json').read_text())
if not service_receipt.get('passed') or hashlib.sha256((service/'Release/GuardDeskService.exe').read_bytes()).hexdigest()!=service_receipt['sha256']:
    raise ValueError('Service host receipt mismatch')
shutil.copyfile(service/'Release/GuardDeskService.exe',application/'GuardDeskService.exe')
validate_layout(application)
files=[p.relative_to(application).as_posix() for p in application.rglob('*') if p.is_file()]
check_inventory([name for name,_,_ in a.pure],files)
(application/'_internal/remote-endpoint-build.json').write_text(json.dumps({
    'format':1,'build_role':'remote-endpoint','version':__version__,'install_profile':remote_trial.PROFILE,
    'cohort_build_id':pins['build_id'],'source_receipt_sha256':hashlib.sha256((root/'ENDPOINT-SOURCE.json').read_bytes()).hexdigest(),
    'removed_modules':sorted(FORBIDDEN_MODULES),'native_notice_manifest_sha256':notice_hash,
    'lifecycle':'native-service-v1','installer_entry':'GuardDeskInstaller.exe',
    'internal_review_only':True,'deployable':False},sort_keys=True),encoding='utf-8')
from guarddesk.release_scope import METADATA
(application/METADATA).write_text(json.dumps(deployment_scope(__version__),sort_keys=True),encoding='utf-8')
files={p.relative_to(application).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
       for p in application.rglob('*') if p.is_file()}
(application/'_internal/agent-release.json').write_text(json.dumps({
    'format':1,'version':__version__,'files':files},sort_keys=True),encoding='utf-8')
