# Shared runtime, console tools, windowless Agent and independent MIS viewer.
from pathlib import Path
root = Path(SPECPATH).parent
from tools.build_dependencies import verify
verify(root)
from guarddesk import __version__
from tools.check_deployment_scope import check
check()
import hashlib,json
native=root/'guarddesk/windows/native'
native_info=json.loads((native/'document-trace-build.json').read_text(encoding='utf-8'))
if hashlib.sha256((native/'GuardDeskFileTrace.dll').read_bytes()).hexdigest()!=native_info['dll_sha256'] or hashlib.sha256((root/'native/document_trace.cpp').read_bytes()).hexdigest()!=native_info['source_sha256']:
    raise ValueError('原生文件收集器來源／DLL 已變更；先以固定工具鏈重新建置')
from guarddesk.machine_service import enabled as full_service
service_data=[]
if full_service():
    import os
    service=Path(os.environ['GUARDDESK_REMOTE_SERVICE_ROOT']).resolve(strict=True)
    if not service.is_relative_to(root.parents[1]/'runtime'):raise ValueError('Service escaped runtime')
    service_info=json.loads((service/'receipt.json').read_text())
    host=service/'Release/GuardDeskService.exe'
    if not service_info.get('passed') or hashlib.sha256(host.read_bytes()).hexdigest()!=service_info['sha256']:raise ValueError('Service receipt mismatch')
    if not all(hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in service_info['sources'].items()):raise ValueError('Service source changed')
    service_data=[(str(host),'.')]
# Refuse stale hard-coded UI stamps before creating a mixed-version build.
ui = (root/'guarddesk/static/index.html').read_text(encoding='utf-8')
if f'內部試用版 {__version__}' not in ui or f'{__version__} · 內部試用版' not in ui:
    raise ValueError('網頁登入／頁尾版本與程式不一致；請同步 index.html 後重新建置')
from guarddesk.remote_components import read_cohort,REMOTE_FILES,COHORT_MANIFEST
import os
from tools.remote_notices import verify as verify_notices
notices,notice_hash=verify_notices(root)
cohort_root=Path(os.environ.get('GUARDDESK_REMOTE_COHORT_ROOT',str(root/'dist/GuardDesk'))).resolve()
if os.environ.get('GUARDDESK_REMOTE_COHORT_ROOT') and not cohort_root.is_relative_to(root.parents[1]/'runtime'):
    raise ValueError('Owned native build cohort escaped workspace runtime')
remote=cohort_root/'_internal/remote'
remote_data=[]
if remote.exists():
    read_cohort(cohort_root)
    remote_data=[(str(remote/name),'remote') for name in (*REMOTE_FILES,COHORT_MANIFEST) if name!='GuardDeskMisNative.dll']
elif os.environ.get('GUARDDESK_REMOTE_COHORT_ROOT'):
    raise ValueError('Explicit native build cohort is missing')
mis_build=Path(os.environ.get('GUARDDESK_MIS_BUILD_PATH',str(root/'.build-deps/mis/GuardDeskMIS.exe'))).resolve()
if os.environ.get('GUARDDESK_MIS_BUILD_PATH') and (not mis_build.is_relative_to(root.parents[1]/'runtime') or not mis_build.is_file()):
    raise ValueError('Explicit owned MIS build is missing or outside runtime')
a = Analysis([str(root / 'app.py')], pathex=[str(root)], binaries=[],
    datas=[(str(root / 'guarddesk/static'), 'guarddesk/static'),
           (str(root / 'guarddesk/windows'), 'guarddesk/windows'),
           (str(root / 'browser-extension'), 'browser-extension'),
           (str(mis_build), '.'),(str(notices),'remote-notices'),*remote_data,*service_data],
    # Pillow's optional array bridge is unused; do not bundle a machine-local
    # NumPy installation as an undeclared imaging/runtime dependency.
    hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=['numpy'], noarchive=False)
pyz = PYZ(a.pure)
console = EXE(pyz, a.scripts, [], exclude_binaries=True, name='GuardDesk', debug=False,
    bootloader_ignore_signals=False, strip=False, upx=False, console=True)
agent = EXE(pyz, a.scripts, [], exclude_binaries=True, name='GuardDeskAgent', debug=False,
    bootloader_ignore_signals=False, strip=False, upx=False, console=False, disable_windowed_traceback=True)
viewer = EXE(pyz, a.scripts, [], exclude_binaries=True, name='GuardDeskRemote', debug=False,
    bootloader_ignore_signals=False, strip=False, upx=False, console=False,
    disable_windowed_traceback=True, contents_directory='.')
coll = COLLECT(console, agent, viewer, a.binaries, a.datas, strip=False, upx=False, name='GuardDesk')
# Keep the update protocol-1 root whitelist compatible with the installed
# independent SYSTEM updater. This GUI is never launched by that updater.
import os
os.replace(str(Path(coll.name)/'GuardDeskRemote.exe'),str(Path(coll.name)/'_internal/GuardDeskRemote.exe'))
# Public, non-recursive manifest: included files exclude this manifest itself.
# The outer signed update manifest will additionally hash this metadata file.
import hashlib,json
from guarddesk import __version__
application=Path(coll.name)
from guarddesk.remote_components import validate_layout
validate_layout(application)
from guarddesk.release_scope import profile,METADATA
(application/METADATA).write_text(json.dumps(profile(__version__),sort_keys=True),encoding='utf-8')
bundled_files={p.relative_to(application).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in application.rglob('*') if p.is_file()}
(application/'_internal/agent-release.json').write_text(json.dumps({'format':1,'version':__version__,'files':bundled_files},sort_keys=True),encoding='utf-8')
