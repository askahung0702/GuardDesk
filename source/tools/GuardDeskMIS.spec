# Single-file standard-user MIS tool. No console, services, UPX or global CA.
from pathlib import Path
import os
root=Path(SPECPATH).parent
from tools.build_dependencies import verify
verify(root)
from guarddesk.remote_components import REMOTE_FILES,COHORT_MANIFEST,read_cohort
from tools.remote_notices import verify as verify_notices
notices,notice_hash=verify_notices(root)
application=root/'dist/GuardDesk'
if os.environ.get('GUARDDESK_REMOTE_COHORT_ROOT'):
    application=Path(os.environ['GUARDDESK_REMOTE_COHORT_ROOT']).resolve(strict=True)
    runtime=root.parents[1]/'runtime'
    if not application.is_relative_to(runtime.resolve()):raise ValueError('Preview cohort must be under workspace runtime')
    read_cohort(application,role='mis')
cohort=application/'_internal/remote'
native_data=[];native_binaries=[]
if cohort.exists():
    read_cohort(application,role='mis') # shared build identity; MIS role needs only its DLL
    native_binaries=[(str(cohort/'GuardDeskMisNative.dll'),'_internal/remote')]
    native_data=[(str(cohort/COHORT_MANIFEST),'_internal/remote')]
a=Analysis([str(root/'mis_remote_app.py')],pathex=[str(root)],binaries=native_binaries,datas=[*native_data,(str(notices),'_internal/remote-notices')],
    hiddenimports=[],hookspath=[],hooksconfig={},runtime_hooks=[],
    excludes=['numpy','guarddesk.server','guarddesk.agent','guarddesk.desktop_agent','guarddesk.store','guarddesk.remote','guarddesk.endpoint_package','guarddesk.server_setup','guarddesk.update_packages'],noarchive=False)
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,a.binaries,a.datas,[],name='GuardDeskMIS',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=False,disable_windowed_traceback=False)
