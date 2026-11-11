"""Exact PYZ offline import/dispatch and staging checks; no install/enrollment.

Imports only verified GuardDesk bytecode from the artifact. Dependencies use
the pinned build environment. Real frozen EXE entry checks are in the builder;
this fixture does not claim to launch SYSTEM/native sessions.
"""
import argparse
import contextlib
import hashlib
import importlib.abc
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import types
from unittest.mock import Mock,patch
from PyInstaller.archive.readers import CArchiveReader

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True)
    args=parser.parse_args();build=args.build.resolve(strict=True)
    runtime=Path(__file__).resolve().parents[2]
    if build.parent!=runtime or not build.name.startswith('remote-endpoint-build-'):raise ValueError('Owned endpoint build required')
    receipt=json.loads((build/'receipt.json').read_text())
    if not receipt['passed']:raise ValueError('Build not passed')
    product=build/'product/GuardDesk'
    for name,value in receipt['files'].items():
        if digest(product/name)!=value['sha256']:raise ValueError('Artifact changed')
    runtime_archive=CArchiveReader(str(product/'GuardDesk.exe'))
    runtime_pyz=runtime_archive.open_embedded_archive(next(n for n in runtime_archive.toc if n.startswith('PYZ')))
    from tools.remote_endpoint_artifact import RUNTIME_FORBIDDEN
    if RUNTIME_FORBIDDEN.intersection(runtime_pyz.toc):raise ValueError('Installer code in runtime')
    archive=CArchiveReader(str(product/'GuardDeskInstaller.exe'))
    pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
    class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='guarddesk' or fullname.startswith('guarddesk.'):
                if fullname not in pyz.toc:raise ModuleNotFoundError('Absent frozen module: '+fullname)
                return importlib.util.spec_from_loader(fullname,self,is_package=fullname=='guarddesk')
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(product/'_internal'/module.__name__.replace('.','/'))+'.py'
            exec(pyz.extract(module.__name__),module.__dict__)
    if any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules):raise ValueError('Fresh interpreter required')
    finder=Frozen();sys.meta_path.insert(0,finder)
    checks=[]
    # Exercise the nested runtime dependency, not only top-level imports/help.
    # 0.4.88 shipped document_context -> removed custom_windows; the first tick
    # killed its supervisor thread and closed IPC while heartbeats continued.
    from guarddesk import document_context
    if document_context.user_session_states([])!={}:raise ValueError('Empty WTS state mismatch')
    if 'guarddesk.windows_sessions' not in runtime_pyz.toc:raise ValueError('Read-only WTS runtime module missing')
    if 'guarddesk.custom_windows' in runtime_pyz.toc:raise ValueError('Control module restored to runtime')
    checks.append('nested_WTS_metadata_path_executes_with_control_module_absent')
    for name in ('endpoint_setup','usb_install','native_installer','machine_agent',
                 'machine_agent_windows','machine_agent_session','remote_native_broker',
                 'remote_admin_windows','remote_trial','endpoint_files','endpoint_package',
                 'remote_endpoint_state','endpoint_transport','windows_privilege'):
        __import__('guarddesk.'+name);checks.append('frozen_import:'+name)
    from guarddesk import remote_trial,remote_installer_entry
    # Runtime dispatcher is loaded only from its separate exact PYZ.
    runtime_entry=types.ModuleType('guarddesk.remote_endpoint_entry')
    exec(runtime_pyz.extract('guarddesk.remote_endpoint_entry'),runtime_entry.__dict__)
    entry=runtime_entry
    if not remote_trial.enabled():raise ValueError('Not a compiled trial')
    with contextlib.redirect_stdout(io.StringIO()),patch('signal.signal'),patch.object(remote_trial,'worker',return_value={'owned':True}) as worker:
        entry.main(['usb-worker','--extended','--config','owned-unused.json','--once'])
        if worker.call_args.args[0]!='owned-unused.json' or worker.call_args.kwargs!={'once':True,'restore':False}:raise ValueError('Worker dispatch mismatch')
    checks.append('frozen_worker_dispatch_legacy_argv_no_control_worker')
    cases=[('endpoint-setup',['--connection','owned.json'],'guarddesk.endpoint_setup','install',('owned.json',)),
           ('endpoint-uninstall',[],'guarddesk.endpoint_setup','uninstall',()),
           ('usb-install',['--config','owned.json','--action','Status'],'guarddesk.usb_install','install',('owned.json','Status')),
           ('machine-session',['--parent','123'],'guarddesk.machine_agent_session','run',(123,)),
           ('remote-admin-session',['--device-id','owned','--session-id','fixed'],'guarddesk.remote_admin_windows','run',('owned','fixed'))]
    for command,args,module,name,expected in cases:
        actual=sys.modules[module]
        with contextlib.redirect_stdout(io.StringIO()),patch('signal.signal'),patch.object(actual,name,return_value={}) as call:
            (remote_installer_entry if command in remote_installer_entry.INSTALLER_COMMANDS else entry).main([command,*args])
            if call.call_count!=1 or call.call_args.args[:len(expected)]!=expected:raise ValueError('Dispatch mismatch')
        checks.append('frozen_dispatch:'+command)
    from guarddesk import usb_install
    with patch('signal.signal'),patch.object(usb_install,'helper',return_value=17) as call:
        try:remote_installer_entry.main(['endpoint-native-install','--config','owned','--action','Status','--diagnostic-pipe','fixed'])
        except SystemExit as exc:
            if exc.code!=17:raise
        else:raise ValueError('Helper exit swallowed')
        call.assert_called_once_with('owned','Status','fixed')
    checks.append('frozen_native_helper_exit17_preserved')
    # Verify exact shared helper code and actual artifact bytes at the staging
    # boundary. A dedicated scratch root, no endpoint identity or install call.
    owned=build/'owned-staging-check';owned.mkdir(exist_ok=False)
    for name in ('agent','native_usb','windows_controls','application_control'):
        if 'guarddesk.'+name in pyz.toc:raise ValueError('Full control module retained')
    checks.append('full_agent_and_control_modules_physically_absent')
    from tools.remote_endpoint_artifact import FORBIDDEN_MODULES
    if FORBIDDEN_MODULES.intersection(pyz.toc):raise ValueError('Center/collection payload retained')
    checks.append('center_storage_and_collection_modules_physically_absent')
    from guarddesk.endpoint_files import read_connection
    connection=owned/'connection';connection.mkdir()
    ca=b'owned test public CA bytes only'
    (connection/'GuardDesk-CA.pem').write_bytes(ca)
    (connection/'endpoint-connection.json').write_text(json.dumps({'version':2,
        'server':'https://owned.invalid','ca':'GuardDesk-CA.pem',
        'ca_sha256':hashlib.sha256(ca).hexdigest(),'deployment_code':'a'*43}))
    if read_connection(connection/'endpoint-connection.json')[0]!='https://owned.invalid':raise ValueError('Connection contract mismatch')
    checks.append('frozen_connection_validation_without_center_store')
    from guarddesk.remote_endpoint_state import RemoteEndpointState
    from guarddesk import decommission
    state_root=owned/'remote-state';state_root.mkdir()
    config=state_root/'config.json'
    config.write_text(json.dumps({'server':'https://owned.invalid','token':'owned-fixture-only',
        'device_id':'a'*24,'install_profile':remote_trial.PROFILE}))
    state=RemoteEndpointState(config)
    decommission.remember(state,{'id':'owned-job'},'removed')
    if decommission.saved(RemoteEndpointState(config))!={'id':'owned-job','phase':'removed'}:raise ValueError('Removal state lost')
    checks.append('frozen_minimal_state_preserves_removal_on_reopen')
    with state.db() as db:db.execute("INSERT INTO outbox VALUES('owned','{}',1)")
    try:RemoteEndpointState(config)
    except PermissionError:checks.append('frozen_minimal_state_rejects_existing_audit_queue')
    else:raise ValueError('Existing audit queue adopted')
    package=owned/'package';package.mkdir()
    shutil.copytree(product,package/'GuardDesk')
    from guarddesk import __version__,endpoint_setup
    outer={'version':__version__,'files':{name:value['sha256'] for name,value in receipt['files'].items()}}
    (package/'endpoint-files.json').write_text(json.dumps(outer))
    target=owned/'client';target.mkdir()
    staged=endpoint_setup.stage_application(package,target)
    if any(digest(staged/name)!=expected for name,expected in outer['files'].items()):raise ValueError('Staged content mismatch')
    checks.append('exact_artifact_stage_application_no_scripts')
    # Same destination/content is reusable; corrupt outer manifest rejects
    # before staging another directory. Do not edit the reviewed artifact.
    if endpoint_setup.stage_application(package,target)!=staged:raise ValueError('Stage not reusable')
    checks.append('stage_reuses_exact_content')
    bad=dict(outer);bad['files']=dict(outer['files']);bad['files']['GuardDesk.exe']='0'*64
    (package/'endpoint-files.json').write_text(json.dumps(bad))
    try:endpoint_setup.stage_application(package,target)
    except ValueError:checks.append('stage_rejects_corrupt_manifest')
    else:raise ValueError('Corrupt manifest accepted')
    if len(list((target/'app').iterdir()))!=1:raise ValueError('Corrupt attempt wrote alternate installation')
    for name,value in receipt['files'].items():
        if digest(product/name)!=value['sha256']:raise ValueError('Reviewed artifact changed')
    report={'passed':True,'build_receipt_sha256':digest(build/'receipt.json'),'checks':checks,
            'check_count':len(checks),'artifact_unchanged':True,'installed':False,'network_requests':False,
            'OS_input':False,'SYSTEM_tested':False,'deployable':False,
            'scope':'Exact PYZ with mocked role effects, and real artifact staging only'}
    (build/'frozen-probe.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'checks':len(checks),'deployable':False}))

if __name__=='__main__':main()
