"""Execute exact resident PYZ startup boundaries with owned files/OS adapters."""
import argparse
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import types
from unittest.mock import patch
from PyInstaller.archive.readers import CArchiveReader

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True);args=parser.parse_args()
    build=args.build.resolve(strict=True);product=build/'product/GuardDesk'
    receipt=json.loads((build/'receipt.json').read_text())
    if not receipt['passed']:raise ValueError('Reviewed build required')
    image=product/'GuardDesk.exe'
    if hashlib.sha256(image.read_bytes()).hexdigest()!=receipt['files']['GuardDesk.exe']['sha256']:raise ValueError('Resident changed')
    archive=CArchiveReader(str(image));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
    class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='guarddesk' or fullname.startswith('guarddesk.'):
                if fullname not in pyz.toc:raise ModuleNotFoundError('Absent resident module: '+fullname)
                return importlib.util.spec_from_loader(fullname,self,is_package=fullname=='guarddesk')
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(product/'_internal'/module.__name__.replace('.','/'))+'.py'
            exec(pyz.extract(module.__name__),module.__dict__)
    if any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules):raise ValueError('Fresh process required')
    sys.meta_path.insert(0,Frozen())
    owned=build/'resident-owned';owned.mkdir(exist_ok=False)
    report={'passed':False,'SYSTEM_tested':False,'installed':False,'network_requests':False,'checks':[]}
    try:
        from guarddesk import machine_agent_windows as maw,protected_files,context_permissions,remote_admin_windows,remote_service_worker,worker_startup
        for name in ('native_installer','usb_install','endpoint_setup','installer_channel'):
            if 'guarddesk.'+name in pyz.toc:raise ValueError('Installer retained in resident')
        report['checks'].append('installer_modules_physically_absent')
        path=owned/'marker.json'
        agent=types.SimpleNamespace(config={'device_id':'a'*24,'server':'https://owned.invalid','install_profile':'remote-only-trial-v1'},config_path=owned/'config.json')
        with patch.object(maw,'marker_path',return_value=path),patch.object(protected_files.ProtectedFiles,'write',side_effect=lambda path,raw:path.write_bytes(raw)),patch.object(context_permissions,'grant_read_execute'):
            maw.publish_marker(agent)
        if json.loads(path.read_text())['device_id']!='a'*24:raise ValueError('Marker publication failed')
        report['checks'].append('runtime_marker_publication_without_installer')
        platform=maw.Platform.__new__(maw.Platform);platform.agent=agent
        if not platform.can_launch():raise ValueError('Quiescent handoff failed')
        (owned/'install-transaction.json').write_text('{"phase":"switching"}')
        if platform.can_launch():raise ValueError('In-progress transaction accepted')
        report['checks'].append('runtime_handoff_rejects_active_transaction')
        # Bounded fixed status reader is also needed by real UAC helpers.
        if protected_files.read_json(path)['device_id']!='a'*24:raise ValueError('Status reader unavailable')
        report['checks'].append('runtime_protected_status_reader')
        report['passed']=True
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    (build/'resident-probe.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
    if not report['passed']:raise SystemExit(1)
if __name__=='__main__':main()
