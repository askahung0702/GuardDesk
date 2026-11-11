"""Exact frozen product/MIS lifecycle gate; fake HTTP/native only, no center."""
import argparse,hashlib,importlib.abc,importlib.util,json,sys,unittest
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True)
    p.add_argument('--role',choices=('product','mis'),required=True)
    p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[3];exe=a.exe.resolve(strict=True);report=a.report.absolute()
    if not exe.is_relative_to(root/'runtime') or not report.is_relative_to(root/'runtime') or report.exists():raise ValueError('New owned build evidence required')
    if any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules):raise ValueError('Fresh interpreter required')
    archive=CArchiveReader(str(exe));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
    class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,name,path=None,target=None):
            if name=='guarddesk' or name.startswith('guarddesk.'):
                if name not in pyz.toc:raise ModuleNotFoundError('Absent frozen module '+name)
                return importlib.util.spec_from_loader(name,self,is_package=pyz.toc[name][0] in (1,3))
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(exe.parent/'_internal'/module.__name__.replace('.','/'))+'.py'
            code=pyz.extract(module.__name__)
            if code is not None:exec(code,module.__dict__)
    sys.meta_path.insert(0,Frozen())
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
    if a.role=='product':
        names=['test_remote_session_lifecycle','test_remote_consent_once','test_remote_native_broker','test_remote_transport_recovery']
    else:
        # ImagePinTests deliberately use the product's server_setup fixture;
        # it is excluded from the MIS role. The source suite verifies that
        # boundary separately; do not add installer modules or use fallback.
        names=['test_mis_native_media.NativeControllerTests',
            'test_mis_native_media.ModuleLifetimePinsTest.test_loaded_module_capacity_and_identity_are_bounded',
            'test_mis_native_media.ModuleLifetimePinsTest.test_dll_load_failure_explicitly_releases_both_pin_sets',
            'test_mis_heartbeat_recovery.MisHeartbeatRecoveryTest',
            'test_mis_heartbeat_recovery.NativeHttpClassificationTest',
            'test_mis_heartbeat_recovery.NativeStopDiagnosticTest.test_unknown_metadata_never_leaks_or_breaks_error_handling',
            'test_mis_heartbeat_recovery.NativeStopDiagnosticTest.test_fixed_http_tls_and_authority_categories_have_specific_safe_messages',
            'test_mis_heartbeat_recovery.NativeStopDiagnosticTest.test_center_denial_and_consent_expiry_still_stop_without_retry']
    suite=unittest.defaultTestLoader.loadTestsFromNames(names)
    with report.with_suffix('.log').open('x',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    body={'passed':result.wasSuccessful() and not result.skipped,'role':a.role,'tests':result.testsRun,
        'failures':len(result.failures),'errors':len(result.errors),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
        'source_fallback_allowed':False,'center_started':False,'product_installed':False,'OS_input':False}
    report.write_text(json.dumps(body,indent=2),encoding='utf-8');print(json.dumps(body));return int(not body['passed'])

if __name__=='__main__':raise SystemExit(main())
