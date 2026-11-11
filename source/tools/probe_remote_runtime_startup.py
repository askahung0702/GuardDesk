"""Mandatory runtime-PYZ startup gate. No install, enrollment, WTS launch or network."""
import argparse
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import threading
import types
import unittest
from PyInstaller.archive.readers import CArchiveReader


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--product',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    runtime=Path(__file__).resolve().parents[2]
    product=args.product.resolve(strict=True);report_path=args.report.absolute()
    if (product.name!='GuardDesk' or product.parent.name!='product' or
        not product.parent.parent.name.startswith(('remote-endpoint-build-','remote-center-build-')) or
        product.parent.parent.parent!=runtime):raise ValueError('Owned endpoint build required')
    if not report_path.resolve().is_relative_to(runtime) or report_path.exists():raise ValueError('New owned evidence path required')
    if any(name=='guarddesk' or name.startswith('guarddesk.') for name in sys.modules):raise ValueError('Fresh interpreter required')
    exe=product/'GuardDesk.exe'
    with exe.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    report={'passed':False,'runtime_exe_sha256':digest,'source_fallback_allowed':False,
        'Agent_installed':False,'network_requests':False,'WTS_user_process_launched':False,'deployable':False}
    try:
        archive=CArchiveReader(str(exe));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
        class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
            def find_spec(self,name,path=None,target=None):
                if name=='guarddesk' or name.startswith('guarddesk.'):
                    if name not in pyz.toc:raise ModuleNotFoundError('Absent frozen module '+name,name=name)
                    return importlib.util.spec_from_loader(name,self,is_package=name=='guarddesk')
            def create_module(self,spec):return None
            def exec_module(self,module):
                module.__file__=str(product/'_internal'/module.__name__.replace('.','/'))+'.py'
                exec(pyz.extract(module.__name__),module.__dict__)
        sys.meta_path.insert(0,Frozen())
        from guarddesk import document_context,machine_agent
        # Calls the nested dependency even with no logged-on user fixture.
        assert document_context.user_session_states([])=={}
        assert 'guarddesk.windows_sessions' in pyz.toc
        from guarddesk import remote_trial,machine_service
        if product.parent.parent.name.startswith('remote-endpoint-build-'):
            assert remote_trial.enabled() and 'guarddesk.custom_windows' not in pyz.toc
        else:
            assert machine_service.enabled() and not remote_trial.enabled() and 'guarddesk.custom_windows' in pyz.toc
        report['nested_dependency_executes']=True
        closed=threading.Event();stop=threading.Event();ticked=threading.Event()
        # Standard builds legitimately read their cached policy at construction.
        # Use an empty owned in-memory state table, never the installed Agent DB.
        import sqlite3
        owned_database=sqlite3.connect(':memory:');owned_database.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
        agent=types.SimpleNamespace(feature_status={},call=lambda *a,**k:None,db=lambda:owned_database)
        platform=types.SimpleNamespace(listen=lambda router:types.SimpleNamespace(close=closed.set))
        supervisor=machine_agent.Supervisor(agent,stop,platform)
        def tick():document_context.user_session_states([]);ticked.set()
        supervisor.tick=tick
        try:
            supervisor.start();assert ticked.wait(3)
            assert supervisor.thread.is_alive() and not stop.is_set() and not closed.is_set()
            report['successful_tick_preserves_listener']=True
        finally:
            stop.set()
            if supervisor.thread:supervisor.thread.join(5)
        assert not supervisor.thread.is_alive() and closed.is_set()
        owned_database.close()
        report['controlled_stop_closes_listener']=True
        # Exercise actual frozen Listener.pipe SDDL conversion and retain the
        # client's non-SYSTEM rejection using owned random pipes. Creation with
        # SYSTEM token remains an explicit field-acceptance boundary.
        spec=importlib.util.spec_from_file_location('owned_pipe_contract_tests',
            Path(__file__).resolve().parents[1]/'tests/test_machine_agent_windows.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        suite=unittest.TestSuite(fixture.WindowsTransportTest(name) for name in (
            'test_production_descriptor_explicit_system_owner_and_unchanged_dacl',
            'test_actual_pipe_owner_is_readable_and_unprivileged_server_is_rejected',
            'test_actual_authenticated_remote_bootstrap_needs_no_user_profile'))
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        assert result.wasSuccessful() and result.testsRun==3 and not result.skipped
        report['frozen_pipe_owner_contract_tests']=3
        spec=importlib.util.spec_from_file_location('owned_control_diagnostic_tests',
            Path(__file__).resolve().parents[1]/'tests/test_remote_native_broker.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        suite=unittest.TestSuite([fixture.NativeBrokerTest('test_worker_status_is_scalar_only_and_never_grants_authority')])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        assert result.wasSuccessful() and result.testsRun==1 and not result.skipped
        report['frozen_worker_status_v3_tests']=1
        report['SYSTEM_pipe_creation_tested']=False
        report['passed']=True
    except Exception as exc:
        report['error_type']=type(exc).__name__
        if isinstance(exc,AttributeError):report['missing_attribute']=exc.name
        if isinstance(exc,ModuleNotFoundError):report['missing_module']=exc.name
    with report_path.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
