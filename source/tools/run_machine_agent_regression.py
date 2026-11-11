"""Bounded source and owned-pipe regressions; never change installed endpoints."""
import hashlib,json,os,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
NAMES=['test_machine_agent','test_machine_agent_windows','test_machine_remote_global','test_machine_handoff_journals','test_transaction_status','test_native_connector_pipe','test_endpoint_setup',
       'test_native_installer','test_installer_recovery','test_source_permissions','test_updates',
       'test_update_windows','test_updater_refresh','test_update_notify','test_browser_history','test_web_upload',
       'test_browser_deployment_lifecycle','test_native_remote','test_remote_clarity','test_remote_all_grants',
       'test_mis_support','test_file_collection_scope','test_internal_health_exclusions','test_startup_file_exclusions',
       'test_application_exclusions','test_user_path_exclusions','test_development_exclusions']

def snapshot():
    paths=[p for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.html','.js','.ps1','.dll','.json')]
    paths += [ROOT/'tests'/(n+'.py') for n in NAMES]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

def main():
    from guarddesk import __version__
    before=snapshot();uid=uuid.uuid4().hex;start=time.monotonic()
    log=ROOT/'runtime'/('machine-agent-regression-'+uid+'.log')
    with log.open('x',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
    report={'version':__version__,'scope':'source_and_owned_windows_pipe_not_SYSTEM_or_field',
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':result.skipped,
        'passed':result.wasSuccessful() and before==snapshot(),'source_stable':before==snapshot(),
        'seconds':time.monotonic()-start,'source_sha256':before,'log':str(log.relative_to(ROOT)),
        'company_changed':False,'system_or_account_installed':False,'employee_desktop_captured':False}
    path=ROOT/'evidence'/('machine-agent-regression-'+uid+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'},ensure_ascii=False));print(str(path))
    if not report['passed']:print(log.read_text(encoding='utf-8')[-17000:])
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
