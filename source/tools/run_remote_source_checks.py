"""Run isolated remote/control/rollout regressions and preserve a numbered receipt.

Never imports the root 0.4.70 tree, operates an installed endpoint or invokes
desktop/UAC probes. Tests own localhost servers, synthetic data and fixtures.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from contextlib import nullcontext
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
MODULES=('test_build_dependencies','test_cli_role_imports','test_updates','test_system','test_browser_trust','test_browser_publication','test_remote_test_install','test_remote_consent_once','test_native_remote','test_remote_admin','test_machine_remote_global','test_machine_agent',
    'test_remote_clarity','test_mis_support','test_remote_broker_concurrency','test_remote_m2_lifecycle',
    'test_remote_native_signaling','test_remote_components','test_remote_cohort_rollout',
    'test_remote_native_broker','test_mis_native_media','test_endpoint_payload','test_bundled_release','test_endpoint_setup','test_remote_relay','test_remote_preview_config',
    'test_remote_trial','test_remote_trial_install','test_native_installer','test_shared_deployment','test_easy_server_setup',
    'test_context_permissions','test_trial_runtime_permissions','test_worker_startup','test_install_failure_evidence',
    'test_installer_entry','test_installer_recovery','test_machine_agent_windows',
    'test_remote_transport_recovery','test_remote_endpoint_entry','test_development_exclusions','test_file_collection_scope','test_update_notify')


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def sources():
    paths=list((SOURCE/'guarddesk').glob('*.py'))+[SOURCE/'tests'/(name+'.py') for name in MODULES]+[Path(__file__).resolve(),SOURCE/'app.py',SOURCE/'app_remote_endpoint.py']
    return {p.relative_to(SOURCE).as_posix():digest(p) for p in sorted(paths)}


def main():
    if sys.argv[1:]!=['--owned-tests']:raise SystemExit('Use --owned-tests')
    # Child interpreters search cwd before PYTHONPATH. Pin both so an invocation
    # from workspace root cannot load the separate 0.4.70 product line.
    os.chdir(SOURCE)
    os.environ['PYTHONPATH']=str(SOURCE)
    os.environ['PYTHONNOUSERSITE']='1'
    sys.path[:0]=[str(SOURCE),str(SOURCE/'tests')]
    import guarddesk
    if Path(guarddesk.__file__).resolve().parent!=SOURCE/'guarddesk':raise RuntimeError('Refuse another development line')
    before=sources();number=1
    while (WORKSPACE/f'runtime/remote-m2-source-next-{number:03}.log').exists():number+=1
    path=WORKSPACE/f'runtime/remote-m2-source-next-{number:03}.log'
    suite=unittest.TestSuite()
    for name in MODULES:
        module=importlib.import_module(name)
        if Path(module.__file__).resolve().parent!=SOURCE/'tests':raise RuntimeError('Refuse external test module')
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    from guarddesk import remote_trial
    trial_build=remote_trial.enabled()
    # Existing standard-path regressions keep their original semantics. Trial
    # cases explicitly enable the compiled branch inside their individual tests.
    # Report this distinction; frozen trial CLI checks are a separate gate.
    with (patch.object(remote_trial,'ENABLED',False) if trial_build else nullcontext()):
        with path.open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    report={'format':1,'modules':list(MODULES),'sources':before,'source_stable':before==sources(),'working_directory':str(SOURCE),
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'passed':result.wasSuccessful() and before==sources(),'log_sha256':digest(path),
        'desktop_capture':False,'OS_input':False,'company_product_changed':False,'deployable':False,
        'compiled_remote_trial':trial_build,'standard_compatibility_override':trial_build,
        'trial_branch_tests':'test_remote_trial and test_remote_trial_install explicitly enable trial; frozen entry verification required'}
    with path.with_suffix('.json').open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'receipt':str(path.with_suffix('.json')),'tests':report['tests'],'passed':report['passed']}),flush=True)
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
