"""Targeted regression and source evidence; no release packaging or deployment."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tests'),str(ROOT)]
os.environ['GUARDDESK_HANDOFF_NATIVE'] = '1'
SOURCES = [
    'guarddesk/native_browser_identity.py','guarddesk/native_handoff_runtime.py','guarddesk/native_connector_pipe.py',
    'guarddesk/native_connector.py','guarddesk/file_handoff.py','guarddesk/agent.py',
    'guarddesk/document_audit.py','guarddesk/static/audit_ui.js',
    'tests/test_native_browser_identity.py','tests/test_native_handoff_runtime.py','tests/test_native_connector_pipe.py',
    'tests/test_native_connector.py',
    'tools/check_native_browser_identity.py','tools/review_native_handoff_runtime.py',
    'guarddesk/browser_identity.py']
MODULES = ['test_native_browser_identity','test_native_handoff_runtime','test_native_connector_pipe','test_native_connector',
           'test_file_handoff','test_file_handoff_center','test_document_audit','test_audit_sort',
           'test_performance','test_browser_deployment_lifecycle','test_browser_dispatch']


def hashes():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES}


def main():
    before = hashes()
    for name in SOURCES:
        if name.endswith('.py'):
            ast.parse((ROOT/name).read_text(encoding='utf-8-sig'),filename=name)
    js = subprocess.run(['node','--check',str(ROOT/'guarddesk/static/audit_ui.js')],capture_output=True,text=True)
    log = ROOT/'runtime/native-handoff-runtime-regression-20261028.log'
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    started = time.perf_counter()
    with log.open('w',encoding='utf-8') as stream:
        result = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    report = {'date':'2026-10-28','scope':'targeted_native_runtime_agent_and_adjacent_regression',
              'modules':MODULES,'tests_run':result.testsRun,'failures':len(result.failures),
              'errors':len(result.errors),'skipped':len(result.skipped),
              'duration_seconds':round(time.perf_counter()-started,3),
              'failure_details':[{'test':str(t),'traceback':message} for t,message in result.failures+result.errors],
              'skip_details':[{'test':str(t),'reason':message} for t,message in result.skipped],
              'ast_parse_passed':True,'javascript_syntax_passed':js.returncode==0,
              'source_sha256':before,'source_unchanged_during_tests':before==hashes(),
              'browser_capture_via_existing_profile_verified':False,
              'installed_runtime_deployment_verified':False,
              'log':str(log.relative_to(ROOT))}
    output = ROOT/'evidence/native-handoff-runtime-regression-20261028.json'
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('failure_details','skip_details','source_sha256')},ensure_ascii=False,indent=2))
    return 0 if result.wasSuccessful() and js.returncode==0 and report['source_unchanged_during_tests'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
