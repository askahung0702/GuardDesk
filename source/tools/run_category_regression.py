"""Targeted source regression; real registry fixture uses only its owned HKCU tree."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
NAMES=['test_category_wildcards','test_category_library','test_category_api','test_category_native_worker','test_website_control','test_website_control_windows',
       'test_management','test_policy_operations','test_policy_defaults','test_custom_library','test_custom_settings',
       'test_internal_health_exclusions','test_improvements_integration','test_system','test_native_handoff_runtime',
       'test_native_browser_identity','test_native_connector_pipe','test_file_handoff','test_file_handoff_center','test_browser_drop_contract']


def hashes():
    files=[p for base in ('guarddesk','native') for p in (ROOT/base).rglob('*') if p.suffix in ('.py','.js','.html','.cpp','.h') and '__pycache__' not in str(p)]
    files += [ROOT/'tests'/(name+'.py') for name in NAMES]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def main():
    os.chdir(ROOT)
    if '--native' in sys.argv:os.environ['GUARDDESK_HANDOFF_NATIVE']='1'
    # A managed sandbox can prohibit HKCU mutation. Run that same OS fixture
    # separately with explicit tool elevation; never hide it as a passed skip.
    if '--no-registry' in sys.argv:NAMES.remove('test_website_control_windows')
    probe=uuid.uuid4().hex;log=ROOT/'runtime'/('category-regression-'+probe+'.txt');before=hashes();started=time.time()
    with log.open('w',encoding='utf-8') as output:
        result=unittest.TextTestRunner(stream=output,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
    after=hashes()
    report={'scope':'targeted_source_regression_owned_fixtures_not_field_acceptance','modules':NAMES,'tests':result.testsRun,
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'skip_reasons':result.skipped,
        'seconds':time.time()-started,'passed':result.wasSuccessful() and before==after,'source_unchanged_during_run':before==after,
        'source_sha256':after,'log':str(log.relative_to(ROOT)),'machine_browser_policy_modified':False,'new_installed_agent_test':False}
    path=ROOT/'evidence'/('category-regression-'+probe+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('source_sha256','skip_reasons')},ensure_ascii=False))
    print('evidence='+str(path))
    if not report['passed']:print(log.read_text(encoding='utf-8')[-18000:])
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
