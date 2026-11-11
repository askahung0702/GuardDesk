"""MIS workstation and adjacent regressions, own fixtures only."""
import hashlib,json,os,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
NAMES=['test_mis_support','test_native_remote','test_remote_clarity','test_remote_all_grants','test_remote_launcher',
 'test_easy_server_setup','test_endpoint_setup','test_installer_recovery','test_system','test_category_library','test_category_api',
 'test_management','test_updates','test_update_windows','test_update_notify']
def snapshot():
    files=[p for area in ('guarddesk','native','browser-extension') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.cpp','.h','.dll','.json') and '__pycache__' not in p.parts]
    files += [ROOT/'tests'/(n+'.py') for n in NAMES]
    files += [ROOT/'app.py',ROOT/'Start-MIS-Remote.cmd']
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
def main():
    os.chdir(ROOT);before=snapshot();uid=uuid.uuid4().hex;log=ROOT/'runtime'/('mis-regression-'+uid+'.log');start=time.monotonic()
    with log.open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
    report={'version':'0.4.61','scope':'MIS_HTTPS_and_adjacent_source_fixtures_not_field','passed':result.wasSuccessful() and before==snapshot(),
      'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skipped':result.skipped,
      'source_unchanged_during_run':before==snapshot(),'source_sha256':before,'seconds':time.monotonic()-start,'log':str(log.relative_to(ROOT)),
      'real_desktop_captured':False,'real_input_sent':False,'company_changed':False}
    path=ROOT/'evidence'/('mis-regression-'+uid+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'evidence':str(path),**{k:v for k,v in report.items() if k!='source_sha256'}}))
    if not report['passed']:print(log.read_text(encoding='utf-8')[-18000:])
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
