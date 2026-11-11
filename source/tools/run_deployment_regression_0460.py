"""Scoped deployment source regression; no company installation changes."""
import hashlib,json,os,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
NAMES=['test_bundled_release','test_easy_server_setup','test_source_permissions',
       'test_installer_entry','test_updates','test_update_windows','test_updater_refresh']

def main():
    os.chdir(ROOT);probe=uuid.uuid4().hex;log=ROOT/'runtime'/('deployment-regression-0460-'+probe+'.txt')
    files=[p for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css') and '__pycache__' not in p.parts]
    hashes=lambda:{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    before=hashes();started=time.monotonic()
    with log.open('x',encoding='utf-8') as output:result=unittest.TextTestRunner(stream=output,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
    report={'version':'0.4.60','scope':'deployment_source_and_owned_fixtures_not_field',
      'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skipped':result.skipped,
      'passed':result.wasSuccessful() and before==hashes(),'source_unchanged_during_run':before==hashes(),
      'source_sha256':before,'seconds':time.monotonic()-started,'log':str(log.relative_to(ROOT)),
      'company_changed':False,'actual_installed_updater_test':False}
    path=ROOT/'evidence'/('deployment-regression-0460-'+probe+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'}));print('evidence='+str(path))
    if not report['passed']:print(log.read_text(encoding='utf-8')[-14000:])
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
