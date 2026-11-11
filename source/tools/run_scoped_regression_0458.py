import hashlib,json,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from run_regression_0458 import snapshot


def main():
    before=snapshot();start=time.monotonic();suite=unittest.TestSuite()
    for pattern in ('test_context_permissions.py','test_document_interaction.py','test_browser_dispatch.py','test_browser_publication.py','test_document_audit.py'):
        suite.addTests(unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=pattern))
    log=ROOT/'evidence/scoped-regression-0.4.58.log'
    with log.open('w',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    after=snapshot();report={'passed':result.wasSuccessful() and before==after,'tests':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),'source_unchanged_during_run':before==after,'source_sha256':after,'elapsed_seconds':round(time.monotonic()-start,3),'log':log.relative_to(ROOT).as_posix(),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'scope':'Final snapshot context/permissions and signed central deployment, including added native positive/adoption/journal/conflict/restore regression; not added to full-run count'}
    (ROOT/'evidence/scoped-regression-0.4.58.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'}));return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
