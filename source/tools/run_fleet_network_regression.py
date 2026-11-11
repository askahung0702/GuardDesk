"""Scoped read/search regressions, no installed endpoint or company data."""
import hashlib,json,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
NAMES=['test_fleet_network_search','test_improvements_integration','test_management','test_device_report_drilldown']


def snapshot():
    paths=[p for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.html','.js','.ps1','.dll','.json')]
    paths += [ROOT/'tests'/(n+'.py') for n in NAMES]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main():
    from guarddesk import __version__
    before=snapshot();uid=uuid.uuid4().hex;start=time.monotonic()
    log=ROOT/'runtime'/('fleet-network-regression-'+uid+'.log')
    with log.open('x',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
    report=dict(version=__version__,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=result.skipped,
        passed=result.wasSuccessful() and before==snapshot(),source_stable=before==snapshot(),source_sha256=before,
        seconds=time.monotonic()-start,log=str(log.relative_to(ROOT)),company_changed=False,
        scope='Owned authenticated HTTP API and isolated database, not company Server or employee endpoints')
    path=ROOT/'evidence'/('fleet-network-regression-'+uid+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'},ensure_ascii=False));print(path)
    if not report['passed']:print(log.read_text(encoding='utf-8')[-6000:])
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
