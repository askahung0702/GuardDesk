"""Complete a failed final-source run without hiding the original failure."""
import hashlib,io,json,os,re,sys,time,unittest,uuid
from pathlib import Path
from run_regression_0459 import snapshot,ROOT
sys.path.insert(0,str(ROOT))


def main():
    target=ROOT/'evidence/full-tests-0.4.59.json'
    original=json.loads(target.read_text(encoding='utf-8'))
    assert original['source_unchanged_during_run'] and original['source_sha256']==snapshot()
    assert original['tests']==550 and original['exit_code']==1
    log=(ROOT/original['log']).read_text(encoding='utf-8')
    assert hashlib.sha256((ROOT/original['log']).read_bytes()).hexdigest()==original['log_sha256']
    # Exact known failed setup, not a blanket retry of assertion failures.
    failed='test_storage_optimization.FastAuditAPITest.test_running_server_rejects_offline_optimizer'
    assert 'ERROR: test_running_server_rejects_offline_optimizer ('+failed+')' in log
    assert 'TimeoutError: timed out' in log
    attempt=ROOT/'evidence/full-tests-attempt-0.4.59.json'
    if not attempt.exists():attempt.write_text(json.dumps(original,indent=2),encoding='utf-8')
    sys.path.insert(0,str(ROOT/'tests'))
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    def flatten(value):
        for item in value:
            if isinstance(item,unittest.TestSuite):yield from flatten(item)
            else:yield item
    tests=list(flatten(suite));ids={test.id() for test in tests};assert len(ids)==len(tests)
    seen={identity for identity in ids if '('+identity+')' in log}
    assert len(seen)==550 and failed in seen
    remaining=[test for test in tests if test.id()==failed or test.id() not in seen]
    assert len(remaining)==len(tests)-len(seen)+1
    resumed=ROOT/('runtime/resumed-tests-0459-'+uuid.uuid4().hex[:12]+'.txt');start=time.monotonic()
    with resumed.open('w',encoding='utf-8') as out:
        result=unittest.TextTestRunner(stream=out,verbosity=2,failfast=True).run(unittest.TestSuite(remaining))
    unchanged=snapshot()==original['source_sha256']
    report={'passed':result.wasSuccessful() and unchanged,'source_unchanged_during_run':unchanged,'source_sha256':original['source_sha256'],
            'tests':len(tests),'skipped':original['skipped']+len(result.skipped),'exit_code':0 if result.wasSuccessful() else 1,
            'initial_attempt':{'report':attempt.relative_to(ROOT).as_posix(),'tests':550,'failed_setup':failed,'failure':'5-second isolated test Server login timeout before test body; cause not established','log':original['log'],'log_sha256':original['log_sha256']},
            'resume':{'tests':result.testsRun,'passed':result.wasSuccessful(),'log':resumed.relative_to(ROOT).as_posix(),'log_sha256':hashlib.sha256(resumed.read_bytes()).hexdigest(),'elapsed_seconds':round(time.monotonic()-start,3)},
            'validation_method':'One unchanged-source complete suite covered by fail-fast initial attempt plus explicit retry of failed setup and all not-yet-executed cases; original failure retained, distinct cases counted once, no tests suppressed'}
    combined=ROOT/('runtime/complete-tests-0459-'+uuid.uuid4().hex[:12]+'.txt')
    combined.write_text(log+'\n\nEXPLICIT RETRY AND REMAINING CASES\n\n'+resumed.read_text(encoding='utf-8'),encoding='utf-8')
    report.update(log=combined.relative_to(ROOT).as_posix(),log_sha256=hashlib.sha256(combined.read_bytes()).hexdigest())
    target.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'}))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
