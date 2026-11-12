"""The 105 cumulative offline regression inventory: no center/Agent/UI launch."""
from pathlib import Path
import json,os,sys,unittest,time
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'runtime/remote-next-src'
sys.path[:0]=[str(SOURCE),str(SOURCE/'tests')]
from worktree import files
NAMES=['test_remote_session_lifecycle','test_remote_consent_once','test_remote_transport_recovery',
    'test_remote_native_broker','test_mis_native_media','test_mis_heartbeat_recovery',
    'test_remote_autonomous','test_remote_broker_concurrency','test_machine_agent',
    'test_machine_remote_global.GlobalRouterTest','test_machine_remote_global.SessionLifetimeTest',
    'test_remote_admin.AdminRouterTest','test_remote_native_signaling.NativeLeaseTest',
    'test_remote_relay.RelayPolicyTest','test_remote_build_receipts','test_remote_trial.TrialTest']
EXPECTED_SKIPS={
    'test_mis_native_media.ModuleLifetimePinsTest.test_real_cached_module_cannot_rename_after_session_close':
    'owned native cohort fixture unavailable'}
def main():
    os.chdir(SOURCE)
    import guarddesk
    if Path(guarddesk.__file__).resolve().parent!=SOURCE/'guarddesk':raise ValueError('Wrong source imported')
    before=files(ROOT/'source')
    folder=ROOT/'runtime/test-results';folder.mkdir(exist_ok=True)
    stamp=str(time.time_ns());log=folder/('unit-'+stamp+'.log')
    suite=unittest.defaultTestLoader.loadTestsFromNames(NAMES)
    with log.open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    skipped=[{'test':test.id(),'reason':reason} for test,reason in result.skipped]
    unexpected=[r for r in skipped if EXPECTED_SKIPS.get(r['test'])!=r['reason']]
    body={'format':1,'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),
        'skipped':len(result.skipped),'skip_details':skipped,'unexpected_skips':unexpected,
        'passed':result.wasSuccessful() and not unexpected and before==files(ROOT/'source'),
        'inventory':NAMES,'canonical_source_unchanged':before==files(ROOT/'source'),
        'center_started':False,'Agent_installed':False,'desktop_capture_or_input':False,'deployable':False}
    log.with_suffix('.json').write_text(json.dumps(body,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in body.items() if k!='inventory'}));print('Report='+str(log.with_suffix('.json')))
    if not body['passed']:raise SystemExit(1)
if __name__=='__main__':main()
