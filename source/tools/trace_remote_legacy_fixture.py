"""Trace unmodified failing legacy test, scalar timings only, owned HTTP."""
import json
from pathlib import Path
import statistics
import sys
import threading
import time
import unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[1]/'tests')]
from tools.remote_checkpoint_receipts import RUNTIME
from guarddesk.remote_client import RemoteClient,ViewerEngine
from guarddesk.agent import Agent

def main():
    full_suite=sys.argv[1:]==['--owned-suite']
    if not full_suite and sys.argv[1:]!=['--owned-test']:raise SystemExit('Use --owned-test or --owned-suite')
    number=1
    while (RUNTIME/f'remote-legacy-fixture-trace-{number:03}.json').exists():number+=1
    base=RUNTIME/f'remote-legacy-fixture-trace-{number:03}';rows=[];engines=[];lock=threading.Lock()
    def wrap(original,role):
        def call(self,path,*a,**k):
            started=time.perf_counter()
            try:return original(self,path,*a,**k)
            finally:
                with lock:rows.append((role,path.split('?')[0],(time.perf_counter()-started)*1000))
        return call
    RemoteClient.call=wrap(RemoteClient.call,'viewer');Agent.call=wrap(Agent.call,'endpoint')
    original_start=ViewerEngine.start
    def start(self):engines.append(self);return original_start(self)
    ViewerEngine.start=start
    name='test_native_remote.NativeRemoteTest.test_parallel_video_input_and_viewer_lease_do_not_lock_database'
    runner_exit=None
    if full_suite:
        from tools import run_remote_source_checks
        sys.argv=[sys.argv[0],'--owned-tests']
        try:run_remote_source_checks.main();runner_exit=0
        except SystemExit as error:runner_exit=error.code
    else:
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for _ in range(3))
        with base.with_suffix('.log').open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    grouped={}
    for role,path,elapsed in rows:grouped.setdefault(role+' '+path,[]).append(elapsed)
    report={'format':1,'unmodified_test':name,'full_suite':full_suite,'tests':None if full_suite else result.testsRun,'passed':runner_exit==0 if full_suite else result.wasSuccessful(),'frames':[e.stats['frames'] for e in engines],
        'HTTP':{key:{'count':len(v),'median_ms':statistics.median(v),'p95_ms':sorted(v)[max(0,int(len(v)*.95)-1)],'max_ms':max(v)} for key,v in grouped.items()},
        'desktop_capture':False,'OS_input':False,'company_product_changed':False,'product_code_changed':False}
    with base.with_suffix('.json').open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report))

if __name__=='__main__':main()
