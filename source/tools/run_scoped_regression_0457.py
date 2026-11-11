"""Final watcher delta: bounded metadata occurs outside the outbox transaction."""
import contextlib,ctypes,hashlib,io,json,sys,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from run_regression_0457 import snapshot

class TransactionBoundaryTest(unittest.TestCase):
    def test_metadata_precedes_write_and_hidden_only_batch_opens_no_transaction(self):
        from guarddesk.windows_watch import DirectoryMonitor
        from guarddesk.hidden_files import HIDDEN_RULE
        for hidden_only in (False,True):
            state={'inside':False,'transactions':0,'rows':[],'calls':0}
            @contextlib.contextmanager
            def db():
                self.assertFalse(state['inside']);state['inside']=True;state['transactions']+=1
                try:yield 'own-db'
                finally:state['inside']=False
            def queue(kind,details,**kwargs):
                self.assertTrue(state['inside']);self.assertNotIn('_path_attributes',details)
                state['rows'].append((kind,details))
            agent=SimpleNamespace(db=db,queue=queue,root=Path('C:/Owned'),audit_runtime='C:\\OwnRuntime')
            monitor=DirectoryMonitor(agent,{'file_audit':{'exclude_paths':[HIDDEN_RULE]}})
            def read(*args):
                state['calls']+=1
                if state['calls']==1:args[5]._obj.value=1;return True
                monitor.stop_event.set();return False
            def attributes(path):self.assertFalse(state['inside']);return 32
            def excluded(path,*args):self.assertFalse(state['inside']);return hidden_only or path.endswith('hidden.txt')
            monitor.w=SimpleNamespace(DWORD=ctypes.c_uint32)
            monitor.api=SimpleNamespace(ReadDirectoryChangesExW=read,GetFileAttributesW=attributes)
            entries=[(1,'hidden.txt',1,2)] if hidden_only else [(1,'visible.txt',1,32),(1,'hidden.txt',2,2)]
            with patch('guarddesk.windows_watch.decode_extended',return_value=entries),patch('guarddesk.windows_watch.excluded',side_effect=excluded):monitor._watch_background('C:\\Owned',1)
            self.assertEqual(state['transactions'],0 if hidden_only else 1)
            self.assertEqual(len(state['rows']),0 if hidden_only else 1)

def main():
    before=snapshot();start=time.monotonic();suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(TransactionBoundaryTest)])
    for pattern in ('test_hidden_files.py','test_file_collection_scope.py','test_endpoint_controls.py','test_development_exclusions.py','test_user_path_exclusions.py','test_startup_file_exclusions.py','test_internal_health_exclusions.py','test_general_file_audit.py'):
        suite.addTests(unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=pattern))
    log=ROOT/'evidence/scoped-regression-0.4.57.log'
    with log.open('w',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    after=snapshot();report={'passed':result.wasSuccessful() and before==after,'tests':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),'source_unchanged_during_run':before==after,'source_sha256':after,'elapsed_seconds':round(time.monotonic()-start,3),'log':log.relative_to(ROOT).as_posix(),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'scope':'Final watcher transaction/attribute timing delta and all directly related collection/policy tests; not added to full-run count'}
    (ROOT/'evidence/scoped-regression-0.4.57.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k!='source_sha256'}));return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
