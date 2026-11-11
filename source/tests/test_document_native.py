import contextlib
import copy
import io
import json
import sqlite3
import struct
import tempfile
import threading
import time
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from guarddesk.document_sacl import Manager,add_audit
from guarddesk.document_io import CopyCorrelator
from guarddesk import document_settings as settings,browser_release
import test_custom_library as library_tests


def rule(path=r'C:\Company\Documents',**kwargs):return {'path':path,'recursive':True,'read':True,'copy':False,**kwargs}


def queue_fixture(agent,root):
    path=Path(root)/'queue.sqlite3';serial=[0]
    @contextlib.contextmanager
    def db():
        connection=sqlite3.connect(path)
        try:
            with connection:yield connection
        finally:connection.close()
    with db() as connection:
        connection.executescript('CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY,payload TEXT,created REAL);CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);')
    def queue(kind,details,severity,db=None,occurred=None):
        serial[0]+=1;event_id=str(serial[0]);db.execute('INSERT INTO outbox VALUES (?,?,?)',(event_id,json.dumps({'kind':kind,'details':details}),occurred or 0));return event_id
    agent.db=db;agent.queue=queue
    return agent


class Backend:
    def __init__(self):self.files={};self.value=2;self.changed=[]
    def flags(self):return self.value
    def set_flags(self,v):self.changed.append(v);self.value=v
    @contextlib.contextmanager
    def open(self,path,root):
        if str(path) not in self.files:raise FileNotFoundError(path)
        yield str(path),self.files[str(path)]
    def get(self,h):return self.files[h]['acl']
    def set(self,h,value):self.files[h]['acl']=value


class SaclTest(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.b=Backend();self.m=Manager(self.temp.name,self.b)
    def tearDown(self):self.m.close();self.temp.cleanup()
    def fixture(self,path='fixture'):
        self.b.files[path]={'identity':'one','directory':False,'acl':None,'links':1};return path
    def test_ace_preserves_original_no_inherit_no_dacl(self):
        original=add_audit(None,0x10);after=add_audit(original,3)
        self.assertEqual(after[8:28],original[8:]);self.assertEqual(after[29],0x40)
        self.assertEqual(add_audit(after,3),after)
        for malformed in (b'',b'12345678',struct.pack('<BBHHH',2,0,8,1,0)):
            with self.assertRaises(ValueError):add_audit(malformed,1)
    def test_journal_precedes_mutation_and_restore_uses_same_identity(self):
        path=self.fixture();real=self.b.set
        def set_value(h,value):
            row=self.m.db.execute('SELECT * FROM objects').fetchone();self.assertIsNotNone(row);self.assertEqual(row['state'],'pending');real(h,value)
        with patch.object(self.b,'set',side_effect=set_value):self.m.apply_one(path,'root',1)
        row=self.m.db.execute('SELECT * FROM objects').fetchone();self.m.restore_one(row)
        self.assertIsNone(self.b.get(path));self.assertEqual(self.m.db.execute('SELECT count(*) FROM objects').fetchone()[0],0)
    def test_crash_after_journal_before_set_resumes_and_rollback_idempotent(self):
        p=self.fixture()
        with patch.object(self.b,'set',side_effect=OSError('simulated crash')):
            with self.assertRaises(OSError):self.m.apply_one(p,'root',1)
        self.assertEqual(self.m.db.execute('SELECT state FROM objects').fetchone()[0],'pending')
        self.m.apply_one(p,'root',1);self.m.restore_one(self.m.db.execute('SELECT * FROM objects').fetchone());self.assertIsNone(self.b.get(p))
    def test_external_acl_replacement_and_hardlink_preserved(self):
        p=self.fixture();self.m.apply_one(p,'root',1);row=self.m.db.execute('SELECT * FROM objects').fetchone()
        self.b.files[p]['acl']=add_audit(self.b.get(p),0x20)
        with self.assertRaises(OSError):self.m.restore_one(row)
        self.b.files[p]['identity']='replacement'
        with self.assertRaises(OSError):self.m.restore_one(row)
        q=self.fixture('hardlink');self.b.files[q]['links']=2
        with self.assertRaises(OSError):self.m.apply_one(q,'root',1)
    def test_policy_preserves_failure_audit_and_external_change(self):
        self.m.policy(True);self.assertEqual(self.b.value,3)
        self.b.value=1
        with self.assertRaises(OSError):self.m.policy(False)
        self.assertEqual(self.b.value,1);self.b.value=3;self.m.policy(False);self.assertEqual(self.b.value,2)
    def test_restart_keeps_active_scope_does_not_restore_all_files(self):
        from guarddesk.store import canonical
        rules=[rule()];p=self.fixture();self.m.apply_one(p,'root',1)
        with self.m.db:self.m.db.execute("INSERT INTO meta VALUES('active',?)",(canonical(rules),))
        self.m.policy(True)
        self.m.close();self.m=Manager(self.temp.name,self.b)
        self.assertEqual(self.m.rules,rules)
        self.m.next_scan=1e30
        self.m.tick(rules)
        self.assertIsNotNone(self.b.get(p));self.assertEqual(self.m.db.execute('SELECT count(*) FROM objects').fetchone()[0],1)
    def test_restore_budget_and_excluded_files_no_mutations(self):
        for n in range(3):self.m.apply_one(self.fixture(str(n)),'root',1)
        result=self.m.tick([],budget=1,seconds=1)
        self.assertEqual(result['status'],'restoring');self.assertEqual(result['managed_objects'],2)
        self.m.excluded=lambda p:True;self.m.apply_one(self.fixture('excluded'),'root',1);self.assertIsNone(self.b.get('excluded'))
    def test_capacity_blocks_new_objects_but_keeps_existing_objects_verified(self):
        p=self.fixture()
        with patch('guarddesk.document_sacl.MAX_OBJECTS',1):
            self.m.apply_one(p,'root',1);self.m.apply_one(p,'root',1)
            with self.assertRaises(OSError):self.m.apply_one(self.fixture('second'),'root',1)


class DocumentLibraryTest(library_tests.LibraryTest):
    # Inherit fixture helpers, not all parent test methods (removed below).
    def test_document_scope_and_legacy_body_fingerprint_remain_compatible(self):
        old=self.resolve();a=self.create('documents','Case document read',[rule()]);self.bind(a,'group','parent')
        new=self.resolve();self.assertEqual(old['body'],new['body']);self.assertEqual(old['fingerprint'],new['fingerprint'])
        self.assertEqual(settings.check(new['documents']),[rule()]);self.assertFalse(self.resolve('user1')['documents']['rules'])
        self.assertEqual(new['minimum_version'],'0.4.49')
        self.bind(a,'device','dev','exclude');self.assertFalse(self.resolve()['documents']['rules'])
    def test_reject_broad_paths_schema_and_tampered_packet(self):
        for p in ('C:\\','C:\\Users','C:\\Users\\dev','C:\\Windows\\Temp','\\\\server\\share\\docs','C:\\Company\\..\\Docs','C:\\Company\\Docs:stream','C:\\Company\\*'):
            with self.assertRaises(ValueError,msg=p):settings.validate([rule(p)])
        good=settings.packet([rule()]);good['rules'][0]['copy']=True
        with self.assertRaises(ValueError):settings.check(good)
        self.assertFalse(settings.covers(r'C:\Company\Documents-other\f.txt',rule()))
        self.assertFalse(settings.covers(r'C:\Company\Documents\sub\f.txt',rule(recursive=False)))


# Avoid counting inherited cases twice in test discovery; only reuse helpers.
for _name in dir(library_tests.LibraryTest):
    if _name.startswith('test_') and _name not in DocumentLibraryTest.__dict__:setattr(DocumentLibraryTest,_name,None)


class CopyTest(unittest.TestCase):
    def setUp(self):self.now=0;self.output=[];self.c=CopyCorrelator(lambda d,t:self.output.append(d),clock=lambda:self.now)
    def e(self,op,path,**kw):return {'op':op,'path':path,'status':0,'pid':123,'offset':0,'bytes':4096,**kw}
    def test_completed_ranges_emit_only_candidate_and_dedupe(self):
        self.c.feed(self.e('read',r'C:\Docs\a.txt'));self.c.feed(self.e('write',r'C:\Docs\renamed.txt'))
        self.assertEqual(len(self.output),1);self.assertFalse(self.output[0]['operation_confirmed']);self.assertIsNone(self.output[0]['user'])
        self.c.feed(self.e('write',r'C:\Docs\renamed.txt'));self.assertEqual(len(self.output),1)
    def test_ambiguous_failed_different_pid_expired_and_gap_do_not_copy(self):
        self.c.feed(self.e('read','a'));self.c.feed(self.e('read','b'));self.c.feed(self.e('write','c'));self.assertEqual(self.output,[])
        self.c.gap();self.c.feed(self.e('read','a',status=0xC0000001));self.c.feed(self.e('write','c'));self.assertEqual(self.output,[])
        self.c.feed(self.e('read','a'));self.c.feed(self.e('write','c',pid=124));self.assertEqual(self.output,[])
        self.now=11;self.c.feed(self.e('write','c'));self.assertEqual(self.output,[])
        self.c.feed(self.e('read','a'));self.c.gap();self.c.feed(self.e('write','c'));self.assertEqual(self.output,[])
    def test_partial_outside_range_not_attested(self):
        self.c.feed(self.e('read','a'));self.c.feed(self.e('write','b',offset=4096));self.assertEqual(self.output,[])
        self.c.feed(self.e('write','b',status=0x103));self.assertEqual(self.output,[])


class BrowserReleaseTest(unittest.TestCase):
    def test_store_archive_no_keys_and_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'store';result=browser_release.build(out);self.assertEqual(result['status'],'store_publication_required')
            with zipfile.ZipFile(out/'extension-source.zip') as z:self.assertIn('manifest.json',z.namelist());self.assertFalse(any(n.endswith('.pem') for n in z.namelist()))
            with self.assertRaises(ValueError):browser_release.build(out)
    def test_wrong_key_rejected_before_output_and_crx3_signature_real(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        archive,manifest=browser_release.archive_source('https://company.example/extension/updates.xml')
        crx=browser_release.sign_crx(archive,key,public);self.assertEqual(crx[:8],b'Cr24\x03\0\0\0')
        size=struct.unpack_from('<I',crx,8)[0];self.assertEqual(crx[12+size:],archive)
        with self.assertRaises(ValueError):browser_release.sign_crx(archive,key,b'wrong identity')
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'company-key.pem';path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            out=Path(d)/'output'
            with self.assertRaises(ValueError):browser_release.build(out,'https://company.example/extension/',path)
            self.assertFalse(out.exists())


class WorkerTest(unittest.TestCase):
    def test_document_roots_do_not_expand_existing_managed_scope(self):
        from guarddesk.document_worker import DocumentWorker
        from guarddesk.policy import DEFAULT_POLICY
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);agent=SimpleNamespace(root=root,audit_runtime=root/'internal',config={'audit_watch':r'C:\Company\Approved'},custom_packet={'documents':settings.packet([rule(read=False,copy=True)]),'body':{},'busy':False})
            queue_fixture(agent,root)
            worker=DocumentWorker(agent,root);worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['scope']='managed'
            worker.trusted=True
            observed=[]
            trace=SimpleNamespace(active=True,stats={'consumer_result':0,'dropped':0},start_policy=lambda p,w,r:observed.append(w),poll=lambda:[])
            with patch('guarddesk.document_io.NativeTrace',return_value=trace):
                worker.cycle()
            self.assertEqual(observed,[r'C:\Company\Approved'])
            self.assertEqual(worker.status()['provisioning']['status'],'policy_scope_conflict');self.assertFalse(worker.status()['applied'])

    @unittest.skipUnless(sys.platform=='win32','Windows native DLL ABI')
    def test_built_dll_abi_without_starting_any_trace(self):
        from guarddesk.document_io import NativeTrace
        trace=NativeTrace();self.assertFalse(trace.active);trace.stop()

    def test_process_privilege_previous_state_cannot_race_between_companions(self):
        from guarddesk import process_audit
        active=0;maximum=0
        @contextlib.contextmanager
        def fake(api,name):
            nonlocal active,maximum
            active+=1;maximum=max(active,maximum)
            try:time.sleep(.001);yield
            finally:active-=1
        def run():
            for i in range(5):
                with process_audit.security_privilege(None):pass
        with patch('guarddesk.process_audit._security_privilege',fake):
            threads=[threading.Thread(target=run) for _ in range(4)]
            for thread in threads:thread.start()
            for thread in threads:thread.join()
        self.assertEqual((maximum,active),(1,0))

    def test_copy_only_uses_protected_native_trace_and_no_sacl_or_global_audit(self):
        from guarddesk.document_worker import DocumentWorker
        from guarddesk.policy import DEFAULT_POLICY
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);agent=SimpleNamespace(root=root,audit_runtime=root/'internal',config={'device_id':'a'*24},config_path=root/'config.json',custom_packet={'documents':settings.packet([rule(read=False,copy=True)]),'body':{},'busy':False})
            queue_fixture(agent,root)
            worker=DocumentWorker(agent,root);worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['enabled']=True
            class Trace:
                def __init__(self):self.active=False;self.started=False;self.stopped=False;self.stats={'dropped':0,'consumer_result':0,'schema_unresolved':0,'completed':0}
                def start_policy(self,policy,watch,runtime=None):self.started=True;self.active=True
                def stop(self):self.stopped=True
                def poll(self):return []
            with patch('guarddesk.custom_windows.trusted_native',return_value=root) as trusted,patch('guarddesk.update_native.protected_tree'),patch('guarddesk.document_sacl.Manager',side_effect=AssertionError('No SACL manager for copy-only')),patch('guarddesk.document_io.NativeTrace',Trace):
                worker.cycle();trace=worker.trace;self.assertTrue(trace.started);self.assertTrue(trusted.called)
                self.assertEqual(worker.status()['copy']['status'],'collecting_candidates');self.assertTrue(worker.status()['applied'])
                worker.policy['file_audit']['enabled']=False;worker.cycle();self.assertTrue(trace.stopped);self.assertEqual(worker.status()['copy']['status'],'disabled')
            self.assertFalse((root/'document-sacl.sqlite3').exists())

    def test_trace_stopped_externally_is_failure_and_released_for_retry(self):
        from guarddesk.document_worker import DocumentWorker
        from guarddesk.policy import DEFAULT_POLICY
        with tempfile.TemporaryDirectory() as d:
            worker=DocumentWorker(queue_fixture(SimpleNamespace(root=Path(d),audit_runtime=Path(d)/'internal',config={},custom_packet={'documents':settings.packet([rule(read=False,copy=True)]),'body':{},'busy':False}),d),d)
            worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['enabled']=True;worker.trusted=True
            trace=SimpleNamespace(stats={'consumer_result':995,'dropped':0},poll=lambda:[],stop=lambda:None)
            from guarddesk.document_io import ReadObserver
            worker.trace=trace;worker.trace_signature=repr((worker.policy['file_audit'],str(Path(d)),True));worker.correlator=CopyCorrelator(lambda d,t:None);worker.reader=ReadObserver(lambda d,t:None)
            worker.cycle();self.assertIsNone(worker.trace);self.assertEqual(worker.status()['copy']['status'],'trace_failed');self.assertFalse(worker.status()['applied'])


class CandidateBackpressureTest(unittest.TestCase):
    def setUp(self):
        from guarddesk.document_queue import CandidateQueue
        self.temp=tempfile.TemporaryDirectory();self.agent=queue_fixture(SimpleNamespace(),self.temp.name);self.queue=CandidateQueue(self.agent)
    def tearDown(self):self.temp.cleanup()
    def test_cap_preserves_old_events_and_recovers_with_one_durable_gap(self):
        from guarddesk.document_queue import CandidateQueue
        with self.agent.db() as db:db.execute("INSERT INTO outbox VALUES('legacy','untouched',0)")
        with patch('guarddesk.document_queue.MAX_PENDING',2):
            for i in range(3):self.queue.add({'path':str(i)},i)
            report=self.queue.flush();self.assertEqual(report['status'],'backlog_full')
            with self.agent.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM document_copy_outbox').fetchone()[0],2)
                self.assertEqual(db.execute("SELECT payload FROM outbox WHERE event_id='legacy'").fetchone()[0],'untouched')
                db.execute('DELETE FROM outbox WHERE event_id IN (SELECT event_id FROM document_copy_outbox)')
            restarted=CandidateQueue(self.agent);restarted.initialize();self.assertEqual(restarted.report['suppressed_candidates_unreported'],1)
            self.assertEqual(restarted.flush()['status'],'bounded_queue');restarted.flush()
            with self.agent.db() as db:
                rows=[json.loads(r[0]) for r in db.execute("SELECT payload FROM outbox WHERE event_id!='legacy'")]
                self.assertEqual(len(rows),1);self.assertEqual(rows[0]['kind'],'agent.audit_gap');self.assertEqual(rows[0]['details']['suppressed_candidates'],1)
    def test_failed_transaction_keeps_bounded_batch_and_rolls_back_partial_admission(self):
        real=self.agent.queue;calls=[0]
        def fail(*a,**kw):
            calls[0]+=1
            if calls[0]==2:raise sqlite3.OperationalError('fixture disk unavailable')
            return real(*a,**kw)
        self.queue.add({'path':'a'},1);self.queue.add({'path':'b'},2)
        self.agent.queue=fail
        with self.assertRaises(sqlite3.OperationalError):self.queue.flush()
        self.assertEqual(len(self.queue.buffer),2)
        with self.agent.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],0)
        self.agent.queue=real;self.queue.flush()
        with self.agent.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],2)
    def test_memory_and_transaction_batches_are_bounded(self):
        from guarddesk.document_queue import MAX_BATCH,MAX_BUFFER
        for i in range(MAX_BUFFER+10):self.queue.add({'path':str(i)},i)
        self.assertEqual(len(self.queue.buffer),MAX_BUFFER);self.assertEqual(self.queue.overflow,10)
        self.queue.flush();self.assertEqual(len(self.queue.buffer),MAX_BUFFER-MAX_BATCH)
        with self.agent.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],MAX_BATCH)
    def test_native_loss_notifications_share_the_same_durable_quota(self):
        from guarddesk.document_queue import CandidateQueue
        with patch('guarddesk.document_queue.MAX_PENDING',1):
            self.queue.add({'path':'a'},1);self.queue.flush();self.queue.trace_gap(7)
            self.assertEqual(self.queue.flush()['native_loss_counter_unreported'],7)
            with self.agent.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],1)
                db.execute('DELETE FROM outbox')
            restarted=CandidateQueue(self.agent);restarted.initialize();restarted.flush()
            with self.agent.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM document_copy_outbox').fetchone()[0],1)
                payload=json.loads(db.execute('SELECT payload FROM outbox').fetchone()[0]);self.assertEqual(payload['details']['native_loss_counter_delta'],7)
            restarted.trace_gap(3);restarted.flush()
            with self.agent.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],1)


if __name__=='__main__':unittest.main()
