"""Isolated durable-outbox tests. All transport is an in-memory ACK function."""
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guarddesk.agent import Agent, private_write
from guarddesk import event_upload
from guarddesk.serialization import canonical


class EventUploadTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.config = root/'agent.json'
        private_write(self.config, {'watch': str(root), 'device_id': 'device-a'})
        self.agent = Agent(self.config)
        self.batches = []

    def accept(self, path, body):
        self.assertEqual(path, '/api/agent/events')
        events = body['events']
        self.batches.append(events)
        return {'accepted': [e['event_id'] for e in events]}

    def write(self, eid, when=30, **fields):
        evidence = dict(source='windows_etw_file_io', aggregation='completed_write_burst',
                        path='sample.txt', native_open_id=1, process_id=123,
                        process=r'C:\Apps\writer.exe', process_identity_status='creation_time_checked',
                        first_write_observed=when, last_write_observed=when)
        return self.agent.queue('file.written', {**evidence, **fields}, occurred=when, event_id=eid)

    def test_queue_rejects_unconfirmed_writes_and_preserves_other_audit(self):
        self.assertIsNone(self.write('kernel', process_id=4))
        self.assertIsNone(self.write('missing-image', process=None))
        self.assertIsNone(self.write('missing-proof', process_identity_status=None))
        self.assertEqual(self.write('known', user=None), 'known')
        self.agent.queue('file.created', {'path':'sample.txt'}, event_id='name-change')
        self.agent.queue('agent.audit_gap', {'source':'windows_etw_file_io'}, 'warning', event_id='gap')
        self.agent.queue('file.written', {'process_id':4}, 'warning', event_id='write-warning')
        with patch.object(self.agent,'call',self.accept):
            self.assertEqual(self.agent.flush(), {'sent':4,'pending':False})
        self.assertEqual({e['event_id'] for e in self.batches[0]}, {'known','name-change','gap','write-warning'})

    def test_upgrade_drops_unconfirmed_backlog_before_transport_and_preserves_ack_retry(self):
        with self.agent.db() as db:
            for eid, details in [('kernel', {'process_id':4,'process_identity_status':'not_resolved'}),
                                 ('exited', {'process_id':123,'process_identity_status':'unavailable_or_process_replaced'})]:
                event = dict(event_id=eid,kind='file.written',severity='info',occurred=1,details=details)
                db.execute('INSERT INTO outbox VALUES (?,?,?)', (eid,canonical(event),1))
                db.execute('INSERT INTO outbox_priority VALUES (?,?)', (eid,1))
                db.execute('INSERT INTO upload_receipts VALUES (?,?,NULL)', (eid,eid))
        with patch.object(self.agent,'call') as call:
            self.assertEqual(self.agent.flush(), {'sent':0,'pending':False})
            call.assert_not_called()
        self.write('known')
        with self.agent.db() as db:
            db.execute('INSERT INTO outbox VALUES (?,?,?)', (eid,canonical(event),1))
        with patch.object(self.agent,'call',return_value={'accepted':[]}) as call, self.assertRaises(ConnectionError):
            self.agent.flush()
        self.assertEqual([item['event_id'] for item in call.call_args.args[1]['events']],['known'])
        with self.agent.db() as db:
            self.assertEqual(db.execute('SELECT event_id FROM outbox').fetchall(),[('known',)])
            self.assertEqual(db.execute('SELECT event_id FROM outbox_priority').fetchall(),[])
            self.assertEqual(db.execute('SELECT wire_id, acknowledged FROM upload_receipts').fetchall(),[('known',None)])
        self.agent = Agent(self.config)
        with patch.object(self.agent,'call',self.accept):
            self.assertEqual(self.agent.flush(), {'sent':1,'pending':False})
        self.assertEqual(self.batches[0][0]['event_id'],'known')

    def test_two_envelopes_one_upload_distinct_saves_and_users_preserved(self):
        self.write('a')
        self.write('duplicate')
        self.write('another-save', when=30.001)
        self.write('another-open', native_open_id=9)
        self.write('another-user', user='other')
        for eid in ('c', 'd'):
            self.agent.queue('file.created', {'path':'sample.txt'}, occurred=30, event_id=eid)
        with patch.object(self.agent, 'call', self.accept):
            self.assertEqual(self.agent.flush(), {'sent':6, 'pending':False})
        self.assertEqual({e['event_id'] for e in self.batches[0]},
                         {'a','another-save','another-open','another-user','c','d'})

    def test_domain_policy_merges_legacy_visits_before_send_and_after_lost_ack(self):
        from guarddesk.policy import DEFAULT_POLICY
        details = dict(user=r'EXAMPLE\reader', browser='chrome', source='browser_history', coverage='saved_visit')
        with self.agent.db() as db:
            packet = {'version':1, 'body':{**DEFAULT_POLICY, 'browser_audit':True, 'browser_visit_detail':'domain'}}
            db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)", (canonical(packet),))
        def visit(eid, when, **extra):
            self.agent.queue('web.navigation', {**details, 'url':'https://docs.example.test/'+eid,
                             'visit_id':eid, **extra}, occurred=when, event_id=eid)
        for number in range(4):
            visit(str(number), 60+number/10)
        def lose_ack(path, body):
            self.accept(path, body)
            raise ConnectionError('lost ACK')
        with patch.object(self.agent,'call',lose_ack), self.assertRaises(ConnectionError):
            self.agent.flush()
        self.assertEqual(len(self.batches[0]),1)
        self.assertEqual(self.agent.queue_status()['pending'],4)
        self.agent = Agent(self.config)
        with patch.object(self.agent,'call',self.accept):
            self.agent.flush()
            self.assertEqual(self.batches[1], self.batches[0])
            visit('late',60.9,user=r'example\READER')
            visit('next-second',61)
            visit('other-browser',60.1,browser='edge')
            visit('other-user',60.1,user=r'EXAMPLE\other')
            visit('other-domain',60.1,url='https://other.example.test/')
            self.agent.flush()
        self.assertEqual({e['event_id'] for e in self.batches[2]},
                         {'next-second','other-browser','other-user','other-domain'})
        self.assertEqual(self.agent.queue_status()['pending'],0)
        self.assertTrue(all('url' not in e['details'] for batch in self.batches for e in batch))

    def test_ack_loss_and_restart_reuse_first_wire_id(self):
        self.write('first')
        self.write('second')
        def lose_ack(path, body):
            self.accept(path, body)
            return {'accepted':['wrong']}
        with patch.object(self.agent,'call',lose_ack), self.assertRaises(ConnectionError):
            self.agent.flush()
        self.assertEqual(self.agent.queue_status()['pending'],2)
        self.agent = Agent(self.config)
        with self.agent.db() as db:
            db.execute("UPDATE outbox SET created=0 WHERE event_id='second'")
        with patch.object(self.agent, 'call', self.accept):
            self.agent.flush()
            self.write('new-envelope')
            self.agent.flush()
        self.assertEqual(self.batches[0],self.batches[1])
        self.assertEqual(len(self.batches),2)
        self.assertEqual(self.agent.queue_status()['pending'],0)

    def test_partial_ack_only_retries_missing_groups_after_restart(self):
        self.write('first');self.write('same-write')
        self.agent.queue('application.started',{'path':'editor.exe'},event_id='process')
        self.agent.queue('file.created',{'path':'report.txt'},event_id='created')
        for malformed in (['first','unknown'],['first','first']):
            with patch.object(self.agent,'call',return_value={'accepted':malformed}),self.assertRaises(ConnectionError):
                self.agent.flush()
            self.assertEqual(self.agent.queue_status()['pending'],4)
        with patch.object(self.agent,'call',return_value={'accepted':['first','process']}),self.assertRaises(ConnectionError):
            self.agent.flush()
        self.agent=Agent(self.config)
        self.assertEqual(self.agent.queue_status()['pending'],1)
        with patch.object(self.agent,'call',self.accept):
            self.agent.flush()
        self.assertEqual([e['event_id'] for e in self.batches[0]],['created'])

    def test_receipts_after_ack_expire_and_isolate_devices(self):
        for stamp, device in [(100, 'a'),(180, 'a'),(180, 'b'),(221, 'a'),
                              (101+event_upload.RECEIPT_SECONDS, 'a')]:
            self.agent.config['device_id'] = device
            with patch('time.time',return_value=stamp), patch.object(self.agent,'call',self.accept):
                self.agent.queue('web.navigation',{'domain':'fixture.test'},occurred=90,event_id='history-repeat')
                self.agent.flush()
        self.assertEqual(len(self.batches),3)

    def test_native_replay_at_capacity_after_restart_and_after_receipt_expiry(self):
        from guarddesk.document_queue import CandidateQueue
        details=dict(source='windows_etw_file_io',path='report.txt',native_open_id=9,
                     process_id=47,evidence='completed_native_read',read_bytes=64)
        observe=CandidateQueue(self.agent)
        def read(queue,when=19.25,**change):
            queue.add({**details,**change},when,'file.opened')
        with patch('guarddesk.document_queue.MAX_PENDING',1), patch('time.time',return_value=100):
            read(observe);observe.flush();read(observe)
            status=observe.flush()
            self.assertEqual((status['pending_document_events'],status['suppressed_candidates_unreported']),(1,0))
            with patch.object(self.agent,'call',self.accept):
                self.agent.flush()
        self.agent=Agent(self.config)
        observe=CandidateQueue(self.agent)
        with patch('time.time',return_value=500), patch.object(self.agent,'call',self.accept):
            read(observe);read(observe,19.26);read(observe,native_open_id=10)
            observe.flush()
            self.assertEqual(self.agent.flush()['sent'],2)
        with patch('time.time',return_value=501+event_upload.RECEIPT_SECONDS), patch.object(self.agent,'call',self.accept):
            read(observe);observe.flush();self.agent.flush()
        self.assertEqual(self.batches[0],self.batches[-1])
        self.assertEqual(len({e['event_id'] for b in self.batches for e in b}),3)
        from guarddesk.store import Store
        from guarddesk import event_storage
        for mode in ('legacy','daily'):
            store=Store(self.config.parent/(mode+'.sqlite3'))
            with store.connect() as db:
                if mode=='daily':event_storage.enable(db,store.path,snapshot_backup=False)
            for batch in self.batches:
                with store.connect() as db:
                    for e in batch:
                        Store.event(db,'device-a',e['kind'],e['severity'],e['details'],e['event_id'],e['occurred'])
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE device_id='device-a'").fetchone()[0],3)
            self.assertTrue(store.verify()['valid'])

    def test_security_warning_replay_keeps_record_time_and_distinct_records(self):
        from guarddesk.windows_events import SecurityCollector
        from guarddesk.policy import DEFAULT_POLICY
        collector=SecurityCollector(self.agent,object())
        policy={**DEFAULT_POLICY,'file_audit':{**DEFAULT_POLICY['file_audit'],'enabled':True}}
        with self.agent.db() as db:
            for record,kind in [(1,1102),(1,1102),(2,4660),(2,4660),(3,1102)]:
                collector.ingest(db,dict(event_id=kind,record_id=record,occurred=30.5,data={}),policy)
        with patch.object(self.agent,'call',self.accept):
            self.assertEqual(self.agent.flush()['sent'],3)
        self.assertEqual({e['occurred'] for e in self.batches[0]},{30.5})
        self.assertEqual({e['details']['record_id'] for e in self.batches[0]},{1,2,3})

    def test_replayed_native_reads_writes_and_copies_stay_distinct_by_object(self):
        from guarddesk.document_io import CopyCorrelator
        from guarddesk.document_queue import CandidateQueue
        q=CandidateQueue(self.agent)
        def copy():
            trace=CopyCorrelator(lambda d,t:q.add(d,t))
            sample=dict(pid=85,tid=6,offset=0,bytes=64,status=0,occurred=21.5)
            trace.feed(dict(sample,op='read',open_id=1,path='source.docx'))
            trace.feed(dict(sample,op='write',open_id=2,path='dest.docx'))
        def write(target):
            evidence=dict(source='windows_etw_file_io',path=target,process='editor.exe',process_identity_status='creation_time_checked',
                          process_id=85,native_open_id=2,aggregation='completed_write_burst',written_bytes=64,
                          first_write_observed=21.4,last_write_observed=21.5)
            q.add(evidence,21.5,'file.written')
        for _ in range(300):
            copy();write('dest.docx')
        write('different.docx')
        self.assertEqual((len(q.buffer),q.overflow),(3,0))
        q.flush()
        self.assertEqual(self.agent.queue_status()['pending'],3)
        with patch.object(self.agent,'call',self.accept):
            self.assertEqual(self.agent.flush()['sent'],3)
        self.assertEqual([e['kind'] for e in self.batches[0]].count('file.copy_candidate'),1)

    def test_native_loss_counts_survive_restart_between_reports(self):
        from guarddesk.document_queue import CandidateQueue
        q=CandidateQueue(self.agent)
        with patch('time.time') as stamp, patch('time.monotonic') as clock, patch.object(self.agent,'call',self.accept):
            stamp.return_value=100;clock.return_value=10
            q.trace_gap(3);q.flush();self.agent.flush()
            stamp.return_value=115;clock.return_value=25
            q.trace_gap(4);q.flush()
            self.assertEqual(self.agent.flush()['sent'],0)
            q=CandidateQueue(self.agent)
            q.initialize()
            stamp.return_value=130;clock.return_value=40
            q.trace_gap(5);q.flush()
            stamp.return_value=161;clock.return_value=71
            q.flush();self.agent.flush()
        self.assertEqual([b[0]['details']['native_loss_counter_delta'] for b in self.batches],[3,9])

    def test_overlapping_senders_only_one_posts_and_collection_continues(self):
        other = Agent(self.config)
        self.write('first')
        def during_request(path, body):
            self.assertEqual(other.flush(require_empty=False), {'sent':0,'pending':True})
            other.queue('file.created',{'path':'new'},event_id='second')
            return self.accept(path,body)
        with patch.object(self.agent,'call',during_request), patch.object(other,'call',side_effect=AssertionError):
            self.assertEqual(self.agent.flush(max_batches=1,require_empty=False), {'sent':1,'pending':True})
        with patch.object(other,'call',self.accept):
            other.flush()
        self.assertEqual([b[0]['event_id'] for b in self.batches],['first','second'])

    def test_upgrade_sends_warning_from_old_outbox_first_without_changing_id(self):
        with self.agent.db() as db:
            db.execute('DROP TRIGGER upload_release_reservation')
            db.execute('DROP TABLE upload_receipts')
            db.execute('DROP INDEX outbox_urgent_created')
            for n in range(120):
                self.agent.queue('file.created',{'n':n},db=db)
            self.agent.queue('export.blocked',{},'warning',event_id='old-warning',db=db)
        reopened = Agent(self.config)
        with reopened.db() as db:
            plan = db.execute(f'EXPLAIN QUERY PLAN SELECT 1 FROM outbox WHERE {event_upload.URGENT} LIMIT 1')
            self.assertIn('outbox_urgent_created',str(plan.fetchall()))
        with patch.object(reopened,'call',self.accept):
            reopened.flush()
        self.assertEqual(self.batches[0][0]['event_id'],'old-warning')
        self.assertEqual(sum(map(len,self.batches)),121)

    def test_receipt_cap_never_evicts_an_unconfirmed_observation(self):
        with patch.object(event_upload,'MAX_RECEIPTS',3), patch.object(self.agent,'call',self.accept):
            with self.agent.db() as db:
                db.execute("INSERT INTO upload_receipts VALUES ('reserved','original',NULL)")
            for n in range(5):
                self.agent.queue('file.created',{'n':n})
            self.agent.flush()
        with self.agent.db() as db:
            self.assertEqual(db.execute('SELECT count(acknowledged),count(*) FROM upload_receipts').fetchone(),(3,4))

    def test_copy_in_later_batch_and_upload_phases(self):
        self.write('write')
        with self.agent.db() as db:
            for n in range(101):
                self.agent.queue('file.created', {'n':n},db=db)
        self.write('copy')
        for eid, phase in [('r','response'),('r-copy','response'),('s','started'),('hop1','redirected'),('hop2','redirected')]:
            self.agent.queue('web.upload_'+phase,{'source':'browser_webrequest','upload_id':'flow','phase':phase},
                             occurred=20,event_id=eid)
        with patch.object(self.agent,'call',self.accept):
            self.agent.flush()
        ids = [e['event_id'] for batch in self.batches for e in batch]
        self.assertEqual(len(ids),106)
        self.assertTrue({'write','r','s','hop1','hop2'}.issubset(ids))
        self.assertFalse({'copy','r-copy'}.intersection(ids))

    def test_routine_and_priority_and_paced_backlog_use_real_queue(self):
        with patch('time.monotonic') as clock, patch('random.uniform', side_effect=lambda a,b:b), patch.object(self.agent,'call',self.accept):
            clock.return_value=0
            self.agent.queue('application.started',{})
            self.agent.upload_if_due()
            clock.return_value=115
            self.agent.upload_if_due()
            self.assertFalse(self.batches)
            clock.return_value=120
            self.agent.upload_if_due()
            self.assertEqual(len(self.batches),1)
            with self.agent.db() as db:
                for n in range(251):
                    self.agent.queue('file.created',{'n':n},db=db)
            clock.return_value=125
            self.agent.upload_if_due()
            self.assertEqual(len(self.batches),1)
            clock.return_value=130
            self.agent.queue('agent.audit_gap',{},'warning',event_id='urgent')
            self.agent.upload_if_due()
            self.assertEqual(self.batches[1][0]['event_id'],'urgent')
            self.assertEqual(len(self.batches[1]),100)
            clock.return_value=135
            self.agent.upload_if_due()
            self.assertEqual(len(self.batches),2)
            for now in (140,150):
                clock.return_value=now
                self.agent.upload_if_due()
            self.assertEqual([len(b) for b in self.batches],[1,100,100,52])
            self.assertEqual(self.agent.queue_status()['pending'],0)

    def test_200_simultaneous_starts_scatter_normal_deadlines(self):
        rng = random.Random(73)
        with patch('time.monotonic',return_value=0), patch('random.uniform',rng.uniform):
            deadlines = [event_upload.UploadSchedule().next_batch for _ in range(200)]
        self.assertTrue(all(60<=d<=120 for d in deadlines))
        self.assertEqual(len({int((d-60)//5) for d in deadlines}),12)
