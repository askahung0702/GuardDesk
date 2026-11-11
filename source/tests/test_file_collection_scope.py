"""Disabled modifications never enter new logs; historical evidence stays intact."""
import time
import unittest
from unittest.mock import patch
import test_system
from test_endpoint_controls import event
from guarddesk.store import Store
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.windows_events import SecurityCollector
from guarddesk.windows_watch import RenamePairs, NOTIFY_FILTER


class FileCollectionScopeTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_queue_guard_does_not_open_database_and_security_retains_other_accesses(self):
        agent,_,_=self.make_agent()
        with patch.object(agent,'db',side_effect=AssertionError('Excluded event wrote to disk')):
            self.assertIsNone(agent.queue('file.modified',{'path':'ignored.txt'}))
        collector=SecurityCollector(agent,source=object())
        with agent.db() as db,patch.object(agent,'queue') as queue:
            collector.ingest(db,event(1,4663,mask='0x10003'),DEFAULT_POLICY)
            self.assertEqual([c.args[0] for c in queue.call_args_list],['file.opened','file.delete_requested'])
            queue.reset_mock()
            collector.ingest(db,event(2,4663,mask='0x116'),DEFAULT_POLICY)
            queue.assert_not_called()
            collector.ingest(db,event(3,4660),DEFAULT_POLICY)
            self.assertEqual(queue.call_args.args[0],'file.deleted')

    def test_native_notification_scope_preserves_create_delete_and_rename(self):
        self.assertEqual(NOTIFY_FILTER,3)
        pairs=RenamePairs()
        rows=pairs.consume([(1,r'C:\Docs\a.txt'),(3,r'C:\Docs\a.txt'),
                            (4,r'C:\Docs\a.txt'),(5,r'C:\Docs\b.txt'),(2,r'C:\Docs\b.txt')])
        self.assertEqual([r[0] for r in rows],['file.created','file.renamed','file.deleted'])
        self.assertEqual(rows[1][1]['destination_path'],r'C:\Docs\b.txt')

    def test_legacy_batch_is_acknowledged_filtered_replay_safe_and_keeps_history(self):
        agent,did,_=self.make_agent()
        with self.store.connect() as db:
            Store.event(db,did,'file.modified','info',{'path':'historical.txt'},'historical-modification')
            original=dict(db.execute('SELECT * FROM events WHERE event_id=?',('historical-modification',)).fetchone())
        events=[{'event_id':eid,'kind':kind,'details':{'path':'fixture.txt'},'severity':'info','occurred':time.time()}
                for eid,kind in [('legacy-modification','file.modified'),('new-create','file.created')]]
        for _ in range(2):
            self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[e['event_id'] for e in events])
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT id FROM events WHERE event_id=?',('legacy-modification',)).fetchone())
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE event_id=?',('new-create',)).fetchone()[0],1)
            self.assertEqual(dict(db.execute('SELECT * FROM events WHERE event_id=?',('historical-modification',)).fetchone()),original)
        self.assertTrue(self.store.verify()['valid'])
        events[0]['occurred']='invalid'
        with self.assertRaisesRegex(ConnectionError,'HTTP 400'):
            agent.call('/api/agent/events',{'events':events})
