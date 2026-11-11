import copy
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from guarddesk.agent import Agent, private_write
from guarddesk.file_handoff import HandoffQueue, NativeHandoff, handoff_details, KIND, MAX_BUFFER
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import canonical


def record(**changes):
    return {'operation_id': '12'*16, 'occurred': time.time(), 'process_id': 100, 'thread_id': 200,
            'file_index': 0, 'file_count': 1, 'effect': 1, 'path': r'C:\Owned\報告.txt',
            'site_origin': 'https://receiver.example.test', **changes}


class HandoffMetadataTest(unittest.TestCase):
    def test_no_content_io_no_synthetic_upload_url_and_stable_per_file_identity(self):
        value = record()
        with patch('builtins.open', side_effect=AssertionError('Must not open source file')):
            details, occurred, eid = handoff_details(value)
            self.assertEqual(handoff_details(value)[2], eid)
        self.assertEqual(details['source_path'], value['path'])
        self.assertEqual(details['site_origin'], 'https://receiver.example.test')
        self.assertNotIn('url', details)
        self.assertEqual(details['network_transfer'], 'not_observed')
        self.assertEqual(details['application_success'], 'unknown')
        self.assertEqual(details['integration'], 'cooperating_receiver_prototype')
        self.assertIsNone(details['user'])
        self.assertNotEqual(handoff_details(record(operation_id='34'*16))[2], eid)
        self.assertNotEqual(handoff_details(record(file_index=1, file_count=2))[2], eid)
        self.assertEqual(occurred, value['occurred'])

    def test_reject_ambiguous_path_unbound_origin_content_and_invalid_values(self):
        changes = [
            {'path': r'C:\fakepath\x.txt'}, {'path': r'C:\Owned\..\x.txt'}, {'path': 'x.txt'},
            {'path': r'\\?\C:\Owned\x.txt'}, {'path': r'C:\Owned\x.txt:secret'}, {'path': 'C:\\Owned\\x\ny'},
            {'site_origin': 'https://receiver.example.test/?token=secret'},
            {'site_origin': 'https://name:secret@receiver.example.test'},
            {'site_origin': 'https://receiver.example.test:99999'},
            {'site_origin': 'https://receiver.example.test\\@other.test'},
            {'site_origin': 'file:///C:/Owned'}, {'site_origin': 'https://receiver.example.test/file'},
            {'file_count': 33}, {'file_index': -1}, {'file_index': 1}, {'file_count': True},
            {'process_id': True}, {'process_id': 4}, {'effect': 0}, {'effect': 8},
            {'occurred': float('nan')}, {'occurred': float('inf')}, {'occurred': time.time()+400},
            {'operation_id': 'other'}, {'bytes': 'secret'}, {'text_content': 'secret'},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                handoff_details(record(**change))


class HandoffQueueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.watch = self.root/'documents'
        self.watch.mkdir()
        config = self.root/'agent/config.json'
        private_write(config, {'server': 'http://127.0.0.1:1', 'token': 'fixture-token',
                              'device_id': 'fixture', 'watch': str(self.watch), 'audit_watch': r'C:\Owned'})
        self.agent = Agent(config)
        self.policy()
        self.queue = HandoffQueue(self.agent, experimental=True)

    def tearDown(self):
        self.agent.close_collectors()
        self.temp.cleanup()

    def policy(self, enabled=True):
        policy = copy.deepcopy(DEFAULT_POLICY)
        policy['browser_audit'] = enabled
        policy['file_audit'] = {'enabled': True, 'scope': 'managed', 'exclude_paths': [r'C:\Owned\excluded']}
        with self.agent.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES('policy',?)", (canonical({'version': 1, 'body': policy}),))
        return policy

    def rows(self):
        with self.agent.db() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox ORDER BY created,event_id')]

    def test_disabled_by_default_and_replays_survive_reopen_without_merging_new_drop(self):
        with self.assertRaises(ValueError):
            HandoffQueue(self.agent)
        value = record()
        self.queue.add(value)
        self.queue.add(value)
        self.queue.flush()
        other = HandoffQueue(Agent(self.agent.config_path), experimental=True)
        other.add(value)
        other.add(record(operation_id='34'*16))
        other.flush()
        self.assertEqual(len(self.rows()), 2)
        self.assertTrue(all(r['kind'] == KIND for r in self.rows()))
        self.assertFalse(other.report['browser_connected'])
        other.agent.close_collectors()

    def test_policy_change_before_drain_and_path_exclusion_are_enforced(self):
        self.queue.add(record())
        self.policy(False)
        self.queue.flush()
        self.assertFalse(self.rows())
        self.policy(True)
        self.queue.add(record(path=r'C:\Owned\excluded\x.txt'))
        self.queue.add(record(path=r'C:\Outside\x.txt'))
        self.queue.add(record())
        self.queue.flush()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.queue.report['policy_filtered'], 2)

    def test_offline_quota_preserves_other_events_and_persists_loss_until_capacity_returns(self):
        untouched = self.agent.queue('file.created', {'path': 'unrelated'})
        with patch('guarddesk.file_handoff.MAX_PENDING', 2):
            for i in range(3):
                self.queue.add(record(operation_id=f'{i:032x}'))
            self.queue.flush()
            self.assertEqual(self.queue.report['pending'], 2)
            self.assertEqual(self.queue.report['unreported_loss'], 1)
            restarted = HandoffQueue(self.agent, experimental=True)
            restarted.add(record(operation_id='ab'*16))
            restarted.flush()
            self.assertEqual(restarted.report['unreported_loss'], 2)
            with self.agent.db() as db:
                db.execute("DELETE FROM outbox WHERE event_id LIKE 'handoff-%'")
            restarted.next_check = 0
            restarted.flush()
        rows = self.rows()
        self.assertEqual({r['event_id'] for r in rows if r['kind']=='file.created'}, {untouched})
        gaps = [r for r in rows if r['kind']=='agent.audit_gap']
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]['details']['lost_records'], 2)
        self.assertFalse(restarted.report['unreported_loss'])

    def test_transaction_failure_retains_bounded_memory_batch_and_retries(self):
        self.queue.add(record())
        with patch.object(self.agent, 'queue', side_effect=sqlite3.OperationalError('fixture busy')):
            with self.assertRaises(sqlite3.OperationalError):
                self.queue.flush()
        self.assertEqual(len(self.queue.buffer), 1)
        self.assertFalse(self.rows())
        self.queue.flush()
        self.assertEqual(len(self.rows()), 1)
        self.assertFalse(self.queue.buffer)

    def test_persisted_loss_is_recovered_after_restart_without_new_activity(self):
        with self.agent.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES ('file_handoff_loss_v1','9')")
        restarted = HandoffQueue(self.agent, experimental=True)
        restarted.flush()
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['kind'], 'agent.audit_gap')
        self.assertEqual(rows[0]['details']['lost_records'], 9)

    def test_buffer_overflow_is_reported_and_does_not_grow_memory(self):
        for i in range(MAX_BUFFER+7):
            self.queue.add(record(operation_id=f'{i:032x}'))
        self.assertEqual(len(self.queue.buffer), MAX_BUFFER)
        self.assertEqual(self.queue.loss, 7)
        self.queue.flush()
        self.assertEqual(next(r for r in self.rows() if r['kind']=='agent.audit_gap')['details']['lost_records'], 7)

    def test_invalid_record_does_not_discard_valid_peers_or_native_gap(self):
        class Trace:
            def poll(self):
                return [record(path='filename-only.txt'), record()], 2
        result = self.queue.drain_native(Trace())
        self.assertEqual(result, {'admitted': 1, 'invalid': 1, 'native_loss': 2})
        self.queue.flush()
        rows = self.rows()
        self.assertEqual(len([r for r in rows if r['kind']==KIND]), 1)
        self.assertEqual(next(r for r in rows if r['kind']=='agent.audit_gap')['details']['lost_records'], 3)


@unittest.skipUnless(os.name == 'nt' and os.environ.get('GUARDDESK_HANDOFF_NATIVE') == '1',
                     'Explicit native cooperating-receiver build required')
class NativeHandoffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(__file__).resolve().parents[1]/'runtime/file-handoff-build'
        cls.trace = NativeHandoff(cls.directory, experimental=True)
        cls.fixture = ctypes.WinDLL(str(cls.directory/'GuardDeskHandoffFixture.dll'), winmode=0x1100)
        cls.fixture.gd_fixture_drop.argtypes = [ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_uint32,
                                               ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_long, ctypes.c_int, ctypes.c_int, ctypes.c_uint32]
        cls.fixture.gd_fixture_drop.restype = ctypes.c_long
        cls.ole = ctypes.OleDLL('ole32')
        cls.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        cls.ole.CoInitializeEx(None, 2)

    @classmethod
    def tearDownClass(cls):
        cls.ole.CoUninitialize()

    def setUp(self):
        self.trace.poll()

    def drop(self, paths=(r'C:\Owned\報告.txt',), origin='https://receiver.example.test', effect=1, result=0, cancel=False, read_on_enter=False, malformed=0):
        values = (ctypes.c_wchar_p*len(paths))(*paths)
        return self.fixture.gd_fixture_drop(values, len(paths), origin, effect, result, cancel, read_on_enter, malformed)

    def test_accepted_multifile_has_same_operation_exact_path_and_site_and_survives_receiver_release(self):
        paths = [r'C:\Owned\first\same.txt', r'C:\Owned\second\same.txt']
        self.assertEqual(self.drop(paths), 0)
        rows, lost = self.trace.poll()
        self.assertEqual(lost, 0)
        self.assertEqual([r['path'] for r in rows], paths)
        self.assertEqual(rows[0]['operation_id'], rows[1]['operation_id'])
        self.assertEqual([r['file_index'] for r in rows], [0, 1])
        self.assertTrue(all(r['process_id']==os.getpid() for r in rows))
        self.assertTrue(all(handoff_details(r)[0]['network_transfer']=='not_observed' for r in rows))

    def test_drag_enter_leave_rejected_drop_and_failed_drop_do_not_emit(self):
        self.assertEqual(self.drop(cancel=True), 0)
        self.assertEqual(self.drop(effect=0), 0)
        self.assertEqual(self.drop(result=-2147467259), -2147467259)
        rows, lost = self.trace.poll()
        self.assertFalse(rows)
        self.assertEqual(lost, 0)

    def test_context_is_bound_per_callback_and_repeated_drops_are_distinct(self):
        self.drop(origin='https://one.example.test')
        self.drop(origin='https://two.example.test')
        rows, lost = self.trace.poll()
        self.assertEqual([r['site_origin'] for r in rows], ['https://one.example.test', 'https://two.example.test'])
        self.assertNotEqual(rows[0]['operation_id'], rows[1]['operation_id'])
        self.assertEqual(lost, 0)

    def test_observer_does_not_make_extra_synchronous_data_requests(self):
        self.fixture.gd_fixture_get_data_calls.restype = ctypes.c_long
        before = self.fixture.gd_fixture_get_data_calls()
        self.drop()
        self.assertEqual(self.fixture.gd_fixture_get_data_calls() - before, 1)
        rows, lost = self.trace.poll()
        self.assertEqual(len(rows), 1)
        self.assertEqual(lost, 0)

    def test_data_object_identity_and_cached_metadata_preserved_across_enter_and_drop(self):
        self.drop(read_on_enter=True, cancel=True)
        self.assertFalse(self.trace.poll()[0])
        self.drop(read_on_enter=True)
        rows, lost = self.trace.poll()
        self.assertEqual(len(rows), 1)
        self.assertEqual(lost, 0)

    def test_missing_origin_oversized_file_list_and_path_are_gaps_preserving_drop_result(self):
        self.assertEqual(self.drop(origin=None), 0)
        self.assertEqual(self.drop(paths=[r'C:\Owned\x.txt']*33), 0)
        self.assertEqual(self.drop(paths=['C:\\Owned\\'+'x'*4096]), 0)
        rows, lost = self.trace.poll()
        self.assertFalse(rows)
        self.assertGreaterEqual(lost, 3)

    def test_native_queue_overflow_is_atomic_for_each_multifile_operation(self):
        for i in range(32):
            self.drop(paths=[fr'C:\Owned\{i}-a.txt', fr'C:\Owned\{i}-b.txt'])
        self.drop(paths=[r'C:\Owned\overflow-a.txt', r'C:\Owned\overflow-b.txt'])
        rows, lost = self.trace.poll()
        self.assertEqual(len(rows), 64)
        self.assertEqual(lost, 2)
        self.assertFalse(any('overflow' in r['path'] for r in rows))
        self.assertEqual(len({r['operation_id'] for r in rows}), 32)
        self.assertFalse(self.trace.poll()[0])

    def test_malformed_native_payloads_report_gap_without_changing_receiver_result(self):
        for variant in range(1, 6):
            self.assertEqual(self.drop(malformed=variant), 0)
        rows, lost = self.trace.poll()
        self.assertFalse(rows)
        self.assertEqual(lost, 5)

    def test_concurrent_receivers_preserve_association_and_account_for_all_capacity_loss(self):
        def produce(index):
            for i in range(100):
                self.assertEqual(self.drop(paths=[fr'C:\Owned\worker-{index}-{i}.txt'],
                                          origin=f'https://site{index}.example.test'), 0)
        received = []
        losses = 0
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(produce, i) for i in range(4)]
            while not all(f.done() for f in futures):
                rows, lost = self.trace.poll()
                received.extend(rows)
                losses += lost
                if not rows:
                    time.sleep(.001)
            for future in futures:
                future.result()
        rows, lost = self.trace.poll()
        received.extend(rows)
        losses += lost
        self.assertEqual(len(received) + losses, 400)
        self.assertEqual(len({r['operation_id'] for r in received}), len(received))
        for row in received:
            index = row['path'].split('worker-')[1].split('-')[0]
            self.assertEqual(row['site_origin'], f'https://site{index}.example.test')


if __name__ == '__main__':
    unittest.main()
