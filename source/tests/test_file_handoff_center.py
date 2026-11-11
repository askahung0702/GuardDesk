import json
import os
import unittest
from urllib.parse import urlencode

import test_system
import test_file_handoff as fixtures
from guarddesk.file_handoff import HandoffQueue, KIND, handoff_details
from guarddesk import audit_sort
from guarddesk.file_exclusions import excluded_activity


class HandoffCenterTest(unittest.TestCase):
    setUp = test_system.SystemTest.setUp
    tearDown = test_system.SystemTest.tearDown
    api = test_system.SystemTest.api
    make_agent = test_system.SystemTest.make_agent

    def test_original_event_replay_document_filter_csv_and_destination_sort_key(self):
        agent, did, _ = self.make_agent()
        try:
            agent.heartbeat()
            agent.config['audit_watch'] = r'C:\Owned'
            queue = HandoffQueue(agent, experimental=True)
            value = fixtures.record()
            queue.add(value)
            queue.flush()
            agent.flush()
            # Re-enqueue after server ACK, simulating receiver replay/restart.
            restarted = HandoffQueue(agent, experimental=True)
            restarted.add(value)
            restarted.flush()
            agent.flush()
            query = '/api/events?' + urlencode({'device': did, 'category': 'documents', 'kind': KIND})
            events = self.api(query)
            self.assertEqual(events['total'], 1)
            row = events['items'][0]
            details, _, identity = handoff_details(value)
            self.assertEqual(row['event_id'], identity)
            self.assertEqual(row['details'], details)
            self.assertEqual(audit_sort.keys(json.dumps(details))[2], details['site_origin'])
            self.assertEqual(self.api('/api/events?'+urlencode({'device':did,'category':'uploads'}))['total'], 0)
            csv = self.api('/api/events.csv?'+urlencode({'device':did,'category':'documents'})).decode('utf-8-sig')
            self.assertIn(KIND, csv)
            self.assertIn('https://receiver.example.test', csv)
            self.assertNotIn('https://receiver.example.test/'+details['file_name'], csv)
        finally:
            agent.close_collectors()

    def test_server_extra_exclusions_cover_new_kind_without_filtering_cross_boundary_evidence(self):
        details, _, _ = handoff_details(fixtures.record())
        self.assertTrue(excluded_activity(KIND, details, [r'C:\Owned']))
        self.assertFalse(excluded_activity(KIND, details, [r'C:\Other']))
        old = {'destination_path': r'C:\Destination', 'site_origin':'https://example.test', 'title':'old'}
        self.assertEqual(audit_sort.keys(json.dumps(old))[2], r'C:\Destination')


@unittest.skipUnless(os.name == 'nt' and os.environ.get('GUARDDESK_HANDOFF_NATIVE') == '1',
                     'Explicit native cooperating-receiver build required')
class NativeHandoffCenterTest(unittest.TestCase):
    setUp = test_system.SystemTest.setUp
    tearDown = test_system.SystemTest.tearDown
    api = test_system.SystemTest.api
    make_agent = test_system.SystemTest.make_agent
    drop = fixtures.NativeHandoffTest.drop

    @classmethod
    def setUpClass(cls):
        fixtures.NativeHandoffTest.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixtures.NativeHandoffTest.tearDownClass.__func__(cls)

    def test_real_native_com_records_through_offline_agent_to_isolated_center(self):
        self.trace.poll()
        agent, did, _ = self.make_agent()
        try:
            agent.heartbeat()
            agent.config['audit_watch'] = r'C:\Owned'
            queue = HandoffQueue(agent, experimental=True)
            self.drop(cancel=True)
            self.drop(effect=0)
            self.assertFalse(self.trace.poll()[0])
            self.drop(paths=[r'C:\Owned\first\same.txt', r'C:\Owned\second\same.txt'],
                      origin='https://first.example.test', read_on_enter=True)
            self.drop(origin='https://second.example.test')
            records, lost = self.trace.poll()
            self.assertEqual(len(records), 3)
            self.assertEqual(lost, 0)
            class Captured:
                def poll(self):
                    return records, lost
            self.assertEqual(queue.drain_native(Captured())['admitted'], 3)
            queue.flush()
            # Native callbacks have finished; no network was called on them.
            self.assertEqual(agent.queue_status()['pending'], 3)
            self.assertEqual(agent.flush()['sent'], 3)
            result = self.api('/api/events?'+urlencode({'device':did,'category':'documents','kind':KIND}))
            self.assertEqual(result['total'], 3)
            rows = result['items']
            self.assertEqual({r['details']['source_path'] for r in rows}, {r['path'] for r in records})
            self.assertEqual({r['details']['site_origin'] for r in rows}, {'https://first.example.test','https://second.example.test'})
            self.assertTrue(all(r['details']['integration']=='cooperating_receiver_prototype' for r in rows))
            self.assertTrue(all(r['details']['network_transfer']=='not_observed' for r in rows))
        finally:
            agent.close_collectors()


if __name__ == '__main__':
    unittest.main()
