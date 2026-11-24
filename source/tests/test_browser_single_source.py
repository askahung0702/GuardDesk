"""Single-source browsing contract using owned History DBs; no HTTP center."""
import io
import json
import unittest
from unittest.mock import patch

from guarddesk.agent import Agent
from guarddesk.browser_host import handle_message, native_read, native_write, serve_messages
import test_browser_history as history_fixture
import test_web_upload as upload_fixture


class BrowserSingleSourceTest(unittest.TestCase):
    setUp = history_fixture.BrowserHistoryTest.setUp
    tearDown = history_fixture.BrowserHistoryTest.tearDown
    policy = history_fixture.BrowserHistoryTest.policy
    events = history_fixture.BrowserHistoryTest.events

    def rows(self):
        with self.agent.db() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT payload FROM outbox')]

    def test_legacy_navigation_and_title_discarded_before_url_or_queue(self):
        for kind in ('navigation', 'page_title'):
            with self.subTest(kind=kind), patch('guarddesk.browser_host.sanitize_url', side_effect=AssertionError('not collected')), patch.object(self.agent, 'queue') as queue:
                reply = handle_message(self.agent, {'type': kind, 'url': object(), 'title': object()})
                self.assertEqual(reply, {'ok': True, 'discarded': True})
                self.assertNotIn('recorded', reply)
                queue.assert_not_called()
        self.assertEqual(self.rows(), [])

    def test_mixed_old_native_stream_drops_copies_and_keeps_real_upload(self):
        source, target = io.BytesIO(), io.BytesIO()
        messages = [{'type': kind, 'url': 'https://owned.invalid/page', 'request_id': kind}
                    for kind in ('navigation', 'page_title')]
        messages.append(upload_fixture.WebUploadTest.message(self, request_id='upload'))
        for message in messages:
            native_write(source, message)
        source.seek(0)
        serve_messages(self.agent, source, target)
        target.seek(0)
        for kind in ('navigation', 'page_title'):
            self.assertEqual(native_read(target), {'ok': True, 'discarded': True, 'request_id': kind})
        self.assertTrue(native_read(target)['recorded'])
        self.assertIsNone(native_read(target))
        self.assertEqual([row['kind'] for row in self.rows()], ['web.upload_started'])

    def test_saved_visit_and_genuine_revisit_survive_both_extension_copies(self):
        self.collector.poll()
        for ident in (1, 2):
            history_fixture.visit(self.history, ident, 'https://owned.invalid/same', 'Owned page')
            for kind in ('navigation', 'page_title'):
                handle_message(self.agent, {'type': kind, 'url': 'https://owned.invalid/same',
                                           'title': 'Owned page', 'event_id': f'browser-{kind}-{ident}'})
        self.collector.poll()
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['details']['visit_id'] for row in rows}, {1, 2})
        self.assertTrue(all(row['details']['source'] == 'browser_history' for row in rows))
        restarted = Agent(self.config)
        try:
            for kind in ('navigation', 'page_title'):
                self.assertTrue(handle_message(restarted, {'type': kind})['discarded'])
            self.collector.poll()
            self.assertEqual(self.rows(), rows)
        finally:
            restarted.close_collectors()

    def test_central_guard_only_drops_explicit_extension_browsing(self):
        with patch.object(self.agent, 'db', side_effect=AssertionError('no DB access')):
            for kind in ('web.navigation', 'web.page_title'):
                self.assertIsNone(self.agent.queue(kind, {'source': 'browser_extension'}))
        for source in ('browser_history', 'test_fixture', None):
            self.assertIsNotNone(self.agent.queue('web.navigation', {'source': source}))
        self.assertIsNotNone(self.agent.queue('web.upload_started', {'source': 'browser_extension'}))
        self.assertEqual(len(self.rows()), 4)

    def test_disabled_policy_keeps_legacy_retry_and_upload_contract(self):
        self.policy(False)
        for kind in ('navigation', 'page_title'):
            self.assertEqual(handle_message(self.agent, {'type': kind}), {'ok': True, 'recorded': False})
        self.assertFalse(handle_message(self.agent, upload_fixture.WebUploadTest.message(self))['recorded'])
        self.assertEqual(self.rows(), [])

    def test_existing_outbox_is_retained_when_new_copies_are_ignored(self):
        # Model an event collected by an old Agent before this scope changed.
        payload = {'event_id': 'browser-existing', 'kind': 'web.navigation', 'severity': 'info',
                   'occurred': 1, 'details': {'source': 'browser_extension', 'url': 'https://owned.invalid/old'}}
        with self.agent.db() as db:
            db.execute('INSERT INTO outbox VALUES (?,?,?)', (payload['event_id'], json.dumps(payload), 1))
        before = self.rows()
        for kind in ('navigation', 'page_title'):
            handle_message(self.agent, {'type': kind, 'event_id': 'browser-new'})
        self.assertEqual(self.rows(), before)


if __name__ == '__main__':
    unittest.main()
