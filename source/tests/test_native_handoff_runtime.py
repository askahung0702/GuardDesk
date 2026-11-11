import copy
import json
import threading
import time
import unittest
from unittest.mock import patch

from guarddesk.native_handoff_runtime import NativeHandoffRuntime
from guarddesk.file_handoff import HandoffQueue
from guarddesk import document_audit
import test_file_handoff as fixtures
import test_native_connector as connector


def eventually(test, condition, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return
        threading.Event().wait(.02)
    test.fail('Worker did not reach the required state before timeout')


def production_value(**changes):
    # Synthetic source-contract fixture; does not claim Windows authentication.
    details, occurred, eid = connector.normalized(**changes)
    details['integration'] = 'verified_native_connector'
    return details, occurred, eid


class NativeRuntimeTest(unittest.TestCase):
    setUp = fixtures.HandoffQueueTest.setUp
    tearDown = fixtures.HandoffQueueTest.tearDown
    policy = fixtures.HandoffQueueTest.policy
    rows = fixtures.HandoffQueueTest.rows

    def test_installed_default_starts_no_thread_listener_or_queue_and_cannot_claim_connected(self):
        runtime = NativeHandoffRuntime(self.agent)
        policy = self.agent.cached_policy()
        with patch.object(self.agent, 'db', side_effect=AssertionError('No DB for unavailable source')):
            for _ in range(100):
                state = runtime.step(policy)
        self.assertEqual(state['status'], 'native_adapter_missing')
        self.assertFalse(state['source_available'])
        self.assertFalse(state['browser_connected'])
        self.assertFalse(state['provider_deployment_verified'])
        self.assertIsNone(runtime._thread)
        self.assertIsNone(runtime._queue)
        self.assertTrue(runtime.close())

    def test_source_worker_to_durable_queue_and_disable_enable_restart(self):
        started = []
        class Source:
            def run(self, stop, inbox):
                started.append(1)
                inbox.offer(production_value(token='same-request'))
                stop.wait()
        runtime = NativeHandoffRuntime(self.agent, source_factory=Source)
        try:
            runtime.step(self.agent.cached_policy())
            eventually(self, lambda: len(self.rows()) == 1)
            for _ in range(30):
                runtime.step(self.agent.cached_policy())
            self.assertEqual(len(started), 1)
            self.assertFalse(runtime.snapshot()['browser_connected'])
            self.policy(False)
            runtime.step(self.agent.cached_policy())
            eventually(self, lambda: not runtime._thread.is_alive())
            self.policy(True)
            runtime._retry_at = 0
            runtime.step(self.agent.cached_policy())
            eventually(self, lambda: len(started) == 2)
        finally:
            self.assertTrue(runtime.close())
        self.assertEqual(len(self.rows()), 1)  # Stable replay identity survives worker restart.

    def test_failed_source_backoff_and_noncooperating_source_cannot_spawn_more_workers(self):
        class Failed:
            def run(self, stop, inbox):
                raise OSError('do not retain path or secret from exceptions')
        runtime = NativeHandoffRuntime(self.agent, source_factory=Failed)
        try:
            runtime.step(self.agent.cached_policy())
            eventually(self, lambda: runtime.snapshot()['status'] == 'native_source_retry')
            original = runtime._thread
            for _ in range(10):runtime.step(self.agent.cached_policy())
            self.assertIs(runtime._thread, original)
            self.assertNotIn('secret', json.dumps(runtime.snapshot()))
        finally:
            self.assertTrue(runtime.close())
        release = threading.Event()
        entered = threading.Event()
        class Stuck:
            def run(self, stop, inbox):
                entered.set()
                release.wait()
        runtime = NativeHandoffRuntime(self.agent, source_factory=Stuck)
        try:
            runtime.step(self.agent.cached_policy())
            self.assertTrue(entered.wait(2))
            self.assertFalse(runtime.close(timeout=.01))
            original = runtime._thread
            for _ in range(10):runtime.step(self.agent.cached_policy())
            self.assertIs(runtime._thread, original)
            self.assertEqual(runtime.snapshot()['status'], 'native_stopping')
        finally:
            release.set()
            self.assertTrue(runtime.close(timeout=2))

    def test_research_or_malformed_records_are_rejected_without_losing_valid_peers(self):
        queue = HandoffQueue(self.agent, verified_connector=True)
        inbox = connector.ConnectorInbox()
        inbox.offer(connector.normalized())
        inbox.offer(('bad',))
        inbox.offer(production_value(token='accepted'))
        self.assertEqual(inbox.drain(queue), {'received': 1, 'lost': 2})
        queue.flush()
        rows = self.rows()
        self.assertEqual(sum(r['kind'] == 'file.web_handoff' for r in rows), 1)
        self.assertEqual(next(r for r in rows if r['kind'] == 'agent.audit_gap')['details']['lost_records'], 2)
        with self.assertRaises(ValueError):queue.add(fixtures.record())

    def test_actual_agent_loop_reports_missing_adapter_and_closes_owned_runtime(self):
        stop = threading.Event()
        def collect(policy):
            stop.set()
        with patch('guarddesk.browser_history.BrowserHistory'), \
             patch('guarddesk.decommission.main_step', return_value=False), \
             patch.object(self.agent, 'collect_native', side_effect=collect), \
             patch.object(self.agent, 'heartbeat'), patch.object(self.agent, 'flush'):
            self.agent._run_background(stop, interval=.01)
        self.assertEqual(self.agent.feature_status['native_file_handoff']['status'], 'native_adapter_missing')
        self.assertEqual(self.agent.native_handoff.snapshot()['status'], 'stopped')
        self.assertIsNone(self.agent.native_handoff._thread)

    def test_queue_transaction_failure_preserves_batch_until_shutdown_retry(self):
        entered = threading.Event()
        class Source:
            def run(self, stop, inbox):
                inbox.offer(production_value())
                entered.set()
                stop.wait()
        runtime = NativeHandoffRuntime(self.agent, source_factory=Source)
        original = HandoffQueue.flush
        def reject_once(queue):
            if not hasattr(queue, 'test_failed'):
                queue.test_failed = True
                raise OSError('Synthetic queue fault')
            return original(queue)
        try:
            with patch.object(HandoffQueue, 'flush', reject_once):
                runtime.step(self.agent.cached_policy())
                self.assertTrue(entered.wait(2))
                eventually(self, lambda: runtime.snapshot()['status'] == 'native_queue_retry')
                self.assertEqual(len(runtime._queue.buffer), 1)
                self.assertTrue(runtime.close(timeout=2))
            self.assertEqual(len(self.rows()), 1)
        finally:
            runtime.close(timeout=2)

    def test_native_readiness_separate_from_extension_and_stale_disable(self):
        now = time.time()
        policy = self.agent.cached_policy()['body']
        device = {'inventory': {'collectors': {'native_file_handoff': {
            'status': 'native_adapter_missing', 'checked_at': now, 'browser_connected': False}}}}
        state = document_audit.readiness(device, policy, now=now)
        self.assertEqual(state['handoff']['status'], 'native_adapter_missing')
        self.assertEqual(state['upload']['status'], 'agent_not_reported')
        self.assertEqual(document_audit.readiness(device, policy, now=now+181)['handoff']['status'], 'stale')
        disabled = copy.deepcopy(policy)
        disabled['file_audit']['enabled'] = False
        self.assertEqual(document_audit.readiness(device, disabled)['handoff']['status'], 'disabled')


class RuntimeCenterTest(unittest.TestCase):
    setUp = connector.ConnectorCenterTest.setUp
    tearDown = connector.ConnectorCenterTest.tearDown
    api = connector.ConnectorCenterTest.api
    make_agent = connector.ConnectorCenterTest.make_agent

    def test_runtime_contract_source_through_agent_outbox_to_isolated_center(self):
        from urllib.parse import urlencode
        agent, device, _ = self.make_agent()
        expected = production_value()
        class Source:
            def run(self, stop, inbox):
                inbox.offer(expected)
                stop.wait()
        runtime = NativeHandoffRuntime(agent, source_factory=Source)
        try:
            agent.heartbeat()
            agent.config['audit_watch'] = r'C:\Owned'
            runtime.step(agent.cached_policy())
            eventually(self, lambda: runtime.snapshot()['observed_events'] == 1 and runtime.snapshot().get('pending') == 1)
            agent.flush()
            events = self.api('/api/events?' + urlencode({'device':device,'category':'documents','kind':'file.web_handoff'}))
            self.assertEqual(events['total'], 1)
            self.assertEqual(events['items'][0]['details'], expected[0])
        finally:
            self.assertTrue(runtime.close(timeout=2))
            agent.close_collectors()


if __name__ == '__main__':
    unittest.main()
