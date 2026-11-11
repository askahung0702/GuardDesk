"""Real Windows message-mode/cancellation tests; synthetic source metadata.

The positive transport test substitutes only executable verification; it is
NOT evidence that Python is a browser or a production browser provider exists.
The default verifier is exercised by the real-Python rejection test.
"""
from contextlib import contextmanager
import ctypes
import os
import threading
import time
import unittest
from multiprocessing.connection import Client
from unittest.mock import patch

from guarddesk import native_browser_identity as identity
from guarddesk.native_connector import ConnectorInbox
from guarddesk.native_connector_pipe import LocalConnectorSource
import test_native_connector as fixtures
from test_native_browser_identity import verified_fixture
from test_native_handoff_runtime import eventually


@contextmanager
def transport_fixture_verifier(pid, *, session, sid):
    values = (pid,133000000000000000,session,r'C:\Program Files\Google\Chrome\Application\chrome.exe')
    with verified_fixture(snapshot=values,sid=sid), identity.verify_browser(pid,session=session,sid=sid) as lease:
        yield lease


@unittest.skipUnless(os.name == 'nt', 'Windows local message-mode pipe required')
class LocalPipeTest(unittest.TestCase):
    def scope(self):
        api = identity._windows()
        api.GetCurrentProcess.restype = ctypes.c_void_p
        process = api.GetCurrentProcess()
        _,_,session,_ = identity._snapshot(api,process)
        return session,identity._process_sid(process)

    @contextmanager
    def source(self, sessions=None, verify=None):
        session,sid = self.scope()
        source = LocalConnectorSource(sessions or {session:sid}, **({'_verify':verify} if verify else {}))
        stop,inbox = threading.Event(),ConnectorInbox()
        errors = []
        def run():
            try:source.run(stop,inbox)
            except Exception as exc:errors.append(type(exc).__name__)
        worker = threading.Thread(target=run,daemon=True)
        worker.start()
        self.assertTrue(source.ready.wait(3))
        self.assertFalse(errors)
        try:
            yield source,inbox
        finally:
            stop.set()
            worker.join(3)
            self.assertFalse(worker.is_alive(), 'IPC cancellation must finish before handles are released')
            self.assertFalse(errors)
            self.assertEqual(source.snapshot()['active'], 0)

    def test_real_pipe_rejects_python_process_without_queueing_request(self):
        with self.source() as (source,inbox):
            with Client(source.name,family='AF_PIPE') as client:
                client.send_bytes(fixtures.message())
                eventually(self,lambda: source.snapshot()['rejected'] > 0)
            self.assertEqual(source.snapshot()['authenticated'], 0)
            self.assertEqual(source.snapshot()['received'], 0)
            self.assertFalse(inbox._items)

    def test_real_message_mode_allow_reply_metadata_and_idle_stop_with_fixture_verifier(self):
        with self.source(verify=transport_fixture_verifier) as (source,inbox):
            with Client(source.name,family='AF_PIPE') as client:
                client.send_bytes(fixtures.message())
                self.assertTrue(client.poll(2))
                reply = fixtures._fields(client.recv_bytes(2048))
                self.assertIn(1,reply)
                eventually(self,lambda: source.snapshot()['received'] == 1)
                value = inbox._items[0]
                self.assertEqual(value[0]['process_id'], os.getpid())
                self.assertEqual(value[0]['site_origin'],'https://receiver.example.test')
                self.assertEqual(value[0]['network_transfer'],'not_observed')
                self.assertNotIn('DO_NOT_RETAIN',str(value))
            self.assertEqual(source.snapshot()['authenticated'],1)

    def test_stop_cancels_read_while_authenticated_client_stays_connected(self):
        client = None
        try:
            with self.source(verify=transport_fixture_verifier) as (source,inbox):
                client = Client(source.name,family='AF_PIPE')
                client.send_bytes(fixtures.message())
                self.assertTrue(client.poll(2))
                client.recv_bytes(2048)
                eventually(self,lambda: source.snapshot()['received'] == 1)
                self.assertEqual(source.snapshot()['active'],1)
            # The source context stopped with this peer still holding its end.
            self.assertEqual(source.snapshot()['active'],0)
        finally:
            if client:client.close()

    def test_cross_session_and_oversized_frames_never_reach_verifier(self):
        session,sid = self.scope()
        def forbidden(*args,**kwargs):self.fail('Unauthenticated scope reached executable verifier')
        with self.source({session+1000:sid},verify=forbidden) as (source,inbox):
            with Client(source.name,family='AF_PIPE') as client:
                client.send_bytes(fixtures.message())
                eventually(self,lambda: source.snapshot()['rejected'] > 0)
            self.assertFalse(inbox._items)
        with self.source(verify=forbidden) as (source,inbox):
            with Client(source.name,family='AF_PIPE') as client:
                try:client.send_bytes(b'X'*40000)
                except OSError:pass  # Server may close during the oversize write.
                eventually(self,lambda: source.snapshot()['rejected'] > 0)
            self.assertFalse(inbox._items)

    def test_idle_connects_cancel_without_client_and_allowlist_is_bounded(self):
        with self.source() as (source,inbox):
            self.assertEqual(source.snapshot()['received'],0)
        for bad in ({}, {0:'S-1-5-21-1'}, {2:'invalid'}, {i:'S-1-5-21-1' for i in range(1,10)}):
            with self.assertRaises(ValueError):LocalConnectorSource(bad)


@unittest.skipUnless(os.name == 'nt', 'Windows local message-mode pipe required')
class PipeCenterTest(unittest.TestCase):
    setUp = fixtures.ConnectorCenterTest.setUp
    tearDown = fixtures.ConnectorCenterTest.tearDown
    api = fixtures.ConnectorCenterTest.api
    make_agent = fixtures.ConnectorCenterTest.make_agent

    def test_private_pipe_transport_fixture_through_agent_runtime_to_isolated_center(self):
        from urllib.parse import urlencode
        from guarddesk.native_handoff_runtime import NativeHandoffRuntime
        session,sid = LocalPipeTest.scope(self)
        source = LocalConnectorSource({session:sid},_verify=transport_fixture_verifier)
        agent,device,_ = self.make_agent()
        runtime = NativeHandoffRuntime(agent,source_factory=lambda:source)
        try:
            agent.heartbeat()
            agent.config['audit_watch'] = r'C:\Owned'
            runtime.step(agent.cached_policy())
            self.assertTrue(source.ready.wait(3))
            with Client(source.name,family='AF_PIPE') as client:
                client.send_bytes(fixtures.message())
                self.assertTrue(client.poll(2))
                client.recv_bytes(2048)
                eventually(self,lambda: runtime.snapshot().get('pending') == 1)
            agent.flush()
            events = self.api('/api/events?'+urlencode({'device':device,'category':'documents','kind':'file.web_handoff'}))
            self.assertEqual(events['total'],1)
            details = events['items'][0]['details']
            self.assertEqual(details['source_path'],r'C:\Owned\report.txt')
            self.assertEqual(details['site_origin'],'https://receiver.example.test')
            self.assertEqual(details['process_id'],os.getpid())  # Synthetic verifier, not a real browser capture.
            self.assertEqual(details['application_success'],'unknown')
        finally:
            self.assertTrue(runtime.close(timeout=2))
            agent.close_collectors()


if __name__ == '__main__':
    unittest.main()
