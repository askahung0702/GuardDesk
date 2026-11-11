"""Owned HTTP failures and fake native bridge; no desktop or installed Agent."""
import ssl
import unittest
import urllib.error

from guarddesk.agent import request
from guarddesk.transport_errors import CenterTransportError, network_error, transient_heartbeat
from guarddesk.remote_native_broker import NETWORK_SLOTS
import test_remote_native_broker as fixtures


class Opener:
    def __init__(self, error): self.error=error
    def open(self, *args, **kwargs): raise self.error


class TransportCategoryTest(unittest.TestCase):
    def test_http_categories_preserve_status_without_secret_text(self):
        for status in (401,403,409,429,500,502,503,504):
            error=urllib.error.HTTPError('https://private/token',status,'secret-detail',{},None)
            with self.assertRaises(CenterTransportError) as result:
                request('https://owned.invalid','/owned',{},opener=Opener(error))
            self.assertEqual(result.exception.http_status,status)
            self.assertEqual(transient_heartbeat(result.exception),status in (502,503,504))
            self.assertNotIn('secret',str(result.exception))
            self.assertNotIn('private',str(result.exception))

    def test_tls_never_retried_and_unknown_network_not_guessed(self):
        for reason in (ssl.SSLCertVerificationError('secret'),ssl.SSLError('secret'),OSError('secret'),'timeout'):
            with self.assertRaises(CenterTransportError) as result:
                request('https://owned.invalid','/owned',{},opener=Opener(urllib.error.URLError(reason)))
            self.assertFalse(transient_heartbeat(result.exception))
            self.assertNotIn('secret',str(result.exception))
        for reason in (TimeoutError('secret'),ConnectionResetError('secret'),ConnectionAbortedError('secret')):
            self.assertTrue(transient_heartbeat(network_error(reason)))
            with self.assertRaises(CenterTransportError) as result:
                request('https://owned.invalid','/owned',{},opener=Opener(reason))
            self.assertTrue(transient_heartbeat(result.exception))


class RecoveryTest(unittest.TestCase):
    def run_network(self, errors, *, negotiated=True, answer=False, deadline=6000, current=True):
        calls=[]
        job=fixtures.NativeBrokerTest().job()
        job.reserve();job.apply(1000,fixtures.reply());job.deadline=deadline;job.current=lambda:current
        if negotiated:job.negotiated.set()
        if answer:job.signals.put_nowait({'type':'answer','sdp':'v=0\r\n'})
        def call(path,body):
            calls.append(dict(body))
            if errors:raise errors.pop(0)
            job.stop_event.set()
            return fixtures.reply()
        job.call=call
        self.assertTrue(NETWORK_SLOTS.acquire(blocking=False))
        job.network_loop()
        self.assertEqual(job.deadline,deadline) # network loop cannot renew authority
        return job,calls

    def test_established_heartbeat_retries_with_new_sequence_and_no_sdp(self):
        job,calls=self.run_network([network_error(TimeoutError())])
        self.assertEqual([c['sequence'] for c in calls],[1,2])
        self.assertTrue(all('signal' not in c for c in calls))
        self.assertIsNone(job.error)
        self.assertEqual(job.transient_retries,1)

    def test_unconfirmed_or_answer_inflight_never_replayed(self):
        for kwargs in ({'negotiated':False},{'answer':True}):
            job,calls=self.run_network([network_error(TimeoutError())],**kwargs)
            self.assertEqual(len(calls),1);self.assertIsNotNone(job.error)

    def test_two_retries_max_even_when_fake_clock_stalls(self):
        job,calls=self.run_network([network_error(TimeoutError()) for _ in range(4)])
        self.assertEqual(len(calls),3);self.assertEqual(job.transient_retries,2)
        self.assertIsNotNone(job.error)

    def test_no_retry_on_expired_near_expiry_logoff_auth_or_tls(self):
        for kwargs in ({'deadline':1000},{'deadline':1200},{'current':False}):
            job,calls=self.run_network([network_error(TimeoutError())],**kwargs)
            self.assertEqual(len(calls),1)
        for error in (CenterTransportError('http',http_status=403),network_error(ssl.SSLError()),ConnectionError('unknown')):
            job,calls=self.run_network([error]);self.assertEqual(len(calls),1)


if __name__=='__main__':unittest.main()
