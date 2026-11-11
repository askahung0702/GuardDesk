"""Fake native/HTTP/clock only: no center, socket, desktop, Agent or OS input."""
import io
import json
from pathlib import Path
import ssl
import unittest
import urllib.error
from unittest.mock import patch

from guarddesk.remote_client import RemoteClient,RemoteClientError
from guarddesk.transport_errors import CenterTransportError,network_error,transient_heartbeat
import test_mis_native_media as native_fixtures


def reply(answer=False):
    return dict(native_wire=1,transport_generation=1,authorized=True,lease_seconds=4,mode='view',
        signal={'type':'answer','sdp':'v=0\r\nowned-answer'} if answer else None)


class ClockEvent:
    def __init__(self,clock,on_wait=None):self.clock=clock;self.flag=False;self.on_wait=on_wait;self.waits=[]
    def is_set(self):return self.flag
    def set(self):self.flag=True
    def wait(self,delay):
        self.waits.append(delay)
        if not self.flag:
            self.clock[0]+=round(delay*1000)
            if self.on_wait:self.on_wait(delay)
        return self.flag


class Scenario:
    def __init__(self,actions,*,stop_after_grants=2,offer=False):
        self.clock=[1000];self.calls=[];self.timeouts=[];self.actions=list(actions)
        self.library=native_fixtures.FakeLibrary();self.library.tick=lambda:self.clock[0]
        owner=self
        class Client:
            def call(self,path,body):
                owner.calls.append(dict(body))
                value=owner.actions.pop(0)
                if callable(value):value=value()
                if isinstance(value,Exception):raise value
                return value
        self.client=Client()
        self.controller=native_fixtures.NativeControllerTests().controller(self.client,self.library)
        self.controller.handle=1;self.controller.stop_event=ClockEvent(self.clock)
        if offer:self.controller.offers.put_nowait({'type':'offer','sdp':'v=0\r\nowned-offer'})
        def post(handle,deadline,signal):
            if deadline:self.library.grants.append(deadline)
            if len(self.library.grants)>=stop_after_grants:self.controller.stop_event.set()
        self.library.post_reply=post

    def run(self):self.controller._network();return self

    def classified_client(self):
        ordinary=self.client.call
        def exchange(body,*,timeout=3):
            self.timeouts.append(timeout)
            return ordinary('/api/remote/native',body)
        self.client.native_exchange=exchange
        return self


class MisHeartbeatRecoveryTest(unittest.TestCase):
    def test_one_transient_after_answer_recovers_with_new_sequence(self):
        s=Scenario([reply(True),network_error(TimeoutError('owned')),reply()],offer=True).run()
        self.assertEqual([c['sequence'] for c in s.calls],[1,2,3])
        self.assertIn('signal',s.calls[0])
        self.assertTrue(all('signal' not in c for c in s.calls[1:]))
        self.assertEqual(len(s.library.grants),2)
        self.assertIsNone(s.controller.error)
        self.assertEqual(s.controller.transient_retries,1)

    def test_two_retries_bound_and_success_resets_consecutive_failures(self):
        failure=lambda:network_error(TimeoutError('owned'))
        s=Scenario([reply(True),failure(),failure(),failure()]).run()
        self.assertEqual(len(s.calls),4)
        self.assertEqual(s.controller.transient_retries,2)
        self.assertTrue(s.controller.stop_event.is_set())
        self.assertEqual(len(s.library.grants),1)
        recovered=Scenario([reply(True),failure(),reply(),failure(),reply()],stop_after_grants=3).run()
        self.assertEqual(len(recovered.calls),5)
        self.assertIsNone(recovered.controller.error)
        self.assertEqual(len(recovered.library.grants),3)

    def test_offer_or_unanswered_negotiation_is_never_replayed(self):
        failure=network_error(TimeoutError('owned'))
        first=Scenario([failure],offer=True).run()
        self.assertEqual(len(first.calls),1)
        self.assertIn('signal',first.calls[0])
        unconfirmed=Scenario([reply(),failure]).run()
        self.assertEqual(len(unconfirmed.calls),2)
        self.assertEqual(getattr(unconfirmed.controller,'transient_retries',0),0)

    def test_auth_tls_unknown_and_nontransient_http_do_not_retry(self):
        errors=[network_error(ssl.SSLCertVerificationError('secret')),OSError('secret')]
        errors.extend(CenterTransportError('http',http_status=status) for status in (401,403,409,429,500))
        for error in errors:
            with self.subTest(error=type(error).__name__,status=getattr(error,'http_status',None)):
                s=Scenario([reply(True),error]).run()
                self.assertEqual(len(s.calls),2)
                self.assertEqual(len(s.library.grants),1)
                self.assertIsNotNone(s.controller.error)
                self.assertNotIn('secret',json.dumps(s.controller.error))

    def test_gateway_transients_recover_only_with_live_grant(self):
        for status in (502,503,504):
            with self.subTest(status=status):
                s=Scenario([reply(True),CenterTransportError('http',http_status=status),reply()]).run()
                self.assertEqual(len(s.calls),3)
                self.assertIsNone(s.controller.error)

    def test_near_expiry_and_cancellation_do_not_retry(self):
        s=Scenario([reply(True)])
        def expired():s.clock[0]=4900;return network_error(TimeoutError())
        s.actions.append(expired);s.run()
        self.assertEqual(len(s.calls),2)
        self.assertEqual(getattr(s.controller,'transient_retries',0),0)
        cancelled=Scenario([reply(True),network_error(TimeoutError()),reply()])
        cancelled.controller.stop_event.on_wait=lambda delay:cancelled.controller.stop_event.set() if delay<.3 else None
        cancelled.run()
        self.assertEqual(len(cancelled.calls),2)
        self.assertEqual(len(cancelled.library.grants),1)

    def test_success_after_original_lease_expired_cannot_revive(self):
        for transient in (False,True):
            s=Scenario([reply(True)])
            if transient:s.actions.append(network_error(TimeoutError()))
            def late():s.clock[0]=5001;return reply()
            s.actions.append(late);s.run()
            with self.subTest(transient=transient):
                self.assertEqual(len(s.library.grants),1)
                self.assertEqual(s.controller.error['diagnostic'],'native_short_lease_expired')

    def test_native_http_timeout_is_capped_by_remaining_lease(self):
        s=Scenario([reply(True)])
        def short():
            s.clock[0]=4500
            return network_error(TimeoutError())
        s.actions.extend([short,reply()])
        s.classified_client().run()
        self.assertEqual(len(s.calls),3)
        self.assertEqual(s.timeouts[0],3)
        self.assertGreater(s.timeouts[-1],0)
        self.assertLessEqual(s.timeouts[-1],.4)
        self.assertIsNone(s.controller.error)


class Opener:
    def __init__(self,error):self.error=error;self.timeouts=[]
    def open(self,request,timeout):self.timeouts.append(timeout);raise self.error


class NativeHttpClassificationTest(unittest.TestCase):
    def client(self,error):
        client=RemoteClient();client.opener=Opener(error);return client

    def test_native_classifies_http_without_leaking_body_or_url(self):
        for status in (401,403,429,500,502,503,504):
            body=io.BytesIO(b'{"error":"secret-body"}')
            client=self.client(urllib.error.HTTPError('https://secret/private',status,'secret-reason',{},body))
            with self.subTest(status=status),self.assertRaises(CenterTransportError) as caught:
                client.native_exchange({'sequence':1})
            self.assertEqual(caught.exception.http_status,status)
            self.assertEqual(transient_heartbeat(caught.exception),status in (502,503,504))
            self.assertNotIn('secret',str(caught.exception))
            self.assertTrue(body.closed)

    def test_tls_unknown_and_temporary_errors_keep_narrow_categories(self):
        for reason,retry in ((ssl.SSLCertVerificationError('secret'),False),(ssl.SSLError('secret'),False),
            (OSError('secret'),False),(TimeoutError('secret'),True),(ConnectionResetError('secret'),True)):
            client=self.client(urllib.error.URLError(reason))
            with self.subTest(kind=type(reason).__name__),self.assertRaises(CenterTransportError) as caught:
                client.native_exchange({})
            self.assertEqual(transient_heartbeat(caught.exception),retry)
            self.assertNotIn('secret',str(caught.exception))

    def test_legacy_call_keeps_exception_and_message_contract(self):
        client=self.client(urllib.error.HTTPError('https://owned.invalid',403,'owned',{},io.BytesIO(b'{"error":"owned legacy message"}')))
        with self.assertRaises(RemoteClientError) as caught:client.call('/api/remote/native',{})
        self.assertEqual(str(caught.exception),'owned legacy message')
        client=self.client(urllib.error.URLError(TimeoutError()))
        with self.assertRaises(RemoteClientError) as caught:client.call('/api/remote/native',{})
        self.assertEqual(str(caught.exception),'管理中心連線中斷；已停止遠端操作')

    def test_native_timeout_is_bounded_and_legacy_timeout_unchanged(self):
        for timeout in (0,-1,3.1,float('nan'),float('inf'),True):
            client=self.client(TimeoutError())
            with self.subTest(timeout=str(timeout)),self.assertRaises(ValueError):client.native_exchange({},timeout=timeout)
            self.assertEqual(client.opener.timeouts,[])
        client=self.client(TimeoutError())
        with self.assertRaises(CenterTransportError):client.native_exchange({},timeout=.25)
        self.assertEqual(client.opener.timeouts,[.25])
        client=self.client(TimeoutError())
        with self.assertRaises(RemoteClientError):client.call('/api/remote/native',{})
        self.assertEqual(client.opener.timeouts,[3])



    def test_native_and_legacy_success_preserve_routing_body_and_csrf(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return b'{"ok":true}'
        class Success:
            def open(self,request,timeout):self.request=request;self.timeout=timeout;return Response()
        for workstation in (False,True):
            for native in (False,True):
                client=RemoteClient()
                client.workstation=workstation
                client.server='https://owned.invalid' if workstation else 'http://127.0.0.1:8788'
                client.csrf='owned-csrf'
                client.opener=Success()
                body={'sequence':1}
                result=client.native_exchange(body) if native else client.call('/api/remote/native',body)
                with self.subTest(workstation=workstation,native=native):
                    self.assertEqual(result,{'ok':True})
                    expected='/api/support/native' if workstation else '/api/remote/native'
                    self.assertEqual(client.opener.request.full_url,client.server+expected)
                    self.assertEqual(client.opener.request.get_method(),'POST')
                    self.assertEqual(json.loads(client.opener.request.data),body)
                    headers={k.lower():v for k,v in client.opener.request.header_items()}
                    self.assertEqual(headers['x-csrf-token'],'owned-csrf')
                    self.assertEqual(client.opener.timeout,3)

    def test_malformed_or_oversized_response_never_becomes_retryable(self):
        class Response:
            def __init__(self,payload):self.payload=payload
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return self.payload
        for payload in (b'[]',b'secret-invalid-json',b'x'*(1048576+1)):
            client=RemoteClient()
            class Success:
                def open(self,*args,**kwargs):return Response(payload)
            client.opener=Success()
            with self.assertRaises(RemoteClientError) as caught:client.native_exchange({})
            self.assertFalse(transient_heartbeat(caught.exception))
            self.assertNotIn('secret',str(caught.exception))



class NativeStopDiagnosticTest(unittest.TestCase):
    def test_unknown_metadata_never_leaks_or_breaks_error_handling(self):
        from guarddesk.mis_native_media import native_stop_message
        for diagnostic in ('secret-body',['secret-body'],{'secret':'body'},None):
            controller=Scenario([]).controller
            error=OSError('secret-body')
            error.remote_diagnostic=diagnostic
            controller._fail(error)
            self.assertNotIn('secret',json.dumps(controller.error))
            message=native_stop_message({'diagnostic':diagnostic,'message':'secret-body'})
            self.assertNotIn('secret',message)

    def test_fixed_http_tls_and_authority_categories_have_specific_safe_messages(self):
        from guarddesk.mis_native_media import native_stop_message
        from guarddesk.transport_errors import native_authority_error
        for error,expected in ((CenterTransportError('http',http_status=403),'中心登入或協助授權'),
            (network_error(ssl.SSLCertVerificationError('secret')),'安全連線驗證'),
            (native_authority_error('native_short_lease_expired'),'未能及時續期')):
            controller=Scenario([]).controller
            controller._fail(error)
            self.assertIn(expected,native_stop_message(controller.error))
            self.assertNotIn('secret',json.dumps(controller.error))

    def test_center_denial_and_consent_expiry_still_stop_without_retry(self):
        s=Scenario([reply(True),{**reply(),'authorized':False,'lease_seconds':0}]).run()
        self.assertEqual(len(s.calls),2)
        self.assertEqual(len(s.library.grants),1)
        self.assertEqual(s.controller.error['diagnostic'],'native_authority_lost')
        expired=Scenario([reply(True)])
        expired.controller.config.consent_deadline=1000
        expired.run()
        self.assertEqual(expired.calls,[])
        self.assertEqual(expired.controller.error['diagnostic'],'native_consent_expired')

    def test_endpoint_permission_errors_keep_bounded_exact_reason_through_inventory(self):
        import test_remote_native_broker as fixtures
        from guarddesk.remote_native_broker import NETWORK_SLOTS
        from guarddesk.remote_trial import native_diagnostics
        for reason in ('native_binding_expired','native_consent_expired','native_short_lease_expired','native_handshake_timeout'):
            job=fixtures.NativeBrokerTest().job()
            job.reserve()
            if reason=='native_binding_expired':job.current=lambda:False
            elif reason=='native_consent_expired':job.spec.consent_tick_deadline=1000
            elif reason=='native_short_lease_expired':job.granted=True;job.deadline=1000
            else:
                ticks=iter((1000,17000))
                job.library.tick=lambda:next(ticks)
            job.network_loop=lambda:NETWORK_SLOTS.release()
            job.run()
            with self.subTest(reason=reason):
                self.assertEqual(job.error['error_type'],'PermissionError')
                self.assertEqual(job.error['diagnostic'],reason)
                self.assertTrue(job.done.is_set())
                class Launcher:
                    def snapshot(self):
                        return {'contexts':[{'phase':'native_transport','state':'ended','error':job.error,
                            'media':{'age_ms':400000},'worker':{'age_ms':400000}}]}
                diagnostic=native_diagnostics(launcher=Launcher())['contexts'][0]
                self.assertEqual(diagnostic['error']['diagnostic'],reason)
                self.assertFalse(diagnostic['fresh'])


if __name__=='__main__':
    unittest.main()
