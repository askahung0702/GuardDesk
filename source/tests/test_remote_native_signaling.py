"""Native signaling authorization over owned HTTP; no desktop, input or Agent install."""
import json
import unittest
from unittest.mock import patch
from guarddesk.remote_native import NativeSession,FEATURES
from guarddesk.remote import RemoteError
from guarddesk.remote_client import RemoteClient,RemoteClientError
import test_native_remote

SDP='v=0\r\na=fingerprint:sha-256 '+':'.join(['AB']*32)+'\r\n'
BIND={'wts_session':6,'logon_generation':'a'*32}
CAPS={'wire':1,'cohort_sha256':'c'*64,'features':list(FEATURES),'secure_desktop':False}


class NativeLeaseTest(unittest.TestCase):
    def make(self):
        now=[100.0];state=NativeSession(BIND,can_control=True,can_elevate=False,clock=lambda:now[0])
        return state,now

    def message(self,role,seq,state,**values):
        return dict(session_id='d'*32,transport_generation=1,sequence=seq,
            **({'native_nonce':state.nonce,'native_logon':BIND} if role=='endpoint' else {}),**values)

    def test_no_viewer_means_no_capture_lease_and_no_ten_minute_session_cap(self):
        state,now=self.make()
        first=state.exchange('endpoint',self.message('endpoint',1,state));self.assertFalse(first['authorized'])
        self.assertTrue(state.exchange('viewer',self.message('viewer',1,state))['authorized'])
        now[0]=105.0;self.assertFalse(state.exchange('endpoint',self.message('endpoint',2,state))['authorized'])
        for i,instant in enumerate((699.9,700.0,701.0,3700.0),3):
            now[0]=instant
            state.exchange('endpoint',self.message('endpoint',i,state))
            reply=state.exchange('viewer',self.message('viewer',i,state))
            self.assertTrue(reply['authorized']);self.assertLessEqual(reply['lease_seconds'],5)
            self.assertIsNone(reply['consent_seconds'])
        state.close()
        with self.assertRaises(RemoteError):state.exchange('viewer',self.message('viewer',20,state))

    def test_one_slot_sdp_and_replay_does_not_resurrect(self):
        state,now=self.make();offer=self.message('viewer',1,state,signal={'type':'offer','sdp':SDP})
        self.assertIsNone(state.exchange('viewer',offer)['signal'])
        with self.assertRaises(RemoteError):state.exchange('viewer',offer)
        answer=state.exchange('endpoint',self.message('endpoint',1,state,signal={'type':'answer','sdp':SDP}))
        self.assertEqual(answer['signal']['sdp'],SDP)
        self.assertEqual(state.exchange('viewer',self.message('viewer',2,state))['signal']['type'],'answer')
        self.assertIsNone(state.exchange('viewer',self.message('viewer',3,state))['signal'])
        self.assertEqual(state.deadline,float('inf'))

    def test_logon_change_closes_and_wrong_nonce_is_not_a_logon_change(self):
        state,now=self.make();body=self.message('endpoint',1,state);body['native_nonce']='f'*64
        with self.assertRaises(RemoteError):state.exchange('endpoint',body)
        self.assertFalse(state.ended)
        body=self.message('endpoint',1,state);body['native_logon']={**BIND,'logon_generation':'b'*32}
        with self.assertRaises(RemoteError):state.exchange('endpoint',body)
        self.assertTrue(state.ended)

    def test_network_cannot_supply_input_lease_or_handle_fields(self):
        for extra in ({'lease_seconds':600},{'input':[]},{'mapping_handle':123},{'mode':'control'}):
            state,now=self.make()
            with self.assertRaises(RemoteError):state.exchange('viewer',self.message('viewer',1,state,**extra))

    def test_rate_bounded_and_clock_reversal_terminal(self):
        state,now=self.make()
        for seq in range(1,9):state.exchange('viewer',self.message('viewer',seq,state))
        with self.assertRaises(RemoteError):state.exchange('viewer',self.message('viewer',9,state))
        self.assertTrue(state.ended)
        state,now=self.make();now[0]=99
        with self.assertRaises(RemoteError):state.exchange('viewer',self.message('viewer',1,state))
        self.assertTrue(state.ended)

    def test_oversize_or_wrong_type_sdp_never_enters_slot(self):
        for signal in ({'type':'answer','sdp':SDP},{'type':'offer','sdp':'v=0\r\n'+'x'*65536},{'type':'offer','sdp':SDP+'\x00'}):
            state,now=self.make()
            with self.assertRaises(RemoteError):state.exchange('viewer',self.message('viewer',1,state,signal=signal))
            self.assertIsNone(state.slots['endpoint'])


class NativeSignalingHTTPTest(unittest.TestCase):
    api=test_native_remote.NativeRemoteTest.api
    setUp=test_native_remote.NativeRemoteTest.setUp
    tearDown=test_native_remote.NativeRemoteTest.tearDown
    prepare=test_native_remote.NativeRemoteTest.prepare
    def native_setup(self,enabled=True):
        client,agent,did=self.prepare(protocol=6);self.server.remote_native_preview=enabled;self.server.remote_native_owned_loopback=True
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=6,native=CAPS))
        return client,agent,did

    def request(self,client,did):
        return client.call('/api/remote/request',dict(device_id=did,mode='control',reason='',viewer='desktop',quality='balanced',transport='native_webrtc',native_wire=1,native_cohort_sha256=CAPS['cohort_sha256']))

    def test_default_off_and_missing_capabilities_refuse_native(self):
        client,agent,did=self.native_setup(False)
        self.assertIsNone(client.catalog()['devices'][0]['native'])
        with self.assertRaises(RemoteClientError):self.request(client,did)

    def test_trial_legacy_request_rejected_before_consent_but_native_is_available(self):
        client,agent,did=self.native_setup()
        with patch('guarddesk.remote_trial.ENABLED',True):
            self.assertTrue(client.catalog()['native_only_trial'])
            with self.assertRaisesRegex(RemoteClientError,'僅支援'):
                client.request(did,'control','','clarity')
            with self.store.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM remote_sessions').fetchone()[0],0)
            self.assertEqual(self.request(client,did)['transport'],'native_webrtc')

    def test_cohort_mismatch_rejected_before_consent_and_after_endpoint_changes(self):
        client,agent,did=self.native_setup()
        body=dict(device_id=did,mode='control',reason='',viewer='desktop',quality='balanced',transport='native_webrtc',native_wire=1)
        for extra in ({},{'native_cohort_sha256':'e'*64}):
            with self.assertRaises(RemoteClientError):client.call('/api/remote/request',{**body,**extra})
        session=self.request(client,did)
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=6,native={**CAPS,'cohort_sha256':'e'*64}))
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',dict(session_id=session['id'],action='approve',account='TEST\\employee',native_logon=BIND))

    def test_real_http_consent_nonce_SDP_scope_and_no_image_fallback(self):
        client,agent,did=self.native_setup();session=self.request(client,did);sid=session['id']
        body=dict(session_id=sid,transport_generation=1,sequence=1,signal={'type':'offer','sdp':SDP})
        with self.assertRaises(RemoteClientError):client.call('/api/remote/native',body)
        consent=agent.call('/api/agent/remote/update',dict(session_id=sid,action='approve',account='TEST\\employee',native_logon=BIND))
        reply=client.call('/api/remote/native',body);self.assertFalse(reply['authorized']);self.assertNotIn('native_nonce',reply)
        endpoint=dict(session_id=sid,transport_generation=1,sequence=1,native_nonce=consent['native_nonce'],native_logon=BIND)
        reply=agent.call('/api/agent/remote/native',endpoint);self.assertTrue(reply['authorized']);self.assertEqual(reply['signal']['sdp'],SDP)
        with self.assertRaises(RemoteClientError):client.call('/api/remote/input',dict(session_id=sid,actions=[{'type':'key','key':65,'down':True}]))
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',dict(session_id=sid,action='frame',frame={}))
        with self.store.connect() as db:logs=' '.join(row[0] for row in db.execute("SELECT details FROM events WHERE kind LIKE 'remote.%'"))
        self.assertNotIn(SDP,logs);self.assertNotIn(consent['native_nonce'],logs)
        other=RemoteClient(self.url);other.login('admin',self.password);self.clients.append(other)
        with self.assertRaises(RemoteClientError):other.call('/api/remote/native',{**body,'sequence':2})

    def test_restart_loses_authority_and_revoke_stops_next_lease(self):
        client,agent,did=self.native_setup();session=self.request(client,did);sid=session['id']
        agent.call('/api/agent/remote/update',dict(session_id=sid,action='approve',account='TEST\\employee',native_logon=BIND))
        with self.server.remote_lock:self.server.remote_memory.clear()
        with self.assertRaises(RemoteClientError):client.call('/api/remote/native',dict(session_id=sid,transport_generation=1,sequence=1))
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=False,can_control=False))
        with self.assertRaises(RemoteClientError):client.call('/api/remote/native',dict(session_id=sid,transport_generation=1,sequence=2))


if __name__=='__main__':unittest.main()
