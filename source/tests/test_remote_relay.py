"""Owned policy/lease/HTTP tests. No DNS, TURN deployment or desktop access."""
import base64
import hashlib
import hmac
import json
import struct
import unittest
from guarddesk.remote_relay import RelayAuthority,policy,validate,encode_relay,relay_identity
from guarddesk.remote_native import NativeSession
from guarddesk.remote import RemoteError
import test_native_remote
from test_remote_native_signaling import BIND,CAPS

POLICY={'mode':'tls','turn_ipv4':'10.8.0.10','turn_port':5349,'tls_hostname':'turn.owned.test',
    'allocation_ipv4':['10.8.0.10'],'allocation_port_min':50000,'allocation_port_max':55000}
SECRET=b'owned TURN fixture secret - never product key'
SID='d'*32;COHORT='c'*64

def credential():
    authority=RelayAuthority(POLICY,SECRET,wall_clock=lambda:1000)
    roles,_=authority.issue(SID,COHORT)
    return {**roles['viewer'],'remaining_seconds':599}

class RelayPolicyTest(unittest.TestCase):
    def test_turn_rest_credential_bound_to_session_cohort_and_role(self):
        authority=RelayAuthority(POLICY,SECRET,wall_clock=lambda:1000)
        roles,expiry=authority.issue(SID,COHORT);self.assertEqual(expiry,1600)
        self.assertNotEqual(roles['viewer']['username'],roles['endpoint']['username'])
        self.assertNotEqual(roles['viewer']['password'],roles['endpoint']['password'])
        self.assertEqual(roles['viewer']['password'],base64.b64encode(hmac.new(SECRET,roles['viewer']['username'].encode(),hashlib.sha1).digest()).decode())
        other,_=authority.issue('e'*32,COHORT);self.assertNotEqual(other['viewer']['password'],roles['viewer']['password'])
        other,_=authority.issue(SID,'f'*64);self.assertNotEqual(other['viewer']['policy_sha256'],roles['viewer']['policy_sha256'])

    def test_production_rejects_public_loopback_unknown_destinations_and_bad_TLS_hostname(self):
        for fields in ({'turn_ipv4':'8.8.8.8'},{'turn_ipv4':'127.0.0.1'},{'turn_ipv4':'0.0.0.0'},
            {'turn_ipv4':'10.0.0.0/8'},{'allocation_ipv4':['10.8.0.10','10.8.0.10']},
            {'allocation_ipv4':['169.254.1.2']},{'tls_hostname':'turn.owned.test/evil'},
            {'tls_hostname':'-turn.test'},{'tls_hostname':'turn.test.'},{'tls_hostname':''},{'tls_hostname':'10.8.0.10'},
            {'allocation_port_min':55001},{'turn_port':True},{'mode':'owned_udp','tls_hostname':''}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):policy({**POLICY,**fields})
        with self.assertRaises(ValueError):policy({**POLICY,'ignore_bad_certificate':True})

    def test_owned_UDP_requires_explicit_owned_loopback_flag(self):
        value={**POLICY,'mode':'owned_udp','tls_hostname':'','turn_ipv4':'127.0.0.1','allocation_ipv4':['127.0.0.1']}
        with self.assertRaises(ValueError):RelayAuthority(value,SECRET)
        authority=RelayAuthority(value,SECRET,owned_loopback=True,wall_clock=lambda:1000)
        roles,_=authority.issue(SID,COHORT);value={**roles['viewer'],'remaining_seconds':60}
        with self.assertRaises(ValueError):encode_relay(value,100,100,60100)
        self.assertEqual(struct.unpack_from('<H',encode_relay(value,100,100,60100,owned_loopback=True),6)[0],2)

    def test_wire_exact_offsets_and_request_start_deadline_clamp(self):
        value=credential();wire=encode_relay(value,10000,10100,30000)
        self.assertEqual(wire[:4],b'GDR3');self.assertEqual(struct.unpack_from('<HHII',wire,4),(1,1,len(wire),0))
        self.assertEqual(wire[16:48],bytes.fromhex(value['policy_sha256']))
        self.assertEqual(struct.unpack_from('<Q',wire,48)[0],30000)
        self.assertEqual(wire[56:60],bytes((10,8,0,10)));self.assertEqual(struct.unpack_from('<HHHHI',wire,60),(5349,len(value['tls_hostname']),len(value['username']),len(value['password']),1))
        self.assertEqual(wire[76:88],b'\0'*12);self.assertEqual(wire[92:128],b'\0'*36)
        self.assertEqual(wire[128:],(value['tls_hostname']+value['username']+value['password']).encode())
        self.assertLessEqual(len(wire),1152)

    def test_expiry_wrong_clock_and_nonfinite_limits_never_extend_lease(self):
        for fields in ({'remaining_seconds':0},{'remaining_seconds':601},{'remaining_seconds':float('nan')},
            {'remaining_seconds':True},{'username':'x'*257},{'password':'x'*513},{'password':'bad secret has spaces'},
            {'username':'\x00'},{'policy_sha256':'F'*64}):
            with self.subTest(fields=list(fields)),self.assertRaises(ValueError):validate({**credential(),**fields})
        with self.assertRaises(ValueError):encode_relay({**credential(),'remaining_seconds':1},1000,2000,601000)
        with self.assertRaises(ValueError):encode_relay(credential(),2000,1000,601000)

    def test_policy_identity_cannot_be_changed_but_TTL_counts_down(self):
        value=credential();self.assertEqual(relay_identity(value),relay_identity({**value,'remaining_seconds':5}))
        self.assertNotEqual(relay_identity(value),relay_identity({**value,'turn_port':443}))
        self.assertNotEqual(relay_identity(value),relay_identity({**value,'password':'other-owned-password'}))

    def test_same_consent_does_not_renew_credentials_and_close_drops_authority(self):
        now=[100.0];wall=[1000.0];authority=RelayAuthority(POLICY,SECRET,wall_clock=lambda:wall[0])
        state=NativeSession(BIND,can_control=True,can_elevate=False,clock=lambda:now[0],cohort_sha256=COHORT,session_id=SID,relay_authority=authority)
        first=state.exchange('viewer',dict(session_id=SID,transport_generation=1,sequence=1))['relay']
        now[0]+=10;wall[0]+=10
        second=state.exchange('viewer',dict(session_id=SID,transport_generation=1,sequence=2))['relay']
        self.assertEqual(first['password'],second['password']);self.assertEqual(first['remaining_seconds']-10,second['remaining_seconds'])
        state.close();self.assertIsNone(state.relay_roles)
        with self.assertRaises(RemoteError):state.exchange('viewer',dict(session_id=SID,transport_generation=1,sequence=3))

    def test_wall_expiry_cannot_outlive_original_consent(self):
        wall=[1000.0];authority=RelayAuthority(POLICY,SECRET,wall_clock=lambda:wall[0])
        state=NativeSession(BIND,can_control=True,can_elevate=False,clock=lambda:100,cohort_sha256=COHORT,session_id=SID,relay_authority=authority)
        wall[0]=1601
        with self.assertRaises(RemoteError):state.exchange('viewer',dict(session_id=SID,transport_generation=1,sequence=1))
        self.assertTrue(state.ended)

class RelayHTTPTest(unittest.TestCase):
    setUp=test_native_remote.NativeRemoteTest.setUp
    tearDown=test_native_remote.NativeRemoteTest.tearDown
    api=test_native_remote.NativeRemoteTest.api
    prepare=test_native_remote.NativeRemoteTest.prepare

    def test_authenticated_exchange_only_no_credentials_in_DB_or_events(self):
        client,agent,did=self.prepare(protocol=6);self.server.remote_native_preview=True;self.server.remote_native_owned_loopback=True
        self.server.remote_native_relay_authority=RelayAuthority(POLICY,SECRET)
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=6,native=CAPS))
        session=client.call('/api/remote/request',dict(device_id=did,mode='control',reason='',viewer='desktop',quality='balanced',transport='native_webrtc',native_wire=1,native_cohort_sha256=COHORT))
        consent=agent.call('/api/agent/remote/update',dict(session_id=session['id'],action='approve',account='TEST\\employee',native_logon=BIND))
        viewer=client.call('/api/remote/native',dict(session_id=session['id'],transport_generation=1,sequence=1))
        endpoint=agent.call('/api/agent/remote/native',dict(session_id=session['id'],transport_generation=1,sequence=1,native_nonce=consent['native_nonce'],native_logon=BIND))
        self.assertEqual(viewer['relay']['policy_sha256'],endpoint['relay']['policy_sha256'])
        self.assertNotEqual(viewer['relay']['username'],endpoint['relay']['username'])
        self.assertTrue(endpoint['authorized']);self.assertNotIn('relay',session)
        with self.store.connect() as db:
            stored=' '.join(str(tuple(row)) for row in db.execute('SELECT * FROM remote_sessions'))+' '.join(row[0] for row in db.execute('SELECT details FROM events'))
        for secret in (SECRET.decode(),viewer['relay']['password'],endpoint['relay']['password'],viewer['relay']['username']):self.assertNotIn(secret,stored)

if __name__=='__main__':unittest.main()
