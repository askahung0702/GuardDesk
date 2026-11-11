"""Owned coordinator fixtures; never loads installed DLLs, WTS or OS input."""
import queue
import struct
import threading
import time
import unittest
from types import SimpleNamespace

from guarddesk.remote_native_broker import NativeJob,Launcher,binding,configuration,lease_deadline,media_packet,HEADER
from guarddesk.machine_agent import Router

PEER={'session':6,'logon':133000000000000000,'sid':'S-1-5-21-1-2-3-1001'}
SID='d'*32
REQUEST={'id':SID,'mode':'control','admin_control':True,'transport':'native_webrtc','operator':'owned','reason':'','native_cohort_sha256':'c'*64}
NETWORK={'local_ipv4':['192.168.1.10'],'peer_ipv4':['192.168.1.11'],'owned_loopback':False}
APPROVAL={'native_wire':1,'transport_generation':1,'native_nonce':'a'*64,'approval_started_tick':1000,'approval_filetime':133000000000000001}


def reply(**changes):
    return dict(native_wire=1,transport_generation=1,authorized=True,mode='control',admin_control=True,
        lease_seconds=5,network=NETWORK,signal=None,native_cohort_sha256='c'*64,**changes)


class Library:
    capabilities={'wire':1,'cohort_sha256':'c'*64}
    def __init__(self):
        self.now=1000;self.commands=[];self.writes=[];self.stops=[];self.closes=[]
        self.enter=threading.Event();self.proceed=threading.Event();self.block=False
    def tick(self):return self.now
    def reserve(self,spec):return 7
    def launch(self,context):
        self.enter.set()
        if self.block and not self.proceed.wait(2):raise TimeoutError('Owned launch fixture timeout')
    def command(self,context,packet):self.commands.append(packet)
    def write(self,context,packet):self.writes.append(packet)
    def poll(self,context):return None
    def worker_poll(self,context):return None
    def stop(self,context):self.stops.append(context);self.proceed.set()
    def close(self,context):self.closes.append(context)


class NativeBrokerTest(unittest.TestCase):
    def test_worker_status_is_scalar_only_and_never_grants_authority(self):
        lib=Library();job=self.job(lib)
        self.assertIsNone(job.worker_snapshot())
        values=[3,3,106,0x887a0022,7,0,0,1,10,7,3,2,12,4,99,17]+[0]*80
        job.receive_worker(struct.pack('<96I',*values))
        lib.now+=25
        self.assertEqual(job.worker_snapshot(),dict(stage=3,api=106,error=0x887a0022,polls=7,acquired=0,published=0,resets=1,age_ms=25,
            input_received=10,input_accepted=7,input_rejected=3,input_stale=2,moves_coalesced=12,queue_high_water=4,queue_age_max_ms=99,command_max_ms=17,
            last_pause_reason=0,housekeeping=0,guard_checks=0,capture_pending=0,reset_reasons=[0]*8,
            input_reject_reasons={name:0 for name in ('other','schema_identity_sequence','authorization','rate','desktop','frame_or_stale','view_only','payload_or_ledger')},
            latency_us={name:{'count':0,'max':0,'bins':[0]*8} for name in ('queue','command','guard','send_input','capture')}))
        self.assertFalse(job.granted);self.assertEqual(lib.commands,[]);self.assertEqual(lib.writes,[])
        for at,value in ((0,2),(1,14),(2,113),(13,33),(16,8),(95,1)):
            invalid=values.copy();invalid[at]=value
            with self.subTest(field=at),self.assertRaises(ValueError):job.receive_worker(struct.pack('<96I',*invalid))
        for data in (b'',b'X'*65,struct.pack('<8I',1,3,106,0,0,0,0,0),
                     struct.pack('<16I',1,3,106,0,*([0]*12)),struct.pack('<16I',2,14,106,0,*([0]*12)),
                     struct.pack('<16I',2,3,113,0,*([0]*12)),struct.pack('<16I',2,3,106,0,*([0]*9),33,0,0)):
            with self.subTest(data=data),self.assertRaises(ValueError):job.receive_worker(data)
    def job(self,library=None,call=None):
        return NativeJob(library or Library(),call or (lambda p,b:reply()),REQUEST,PEER,APPROVAL)
    def test_lease_anchors_request_start_and_cannot_broaden_mode(self):
        self.assertEqual(lease_deadline(reply(),1000,4000,601000,can_control=True,administrator=True),6000)
        self.assertEqual(lease_deadline(reply(),1000,6000,601000,can_control=True,administrator=True),0)
        for field,value in [('lease_seconds',float('nan')),('lease_seconds',6),('mode','view'),('native_wire',True),('admin_control',False)]:
            changed=reply();changed[field]=value
            with self.subTest(field=field,value=value),self.assertRaises((ValueError,PermissionError)):
                lease_deadline(changed,1000,1001,601000,can_control=True,administrator=True)
    def test_native_control_and_consumed_never_create_input_ack_in_python(self):
        lib=Library();job=self.job(lib);self.assertTrue(job.reserve());job.apply(1000,reply())
        self.assertEqual(len(lib.commands),1)
        header=HEADER.unpack(lib.commands[0][:64]);self.assertEqual(header[2],3) # trusted lease only
        self.assertEqual(struct.unpack('<QQII',lib.commands[0][64:]),(6000,1,1,0))
        self.assertEqual([p[6] for p in lib.writes],[7,1])
        job.stop();self.assertEqual(lib.stops,[7])
    def test_network_address_change_or_unauthorized_reply_stops_authority(self):
        job=self.job();job.reserve();job.apply(1000,reply())
        changed=reply();changed['network']={**NETWORK,'peer_ipv4':['192.168.1.12']}
        with self.assertRaises(PermissionError):job.apply(1000,changed)
        changed=reply();changed.update(authorized=False,lease_seconds=0)
        with self.assertRaises(PermissionError):job.apply(1000,changed)
        self.assertEqual(job.deadline,6000)
    def test_public_loopback_duplicate_and_unknown_network_fields_refused(self):
        for ip in ('8.8.8.8','127.0.0.1','0.0.0.0','169.254.1.2','224.0.0.1'):
            with self.subTest(ip=ip),self.assertRaises(ValueError):configuration({**NETWORK,'peer_ipv4':[ip]})
        with self.assertRaises(ValueError):configuration({**NETWORK,'server_selected_path':'x'})
        self.assertEqual(len(configuration({'local_ipv4':['127.0.0.1'],'peer_ipv4':['127.0.0.1'],'owned_loopback':True},owned_loopback=True)),80)
    def test_relay_configured_once_before_SDP_and_never_forwarded_to_worker(self):
        from test_remote_relay import credential
        lib=Library();job=self.job(lib);job.reserve();value=credential();answer=reply(relay=value)
        answer['signal']={'type':'offer','sdp':'v=0\r\n'};job.apply(1000,answer)
        self.assertEqual([p[6] for p in lib.writes],[7,8,1,2])
        self.assertEqual([HEADER.unpack(p[:64])[2] for p in lib.commands],[3])
        again=reply(relay={**value,'remaining_seconds':500});job.apply(1000,again)
        self.assertEqual([p[6] for p in lib.writes].count(8),1)
        with self.assertRaises(PermissionError):job.apply(1000,reply(relay={**value,'password':'changed-owned-password'}))
    def test_relay_cannot_appear_after_direct_initialization_or_after_expiry(self):
        from test_remote_relay import credential
        job=self.job();job.reserve();job.apply(1000,reply())
        with self.assertRaises(PermissionError):job.apply(1000,reply(relay=credential()))
        lib=Library();lib.now=4000;job=self.job(lib);job.reserve()
        with self.assertRaises(ValueError):job.apply(1000,reply(relay={**credential(),'remaining_seconds':1}))
        self.assertEqual(lib.commands,[]) # no trusted input/capture lease after a refused relay
    def test_stop_during_native_launch_is_immediate_and_closes_once(self):
        lib=Library();lib.block=True;job=self.job(lib);job.reserve();job.start()
        self.assertTrue(lib.enter.wait(1));started=time.monotonic();job.stop()
        self.assertLess(time.monotonic()-started,.1);self.assertTrue(job.done.wait(2))
        self.assertEqual(lib.closes,[7]);self.assertEqual(lib.commands,[]);self.assertEqual(lib.writes,[])
    def test_signaling_failure_terminates_no_fallback_and_records_only_stage_type(self):
        def refused(path,body):raise ConnectionError('owned synthetic failure must not be logged')
        lib=Library();job=self.job(lib,refused);job.reserve();job.start();self.assertTrue(job.done.wait(2))
        self.assertEqual(job.error,{'phase':'native_signaling','error_type':'ConnectionError'})
        self.assertEqual(lib.closes,[7]);self.assertEqual(lib.commands,[])
    def test_SDP_mailbox_is_single_slot_and_direction_is_not_a_grant(self):
        job=self.job();answer=media_packet(2,SID,1,b'\2'+b'\0'*7+b'v=0\r\n')
        job.receive(answer)
        with self.assertRaises(queue.Full):job.receive(media_packet(2,SID,2,b'\2'+b'\0'*7+b'v=0\r\n'))
        with self.assertRaises(ValueError):job.receive(media_packet(1,SID,3,b'x'*16))
        with self.assertRaises(ValueError):job.receive(media_packet(2,'e'*32,4,b'\2'+b'\0'*7+b'v=0\r\n'))
    def test_logon_binding_is_stable_and_new_user_or_logon_changes_it(self):
        self.assertEqual(binding(PEER),binding(dict(PEER)))
        self.assertNotEqual(binding(PEER),binding({**PEER,'logon':PEER['logon']+1}))
        with self.assertRaises(ValueError):binding({**PEER,'session':True})
    def test_media_status_is_bounded_scalar_snapshot_without_authority(self):
        lib=Library();job=self.job(lib)
        self.assertIsNone(job.media_snapshot())
        for i in range(100):job.receive(media_packet(6,SID,i+1,struct.pack('<IIII',1,11,i,0)))
        lib.now+=2500
        self.assertEqual(job.media_snapshot(),{'peer_connected':True,'channel_open':True,
            'codec_failed':False,'stale_slot':True,'capture_sequence':99,'encoded_frames':0,'age_ms':2500})
        self.assertEqual(lib.commands,[]);self.assertEqual(lib.writes,[]);self.assertFalse(job.granted)
        for payload in (b'',b'x'*17,struct.pack('<IIII',0,0,0,0),struct.pack('<IIII',1,16,0,0)):
            with self.assertRaises(ValueError):job.receive(media_packet(6,SID,101,payload))
    def test_launcher_retains_stopped_jobs_for_bounded_shutdown_join(self):
        lib=Library();lib.block=True;job=self.job(lib);job.reserve();job.start();self.assertTrue(lib.enter.wait(1))
        launcher=Launcher(SimpleNamespace(),library=lib);launcher.entries[SID]=job;launcher.revoke(SID)
        self.assertFalse(launcher.alive(SID));self.assertIs(launcher.entries[SID],job)
        launcher.close();self.assertTrue(job.done.is_set());self.assertEqual(lib.closes,[7]);self.assertFalse(launcher.entries)
    def test_four_stuck_signaling_calls_cannot_allocate_a_fifth_thread(self):
        from unittest.mock import patch
        with patch('guarddesk.remote_native_broker.NETWORK_SLOTS',threading.BoundedSemaphore(0)):
            lib=Library();job=self.job(lib);job.reserve();job.start();self.assertTrue(job.done.wait(1))
            self.assertIsNone(job.network);self.assertEqual(lib.closes,[7]);self.assertEqual(job.error['error_type'],'OSError')


class RouterLauncher:
    capabilities={'wire':1,'cohort_sha256':'f'*64}
    def __init__(self):self.reserved=[];self.launched=[];self.revoked=[]
    def tick(self):return 1000
    def reserve(self,sid):self.reserved.append(sid)
    def revoke(self,sid):self.revoked.append(sid)
    def stop(self,sid):self.revoke(sid)
    def alive(self,sid):return sid not in self.revoked
    def launch(self,*args,**kwargs):self.launched.append((args,kwargs))


class NativeRouterTest(unittest.TestCase):
    def test_approved_native_owner_has_no_twelve_minute_request_timeout(self):
        from unittest.mock import patch
        def online(path,body):
            if path.endswith('/poll'):return {'session':{**REQUEST,'status':'requested'}}
            if body.get('action')=='approve':return {'status':'active',**APPROVAL,'session_lifetime':'until_stopped'}
            return {'status':'active'}
        router=self.make(online)
        with patch('guarddesk.machine_agent.time.monotonic',return_value=100):
            self.poll(router);self.request(router,'update',{'session_id':SID,'action':'approve'})
        self.assertEqual(router.remote_owner[SID][1],float('inf'))
        current=self.launcher.launched[0][1]['current'];self.assertTrue(current())
        with patch('guarddesk.machine_agent.time.monotonic',return_value=4000):
            self.assertEqual(self.request(router,'update',{'session_id':SID,'action':'admin_watch'})['status'],'active')
        router.end_session(6,PEER['logon']);self.assertFalse(current())
    def make(self,call=None):
        self.launcher=RouterLauncher();self.calls=[]
        def online(path,body):
            self.calls.append((path,body))
            if call:return call(path,body)
            if path.endswith('/poll'):return {'session':{**REQUEST,'status':'requested'}}
            if body.get('action')=='approve':return {'status':'active',**APPROVAL,'admin_nonce':'b'*64}
            return {'status':'active'}
        self.states={6:{**PEER,'account':'OWNED\\user','active':True,'locked':False}}
        return Router(SimpleNamespace(call=online),lambda:self.states,online_call=online,native_launcher=self.launcher)
    def request(self,router,path,body):return router.dispatch({'path':'/api/agent/remote/'+path,'body':body},PEER)
    def poll(self,router):return self.request(router,'poll',{'account':'caller-text','ready':True,'protocol':3,'native':{'spoofed':True}})
    def test_native_only_broker_cannot_approve_legacy_admin_request(self):
        # Field combination: protocol6 comes from native cohort, but the old
        # clarity viewer asks for legacy admin control with no legacy launcher.
        calls=[]
        def online(path,body):
            calls.append((path,body))
            return {'session':{**REQUEST,'transport':'legacy_images','status':'requested'}}
        router=self.make(online);self.poll(router)
        with self.assertRaisesRegex(PermissionError,'Management assistance not installed'):
            self.request(router,'update',{'session_id':SID,'action':'approve'})
        self.assertEqual(len(calls),1)  # approval never reaches center
        self.assertEqual(self.poll(router)['session']['status'],'requested')

    def test_reserve_failure_remains_visible_after_router_revokes_reservation(self):
        lib=Library()
        def reserve(spec):
            error=OSError('PRIVATE exception must not be retained')
            error.native_code=1627;error.remote_diagnostic='broker_image_trust:native_broker_rejected'
            raise error
        lib.reserve=reserve
        launcher=Launcher(SimpleNamespace(call=lambda *a,**k:{}),library=lib)
        launcher.reserve(SID)
        with self.assertRaises(OSError):launcher.launch(REQUEST,PEER,{},APPROVAL,current=lambda:True)
        launcher.revoke(SID)
        result=launcher.snapshot()
        self.assertEqual(result['contexts'],[])
        self.assertEqual(result['last_failure'],{'phase':'native_reserve','error_type':'OSError',
            'native_code':1627,'diagnostic':'broker_image_trust:native_broker_rejected'})
        self.assertNotIn('PRIVATE',str(result))
    def test_system_overrides_native_presence_binding_and_keeps_nonces_private(self):
        router=self.make();self.poll(router)
        self.assertEqual(self.calls[0][1]['native'],self.launcher.capabilities);self.assertEqual(self.calls[0][1]['protocol'],6)
        result=self.request(router,'update',{'session_id':SID,'action':'approve','account':'caller-text','native_logon':{'spoofed':True}})
        self.assertNotIn('native_nonce',result);self.assertNotIn('admin_nonce',result)
        self.assertEqual(self.calls[1][1]['native_logon'],binding(PEER));self.assertEqual(self.launcher.reserved,[SID])
        args,options=self.launcher.launched[0];self.assertTrue(options['current']());self.assertEqual(args[3]['native_nonce'],'a'*64)
        router.end_session(6,PEER['logon']);self.assertFalse(options['current']());self.assertIn(SID,self.launcher.revoked)
    def test_native_helper_cannot_request_frames_or_supply_private_network_commands(self):
        router=self.make();self.poll(router)
        with self.assertRaises(PermissionError):self.request(router,'update',{'session_id':SID,'action':'frame','data':'not used'})
        self.assertEqual(len(self.calls),1)
    def test_stop_while_approval_HTTP_waits_never_launches_stale_cohort(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def online(path,body):
            if path.endswith('/poll'):return {'session':{**REQUEST,'status':'requested'}}
            if body.get('action')=='approve':entered.set();release.wait(2);return {'status':'active',**APPROVAL}
            return {'status':'closed'}
        router=self.make(online);self.poll(router)
        def approve():
            try:self.request(router,'update',{'session_id':SID,'action':'approve'})
            except PermissionError:errors.append('stale')
        thread=threading.Thread(target=approve);thread.start();self.assertTrue(entered.wait(1))
        router.end_session(6,PEER['logon']);release.set();thread.join(2)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,['stale']);self.assertEqual(self.launcher.launched,[])


class NativeReadinessTrustTests(unittest.TestCase):
    def initialize(self,code=0,missing=False):
        import ctypes
        from pathlib import Path
        from unittest.mock import Mock,patch
        from guarddesk.remote_native_broker import NativeLibrary
        root=Path('C:/owned-trust-fixture').resolve()
        dll=Mock()
        dll.GDRemoteCheckTrust.return_value=code
        def last_error(buffer,size):
            buffer.value=b'broker_process_trust:kernel_untrusted_rights'
            return 0
        dll.GDRemoteLastError.side_effect=last_error
        if missing:del dll.GDRemoteCheckTrust
        with patch('guarddesk.machine_agent.eligible',return_value=True), \
             patch('guarddesk.update_native.folder',return_value=root), \
             patch('sys.executable',str(root/'USBControl/GuardDesk.exe')), \
             patch('guarddesk.remote_admin_windows.identity'), \
             patch('guarddesk.update_native.protected_tree'), \
             patch('guarddesk.remote_components.read_cohort',return_value={'build_id':'a'*64}), \
             patch.object(ctypes,'WinDLL',return_value=dll):
            result=NativeLibrary(object())
        return result,dll
    def test_native_readiness_runs_process_and_token_preflight(self):
        result,dll=self.initialize()
        dll.GDRemoteCheckTrust.assert_called_once_with()
        dll.GDRemoteReserve.assert_not_called()
        self.assertEqual(result.capabilities['wire'],1)
    def test_native_readiness_rejects_kernel_failure_with_fixed_diagnostic(self):
        with self.assertRaises(OSError) as raised:self.initialize(code=1627)
        self.assertEqual(raised.exception.native_code,1627)
        self.assertEqual(raised.exception.remote_diagnostic,'broker_process_trust:kernel_untrusted_rights')
    def test_native_readiness_rejects_old_bridge_missing_preflight(self):
        with self.assertRaises(AttributeError):self.initialize(missing=True)


if __name__=='__main__':unittest.main()
