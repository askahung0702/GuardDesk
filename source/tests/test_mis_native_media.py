"""Owned synthetic native controller / private NTFS loader tests. No desktop IO."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from guarddesk.mis_native_media import Config,NativeMisController,addresses
from guarddesk.remote_components import REMOTE_FILES,cohort_manifest


class FakeLibrary:
    def __init__(self):self.owner=None;self.closed=threading.Event();self.ended=threading.Event();self.offered=False;self.grants=[];self.stops=0;self.activations=[];self.runs=0
    def tick(self):return int(time.monotonic()*1000)
    def create(self,config):self.owner=threading.get_ident();return 1
    def check_owner(self):assert threading.get_ident()==self.owner
    def offer(self,handle):self.check_owner();time.sleep(.65)
    def take_signal(self,handle):self.check_owner();return {'type':'offer','sdp':'v=0\r\nowned'}
    def grant(self,handle,deadline):self.check_owner();self.grants.append(deadline)
    def signal(self,handle,value):self.check_owner()
    def pump(self,handle):self.check_owner()
    def wait(self,handle):self.check_owner();self.closed.wait(.01)
    def wake(self,handle):pass
    def diagnostics(self,handle):return {'input_offered':0,'input_sent':0}
    def run(self,handle):self.check_owner();self.runs+=1;self.ended.wait(5)
    def activate(self,handle,toggle=False):self.activations[:]=[toggle]
    def post_reply(self,handle,deadline,signal):
        if deadline:self.grants.append(deadline)
    def stop(self,handle):self.stops+=1;self.ended.set()
    def close(self,handle):self.check_owner();self.closed.set()


class Client:
    def __init__(self):self.calls=[]
    def call(self,path,body):
        self.calls.append(body)
        return {'native_wire':1,'transport_generation':1,'authorized':True,'lease_seconds':4,'mode':'view','signal':None}


class NativeControllerTests(unittest.TestCase):
    def test_native_cancelled_result_preserves_first_scalar_end_reason(self):
        from types import SimpleNamespace
        from guarddesk.mis_native_media import NativeLibrary
        for reason in range(8):
            def read_reason(handle,output):output._obj.value=reason;return 0
            library=NativeLibrary.__new__(NativeLibrary)
            library.dll=SimpleNamespace(GDMisRun=lambda handle:1223,GDMisEndReason=read_reason)
            if reason in (0,1):library.run(1)
            else:
                with self.assertRaises(OSError) as error:library.run(1)
                self.assertTrue(error.exception.remote_diagnostic.startswith('native_'))
                controller=self.controller();controller._fail(error.exception)
                self.assertEqual(controller.error['diagnostic'],error.exception.remote_diagnostic)

    def test_local_window_requests_are_bounded_and_cannot_run_after_stop_or_hidden(self):
        controller=self.controller()
        self.assertFalse(controller.activate_window())
        controller.config.hidden=0
        controller.handle=1
        for i in range(200):self.assertTrue(controller.activate_window(bool(i%2)))
        self.assertEqual(controller.library.activations,[True])
        with self.assertRaises(ValueError):controller.activate_window('arbitrary')
        controller.stop();self.assertFalse(controller.activate_window())

    def test_optional_focus_failure_does_not_end_transport(self):
        library=FakeLibrary();library.offer=lambda handle:library.check_owner()
        controller=self.controller(library=library);controller.config.hidden=0
        with patch.object(library,'activate',side_effect=OSError('owned focus denied')) as activation:
            try:
                controller.start();deadline=time.monotonic()+2
                while not library.runs and time.monotonic()<deadline:time.sleep(.01)
                self.assertFalse(controller.stop_event.is_set());self.assertIsNone(controller.error)
                self.assertTrue(activation.called)
            finally:controller.stop();controller.join()

    def controller(self,client=None,library=None):
        library=library or FakeLibrary()
        result=NativeMisController(client or Client(),Path('.'),'a'*32,local_ipv4=['127.0.0.1'],peer_ipv4=['127.0.0.1'],
            can_control=False,consent_deadline=library.tick()+10000,library=library,owned_loopback=True,hidden=True)
        result.ui_ready.set() # Direct network-negative fixtures have no UI thread.
        return result

    def test_explicit_private_addresses_no_wildcard_public_or_implicit_loopback(self):
        for value in ('0.0.0.0','8.8.8.8','169.254.1.1','127.0.0.1','224.0.0.1'):
            with self.assertRaises(ValueError):addresses([value])
        self.assertEqual(str(addresses(['192.168.1.7'])[0]),'192.168.1.7')
        with self.assertRaises(ValueError):addresses(['192.168.1.7']*2)

    def test_native_abi_layout(self):
        self.assertEqual(ctypes.sizeof(Config),128)
        self.assertEqual(Config.transport.offset,32)
        self.assertEqual(Config.hidden.offset,120)

    def test_slow_offer_uses_latest_lease_and_stops_on_creator_thread(self):
        client=Client();library=FakeLibrary();controller=self.controller(client,library).start()
        try:
            until=time.monotonic()+3
            while not library.grants and time.monotonic()<until:time.sleep(.01)
            self.assertTrue(library.grants);self.assertIsNone(controller.error)
            self.assertLessEqual(controller.replies.qsize(),1)
            until=time.monotonic()+2
            while not library.runs and time.monotonic()<until:time.sleep(.01)
            self.assertEqual(library.runs,1)
        finally:controller.stop();controller.join()
        self.assertTrue(library.closed.is_set());self.assertGreater(library.stops,0)
        self.assertTrue(any('signal' in body for body in client.calls) or controller.offers.qsize()==1)

    def test_mode_change_fails_closed_no_exception_secret_retained(self):
        client=Client();original=client.call
        client.call=lambda *args:{**original(*args),'mode':'control'}
        controller=self.controller(client);controller._network()
        self.assertTrue(controller.stop_event.is_set());self.assertEqual(controller.error['type'],'ValueError')
        self.assertEqual(set(controller.error),{'type','code'})

    def test_relay_before_offer_and_identity_change_ends_session(self):
        value={'policy_sha256':'1'*64,'mode':'owned_udp','turn_ipv4':'127.0.0.1','turn_port':3478,
            'tls_hostname':'','allocation_ipv4':['127.0.0.1'],'allocation_port_min':1,'allocation_port_max':65535,
            'username':'owned-relay-user','password':'owned-relay-password','remaining_seconds':10}
        library=FakeLibrary();events=[];library.relay=lambda handle,wire:events.append(('relay',wire))
        original_offer=library.offer
        def offer(handle):events.append(('offer',None));original_offer(handle)
        library.offer=offer;client=Client();original=client.call
        client.call=lambda *args:{**original(*args),'relay':dict(value)}
        controller=NativeMisController(client,Path('.'),'a'*32,local_ipv4=['127.0.0.1'],peer_ipv4=['127.0.0.1'],can_control=False,
            consent_deadline=library.tick()+10000,library=library,owned_loopback=True,hidden=True,relay=value).start()
        try:
            until=time.monotonic()+2
            while len(events)<2 and time.monotonic()<until:time.sleep(.01)
            self.assertEqual([e[0] for e in events[:2]],['relay','offer']);self.assertEqual(events[0][1][:4],b'GDR3')
            value['username']='changed-relay-user'
            self.assertTrue(controller.stop_event.wait(2));self.assertEqual(controller.error['type'],'ValueError')
        finally:controller.stop();controller.join()
        self.assertTrue(library.closed.is_set())

    def test_relay_delayed_initial_response_does_not_extend_deadline(self):
        value={'policy_sha256':'1'*64,'mode':'owned_udp','turn_ipv4':'127.0.0.1','turn_port':3478,'tls_hostname':'',
            'allocation_ipv4':['127.0.0.1'],'allocation_port_min':1,'allocation_port_max':65535,
            'username':'owned-relay-user','password':'owned-relay-password','remaining_seconds':1}
        library=FakeLibrary();library.tick=lambda:5000
        with self.assertRaises(ValueError):
            NativeMisController(Client(),Path('.'),'a'*32,local_ipv4=['127.0.0.1'],peer_ipv4=['127.0.0.1'],can_control=False,
                consent_deadline=10000,library=library,owned_loopback=True,hidden=True,relay=value,relay_started_tick=1000)

    def test_network_cohort_mismatch_is_terminal(self):
        library=FakeLibrary();controller=self.controller(library=library);controller.cohort='f'*64
        controller._network()
        self.assertTrue(controller.stop_event.is_set());self.assertTrue(controller.replies.empty())

    def test_expired_reply_uses_request_start_not_arrival(self):
        library=FakeLibrary();tick=[1000];library.tick=lambda:tick[0]
        client=Client();original=client.call
        def delayed(*args):tick[0]+=5000;return original(*args)
        client.call=delayed;controller=self.controller(client,library);controller._network()
        self.assertTrue(controller.stop_event.is_set());self.assertTrue(controller.replies.empty())

    def test_late_reply_after_stop_is_not_delivered(self):
        client=Client();controller=self.controller(client);original=client.call
        def late(*args):controller.stop();return original(*args)
        client.call=late;controller._network();self.assertTrue(controller.replies.empty())

    def test_plain_cohort_import_does_not_load_agent_or_store(self):
        code="import guarddesk.remote_components,sys;assert 'guarddesk.agent' not in sys.modules;assert 'guarddesk.store' not in sys.modules"
        result=subprocess.run([sys.executable,'-c',code],cwd=Path(__file__).resolve().parents[1],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_live_http_threads_keep_capacity_after_stop_join_timeout(self):
        entered=threading.Condition();release=threading.Event();calls=[0]
        class BlockingClient(Client):
            def call(self,*args):
                with entered:calls[0]+=1;entered.notify_all()
                release.wait(3)
                return super().call(*args)
        controllers=[]
        try:
            for _ in range(4):controllers.append(self.controller(BlockingClient()).start())
            with entered:self.assertTrue(entered.wait_for(lambda:calls[0]==4,2))
            for controller in controllers:
                controller.stop()
                with self.assertRaises(TimeoutError):controller.join(.001)
            with self.assertRaises(TimeoutError):self.controller().start()
        finally:
            release.set()
            for controller in controllers:controller.stop();controller.join(4)
        fresh=self.controller().start();fresh.stop();fresh.join(4)

    def test_pending_consent_http_threads_are_also_bounded(self):
        from guarddesk.mis_native_media import NativeViewerEngine
        release=threading.Event();entered=threading.Condition();count=[0]
        class Pending:
            def call(self,path,body=None):
                if path.startswith('/api/remote/session?'):
                    with entered:count[0]+=1;entered.notify_all()
                    release.wait(3);return {'id':'b'*32,'status':'requested','mode':'view'}
                return {'ok':True}
        engines=[]
        try:
            for _ in range(4):engines.append(NativeViewerEngine(Pending(),{'id':'b'*32},'.').start())
            with entered:self.assertTrue(entered.wait_for(lambda:count[0]==4,2))
            for engine in engines:engine.stop()
            with self.assertRaises(TimeoutError):NativeViewerEngine(Pending(),{'id':'b'*32},'.').start()
        finally:
            release.set()
            for engine in engines:
                engine.thread.join(4);self.assertFalse(engine.thread.is_alive())

    def test_shell_native_choice_requires_local_and_endpoint_cohort(self):
        from guarddesk.remote_viewer import RemoteViewer
        class Value:
            def __init__(self,value=None):self.value=value;self.options={}
            def get(self):return self.value
            def set(self,value):self.value=value
            def current(self):return 0
            def configure(self,**kwargs):self.options.update(kwargs)
        viewer=RemoteViewer.__new__(RemoteViewer)
        viewer.device_box=Value();viewer.mode_box=Value();viewer.quality_box=Value();viewer.connect_button=Value()
        viewer.mode=Value('僅檢視');viewer.quality=Value('清晰 · 原始解析度／最高 2 FPS');viewer.status=Value()
        viewer.catalog_data={'clarity_protocol':3};viewer.engine=None;viewer.busy=False;viewer.native_root=Path('owned');viewer.native_cohort='a'*64
        device={'id':'a'*24,'grant':{'can_control':True},'ready':True,'protocol':6,'native':{'wire':1,'cohort_sha256':'a'*64,'features':['native_capture','native_input','webrtc_video','native_renderer']}}
        viewer.devices=[device];viewer.selection_changed()
        self.assertIn('原生即時 · 內部預覽',viewer.quality_box.options['values'])
        self.assertEqual(viewer.quality.get(),'原生即時 · 內部預覽');self.assertEqual(viewer.mode.get(),'僅檢視')
        viewer.quality_manual=True;viewer.quality.set('清晰 · 原始解析度／最高 2 FPS');viewer.selection_changed()
        self.assertEqual(viewer.quality.get(),'清晰 · 原始解析度／最高 2 FPS')
        viewer.native_root=None;viewer.selection_changed()
        self.assertNotIn('原生即時 · 內部預覽',viewer.quality_box.options['values'])
        viewer.native_root=Path('owned');device['native']['features']=['native_capture'];viewer.selection_changed()
        self.assertNotIn('原生即時 · 內部預覽',viewer.quality_box.options['values'])
        device['native']['features']=['native_capture','native_input','webrtc_video','native_renderer']
        viewer.catalog_data['native_only_trial']=True;viewer.selection_changed()
        self.assertEqual(viewer.quality_box.options['values'],['原生即時 · 內部預覽'])
        self.assertEqual(viewer.quality.get(),'原生即時 · 內部預覽')
        viewer.native_root=None;viewer.selection_changed()
        self.assertEqual(viewer.quality_box.options['values'],[])
        self.assertEqual(viewer.connect_button.options['state'],'disabled')


@unittest.skipUnless(os.name=='nt','Windows private file pins')
class ImagePinTests(unittest.TestCase):
    def setUp(self):
        parent=Path(__file__).resolve().parents[1]/'runtime';parent.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=parent);self.addCleanup(self.temp.cleanup)
        from guarddesk.server_setup import secure_directory
        self.root=secure_directory(Path(self.temp.name),allow_empty=True);self.folder=self.root/'_internal/remote';self.folder.mkdir(parents=True)
        hashes={}
        for name in REMOTE_FILES:
            data=('owned-'+name).encode();(self.folder/name).write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
        (self.folder/'remote-cohort.json').write_text(json.dumps(cohort_manifest(hashes,build_id='a'*64)),encoding='utf-8')

    def test_standard_user_cohort_pins_prevent_write_delete_then_release(self):
        from guarddesk.mis_native_loader import ImagePins
        pins=ImagePins(self.root)
        try:
            with self.assertRaises(OSError):(self.folder/'GuardDeskMisNative.dll').write_bytes(b'replaced')
            with self.assertRaises(OSError):(self.folder/'GuardDeskMisNative.dll').unlink()
        finally:pins.close()
        (self.folder/'GuardDeskMisNative.dll').write_bytes(b'owned-after-close')

    def test_hash_mismatch_rejected_and_no_handle_leak(self):
        from guarddesk.mis_native_loader import ImagePins
        path=self.folder/'GuardDeskMisNative.dll';path.write_bytes(b'owned-corruption')
        with self.assertRaises(ValueError):ImagePins(self.root)
        path.unlink()

    def test_other_account_write_ace_rejected(self):
        from guarddesk.mis_native_loader import ImagePins
        result=subprocess.run(['icacls',str(self.folder),'/grant','*S-1-1-0:(OI)(CI)(W)'],capture_output=True)
        self.assertEqual(result.returncode,0)
        with self.assertRaises(PermissionError):ImagePins(self.root)

    def test_role_specific_mis_payload_no_endpoint_executables(self):
        from guarddesk.mis_native_loader import ImagePins
        from guarddesk.remote_components import read_cohort,ENDPOINT_REMOTE_FILES
        for name in ENDPOINT_REMOTE_FILES:(self.folder/name).unlink()
        pins=ImagePins(self.root);pins.close()
        with self.assertRaises(ValueError):read_cohort(self.root)
        (self.folder/'GuardDeskMisNative.dll').unlink()
        with self.assertRaises(ValueError):read_cohort(self.root,role='mis')

if __name__=='__main__':unittest.main()

class ModuleLifetimePinsTest(unittest.TestCase):
    def test_loaded_module_capacity_and_identity_are_bounded(self):
        from guarddesk import mis_native_media as module
        class Pins:
            cohort={'build_id':'a'*64,'files':{'GuardDeskMisNative.dll':'b'*64}}
            def __init__(self,*args):self.closed=False
            def close(self):self.closed=True
        with patch.dict(module._MODULE_IMAGES,{},clear=True),patch('guarddesk.mis_native_loader.ImagePins',Pins),patch.object(module.ctypes,'WinDLL',side_effect=lambda *a,**k:object()):
            for i in range(4):module._load_module(Path(str(i)),Path(str(i))/'GuardDeskMisNative.dll',Pins())
            with self.assertRaises(RuntimeError):module._load_module(Path('excess'),Path('excess')/'GuardDeskMisNative.dll',Pins())
            changed=Pins();changed.cohort={'build_id':'c'*64,'files':{'GuardDeskMisNative.dll':'b'*64}}
            with self.assertRaises(RuntimeError):module._load_module(Path('0'),Path('0')/'GuardDeskMisNative.dll',changed)
            self.assertEqual(len(module._MODULE_IMAGES),4)
            for record in module._MODULE_IMAGES.values():record['pins'].close()

    def test_dll_load_failure_explicitly_releases_both_pin_sets(self):
        from guarddesk import mis_native_media as module
        created=[]
        class Pins:
            cohort={'build_id':'a'*64,'files':{'GuardDeskMisNative.dll':'b'*64}}
            def __init__(self,*args):self.closed=False;created.append(self)
            def close(self):self.closed=True
        with patch.dict(module._MODULE_IMAGES,{},clear=True),patch('guarddesk.mis_native_loader.ImagePins',Pins),patch('guarddesk.remote_file_paths.file_hash',return_value='b'*64),patch.object(module.ctypes,'WinDLL',side_effect=OSError('owned load failure')):
            with self.assertRaises(OSError):module.NativeLibrary(Path('owned-unloaded'))
            self.assertEqual(len(created),2);self.assertTrue(all(p.closed for p in created));self.assertEqual(module._MODULE_IMAGES,{})

    @unittest.skipUnless(os.name=='nt' and (Path(os.environ.get('GUARDDESK_TEST_COHORT',str(Path(__file__).resolve().parents[2]/'remote-next-cohort-001')))/'_internal/remote/GuardDeskMisNative.dll').is_file(),'owned native cohort fixture unavailable')
    def test_real_cached_module_cannot_rename_after_session_close(self):
        cohort=Path(os.environ.get('GUARDDESK_TEST_COHORT',str(Path(__file__).resolve().parents[2]/'remote-next-cohort-001'))).resolve(strict=True)
        self.assertTrue(cohort.is_relative_to(Path(__file__).resolve().parents[2]))
        code=r"""
import ctypes,json,shutil,sys
from pathlib import Path
from guarddesk.server_setup import secure_directory
from guarddesk.mis_native_loader import ImagePins
from guarddesk.mis_native_media import Config,_load_module
root=Path(sys.argv[1]);secure_directory(root);folder=root/'_internal/remote';folder.mkdir(parents=True)
for n in ('GuardDeskMisNative.dll','remote-cohort.json'):shutil.copyfile(Path(sys.argv[2])/'_internal/remote'/n,folder/n)
pins=ImagePins(root);dll=_load_module(root,folder/'GuardDeskMisNative.dll',pins)
dll.GDMisCreate.argtypes=[ctypes.POINTER(Config),ctypes.POINTER(ctypes.c_void_p)];dll.GDMisCreate.restype=ctypes.c_uint32
for n in ('GDMisStop','GDMisClose'):getattr(dll,n).argtypes=[ctypes.c_void_p];getattr(dll,n).restype=ctypes.c_uint32
kernel=ctypes.WinDLL('kernel32',winmode=0x800);kernel.GetTickCount64.restype=ctypes.c_uint64
c=Config();c.bytes=ctypes.sizeof(c);c.version=1;c.session[0]=9;c.transport=1;c.consent_deadline=kernel.GetTickCount64()+10000
c.local_count=c.peer_count=1;c.local_ipv4[0]=c.peer_ipv4[0]=0x0100007f;c.owned_loopback=c.hidden=c.software=1
handle=ctypes.c_void_p();assert dll.GDMisCreate(ctypes.byref(c),ctypes.byref(handle))==0
assert dll.GDMisStop(handle)==0 and dll.GDMisClose(handle)==0;pins.close()
for path in (folder/'GuardDeskMisNative.dll',root):
    try:path.rename(path.with_name(path.name+'-renamed'))
    except OSError as error:assert error.winerror==32
    else:raise AssertionError('mapped module or cohort tree could be replaced')
new=ImagePins(root);assert _load_module(root,folder/'GuardDeskMisNative.dll',new)._handle==dll._handle;new.close()
print(json.dumps({'passed':True,'actual_PIN_and_module_lifetime_handles':True,'hidden_own_window':True,'desktop_capture':False,'OS_input':False}))
"""
        with tempfile.TemporaryDirectory() as temporary:
            result=subprocess.run([sys.executable,'-c',code,str(Path(temporary)/'private'),str(cohort)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(json.loads(result.stdout)['passed'])
