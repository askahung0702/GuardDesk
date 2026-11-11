"""Authenticated MIS control plane + native window. No pixels or key logging.

The caller supplies the current, approved native session and explicit interface
addresses. Two bounded threads own network and Win32 work separately. No SDP
retries, consent extension, credential forwarding or legacy-image fallback.
"""
import ctypes
import ipaddress
import math
import queue
import re
import threading
import time
from pathlib import Path
from .remote_relay import encode_relay,relay_identity
from .remote_lifetime import NO_SESSION_DEADLINE,consent_tick
from .transport_errors import (CenterTransportError,transient_heartbeat,native_authority_error,
    NATIVE_HEARTBEAT_RETRIES,NATIVE_HEARTBEAT_RESERVE_MS,NATIVE_HEARTBEAT_BACKOFF_SECONDS,
    NATIVE_AUTHORITY_REASONS)

_SIGNALING_SLOTS=threading.BoundedSemaphore(4)
_CONSENT_SLOTS=threading.BoundedSemaphore(4)
_MODULE_LOCK=threading.Lock()
_MODULE_IMAGES={}  # At most four immutable loaded identities, retained until process exit.
_MEDIA_END_REASONS={2:'native_short_lease_expired',3:'native_media_connection_closed',
    4:'native_media_protocol_rejected',5:'native_media_send_failed',6:'native_media_callback_failed',7:'native_media_cleanup_timeout'}


def _load_module(root,path,pins):
    # Windows PIN blocks unload/write but permits rename. Keep separate no-delete
    # pins for every cached module; closing a session only releases its own pins.
    from .mis_native_loader import ImagePins
    key=str(path.resolve()).casefold();identity=(pins.cohort['build_id'],pins.cohort['files'][path.name])
    with _MODULE_LOCK:
        old=_MODULE_IMAGES.get(key)
        if old is not None:
            if old['identity']!=identity or old['loading']:raise RuntimeError('Native image identity changed or loading')
            return old['dll']
        if len(_MODULE_IMAGES)>=4:raise RuntimeError('Native image lifetime capacity')
        record={'identity':identity,'loading':True,'pins':None,'dll':None};_MODULE_IMAGES[key]=record
    retained=None
    try:
        retained=ImagePins(root)
        dll=ctypes.WinDLL(str(path.resolve()),winmode=0x100|0x800)
        with _MODULE_LOCK:record.update(pins=retained,dll=dll,loading=False)
        return dll
    except Exception:
        if retained is not None:retained.close()
        with _MODULE_LOCK:_MODULE_IMAGES.pop(key,None)
        raise


class Config(ctypes.Structure):
    _fields_=[('bytes',ctypes.c_uint32),('version',ctypes.c_uint32),
        ('can_control',ctypes.c_uint32),('owned_loopback',ctypes.c_uint32),
        ('session',ctypes.c_uint8*16),('transport',ctypes.c_uint64),('consent_deadline',ctypes.c_uint64),
        ('local_count',ctypes.c_uint32),('peer_count',ctypes.c_uint32),
        ('local_ipv4',ctypes.c_uint32*8),('peer_ipv4',ctypes.c_uint32*8),
        ('hidden',ctypes.c_uint32),('software',ctypes.c_uint32)]


def addresses(values,owned_loopback=False):
    if not isinstance(values,(tuple,list)) or not 1<=len(values)<=8:raise ValueError('Explicit IPv4 interfaces required')
    result=[]
    for value in values:
        ip=ipaddress.IPv4Address(value)
        if not ((ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified)
            or (owned_loopback and ip.is_loopback)):raise ValueError('Unapproved media address')
        if ip in result:raise ValueError('Duplicate media address')
        result.append(ip)
    return result


class NativeLibrary:
    def __init__(self,root):
        from .mis_native_loader import ImagePins
        root=Path(root);self.pins=ImagePins(root)
        self._closed=False
        try:
            folder=root/'_internal'/'remote'
            path=folder/'GuardDeskMisNative.dll'
            # read_cohort must cover this image; older cohorts cannot enable it.
            from .remote_file_paths import file_hash
            if self.pins.cohort['files'].get(path.name)!=file_hash(path):raise ValueError('MIS media DLL absent from verified cohort')
            self.dll=_load_module(root,path,self.pins)
            definitions={
                'GDMisCreate':[ctypes.POINTER(Config),ctypes.POINTER(ctypes.c_void_p)],
                'GDMisRelay':[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32],
                'GDMisGrant':[ctypes.c_void_p,ctypes.c_uint64], 'GDMisOffer':[ctypes.c_void_p],
                'GDMisSignal':[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32],
                'GDMisTakeSignal':[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32),ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)],
                'GDMisPump':[ctypes.c_void_p],'GDMisWait':[ctypes.c_void_p],'GDMisWake':[ctypes.c_void_p],
                'GDMisRun':[ctypes.c_void_p],
                'GDMisPostReply':[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint32],
                'GDMisActivate':[ctypes.c_void_p,ctypes.c_uint32],
                'GDMisDiagnostics':[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32],
                'GDMisEndReason':[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)],
                'GDMisTransportDiagnostics':[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32],
                'GDMisStop':[ctypes.c_void_p],'GDMisClose':[ctypes.c_void_p]}
            for name,args in definitions.items():
                method=getattr(self.dll,name);method.argtypes=args;method.restype=ctypes.c_uint32
            self.kernel=ctypes.WinDLL('kernel32',winmode=0x800)
            self.kernel.GetTickCount64.restype=ctypes.c_uint64
        except Exception:
            self.pins.close()
            raise

    def tick(self):return self.kernel.GetTickCount64()
    @staticmethod
    def check(code):
        if code:raise OSError(code,'Native MIS operation failed')
    def create(self,config):
        if self._closed:raise RuntimeError('Native library session owner closed')
        handle=ctypes.c_void_p()
        try:self.check(self.dll.GDMisCreate(ctypes.byref(config),ctypes.byref(handle)));return handle
        except Exception:self._closed=True;self.pins.close();raise
    def grant(self,handle,deadline):self.check(self.dll.GDMisGrant(handle,deadline))
    def relay(self,handle,wire):
        buffer=ctypes.create_string_buffer(wire);self.check(self.dll.GDMisRelay(handle,buffer,len(wire)))
    def offer(self,handle):self.check(self.dll.GDMisOffer(handle))
    def signal(self,handle,value):
        if not isinstance(value,dict) or set(value)!={'type','sdp'} or value['type']!='answer':raise ValueError('Unexpected native media signal')
        encoded=value['sdp'].encode('ascii')
        if not 0<len(encoded)<=65528 or b'\0' in encoded:raise ValueError('Native signal size')
        buffer=ctypes.create_string_buffer(encoded)
        self.check(self.dll.GDMisSignal(handle,0,buffer,len(encoded)))
    def take_signal(self,handle):
        data=ctypes.create_string_buffer(65528);size=ctypes.c_uint32(len(data));offer=ctypes.c_uint32()
        code=self.dll.GDMisTakeSignal(handle,ctypes.byref(offer),data,ctypes.byref(size))
        if code==259:return None
        self.check(code)
        if offer.value!=1 or size.value>len(data):raise ValueError('Native offer contract')
        return {'type':'offer','sdp':data.raw[:size.value].decode('ascii')}
    def pump(self,handle):self.check(self.dll.GDMisPump(handle))
    def wait(self,handle):self.check(self.dll.GDMisWait(handle))
    def wake(self,handle):self.dll.GDMisWake(handle)
    def run(self,handle):
        # WinDLL releases the GIL for the entire native message/render loop.
        code=self.dll.GDMisRun(handle)
        if code!=1223:self.check(code)
        reason=ctypes.c_uint32();self.check(self.dll.GDMisEndReason(handle,ctypes.byref(reason)))
        if reason.value in _MEDIA_END_REASONS:
            error=OSError(code,'Native media ended')
            error.remote_diagnostic=_MEDIA_END_REASONS[reason.value]
            raise error
        if reason.value not in (0,1):raise ValueError('Native end reason schema')
    def activate(self,handle,toggle=False):self.check(self.dll.GDMisActivate(handle,int(toggle)))
    def post_reply(self,handle,deadline,signal):
        buffer=None;size=0
        if signal is not None:
            if not isinstance(signal,dict) or set(signal)!={'type','sdp'} or signal['type']!='answer':raise ValueError('Native answer contract')
            encoded=signal['sdp'].encode('ascii')
            if not 0<len(encoded)<=65528 or b'\0' in encoded:raise ValueError('Native signal size')
            buffer=ctypes.create_string_buffer(encoded);size=len(encoded)
        self.check(self.dll.GDMisPostReply(handle,deadline,buffer,size))
    def diagnostics(self,handle):
        values=(ctypes.c_uint32*32)();self.check(self.dll.GDMisDiagnostics(handle,values,len(values)))
        if values[0]!=1 or values[3]!=0:raise ValueError('MIS diagnostic schema')
        transport=(ctypes.c_uint32*20)();self.check(self.dll.GDMisTransportDiagnostics(handle,transport,len(transport)))
        if transport[0]!=1 or any(transport[16:]) or transport[5]>32:raise ValueError('Native transport diagnostic schema')
        return {'input_offered':values[1],'input_sent':values[2],
            'transport':{'queued':transport[1],'transmitted':transport[2],'discarded':transport[3],'backpressure':transport[4],'high_water':transport[5],
                'queue_us':{'count':transport[6],'max':transport[7],'bins':list(transport[8:16])}},
            'ui_event_us':{'count':values[4],'max':values[5],'bins':list(values[6:14])},
            'send_us':{'count':values[14],'max':values[15],'bins':list(values[16:24])},
            'display_reasons':dict(zip(('pause','generation','hidden','resize','busy','occluded','present_error','stale_result'),values[24:]))}
    def stop(self,handle):self.dll.GDMisStop(handle)
    def close(self,handle):
        try:self.check(self.dll.GDMisClose(handle))
        finally:self._closed=True;self.pins.close()


class NativeMisController:
    """One approved session; start/stop/join fit the existing MIS shell lifecycle."""
    def __init__(self,client,root,session,*,local_ipv4,peer_ipv4,can_control,
                 consent_deadline,transport=1,library=None,owned_loopback=False,hidden=False,initial_sequence=0,relay=None,relay_started_tick=None):
        if not re.fullmatch('[0-9a-f]{32}',session) or type(transport) is not int or not 0<transport<2**64:
            raise ValueError('Native session identity')
        if type(can_control) is not bool or type(consent_deadline) is not int or (hidden and not owned_loopback):raise ValueError('Native consent')
        self.client=client;self.session=session;self.transport=transport;self.can_control=can_control
        parsed_addresses=[(name,addresses(values,owned_loopback)) for name,values in [('local',local_ipv4),('peer',peer_ipv4)]]
        relay_id=relay_identity(relay,owned_loopback=owned_loopback)
        self.library=library or NativeLibrary(root)
        now=self.library.tick()
        if consent_deadline!=NO_SESSION_DEADLINE and not now<consent_deadline<=now+600000:
            if hasattr(self.library,'pins'):self.library.pins.close()
            raise ValueError('Native consent expired')
        self.relay_id=relay_id;self.owned_loopback=owned_loopback
        try:self.relay_wire=encode_relay(relay,now if relay_started_tick is None else relay_started_tick,now,consent_deadline,owned_loopback=owned_loopback) if relay is not None else None
        except Exception:
            if hasattr(self.library,'pins'):self.library.pins.close()
            raise
        self.config=Config();self.config.bytes=ctypes.sizeof(Config);self.config.version=1
        self.config.can_control=int(can_control);self.config.owned_loopback=int(owned_loopback)
        self.config.session[:]=bytes.fromhex(session);self.config.transport=transport;self.config.consent_deadline=consent_deadline
        for name,values in parsed_addresses:
            setattr(self.config,name+'_count',len(values))
            for i,ip in enumerate(values):getattr(self.config,name+'_ipv4')[i]=int.from_bytes(ip.packed,'little')
        self.config.hidden=int(hidden);self.config.software=int(hidden)
        pins=getattr(self.library,'pins',None);self.cohort=pins.cohort['build_id'] if pins else None
        self.stop_event=threading.Event();self.lock=threading.Lock();self.handle=None;self.error=None
        self.offers=queue.Queue(maxsize=1);self.replies=queue.Queue(maxsize=1)
        self.ui_ready=threading.Event()
        self.ui=None;self.network=None;self.started=False
        self.initial_sequence=initial_sequence
        self._permit=False;self.diagnostic_status=None;self.transient_retries=0

    def _fail(self,exc):
        # Scalar error only. Never preserve exception message/SDP/auth response.
        with self.lock:
            if self.error is None:
                self.error={'type':type(exc).__name__,'code':getattr(exc,'winerror',None)}
                diagnostic=getattr(exc,'remote_diagnostic',None)
                if isinstance(diagnostic,str) and diagnostic in NATIVE_AUTHORITY_REASONS|frozenset(_MEDIA_END_REASONS.values()):self.error['diagnostic']=diagnostic
                elif isinstance(exc,CenterTransportError) and exc.category in ('http','tls','temporary_network','network_unclassified'):
                    self.error['diagnostic']='center_'+exc.category
                    if exc.category=='http' and type(exc.http_status) is int and 100<=exc.http_status<=599:
                        self.error['http_status']=exc.http_status
        self.stop()

    def start(self):
        if self.started:raise RuntimeError('Native viewer already started')
        if not _SIGNALING_SLOTS.acquire(blocking=False):raise TimeoutError('Native signaling capacity still in use')
        self._permit=True
        self.started=True
        self.ui=threading.Thread(target=self._ui,name='GuardDesk native MIS',daemon=True)
        self.network=threading.Thread(target=self._network,name='GuardDesk native signaling',daemon=True)
        try:self.ui.start();self.network.start()
        except Exception:
            self.stop()
            self._permit=False;_SIGNALING_SLOTS.release()
            raise
        return self

    def _ui(self):
        handle=None
        try:
            handle=self.library.create(self.config)
            with self.lock:self.handle=handle
            self.ui_ready.set()
            if self.stop_event.is_set():return
            if not self.config.hidden:
                try:self.library.activate(handle) # native owner loop applies it
                except OSError:pass # optional local UI must not stop transport
            if self.relay_wire is not None:self.library.relay(handle,self.relay_wire);self.relay_wire=None
            self.library.offer(handle)
            value=self.library.take_signal(handle)
            if value is not None:self.offers.put_nowait(value)
            self.library.run(handle)
            self.stop_event.set()
        except Exception as exc:self._fail(exc)
        finally:
            self.ui_ready.set()
            if handle is not None:
                self.library.stop(handle)
                with self.lock:self.handle=None
                self.library.close(handle)

    def activate_window(self,toggle_maximize=False):
        if type(toggle_maximize) is not bool:raise ValueError('Invalid local viewer action')
        if self.stop_event.is_set() or self.config.hidden:return False
        with self.lock:
            if self.handle is None:return False
            self.library.activate(self.handle,toggle_maximize)
            return True

    def _network(self):
        sequence=self.initial_sequence;ever_granted=False;answer_confirmed=False
        last_deadline=0;consecutive=0
        try:
            while not self.ui_ready.wait(.1):
                if self.stop_event.is_set():return
            while not self.stop_event.is_set():
                sequence+=1;body={'session_id':self.session,'transport_generation':self.transport,'sequence':sequence}
                try:body['signal']=self.offers.get_nowait()
                except queue.Empty:pass
                started=self.library.tick()
                if started>=self.config.consent_deadline:raise native_authority_error('native_consent_expired')
                if ever_granted and started>=last_deadline:raise native_authority_error('native_short_lease_expired')
                try:
                    exchange=getattr(self.client,'native_exchange',None)
                    timeout=min(3,(min(last_deadline,self.config.consent_deadline)-started)/1000) if ever_granted else 3
                    reply=exchange(body,timeout=timeout) if callable(exchange) else self.client.call('/api/remote/native',body)
                except Exception as exc:
                    # Recover only a confirmed heartbeat, never an offer/answer,
                    # and never beyond the already issued native short lease.
                    now=self.library.tick()
                    if (not transient_heartbeat(exc) or not answer_confirmed or not ever_granted
                        or 'signal' in body or consecutive>=NATIVE_HEARTBEAT_RETRIES
                        or self.stop_event.is_set()
                        or now+NATIVE_HEARTBEAT_RESERVE_MS>=min(last_deadline,self.config.consent_deadline)):
                        raise
                    consecutive+=1;self.transient_retries+=1
                    if self.stop_event.wait(NATIVE_HEARTBEAT_BACKOFF_SECONDS*consecutive):return
                    continue
                if self.stop_event.is_set():return
                now=self.library.tick()
                if now>=self.config.consent_deadline:raise native_authority_error('native_consent_expired')
                if ever_granted and now>=last_deadline:raise native_authority_error('native_short_lease_expired')
                consecutive=0
                if (not isinstance(reply,dict) or reply.get('native_wire')!=1 or reply.get('transport_generation')!=self.transport
                    or (self.cohort is not None and reply.get('native_cohort_sha256')!=self.cohort)):
                    raise ValueError('Native transport changed')
                if relay_identity(reply.get('relay'),owned_loopback=self.owned_loopback)!=self.relay_id:raise ValueError('Native relay changed')
                duration=reply.get('lease_seconds');authorized=reply.get('authorized')
                if type(authorized) is not bool or type(duration) not in (int,float) or not math.isfinite(duration) or not 0<=duration<=5:
                    raise ValueError('Native lease contract')
                if reply.get('mode')!=('control' if self.can_control else 'view'):raise ValueError('Native mode changed')
                deadline=min(self.config.consent_deadline,started+int(duration*1000)) if authorized else 0
                if authorized:
                    if duration<=0 or deadline<=now:raise ValueError('Delayed native lease')
                    ever_granted=True
                elif ever_granted:raise native_authority_error('native_authority_lost','Native authorization ended')
                signal=reply.get('signal')
                if signal is not None and (not isinstance(signal,dict) or set(signal)!={'type','sdp'} or signal['type']!='answer'):
                    raise ValueError('Native answer contract')
                with self.lock:
                    if self.handle is None or self.stop_event.is_set():return
                    self.library.post_reply(self.handle,deadline,signal)
                    if deadline:last_deadline=deadline
                    if signal is not None:answer_confirmed=True
                    self.diagnostic_status=self.library.diagnostics(self.handle)
                self.stop_event.wait(.3)
        except Exception as exc:self._fail(exc)
        finally:
            # A join timeout does not free capacity held by a live socket call.
            if self._permit:self._permit=False;_SIGNALING_SLOTS.release()

    def stop(self):
        self.stop_event.set()
        with self.lock:
            if self.handle is not None:self.library.stop(self.handle)

    def join(self,timeout=5):
        deadline=time.monotonic()+timeout
        for thread in (self.ui,self.network):
            if thread:thread.join(max(0,deadline-time.monotonic()))
        if any(t and t.is_alive() for t in (self.ui,self.network)):raise TimeoutError('Native MIS still stopping')


def native_stop_message(error):
    """Translate only fixed local categories, never server text or SDP."""
    generic='原生協助已停止；請確認能力、網路與本次同意後重新連線。'
    if not isinstance(error,dict):return generic
    diagnostic=error.get('diagnostic')
    if not isinstance(diagnostic,str):return generic
    if diagnostic=='center_http':
        if error.get('http_status') in (401,403):
            return '中心登入或協助授權已失效，已停止協助；請重新登入並取得使用者同意。'
        return '管理中心無法處理協助心跳，已停止協助；請確認 Server 狀態。'
    return {
        'center_temporary_network':'管理中心心跳連線失敗，已停止協助；請確認 Server 連線後重新取得同意。',
        'center_network_unclassified':'管理中心連線失敗，已停止協助；請確認 Server 連線。',
        'center_tls':'管理中心安全連線驗證失敗，已停止協助；請檢查憑證與 Server 設定。',
        'native_short_lease_expired':'協助授權未能及時續期，已停止協助；請確認 Server 連線後重新取得同意。',
        'native_consent_expired':'本次協助同意已到期，已停止協助；請重新取得同意。',
        'native_binding_expired':'登入工作階段或本次同意已改變，已停止協助；請重新取得同意。',
        'native_authority_lost':'中心未再授予本次協助權限，已停止協助；請重新取得同意。',
        'native_handshake_timeout':'遠端協商未能在時限內完成，已停止協助。'
        ,'native_media_connection_closed':'影像傳輸連線已中斷，已停止協助。'
        ,'native_media_protocol_rejected':'遠端傳輸資料未通過協定檢查，已停止協助。'
        ,'native_media_send_failed':'遠端輸入傳送失敗，已停止協助。'
        ,'native_media_callback_failed':'原生影像處理失敗，已停止協助。'
        ,'native_media_cleanup_timeout':'遠端輸入佇列未能安全清理，已停止協助。'
    }.get(diagnostic,generic)


class NativeViewerEngine:
    native_media=True
    """MIS shell adapter. Native window owns rendering, focus and all input."""
    def __init__(self,client,session,root):
        self.client=client;self.session=dict(session);self.root=root;self.stats={'codec':'原生 H.264／WebRTC'}
        self.fresh_until=0;self.closed=threading.Event();self.cancel=threading.Event();self.lock=threading.Lock()
        self.latest=None;self.error=None;self.controller=None;self.thread=None
        self._permit=False

    def start(self):
        if self.thread is not None:raise RuntimeError('Native consent already started')
        if not _CONSENT_SLOTS.acquire(blocking=False):raise TimeoutError('Native consent capacity still in use')
        self._permit=True
        self.thread=threading.Thread(target=self._run,name='GuardDesk native consent',daemon=True)
        try:self.thread.start()
        except Exception:self._permit=False;_CONSENT_SLOTS.release();raise
        return self

    def _run(self):
        library=None;controller=None
        try:
            until=time.monotonic()+600
            while not self.cancel.is_set():
                packet=self.client.call('/api/remote/session?id='+self.session['id'])
                if packet['status'] not in ('requested','active'):raise PermissionError('原生協助已結束')
                self.session=packet
                with self.lock:self.latest=(dict(packet),None)
                if packet['status']=='active':break
                if time.monotonic()>=until:raise TimeoutError('等待同意逾時')
                self.cancel.wait(.3)
            if self.cancel.is_set():return
            library=NativeLibrary(self.root);started=library.tick()
            if self.session.get('native_cohort_sha256')!=library.pins.cohort['build_id']:
                library.pins.close();raise ValueError('Native cohort mismatch')
            initial=self.client.call('/api/remote/native',{'session_id':self.session['id'],'transport_generation':1,'sequence':1})
            network=initial.get('network');seconds=initial.get('consent_seconds')
            if (not isinstance(network,dict) or set(network)!={'local_ipv4','peer_ipv4','owned_loopback'}
                or network['owned_loopback'] is not False or (seconds is not None and type(seconds) not in (int,float)) or 'consent_seconds' not in initial
                or (seconds is not None and (not math.isfinite(seconds) or not 0<seconds<=600)) or initial.get('native_wire')!=1
                or initial.get('transport_generation')!=1 or initial.get('native_cohort_sha256')!=library.pins.cohort['build_id']):
                library.pins.close();raise ValueError('原生網路／本次同意尚未就緒')
            deadline=consent_tick(seconds,started)
            controller=NativeMisController(self.client,self.root,self.session['id'],
                local_ipv4=network['local_ipv4'],peer_ipv4=network['peer_ipv4'],can_control=self.session['mode']=='control',
                consent_deadline=deadline,library=library,initial_sequence=1,relay=initial.get('relay'),relay_started_tick=started)
            with self.lock:
                self.controller=controller
                if self.cancel.is_set():controller.stop();return
            controller.start()
            while not self.cancel.is_set() and not controller.stop_event.wait(.1):pass
            controller.stop();controller.join()
            if controller.error and not self.cancel.is_set():raise OSError('原生媒體已停止；請重新取得同意')
        except Exception:
            # No server error text/SDP persists into diagnostics.
            with self.lock:self.error=native_stop_message(controller.error if controller is not None else None)
        finally:
            if library is not None and controller is None:library.pins.close()
            try:self.client.call('/api/remote/stop',{'session_id':self.session['id']})
            except (OSError,ValueError):pass
            self.closed.set()
            if self._permit:self._permit=False;_CONSENT_SLOTS.release()

    def stop(self):
        self.cancel.set()
        with self.lock:
            if self.controller:self.controller.stop()

    def send(self,action):return False  # Never inject from the old Tk canvas.
    def activate_window(self,toggle_maximize=False):
        with self.lock:controller=self.controller
        return bool(controller and not self.cancel.is_set() and controller.activate_window(toggle_maximize))
    def presented(self,*args):return False  # Only actual native Present can ACK.
    def take(self):
        with self.lock:
            latest,error=self.latest,self.error;self.latest=self.error=None
        return latest,error
