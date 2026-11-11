"""Protected native cohort coordinator; credentials remain in the SYSTEM Agent.

Only consent, signaling and short leases use Python/HTTPS. Pixels, presentation
ACKs and input pass through retained native processes. This development path is
opt-in and never falls back to the legacy image transport after an error.
"""
import ctypes
import hashlib
import ipaddress
import math
import queue
import re
import struct
import threading
import time
from pathlib import Path
from .transport_errors import (CenterTransportError,transient_heartbeat,native_authority_error,
    NATIVE_HEARTBEAT_RETRIES,NATIVE_HEARTBEAT_RESERVE_MS,NATIVE_HEARTBEAT_BACKOFF_SECONDS)

HEADER=struct.Struct('<4sHHII16sQQQQ')
MEDIA=struct.Struct('<4sHHII16sQQ16s')
CAPACITY=64+65536
NETWORK_SLOTS=threading.BoundedSemaphore(4)


def failure(phase,error):
    kind='ConnectionError' if isinstance(error,CenterTransportError) else type(error).__name__
    if kind not in ('OSError','PermissionError','ValueError','ConnectionError','TimeoutError',
                    'FileNotFoundError','RuntimeError','Full'):
        kind='OtherError'
    result={'phase':phase,'error_type':kind}
    diagnostic=getattr(error,'remote_diagnostic',None);code=getattr(error,'native_code',None)
    if isinstance(diagnostic,str) and re.fullmatch(r'[a-zA-Z0-9_/:=.-]{1,127}',diagnostic):result['diagnostic']=diagnostic
    if type(code) is int and 0<=code<=0xffffffff:result['native_code']=code
    return result


class Start(ctypes.Structure):
    _fields_=[('bytes',ctypes.c_uint32),('format',ctypes.c_uint32),('wts_session',ctypes.c_uint32),
        ('administrator',ctypes.c_uint32),('can_control',ctypes.c_uint32),('reserved',ctypes.c_uint32),
        ('authentication',ctypes.c_uint64),('logon_time',ctypes.c_uint64),('consent_filetime',ctypes.c_uint64),
        ('consent_tick_deadline',ctypes.c_uint64),('transport',ctypes.c_uint64),
        ('session',ctypes.c_uint8*16),('user_sid',ctypes.c_wchar*184)]


def binding(peer):
    session=peer.get('session');logon=peer.get('logon');sid=peer.get('sid')
    if type(session) is not int or not 0<session<2**32 or type(logon) is not int or logon<=0 or not isinstance(sid,str) or not re.fullmatch(r'S-1-(?:\d+-)+\d+',sid):
        raise ValueError('Invalid authenticated logon snapshot')
    generation=hashlib.sha256(f'{session}:{logon}:{sid}'.encode('ascii')).hexdigest()[:32]
    return {'wts_session':session,'logon_generation':generation}


def lease_deadline(reply,started,now,consent,*,can_control,administrator):
    if not isinstance(reply,dict) or type(reply.get('native_wire')) is not int or reply['native_wire']!=1 or type(reply.get('transport_generation')) is not int or reply['transport_generation']!=1:
        raise ValueError('Native lease contract')
    if reply.get('mode')!=('control' if can_control else 'view') or reply.get('admin_control') is not administrator:
        raise PermissionError('Native mode changed; new consent required')
    seconds=reply.get('lease_seconds')
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<=seconds<=5 or type(reply.get('authorized')) is not bool:
        raise ValueError('Native lease duration')
    if reply['authorized']!=(seconds>0):raise ValueError('Native lease authority')
    deadline=min(consent,started+int(seconds*1000))
    return deadline if reply['authorized'] and deadline>now else 0


def media_packet(kind,sid,sequence,payload=b''):
    if len(payload)>65536 or not 0<sequence<2**64:raise ValueError('Media packet bound')
    return MEDIA.pack(b'GDM3',1,kind,len(payload),0,bytes.fromhex(sid),1,sequence,b'\0'*16)+payload


def configuration(value,*,owned_loopback=False):
    if not isinstance(value,dict) or set(value)!={'local_ipv4','peer_ipv4','owned_loopback'} or value['owned_loopback'] is not owned_loopback:
        raise ValueError('Native network binding')
    result=[]
    for name in ('local_ipv4','peer_ipv4'):
        values=value[name]
        if not isinstance(values,list) or not 1<=len(values)<=8 or len(set(values))!=len(values):raise ValueError('Native interface count')
        packed=[]
        for text in values:
            ip=ipaddress.IPv4Address(text)
            if not ((ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast))
                    or (owned_loopback and ip.is_loopback)):raise ValueError('Native interface scope')
            packed.append(ip.packed)
        result.append((len(packed),b''.join(packed).ljust(32,b'\0')))
    return struct.pack('<IIII',result[0][0],result[1][0],int(owned_loopback),0)+result[0][1]+result[1][1]


class NativeLibrary:
    def __init__(self,agent):
        import sys
        from .machine_agent import eligible
        from .remote_components import read_cohort
        from .update_native import folder,protected_tree
        if not eligible(agent):raise PermissionError('Installed SYSTEM native broker required')
        root=folder(0x26)/'USBControl'
        if Path(sys.executable).resolve()!=root/'GuardDesk.exe':raise PermissionError('Fixed native broker image required')
        from .remote_admin_windows import identity
        identity()  # verifies the current token is SYSTEM, returns API/snapshot
        protected_tree(root,recursive=False);protected_tree(root/'_internal',recursive=False)
        protected_tree(root/'_internal'/'remote')
        cohort=read_cohort(root);self.capabilities={'wire':1,'cohort_sha256':cohort['build_id'],
            'features':['native_capture','native_input','webrtc_video','native_renderer'],'secure_desktop':True}
        self.dll=ctypes.WinDLL(str(root/'_internal'/'remote'/'GuardDeskRemoteBridge.dll'),winmode=0x100|0x800)
        definitions={'GDRemoteCheckTrust':[],
            'GDRemoteReserve':[ctypes.POINTER(Start),ctypes.POINTER(ctypes.c_void_p)],
            'GDRemoteLaunch':[ctypes.c_void_p], 'GDRemoteCommand':[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32],
            'GDRemoteMediaWrite':[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32],
            'GDRemoteMediaPoll':[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)],
            'GDRemoteWorkerPoll':[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)],
            'GDRemoteStop':[ctypes.c_void_p],'GDRemoteClose':[ctypes.c_void_p],
            'GDRemoteLastError':[ctypes.c_void_p,ctypes.c_uint32]}
        for name,args in definitions.items():
            method=getattr(self.dll,name);method.argtypes=args;method.restype=ctypes.c_uint32
        self.kernel=ctypes.WinDLL('kernel32',winmode=0x800);self.kernel.GetTickCount64.restype=ctypes.c_uint64
        self.verify_trust()  # Fail before publishing native capability/readiness.
    def verify_trust(self):self.check(self.dll.GDRemoteCheckTrust())
    def tick(self):return self.kernel.GetTickCount64()
    def check(self,code):
        if code:
            # Native diagnostic is a fixed stage/code string; no SDP, inputs,
            # employee paths or credentials are returned or persisted here.
            text=ctypes.create_string_buffer(128);self.dll.GDRemoteLastError(text,len(text))
            diagnostic=text.value.decode('ascii',errors='replace');error=OSError(code,'Native broker operation failed')
            if re.fullmatch(r'[a-zA-Z0-9_/:=.-]{1,127}',diagnostic):error.remote_diagnostic=diagnostic
            error.native_code=code;raise error
    def reserve(self,spec):
        handle=ctypes.c_void_p();self.check(self.dll.GDRemoteReserve(ctypes.byref(spec),ctypes.byref(handle)));return handle
    def launch(self,context):self.check(self.dll.GDRemoteLaunch(context))
    def command(self,context,packet):self.check(self.dll.GDRemoteCommand(context,packet,len(packet)))
    def write(self,context,packet):self.check(self.dll.GDRemoteMediaWrite(context,packet,len(packet)))
    def poll(self,context):
        buffer=ctypes.create_string_buffer(CAPACITY);size=ctypes.c_uint32()
        code=self.dll.GDRemoteMediaPoll(context,buffer,len(buffer),ctypes.byref(size))
        if code==232:return None  # ERROR_NO_DATA is an empty bounded mailbox.
        if code==234:return b''  # Native control/consumed handled; no key bytes.
        self.check(code)
        if not 64<=size.value<=CAPACITY:raise ValueError('Native media response length')
        return buffer.raw[:size.value]
    def stop(self,context):self.dll.GDRemoteStop(context)
    def worker_poll(self,context):
        buffer=ctypes.create_string_buffer(384);size=ctypes.c_uint32()
        code=self.dll.GDRemoteWorkerPoll(context,buffer,len(buffer),ctypes.byref(size))
        if code==232:return None
        self.check(code)
        if size.value!=384:raise ValueError('Native worker status length')
        return buffer.raw
    def close(self,context):self.dll.GDRemoteClose(context)


class NativeJob:
    def __init__(self,library,call,request,peer,approval,*,current=lambda:True,owned_loopback=False):
        self.library=library;self.call=call;self.request=dict(request);self.peer=dict(peer);self.current=current
        self.sid=request['id'];self.logon=binding(peer);self.owned_loopback=owned_loopback
        self.cohort_sha256=request.get('native_cohort_sha256')
        if not isinstance(self.cohort_sha256,str) or not re.fullmatch('[0-9a-f]{64}',self.cohort_sha256) or self.cohort_sha256!=library.capabilities['cohort_sha256']:
            raise ValueError('Native approval cohort changed')
        if not re.fullmatch('[0-9a-f]{32}',self.sid) or approval.get('native_wire')!=1 or approval.get('transport_generation')!=1:
            raise ValueError('Native approval contract')
        self.nonce=approval.get('native_nonce')
        if not isinstance(self.nonce,str) or not re.fullmatch('[0-9a-f]{64}',self.nonce):raise ValueError('Native approval nonce')
        self.spec=Start();self.spec.bytes=ctypes.sizeof(Start);self.spec.format=1
        self.spec.wts_session=peer['session'];self.spec.logon_time=peer['logon'];self.spec.user_sid=peer['sid']
        self.spec.administrator=int(request.get('admin_control') is True);self.spec.can_control=int(request['mode']=='control')
        from .remote_lifetime import NO_SESSION_DEADLINE
        self.spec.consent_filetime=approval['approval_filetime']
        self.spec.consent_tick_deadline=NO_SESSION_DEADLINE if approval.get('session_lifetime')=='until_stopped' else approval['approval_started_tick']+600000
        self.spec.transport=1;self.spec.session[:]=bytes.fromhex(self.sid)
        self.lock=threading.Lock();self.context=None;self.stop_event=threading.Event();self.done=threading.Event()
        self.replies=queue.Queue(maxsize=1);self.signals=queue.Queue(maxsize=1);self.error=None;self.phase='reserved'
        self.thread=None;self.network=None;self.sequence=0;self.media_sequence=0;self.granted=False;self.deadline=0;self.configured=None
        self.relay_configured=False;self.relay_identity=None
        self.negotiated=threading.Event();self.transient_retries=0
        self.recovering=False
        self.media_status=None;self.media_status_tick=None
        self.worker_status=None;self.worker_status_tick=None
    def reserve(self):
        context=self.library.reserve(self.spec)
        with self.lock:
            cancelled=self.stop_event.is_set()
            if not cancelled:self.context=context
        if cancelled:self.library.stop(context);self.library.close(context);return False
        return True
    def stop(self):
        self.stop_event.set()
        with self.lock:context=self.context
        if context:self.library.stop(context)  # independent of launch/pump lock
    def record_failure(self,phase,error):
        # Preserve the first cause; teardown errors must not replace it.
        value=failure(phase,error)
        with self.lock:
            if self.error is None:self.error=value
    def lifecycle_snapshot(self):
        now=self.library.tick()
        with self.lock:
            media=self.media_status or {};age=None if self.media_status_tick is None else max(0,now-self.media_status_tick)
            if self.done.is_set():state='ended'
            elif self.stop_event.is_set():state='stopping'
            elif self.recovering:state='recovering'
            elif self.granted and age is not None and age<=2000 and media.get('peer_connected') and media.get('channel_open') and media.get('encoded_frames',0)>0:state='streaming'
            elif self.phase in ('reserved','native_launch'):state='starting'
            else:state='negotiating'
            return {'state':state,'lease_remaining_ms':max(0,min(5000,self.deadline-now)) if self.granted else 0,
                'transient_retries':min(self.transient_retries,0xffffffff)}
    def start(self):
        self.thread=threading.Thread(target=self.run,name='GuardDesk native remote cohort',daemon=True);self.thread.start()
    def send(self,kind,payload=b''):
        self.media_sequence+=1;self.library.write(self.context,media_packet(kind,self.sid,self.media_sequence,payload))
    def network_loop(self):
        sequence=0;consecutive=0
        try:
            while not self.stop_event.is_set():
                sequence+=1;body={'session_id':self.sid,'transport_generation':1,'sequence':sequence,'native_nonce':self.nonce,'native_logon':self.logon}
                try:body['signal']=self.signals.get_nowait()
                except queue.Empty:pass
                started=self.library.tick()
                try:reply=self.call('/api/agent/remote/native',body)
                except Exception as error:
                    # Offers/answers are destructive single-consumption slots.
                    # Never replay SDP or retry an uncertain negotiation. Only
                    # fresh heartbeat sequences after a validated answer reply
                    # can recover within the already issued short lease.
                    now=self.library.tick()
                    if (not transient_heartbeat(error) or not self.negotiated.is_set()
                        or 'signal' in body or not self.granted or consecutive>=NATIVE_HEARTBEAT_RETRIES
                        or not self.current() or now+NATIVE_HEARTBEAT_RESERVE_MS>=min(self.deadline,self.spec.consent_tick_deadline)):
                        raise
                    consecutive+=1;self.transient_retries+=1;self.recovering=True
                    if self.stop_event.wait(NATIVE_HEARTBEAT_BACKOFF_SECONDS*consecutive):break
                    continue
                if self.stop_event.is_set():break
                consecutive=0;self.recovering=False
                self.replies.put_nowait((started,reply,'signal' in body));self.stop_event.wait(.35)
        except Exception as error:
            self.record_failure('native_signaling',error);self.stop()
        finally:NETWORK_SLOTS.release()
    def apply(self,started,reply):
        now=self.library.tick();deadline=lease_deadline(reply,started,now,self.spec.consent_tick_deadline,
            can_control=bool(self.spec.can_control),administrator=bool(self.spec.administrator))
        if reply.get('native_cohort_sha256')!=self.cohort_sha256:raise PermissionError('Native cohort changed; new consent required')
        network=configuration(reply.get('network'),owned_loopback=self.owned_loopback)
        if self.configured is None:self.send(7,network);self.configured=network
        elif network!=self.configured:raise PermissionError('Media network binding changed')
        from .remote_relay import relay_identity,encode_relay
        relay=reply.get('relay');identity=relay_identity(relay,owned_loopback=self.owned_loopback)
        if not self.relay_configured:
            if relay is not None:self.send(8,encode_relay(relay,started,now,self.spec.consent_tick_deadline,owned_loopback=self.owned_loopback))
            self.relay_identity=identity;self.relay_configured=True
        elif identity!=self.relay_identity:raise PermissionError('Media relay binding changed; new consent required')
        if deadline:
            self.sequence+=1
            payload=struct.pack('<QQII',deadline,1,self.spec.can_control,0)
            packet=HEADER.pack(b'GDR2',2,3,len(payload),0,bytes.fromhex(self.sid),0,self.sequence,0,1)+payload
            self.library.command(self.context,packet);self.send(1,struct.pack('<QII',deadline,self.spec.can_control,0))
            self.deadline=deadline;self.granted=True
        elif self.granted:raise native_authority_error('native_authority_lost','Native short lease lost')
        signal=reply.get('signal')
        if signal is not None:
            if not isinstance(signal,dict) or set(signal)!={'type','sdp'} or signal['type']!='offer':raise ValueError('Endpoint accepts one offer only')
            sdp=signal['sdp'].encode('ascii')
            if not 0<len(sdp)<=65528 or b'\0' in sdp:raise ValueError('Native SDP bound')
            self.send(2,b'\1'+b'\0'*7+sdp)
    def receive(self,packet):
        if len(packet)<64:raise ValueError('Media header truncated')
        magic,version,kind,count,reserved,session,transport,sequence,zeros=MEDIA.unpack(packet[:64])
        if (magic!=b'GDM3' or version!=1 or reserved or zeros!=b'\0'*16 or session!=bytes.fromhex(self.sid)
            or transport!=1 or not sequence or len(packet)!=64+count or count>65536):raise ValueError('Native media identity')
        if kind==2:
            payload=packet[64:]
            if not 8<len(payload)<=65536 or payload[:8]!=b'\2'+b'\0'*7:raise ValueError('Endpoint accepts native answer output only')
            self.signals.put_nowait({'type':'answer','sdp':payload[8:].decode('ascii')})
        elif kind==6:
            if count!=16:raise ValueError('Native media status size')
            version,flags,captured,encoded=struct.unpack('<IIII',packet[64:])
            if version!=1 or flags&~15:raise ValueError('Native media status schema')
            status={'peer_connected':bool(flags&1),'channel_open':bool(flags&2),
                'codec_failed':bool(flags&4),'stale_slot':bool(flags&8),
                'capture_sequence':captured,'encoded_frames':encoded}
            with self.lock:self.media_status=status;self.media_status_tick=self.library.tick()
        elif kind not in (3,4):raise ValueError('Native media direction')
        # Input and consumed are already validated/forwarded inside the native
        # bridge. They are not retained, logged or relayed through HTTP/Python.
    def media_snapshot(self):
        with self.lock:
            if self.media_status is None:return None
            return {**self.media_status,'age_ms':max(0,self.library.tick()-self.media_status_tick)}
    def receive_worker(self,packet):
        if len(packet)!=384:raise ValueError('Native worker status length')
        values=struct.unpack('<96I',packet)
        version,stage,api,error,polls,acquired,published,resets=values[:8];control=values[8:16]
        if version!=3 or stage>13 or (api!=0 and not 100<=api<=112) or control[5]>32 or values[16]>7 or any(values[86:]):raise ValueError('Native worker status schema')
        status=dict(stage=stage,api=api,error=error,polls=polls,acquired=acquired,published=published,resets=resets)
        status.update(zip(('input_received','input_accepted','input_rejected','input_stale','moves_coalesced',
            'queue_high_water','queue_age_max_ms','command_max_ms'),control))
        status.update(last_pause_reason=values[16],housekeeping=values[17],guard_checks=values[18],capture_pending=values[19])
        status['latency_us']={name:{'count':values[20+i*10],'max':values[21+i*10],'bins':list(values[22+i*10:30+i*10])}
            for i,name in enumerate(('queue','command','guard','send_input','capture'))}
        status['reset_reasons']=list(values[70:78])
        status['input_reject_reasons']=dict(zip(('other','schema_identity_sequence','authorization','rate','desktop','frame_or_stale','view_only','payload_or_ledger'),values[78:86]))
        with self.lock:self.worker_status=status;self.worker_status_tick=self.library.tick()
    def worker_snapshot(self):
        with self.lock:
            if self.worker_status is None:return None
            return {**self.worker_status,'age_ms':max(0,self.library.tick()-self.worker_status_tick)}
    def run(self):
        try:
            if self.stop_event.is_set():return
            self.phase='native_launch';self.library.launch(self.context)
            if self.stop_event.is_set():return
            self.phase='native_transport';handshake_deadline=min(self.spec.consent_tick_deadline,self.library.tick()+15000)
            if not NETWORK_SLOTS.acquire(blocking=False):raise OSError('Native signaling still draining; bounded capacity reached')
            try:
                self.network=threading.Thread(target=self.network_loop,name='GuardDesk native signaling',daemon=True);self.network.start()
            except BaseException:NETWORK_SLOTS.release();self.network=None;raise
            while not self.stop_event.is_set():
                now=self.library.tick()
                reason=None
                if not self.current():reason='native_binding_expired'
                elif now>=self.spec.consent_tick_deadline:reason='native_consent_expired'
                elif self.granted and now>=self.deadline:reason='native_short_lease_expired'
                elif not self.granted and now>=handshake_deadline:reason='native_handshake_timeout'
                if reason:raise native_authority_error(reason)
                try:
                    started,reply,answered=self.replies.get_nowait();self.apply(started,reply)
                    if answered:self.negotiated.set()
                except queue.Empty:pass
                worker_packet=self.library.worker_poll(self.context)
                if worker_packet is not None:self.receive_worker(worker_packet)
                for _ in range(16):
                    packet=self.library.poll(self.context)
                    if packet is None:break
                    if packet==b'':continue
                    self.receive(packet)
                # Native pump owns all control I/O. Python polls scalar state
                # and center replies only; delaying this loop cannot queue keys.
                self.stop_event.wait(.02)
        except Exception as error:
            self.record_failure(self.phase,error)
        finally:
            self.stop()
            if self.network:self.network.join(3.5)
            with self.lock:context=self.context;self.context=None
            if context:self.library.close(context)
            self.done.set()


class Launcher:
    def __init__(self,agent,*,library=None):
        self.library=library or NativeLibrary(agent);self.agent=agent;self.lock=threading.Lock();self.entries={}
        self.capabilities=dict(self.library.capabilities);self.last_failure=None
    def tick(self):return self.library.tick()
    def reserve(self,sid):
        with self.lock:
            self.entries={key:value for key,value in self.entries.items() if not isinstance(value,NativeJob) or not value.done.is_set()}
            if sid in self.entries:raise PermissionError('Native session already reserved')
            if len(self.entries)>=4:raise PermissionError('Native cohort capacity exceeded')
            self.entries[sid]=object()
    def revoke(self,sid):
        with self.lock:
            job=self.entries.get(sid)
            if not isinstance(job,NativeJob):self.entries.pop(sid,None)
        if isinstance(job,NativeJob):job.stop()
    def stop(self,sid):self.revoke(sid)
    def alive(self,sid):
        with self.lock:job=self.entries.get(sid)
        return isinstance(job,NativeJob) and not job.stop_event.is_set() and not job.done.is_set()
    def observe(self,sid):
        with self.lock:job=self.entries.get(sid)
        return job.lifecycle_snapshot() if isinstance(job,NativeJob) else None
    def snapshot(self):
        with self.lock:items=list(self.entries.items());last=dict(self.last_failure) if self.last_failure else None
        return {'preview':True,'cohort_sha256':self.capabilities['cohort_sha256'],
            'last_failure':last,
            'contexts':[{'id':sid,'phase':job.phase,'state':'ended' if job.done.is_set() else 'stopping' if job.stop_event.is_set() else 'active',
                'error':dict(job.error) if job.error else None,'media':job.media_snapshot(),'worker':job.worker_snapshot(),
                'lifecycle':job.lifecycle_snapshot()} for sid,job in items if isinstance(job,NativeJob)]}
    def launch(self,request,peer,state,approval,*,current):
        sid=request['id']
        with self.lock:reservation=self.entries.get(sid)
        if reservation is None or isinstance(reservation,NativeJob):raise PermissionError('Native reservation revoked or consumed')
        try:
            job=NativeJob(self.library,lambda path,body:self.agent.call(path,body,timeout=3),request,peer,approval,current=current)
            if not job.reserve():return
        except Exception as error:
            with self.lock:self.last_failure=failure('native_reserve',error)
            raise
        with self.lock:
            valid=self.entries.get(sid) is reservation
            if valid:self.entries[sid]=job
        if not valid:job.stop();self.library.close(job.context);job.context=None;raise PermissionError('Native launch revoked')
        job.start()
    def close(self):
        with self.lock:jobs=[job for job in self.entries.values() if isinstance(job,NativeJob)];self.entries.clear()
        for job in jobs:job.stop()
        # Stop signals precede every join. One shared deadline bounds teardown,
        # so four contexts cannot multiply it while the updater waits to switch.
        deadline=time.monotonic()+5
        for job in jobs:
            if job.thread:job.thread.join(max(0,deadline-time.monotonic()))
        if any(job.thread and job.thread.is_alive() for job in jobs):raise OSError('Native cohort has not finished protected teardown')
