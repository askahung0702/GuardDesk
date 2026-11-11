"""Native remote control plane. SDP only; pixels/input never pass through SQLite.

The existing remote route authenticates every caller, rechecks grants/consent,
and owns this object's lifetime. A server restart loses all native authority.
This development path is disabled unless explicitly configured; it is not a
claim that native UAC/media/installer field acceptance has passed.
"""
import math
import re
import secrets
import time
import ipaddress

WIRE=1
SDP_BYTES=65528
FEATURES=('native_capture','native_input','webrtc_video','native_renderer')


def require(value,message='原生遠端狀態不相容',status=409):
    from .remote_errors import RemoteError
    if not value:raise RemoteError(status,message)


def enabled(server):
    return getattr(server,'remote_native_preview',False) is True


def capabilities(value):
    require(isinstance(value,dict) and set(value)=={'wire','cohort_sha256','features','secure_desktop'},status=400)
    require(type(value['wire']) is int and value['wire']==WIRE and isinstance(value['cohort_sha256'],str)
        and re.fullmatch('[0-9a-f]{64}',value['cohort_sha256']) and value['features']==list(FEATURES)
        and type(value['secure_desktop']) is bool,status=400)
    return {**value,'features':list(FEATURES),'experimental':True,'field_accepted':False}


def presence(server,did,value,now):
    clean=capabilities(value)
    if not enabled(server):return
    with server.remote_lock:
        for key,record in list(server.remote_native_presence.items()):
            if now-record['received']>=12:server.remote_native_presence.pop(key,None)
        require(did in server.remote_native_presence or len(server.remote_native_presence)<1024,'原生能力狀態已滿')
        server.remote_native_presence[did]={'received':now,'capabilities':clean}


def reported(server,did,now):
    if not enabled(server):return None
    with server.remote_lock:
        entry=server.remote_native_presence.get(did)
        return dict(entry['capabilities']) if entry and now-entry['received']<12 else None


def logon_binding(value):
    require(isinstance(value,dict) and set(value)=={'wts_session','logon_generation'}
        and type(value['wts_session']) is int and 0<value['wts_session']<2**32
        and isinstance(value['logon_generation'],str) and re.fullmatch('[0-9a-f]{32}',value['logon_generation']),status=400)
    return dict(value)


def approved_network(server,user,device):
    """Only authenticated socket source addresses; never SDP/header inventory IPs."""
    owned=getattr(server,'remote_native_owned_loopback',False) is True
    def clean(values):
        require(isinstance(values,list) and 1<=len(values)<=8,'原生媒體需要明確的內網 IPv4 位址',409)
        result=[]
        for value in values:
            try:ip=ipaddress.IPv4Address(value)
            except (ValueError,TypeError):require(False,'原生媒體 IPv4 不正確',409)
            require((ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified and not ip.is_multicast)
                or (owned and ip.is_loopback),'原生媒體只接受已核對的內網位址',409)
            require(str(ip) not in result,'重複的媒體位址',409);result.append(str(ip))
        return result
    observed=user.get('_remote_address','')
    try:loop=ipaddress.ip_address(observed).is_loopback
    except ValueError:loop=False
    viewer=getattr(server,'remote_native_console_ipv4',[]) if loop and not owned else [observed]
    return {'viewer':clean(viewer),'endpoint':clean([device.get('last_address','')]),'owned_loopback':owned}


class NativeSession:
    """Two bounded signaling slots, consent until stopped, no replay queues.

    Durations are measured from the HTTP request's start at the broker, NOT its
    arrival. The endpoint must clamp the returned duration to request_start+5s
    on GetTickCount64 before passing a native lease to the worker.
    """
    def __init__(self,binding,*,can_control,can_elevate,clock=time.monotonic,network=None,cohort_sha256=None,relay_authority=None,session_id=None):
        self.clock=clock;self.binding=logon_binding(binding)
        self.nonce=secrets.token_hex(32);self.transport=1
        self.can_control=bool(can_control);self.can_elevate=bool(can_elevate)
        self.started=clock();self.deadline=float('inf');self.ended=False
        self.last={'viewer':float('-inf'),'endpoint':float('-inf')}
        self.sequences={'viewer':0,'endpoint':0};self.slots={'viewer':None,'endpoint':None}
        self.signaled={'viewer':False,'endpoint':False}
        self.buckets={'viewer':[self.started,0],'endpoint':[self.started,0]}
        self.network=network
        self.cohort_sha256=cohort_sha256
        self.relay_authority=relay_authority;self.relay_roles=None;self.relay_expires=None
        if relay_authority is not None:self.relay_roles,self.relay_expires=relay_authority.issue(session_id,cohort_sha256)

    def public_network(self,role):
        if self.network is None:return None
        other='endpoint' if role=='viewer' else 'viewer'
        return {'local_ipv4':list(self.network[role]),'peer_ipv4':list(self.network[other]),'owned_loopback':self.network['owned_loopback']}

    def close(self):
        self.ended=True;self.slots={'viewer':None,'endpoint':None}
        self.relay_roles=None

    def public_relay(self,role,now):
        if self.relay_roles is None:return None
        remaining=min(self.deadline-now,self.relay_expires-self.relay_authority.wall_clock())
        if not math.isfinite(remaining) or remaining<=0:
            self.close();require(False,'原生轉送授權已結束')
        return {**self.relay_roles[role],'allocation_ipv4':list(self.relay_roles[role]['allocation_ipv4']),'remaining_seconds':remaining}

    def exchange(self,role,body):
        require(role in self.last,status=400)
        required={'session_id','transport_generation','sequence'}
        optional={'signal'}|({'native_nonce','native_logon'} if role=='endpoint' else set())
        require(isinstance(body,dict) and required<=set(body) and set(body)<=required|optional,status=400)
        now=self.clock()
        if self.ended or now<self.started or now>=self.deadline:
            self.close();require(False,'原生協助授權已結束')
        if role=='endpoint':
            nonce=body.get('native_nonce')
            require(isinstance(nonce,str) and secrets.compare_digest(nonce,self.nonce),status=403)
            if logon_binding(body.get('native_logon'))!=self.binding:
                self.close();require(False,'登入身分已切換，請重新取得同意',403)
        require(type(body['transport_generation']) is int and body['transport_generation']==self.transport,status=409)
        sequence=body['sequence'];require(type(sequence) is int and self.sequences[role]<sequence<2**64,'原生控制序號已失效')
        # Consume every authenticated request sequence, including later refused
        # offers. A retry cannot revive a previous transport or extend consent.
        self.sequences[role]=sequence
        bucket=self.buckets[role]
        if now<bucket[0]:self.close();require(False)
        if now-bucket[0]>=1:bucket[:]=[now,0]
        if bucket[1]>=8:self.close();require(False,'原生控制請求過快',429)
        bucket[1]+=1
        signal=body.get('signal')
        if signal is not None:
            kind='offer' if role=='viewer' else 'answer'
            require(isinstance(signal,dict) and set(signal)=={'type','sdp'} and signal['type']==kind
                and isinstance(signal['sdp'],str),status=400)
            sdp=signal['sdp']
            require(len(sdp)<=SDP_BYTES and len(sdp.encode('utf-8'))<=SDP_BYTES and '\x00' not in sdp
                and sdp.startswith('v=0\r\n') and 'a=fingerprint:sha-256 ' in sdp,'SDP 格式或大小不正確',400)
            other='endpoint' if role=='viewer' else 'viewer'
            require(not self.signaled[role] and self.slots[other] is None,'協商已送出，不能補送舊協商')
            require(role!='endpoint' or self.signaled['viewer'],'尚未收到原生協商')
            self.slots[other]={'type':kind,'sdp':sdp};self.signaled[role]=True
        self.last[role]=now
        other='endpoint' if role=='viewer' else 'viewer'
        duration=max(0,min(5,self.deadline-now,5-(now-self.last[other])))
        require(math.isfinite(duration),status=400)
        reply={'native_wire':WIRE,'transport_generation':self.transport,'authorized':duration>0,
            'lease_seconds':duration,'mode':'control' if self.can_control else 'view',
            'admin_control':self.can_elevate,'signal':self.slots[role]}
        reply.update(network=self.public_network(role),consent_seconds=None,native_cohort_sha256=self.cohort_sha256,relay=self.public_relay(role,now))
        self.slots[role]=None
        return reply
