"""Independent MIS client; local console or scoped TLS support, memory cookies."""
from collections import deque
import http.cookiejar
import json
import math
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .remote_codec import decode_frame,CLARITY_BODY
from .transport_errors import CenterTransportError,network_error


class RemoteClientError(OSError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def console_url(value):
    if not isinstance(value,str) or len(value)>200:raise ValueError('管理中心位址不正確')
    u=urlsplit(value)
    if u.scheme!='http' or u.hostname not in ('127.0.0.1','localhost') or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
        raise ValueError('請在 Server 本機執行，管理位址使用 http://127.0.0.1:8788')
    if not 1 <= (u.port or 80) <= 65535:raise ValueError('連接埠不正確')
    return value.rstrip('/')


class RemoteClient:
    def __init__(self,server='http://127.0.0.1:8788',*,workstation=False,ca=None):
        from .mis_support import server_url
        self.workstation=workstation
        self.server=server_url(server) if workstation else console_url(server)
        self.cookies=http.cookiejar.CookieJar();self.csrf=None
        handlers=[urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(self.cookies),NoRedirect()]
        if workstation:
            context=ssl.create_default_context(cafile=ca)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener=urllib.request.build_opener(*handlers)

    def call(self,path,body=None):
        return self._call(path,body)

    def native_exchange(self,body,*,timeout=3):
        """Classified native exchange; retries remain the approved controller's job."""
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=3:
            raise ValueError('Native exchange timeout must stay within three seconds')
        return self._call('/api/remote/native',body,native_errors=True,timeout=timeout)

    def _call(self,path,body=None,*,native_errors=False,timeout=3):
        allowed=('/api/login','/api/logout','/api/remote/catalog','/api/remote/request','/api/remote/session?','/api/remote/input','/api/remote/stop','/api/remote/presented','/api/remote/native')
        if not any(path==p or (p.endswith('?') and path.startswith(p)) for p in allowed):raise ValueError('不支援的桌面操作')
        headers={'Content-Type':'application/json'}
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        data=json.dumps(body,ensure_ascii=False).encode('utf-8') if body is not None else None
        target=path
        if self.workstation:
            target='/api/support/'+(path[len('/api/remote/'):] if path.startswith('/api/remote/') else path[len('/api/'):])
        request=urllib.request.Request(self.server+target,data=data,headers=headers,method='POST' if body is not None else 'GET')
        try:
            with self.opener.open(request,timeout=timeout) as response:
                limit=CLARITY_BODY if path.startswith('/api/remote/session?') else 1048576
                raw=response.read(limit+1)
                if len(raw)>limit:raise RemoteClientError('管理中心回應超過上限')
                value=json.loads(raw)
                if not isinstance(value,dict):raise ValueError('Invalid response')
                return value
        except urllib.error.HTTPError as exc:
            if native_errors:
                status=exc.code;exc.close()
                raise CenterTransportError('http',http_status=status) from None
            try:
                value=json.loads(exc.read(8192));message=value.get('error','操作失敗')
            except (ValueError,OSError):message='操作失敗'
            finally:exc.close()
            raise RemoteClientError(str(message)[:300]) from None
        except ssl.SSLError as exc:
            if native_errors:raise network_error(exc) from None
            raise
        except (urllib.error.URLError,TimeoutError,ConnectionError) as exc:
            if native_errors:
                raise network_error(exc.reason if isinstance(exc,urllib.error.URLError) else exc) from None
            raise RemoteClientError('管理中心連線中斷；已停止遠端操作') from None
        except ValueError:raise RemoteClientError('管理中心回應格式不正確') from None

    def login(self,username,password):
        result=self.call('/api/login',{'username':username,'password':password});self.csrf=result['csrf']
        try:
            catalog=self.catalog()
            if catalog.get('desktop_protocol')!=2:raise RemoteClientError('管理中心需更新至 0.4.14 才能使用桌面遠端協助')
            return catalog
        except BaseException:
            self.logout();raise

    def catalog(self):return self.call('/api/remote/catalog')

    def request(self,device_id,mode,reason,quality='balanced',*,admin_control=False):
        result=self.call('/api/remote/request',{'device_id':device_id,'mode':mode,'reason':reason,'viewer':'desktop','quality':quality,**({'admin_control':True,'admin_wire':6} if admin_control else {})})
        return {**result,'quality':quality}

    def logout(self):
        try:
            if self.csrf:self.call('/api/logout',{})
        except OSError:pass
        finally:self.csrf=None;self.cookies.clear()


class InputBuffer:
    """Ordered transitions; coalesce pointer moves and fail closed on overflow."""
    def __init__(self):self.lock=threading.Lock();self.items=deque()

    def add(self,action):
        with self.lock:
            if action['type']=='release_all':self.items.clear()
            if action['type']=='move' and self.items and self.items[-1]['type']=='move':self.items[-1]=action;return
            if len(self.items)>=40:raise RemoteClientError('輸入佇列已滿，停止協助以避免延後誤操作')
            self.items.append(action)

    def take(self):
        with self.lock:
            return [self.items.popleft() for _ in range(min(20,len(self.items)))]

    def clear(self):
        with self.lock:self.items.clear()


class ViewerEngine:
    """Latest-frame mailbox and independent bounded input worker; no Tk calls."""
    def __init__(self,client,session):
        self.client=client;self.session=session;self.sid=session['id'];self.stop_event=threading.Event()
        self.inputs=InputBuffer();self.lock=threading.Lock();self.latest=None;self.error=None
        self.fresh_until=0;self.started=False;self.closed=threading.Event();self.frame_sequence=-1
        self.stats={'frames':0,'poll_ms':0};self.threads=[]
        self.high_resolution=session.get('quality')=='clarity'
        self.admin_control=bool(session.get('admin_control'));self.displayed_epoch=None;self.pending_present=None

    def start(self):
        self.started=True
        for target,name in [(self.frames,'frames'),(self.send_inputs,'input')]:
            thread=threading.Thread(target=target,name='GuardDesk viewer '+name,daemon=True);self.threads.append(thread);thread.start()

    def fail(self,message):
        with self.lock:self.error=str(message)[:300]
        self.stop_event.set();self.inputs.clear();self.fresh_until=0

    def frames(self):
        try:
            while not self.stop_event.is_set():
                start=time.monotonic()
                packet=self.client.call('/api/remote/session?id='+self.sid+'&after='+str(self.frame_sequence))
                if self.stop_event.is_set():break
                image=None
                if packet['status']=='active':
                    age=time.time()-packet.get('frame_time',0)
                    self.fresh_until=time.monotonic()+max(0,min(2.5,3-age)) if -2<=age<3 else 0
                    if packet.get('frame'):
                        image=decode_frame(packet['frame'],high_resolution=self.high_resolution);self.frame_sequence=packet.get('frame_seq',self.frame_sequence+1);self.stats['frames']+=1
                        self.stats['codec']='PNG 無損' if 'png' in packet['frame'] else 'JPEG 壓縮'
                else:self.fresh_until=0
                self.stats['poll_ms']=round((time.monotonic()-start)*1000)
                with self.lock:
                    if self.stop_event.is_set():
                        if image:image.close()
                        break
                    if self.admin_control and packet.get('desktop_epoch') != self.session.get('desktop_epoch'):
                        self.inputs.clear();self.displayed_epoch=None;self.pending_present=None
                    # Keep the newest undecorated image if a metadata-only tick arrives.
                    if self.latest and self.latest[1] is not None:
                        if image is None and packet['status']=='active' and (not self.admin_control or packet.get('desktop_epoch')==self.latest[0].get('desktop_epoch')):image=self.latest[1]
                        else:self.latest[1].close()
                    self.latest=(packet,image);self.session=packet
                if packet['status'] not in ('requested','active'):break
                self.stop_event.wait(max(.02,.1-(time.monotonic()-start)))
        except (OSError,ValueError,KeyError) as exc:self.fail(str(exc))
        finally:
            self.stop_event.set();self.inputs.clear();self.fresh_until=0
            self.close_remote();self.closed.set()

    def take(self):
        with self.lock:
            packet=self.latest;self.latest=None
            if self.admin_control and packet:
                epoch=packet[0].get('desktop_epoch')
                if epoch!=self.displayed_epoch:self.inputs.clear()
            return packet,self.error

    def presented(self,epoch,sequence):
        # UI calls only after submitting the corresponding image for display.
        if not self.admin_control:return
        with self.lock:
            if epoch and epoch==self.session.get('desktop_epoch') and type(sequence) is int and sequence>0:
                self.pending_present=(epoch,sequence)

    def send(self,action):
        if self.stop_event.is_set() or self.session['status']!='active' or self.session['mode']!='control':return False
        if action['type']!='release_all' and time.monotonic()>self.fresh_until:return False
        if self.admin_control and (not self.displayed_epoch or self.displayed_epoch!=self.session.get('desktop_epoch')):return False
        try:self.inputs.add(action)
        except OSError as exc:self.fail(str(exc));return False
        return True

    def send_inputs(self):
        try:
            while not self.stop_event.wait(.04):
                with self.lock:present=self.pending_present
                if present:
                    response=self.client.call('/api/remote/presented',{'session_id':self.sid,'desktop_epoch':present[0],'frame_seq':present[1]})
                    with self.lock:
                        if self.pending_present==present:
                            self.pending_present=None
                            self.displayed_epoch=present[0] if response.get('accepted') and present[0]==self.session.get('desktop_epoch') else None
                with self.lock:
                    actions=self.inputs.take();epoch=self.displayed_epoch
                if not actions:continue
                if self.stop_event.is_set():break
                if time.monotonic()>self.fresh_until:
                    # Never replay an old gesture after reconnect or stale video.
                    actions=[{'type':'release_all'}]
                result=self.client.call('/api/remote/input',{'session_id':self.sid,'actions':actions,**({'desktop_epoch':epoch} if self.admin_control else {})})
                if self.admin_control and result.get('resync'):
                    # Drop this batch and anything queued against the stale
                    # display. Keep polling; a fresh displayed frame re-enables
                    # input. Authorization/transport errors still end control.
                    with self.lock:
                        self.inputs.clear();self.fresh_until=0;self.displayed_epoch=None
        except OSError as exc:self.fail(str(exc))

    def close_remote(self):
        try:self.client.call('/api/remote/stop',{'session_id':self.sid})
        except OSError:pass

    def stop(self):
        self.stop_event.set();self.inputs.clear();self.fresh_until=0
        with self.lock:
            if self.latest and self.latest[1] is not None:self.latest[1].close()
            self.latest=None
        if self.started:threading.Thread(target=self.close_remote,name='GuardDesk viewer stop',daemon=True).start()
        if not self.started:self.close_remote();self.closed.set()


def viewport(image_size,canvas_size,native=False):
    width,height=image_size;cw,ch=canvas_size
    scale=1 if native else min(1,cw/width,ch/height)
    shown=(max(1,int(width*scale)),max(1,int(height*scale)))
    return max(0,(cw-shown[0])/2),max(0,(ch-shown[1])/2),*shown


def pointer(x,y,rectangle):
    left,top,width,height=rectangle
    if not left<=x<=left+width or not top<=y<=top+height:return None
    return {'x':max(0,min(1,(x-left)/width)),'y':max(0,min(1,(y-top)/height))}
