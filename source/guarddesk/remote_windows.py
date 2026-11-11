"""Visible standard-user assistance; secure control is a separate consented child.

The default entry retains its original desktop/integrity restrictions. No shell,
clipboard, file transfer, unattended acceptance, or screen recording.
"""
import base64
import math
import ctypes
import os
import struct
import threading
import time
import zlib


def interactive_desktop():
    if os.name!='nt':return False
    from ctypes import wintypes as w
    session=w.DWORD()
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(),ctypes.byref(session)) or session.value==0:return False
    api=ctypes.WinDLL('user32',use_last_error=True)
    api.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenInputDesktop.restype=w.HANDLE
    api.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    api.CloseDesktop.argtypes=[w.HANDLE]
    desk=api.OpenInputDesktop(0,False,1)
    if not desk:return False
    try:
        name=ctypes.create_unicode_buffer(256);needed=w.DWORD()
        return bool(api.GetUserObjectInformationW(desk,2,name,ctypes.sizeof(name),ctypes.byref(needed)) and name.value.casefold()=='default')
    finally:api.CloseDesktop(desk)


def capture_bgr(max_width=960, max_height=540, max_pixels=None,*,_desktop_guard=None):
    if not (_desktop_guard or interactive_desktop)():
        if _desktop_guard:
            from .remote_admin_windows import DesktopTransition
            raise DesktopTransition('Management desktop changed during capture')
        raise OSError('鎖定或安全桌面，停止遠端協助')
    from ctypes import wintypes as w
    user=ctypes.WinDLL('user32',use_last_error=True);gdi=ctypes.WinDLL('gdi32',use_last_error=True)
    user.GetDC.argtypes=[w.HWND];user.GetDC.restype=w.HDC;user.ReleaseDC.argtypes=[w.HWND,w.HDC]
    gdi.CreateCompatibleDC.argtypes=[w.HDC];gdi.CreateCompatibleDC.restype=w.HDC
    gdi.CreateCompatibleBitmap.argtypes=[w.HDC,ctypes.c_int,ctypes.c_int];gdi.CreateCompatibleBitmap.restype=w.HBITMAP
    gdi.SelectObject.argtypes=[w.HDC,w.HGDIOBJ];gdi.SelectObject.restype=w.HGDIOBJ
    gdi.DeleteObject.argtypes=[w.HGDIOBJ];gdi.DeleteDC.argtypes=[w.HDC]
    gdi.StretchBlt.argtypes=[w.HDC,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,w.HDC,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,w.DWORD]
    gdi.GetDIBits.argtypes=[w.HDC,w.HBITMAP,w.UINT,w.UINT,w.LPVOID,w.LPVOID,w.UINT]
    width,height=user.GetSystemMetrics(0),user.GetSystemMetrics(1)
    if not width or not height:raise OSError('No interactive display')
    scale=min(1,max_width/width,max_height/height)
    if max_pixels:scale=min(scale,math.sqrt(max_pixels/(width*height)))
    outw,outh=max(1,int(width*scale)),max(1,int(height*scale))
    dc=user.GetDC(None);memory=gdi.CreateCompatibleDC(dc);bitmap=gdi.CreateCompatibleBitmap(dc,outw,outh);previous=None
    try:
        if not dc or not memory or not bitmap:raise OSError('Cannot allocate screen capture')
        previous=gdi.SelectObject(memory,bitmap)
        if not gdi.StretchBlt(memory,0,0,outw,outh,dc,0,0,width,height,0x00CC0020):raise OSError('Screen capture failed')
        gdi.SelectObject(memory,previous);previous=None
        stride=(outw*3+3)&~3;pixels=ctypes.create_string_buffer(stride*outh)
        header=ctypes.create_string_buffer(struct.pack('<IiiHHIIiiII',40,outw,-outh,1,24,0,stride*outh,0,0,0,0)+b'\x00'*4)
        if gdi.GetDIBits(memory,bitmap,0,outh,pixels,header,0)!=outh:raise OSError('Screen bitmap read failed')
        return outw,outh,stride,pixels.raw
    finally:
        if previous:gdi.SelectObject(memory,previous)
        if bitmap:gdi.DeleteObject(bitmap)
        if memory:gdi.DeleteDC(memory)
        if dc:user.ReleaseDC(None,dc)


def png_frame(max_width=960):
    outw,outh,stride,raw=capture_bgr(max_width,int(max_width*9/16));rows=[]
    for y in range(outh):
        bgr=raw[y*stride:y*stride+outw*3];rgb=bytearray(outw*3)
        rgb[0::3]=bgr[2::3];rgb[1::3]=bgr[1::3];rgb[2::3]=bgr[0::3];rows.append(b'\0'+rgb)
    def chunk(tag,data):return struct.pack('>I',len(data))+tag+data+struct.pack('>I',zlib.crc32(tag+data)&0xffffffff)
    png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',outw,outh,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),3))+chunk(b'IEND',b'')
    if len(png)>590000:
        if max_width>480:return png_frame(640 if max_width>640 else 480)
        raise OSError('畫面超過傳輸上限，停止協助')
    return {'width':outw,'height':outh,'png':base64.b64encode(png).decode('ascii')}


def jpeg_frame(economy=False,*,_capture=None):
    from PIL import Image
    from .remote_codec import encode_jpeg
    width,height,stride,raw=(_capture or capture_bgr)(1280 if economy else 1600,720 if economy else 900)
    image=Image.frombytes('RGB',(width,height),raw,'raw','BGR',stride,1)
    try:
        for quality in ([65,50] if economy else [78,65,50]):
            try:return encode_jpeg(image,quality)
            except ValueError:continue
        small=image.resize((max(1,width//2),max(1,height//2)),Image.Resampling.BILINEAR)
        try:return encode_jpeg(small,60)
        finally:small.close()
    finally:image.close()


def clarity_frame(*,_capture=None):
    from PIL import Image
    from .remote_codec import encode_clarity,CLARITY_DIMENSION,CLARITY_PIXELS
    width,height,stride,raw=(_capture or capture_bgr)(CLARITY_DIMENSION,CLARITY_DIMENSION,max_pixels=CLARITY_PIXELS)
    image=Image.frombytes('RGB',(width,height),raw,'raw','BGR',stride,1)
    del raw
    from .performance import background_work
    try:
        with background_work():return encode_clarity(image)
    finally:image.close()


class InputFailure(OSError):
    """Scalar Windows diagnostics only; never retain key/button contents."""
    def __init__(self,code,size,accepted):
        super().__init__('Windows SendInput refused input; native code '+str(code))
        self.winerror=code;self.input_size=size;self.accepted=accepted


class Input:
    def __init__(self,guard=None,release_guard=None,epoch=None):
        self.keys=set();self.buttons=set();self.position=(.5,.5);self.guard=guard or interactive_desktop
        self.release_guard=release_guard or self.guard;self.epoch=epoch;self.held_epoch=None

    def send(self,action,*,_release=False):
        if action['type']=='release_all':self.release();return
        guard=self.release_guard if _release else self.guard
        if _release and (action['type'] not in ('key','button') or action.get('down') is not False):
            raise PermissionError('Release path accepts only tracked key/button up')
        if not guard():raise OSError('Secure desktop input refused')
        if not _release and self.epoch:
            current=self.epoch()
            if current!=self.held_epoch:self.keys.clear();self.buttons.clear();self.held_epoch=current
        from ctypes import wintypes as w
        pointer=ctypes.c_size_t
        class Mouse(ctypes.Structure):_fields_=[('dx',w.LONG),('dy',w.LONG),('mouseData',w.DWORD),('dwFlags',w.DWORD),('time',w.DWORD),('dwExtraInfo',pointer)]
        class Key(ctypes.Structure):_fields_=[('wVk',w.WORD),('wScan',w.WORD),('dwFlags',w.DWORD),('time',w.DWORD),('dwExtraInfo',pointer)]
        class Payload(ctypes.Union):_fields_=[('mi',Mouse),('ki',Key)]
        class Event(ctypes.Structure):_fields_=[('type',w.DWORD),('data',Payload)]
        api=ctypes.WinDLL('user32',use_last_error=True);api.SendInput.argtypes=[w.UINT,ctypes.POINTER(Event),ctypes.c_int];api.SendInput.restype=w.UINT
        def emit(event):
            if not guard():raise OSError('Desktop changed before native input')
            ctypes.set_last_error(0)
            accepted=api.SendInput(1,ctypes.byref(event),ctypes.sizeof(event))
            if accepted!=1:
                code=ctypes.get_last_error()
                # A verified desktop switch must discard the event and resync;
                # a stable rejection remains an error, never silently retried.
                self.guard()
                raise InputFailure(code,ctypes.sizeof(event),accepted)
        if action['type']=='key':
            key=action['key'];down=action['down'];emit(Event(1,Payload(ki=Key(key,0,0 if down else 2,0,0))))
            if down:self.keys.add(key)
            else:self.keys.discard(key)
        else:
            # Absolute input maps to the primary monitor captured above.
            if not _release:
                self.position=(action['x'],action['y'])
                emit(Event(0,Payload(mi=Mouse(round(action['x']*65535),round(action['y']*65535),0,0x8001,0,0))))
            if action['type']=='click':
                flags={'left':(0x0002,0x0004),'right':(0x0008,0x0010),'middle':(0x0020,0x0040)}[action.get('button','left')]
                for flag in flags:emit(Event(0,Payload(mi=Mouse(0,0,0,flag,0,0))))
            elif action['type']=='button':
                button=action['button'];down=action['down']
                flags={'left':(0x0002,0x0004),'right':(0x0008,0x0010),'middle':(0x0020,0x0040)}[button]
                emit(Event(0,Payload(mi=Mouse(0,0,0,flags[0 if down else 1],0,0))))
                if down:self.buttons.add(button)
                else:self.buttons.discard(button)
            elif action['type']=='scroll':
                emit(Event(0,Payload(mi=Mouse(0,0,action['delta'] & 0xffffffff,0x0800,0,0))))

    def release(self):
        if self.epoch and self.held_epoch!=self.epoch():
            self.keys.clear();self.buttons.clear();return
        for key in list(self.keys):
            try:self.send({'type':'key','key':key,'down':False},_release=True)
            except OSError:pass
        self.keys.clear()
        for button in list(self.buttons):
            try:self.send({'type':'button','button':button,'down':False,'x':self.position[0],'y':self.position[1]},_release=True)
            except OSError:pass
        self.buttons.clear()


class RemoteAgent:
    def __init__(self,agent,stop,parent_stop=None):
        self.agent=agent;self.stop=stop;self.parent_stop=parent_stop;self.sid=None
        self.local_stop=threading.Event();self.indicator=None
        self.consent_attempts={};self.consent_error=None

    def stopped(self):return self.stop.is_set() or bool(self.parent_stop and self.parent_stop.is_set())

    def start(self):
        if os.name!='nt':return
        self.thread=threading.Thread(target=self.run,name='GuardDesk visible remote assistance',daemon=True)
        self.thread.start()

    def call(self,path,body):return self.agent.call('/api/agent/remote/'+path,body,timeout=3)

    def consent(self,session):
        admin=session.get('admin_control',False)
        mode='管理員協助：可查看及操作 UAC 提示、輸入管理員帳密，並控制提權後的程式' if admin else '檢視畫面並操作鍵盤滑鼠' if session['mode']=='control' else '僅檢視畫面'
        limit='帳密由支援人員在 Windows 提示輸入；不儲存鍵入內容。鎖定、登出會停止。' if admin else '不提供檔案傳輸、剪貼簿或管理員桌面控制。'
        duration='協助持續至停止或授權中止，可隨時按停止。' if session.get('transport')=='native_webrtc' else '最長 10 分鐘，可隨時按停止。'
        return ctypes.windll.user32.MessageBoxW(None,'支援人員：'+session['operator']+'\n原因：'+(session['reason'] or '未填寫')+'\n模式：'+mode+'\n\n是否同意？'+duration+'\n'+limit,'GuardDesk 管理員遠端協助確認' if admin else 'GuardDesk 遠端協助確認',0x24|0x10000)==6

    def show_indicator(self,session):
        self.indicator='GuardDesk 協助中 '+session['id'][:8]
        caption=self.indicator;session_stop=self.local_stop
        def show():
            ctypes.windll.user32.MessageBoxW(None,'遠端協助進行中：'+session['operator']+'\n\n按「確定」立即停止分享與控制。',caption,0x40|0x10000)
            session_stop.set() # A delayed old dialog must not stop a replacement.
        threading.Thread(target=show,daemon=True).start()

    def close_indicator(self):
        if self.indicator:
            from ctypes import wintypes as w
            api=ctypes.windll.user32;api.FindWindowW.argtypes=[w.LPCWSTR,w.LPCWSTR];api.FindWindowW.restype=w.HWND;api.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
            handle=api.FindWindowW(None,self.indicator)
            if handle:api.PostMessageW(handle,0x0010,0,0)
            self.indicator=None

    def handle_request(self,session,account):
        # Reserve BEFORE displaying UI. A lost/rejected approval reply must
        # never cause the same request to prompt the user every poll interval.
        now=time.monotonic()
        self.consent_attempts={sid:until for sid,until in self.consent_attempts.items() if until>now}
        sid=session['id']
        if sid in self.consent_attempts:return
        if len(self.consent_attempts)>=128:
            self.consent_error={'stage':'capacity','error_type':'CapacityExceeded','winerror':None}
            return
        self.consent_attempts[sid]=now+720
        self.consent_error=None;stage='dialog'
        try:
            approved=self.consent(session)
            if self.stopped() or not interactive_desktop():return
            # Dialogs can outlive readiness or the request. Refresh presence
            # and verify the exact displayed request before submitting consent.
            stage='revalidate'
            current=self.call('poll',{'account':account,'ready':True,'protocol':3,'readiness':'ready'}).get('session')
            if not current or any(current.get(k)!=session.get(k) for k in
                    ('id','status','operator','mode','admin_control','transport','reason')):
                self.consent_error={'stage':'revalidate','error_type':'RequestChanged','winerror':None}
                return
            stage='approve' if approved else 'deny'
            result=self.call('update',{'session_id':sid,'action':stage,'account':account})
            if approved and result['status']=='active':
                if session.get('admin_control') or session.get('transport')=='native_webrtc':self.admin_watch(session)
                else:self.assist(session)
        except (ConnectionError,OSError,ValueError) as error:
            # Fixed metadata only: no endpoint paths, credentials, reason text,
            # screenshots or exception strings are retained here.
            code=getattr(error,'winerror',None)
            self.consent_error={'stage':stage,'error_type':type(error).__name__,
                                'winerror':code if type(code) is int and 0<=code<2**31 else None}
            try:self.call('update',{'session_id':sid,'action':'stop'})
            except (ConnectionError,OSError,ValueError):pass

    def run(self):
        from .identity import current_account
        from .windows_privilege import is_admin
        if is_admin():
            # Report the refusal, never run capture/input with an elevated token.
            try:self.call('poll',{'account':current_account(),'ready':False,'protocol':3,'readiness':'elevated_context'})
            except (ConnectionError,OSError,ValueError):pass
            return
        # DPI context is per-thread and does not alter other Agent collectors.
        try:
            api=ctypes.windll.user32;api.SetThreadDpiAwarenessContext.argtypes=[ctypes.c_void_p];api.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        except (AttributeError,OSError):pass
        account=current_account()
        while not self.stopped():
            try:
                ready=interactive_desktop()
                response=self.call('poll',{'account':account,'ready':ready,'protocol':3,
                    'readiness':'ready' if ready else 'locked_or_disconnected'});session=response.get('session')
                if ready and session and session['status']=='requested':
                    self.handle_request(session,account)
            except (ConnectionError,OSError,ValueError):pass
            self.stop.wait(3)

    def admin_watch(self,session):
        # The ordinary user process retains the visible stop button. It never
        # captures secure desktops or receives the SYSTEM child's nonce/token.
        self.local_stop=threading.Event();self.show_indicator(session)
        deadline=float('inf') if session.get('transport')=='native_webrtc' else time.monotonic()+600
        try:
            while not self.stopped() and not self.local_stop.is_set() and time.monotonic()<deadline:
                if self.call('update',{'session_id':session['id'],'action':'admin_watch'})['status']!='active':break
                self.local_stop.wait(.5)
        except (OSError,ValueError):pass
        finally:
            self.local_stop.set();self.close_indicator()
            try:self.call('update',{'session_id':session['id'],'action':'stop'})
            except OSError:pass

    def assist(self,session):
        inputs=Input();self.local_stop=threading.Event();self.show_indicator(session);deadline=time.monotonic()+600
        session_stop=self.local_stop
        desktop=session.get('viewer')=='desktop';input_thread=None;input_done=threading.Event();last_jpeg=None
        last_frame=[time.monotonic()]
        if desktop and session['mode']=='control':
            def poll_inputs():
                try:
                    while not self.stopped() and not session_stop.is_set():
                        if time.monotonic()-last_frame[0]>3:break
                        packet=self.call('update',{'session_id':session['id'],'action':'commands'})
                        if packet['status']!='active':break
                        for action in packet.get('commands',[]):
                            if self.stopped() or session_stop.is_set():break
                            inputs.send(action)
                        session_stop.wait(.05)
                except (OSError,ConnectionError,ValueError):pass
                finally:
                    # The input thread alone owns tracked key/button state.
                    inputs.release();input_done.set();session_stop.set()
            input_thread=threading.Thread(target=poll_inputs,name='GuardDesk consented desktop input',daemon=True)
            input_thread.start()
        try:
            while not self.stopped() and not session_stop.is_set() and time.monotonic()<deadline:
                started=time.monotonic()
                clarity=desktop and session.get('quality')=='clarity'
                frame=clarity_frame() if clarity else jpeg_frame(session.get('quality')=='economy') if desktop else png_frame()
                if session_stop.is_set() or self.stopped():break
                encoded=frame.get('jpeg') or frame.get('png')
                if desktop and encoded==last_jpeg:
                    result=self.call('update',{'session_id':session['id'],'action':'repeat_frame'})
                else:
                    result=self.call('update',{'session_id':session['id'],'action':'frame','frame':frame})
                    if desktop:last_jpeg=encoded
                if result['status']!='active':break
                last_frame[0]=time.monotonic()
                if session['mode']=='control' and not desktop:
                    for action in result.get('commands',[]):
                        if session_stop.is_set() or self.stopped():break
                        inputs.send(action)
                target=(.5 if clarity else 1/3 if session.get('quality')=='economy' else 1/8) if desktop else .8
                # Never queue old frames. Slow capture/network lowers actual FPS.
                session_stop.wait(max(.015,target-(time.monotonic()-started)) if desktop else target)
        except (OSError,ConnectionError,ValueError):pass
        finally:
            session_stop.set()
            if input_thread:input_done.wait(12)
            else:inputs.release()
            self.close_indicator()
            try:self.call('update',{'session_id':session['id'],'action':'stop'})
            except (ConnectionError,OSError):pass
