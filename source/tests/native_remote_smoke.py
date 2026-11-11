"""Own Tk window + simulated endpoint only; no desktop capture or SendInput."""
import ctypes
import json
from pathlib import Path
import statistics
import sys
import threading
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from PIL import Image,ImageDraw,ImageGrab,__version__ as pillow_version
from guarddesk.remote_codec import encode_clarity,decode_frame
from guarddesk import __version__
from guarddesk.remote_viewer import RemoteViewer
from test_native_remote import NativeRemoteTest


def sample(number=0):
    image=Image.new('RGB',(1920,1080),'#eef3f6');d=ImageDraw.Draw(image)
    d.rectangle((0,0,1920,78),fill='#15353d');d.text((30,25),'GUARDDESK   /   SIMULATED ENDPOINT 1920 x 1080',fill='white',font_size=27)
    d.rectangle((0,78,230,900),fill='#dce7eb')
    for i,label in enumerate(['Overview','Documents','Applications','Network','Settings']):d.text((24,115+i*60),label,fill='#234956',font_size=20)
    d.text((280,115),'Native remote assistance test',fill='#15353d',font_size=32)
    d.text((280,175),'Synthetic image only. No employee screen captured.',fill='#526b76',font_size=21)
    for i in range(8):
        y=245+i*60;d.rounded_rectangle((280,y,1540,y+44),radius=7,fill='white')
        d.text((300,y+10),f'Document {i+1:02d}       Local test data       Ready',fill='#345969',font_size=18)
    d.text((280,790),f'Frame {number:05d}  |  input and video use independent workers',fill='#097b75',font_size=23)
    for i in range(7):d.text((280,850+i*24),'Native pixels: 0123456789 / C:\\Documents\\Example.docx / 100% scale',fill='#234956',font_size=14)
    return image


def run():
    import tkinter as tk
    assert pillow_version=='13.0.0',pillow_version
    fixture=NativeRemoteTest();fixture.setUp();stop=threading.Event();commands=[];failures=[];sent=[]
    root=None;app=None;thread=None
    try:
        unused,agent,did=fixture.prepare(protocol=3)
        fixture.api('/api/remote/grant',{'username':'admin','device_id':did,'enabled':False,'can_control':False})
        fixture.api('/api/remote/grant',{'username':'admin','device_id':'*','enabled':True,'can_control':True,'days':0})
        with fixture.store.connect() as db:db.execute('UPDATE devices SET name=? WHERE id=?',('SIMULATED-WINDOWS-11',did))
        def endpoint():
            sid=None;n=0
            try:
                while not stop.is_set():
                    if sid is None:
                        p=agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
                        s=p.get('session')
                        if s and s['status']=='requested':
                            sid=s['id'];agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
                    else:
                        with sample(n) as image:frame=encode_clarity(image)
                        result=agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame})
                        if result['status']!='active':break
                        sent.append(time.monotonic());n+=1
                        commands.extend(agent.call('/api/agent/remote/update',{'session_id':sid,'action':'commands'})['commands'])
                    stop.wait(.5)
            except (OSError,ConnectionError,ValueError) as exc:
                if not stop.is_set():failures.append(str(exc))
        thread=threading.Thread(target=endpoint,daemon=True);thread.start()
        root=tk.Tk();app=RemoteViewer(root,fixture.url);root.update()
        app.user.set('admin');app.password.set(fixture.password);app.login()
        def wait(predicate,seconds=8):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                root.update()
                if predicate():return
                time.sleep(.01)
            raise AssertionError('Tk wait expired: '+app.status.get())
        wait(lambda:app.client is not None and not app.busy)
        assert app.devices and app.device_box.current()==0
        app.mode.set('檢視並控制');app.reason.set('Isolated native viewer acceptance test');app.request()
        wait(lambda:app.image is not None and app.engine and app.engine.session['status']=='active')
        engine=app.engine;started=time.monotonic();frames=engine.stats['frames'];gaps=[];last=started
        while time.monotonic()-started<5:
            root.update();now=time.monotonic();gaps.append((now-last)*1000);last=now;time.sleep(.01)
        assert engine.stats['frames']-frames>=6
        observed_frames=engine.stats['frames']-frames;observed_seconds=time.monotonic()-started
        x,y,w,h=app.rect;e=SimpleNamespace(x=x+w*.5,y=y+h*.5,delta=-120)
        app.button(e,1,True);app.motion(SimpleNamespace(x=x+w*.7,y=y+h*.6));app.button(e,1,False)
        app.wheel(e);app.key(SimpleNamespace(keycode=65,keysym='a',state=0),True);app.key(SimpleNamespace(keycode=65,keysym='a',state=0),False)
        wait(lambda:all(t in {a['type'] for a in commands} for t in ('button','move','scroll','key')))
        app.focus_out();wait(lambda:any(a['type']=='release_all' for a in commands))
        assert app.image.size==(1920,1080) and engine.stats['codec']=='PNG 無損'
        app.toggle_display();wait(lambda:app.rect[2:]==(1920,1080))
        app.canvas.xview_moveto(.1);app.canvas.yview_moveto(.1);root.update()
        mapped=app.position(SimpleNamespace(x=200,y=150))
        assert abs(mapped['x']-(app.canvas.canvasx(200)-app.rect[0])/1920)<.00001
        assert abs(mapped['y']-(app.canvas.canvasy(150)-app.rect[1])/1080)<.00001
        app.toggle_display();root.update()
        app.toggle_fullscreen();root.update();assert app.fullscreen
        assert not app.header.winfo_ismapped() and not app.footer.winfo_ismapped()
        wait(lambda:app.canvas.winfo_width()==root.winfo_width() and app.canvas.winfo_height()==root.winfo_height())
        wait(lambda:not app.fullbar.winfo_ismapped())
        app.motion(SimpleNamespace(x=20,y=0));root.update();assert app.fullbar.winfo_ismapped()
        wait(lambda:not app.fullbar.winfo_ismapped())
        api=ctypes.windll.user32;api.GetAncestor.argtypes=[ctypes.c_void_p,ctypes.c_uint];api.GetAncestor.restype=ctypes.c_void_p
        hwnd=api.GetAncestor(root.winfo_id(),2)
        # Pillow's window option uses PrintWindow for this test's HWND, not the desktop.
        screenshot=ImageGrab.grab(window=hwnd)
        try:screenshot.save(ROOT/f'evidence/native-remote-fullscreen-{__version__}.png')
        finally:screenshot.close()
        app.toggle_fullscreen();root.update();assert not app.fullscreen and app.header.winfo_ismapped() and app.footer.winfo_ismapped()
        root.geometry('1400x920');root.update();time.sleep(.15);root.update();assert app.rect[2]<=app.canvas.winfo_width()
        hwnd=api.GetAncestor(root.winfo_id(),2)
        screenshot=ImageGrab.grab(window=hwnd)
        try:screenshot.save(ROOT/f'evidence/native-remote-window-{__version__}.png')
        finally:screenshot.close()
        measured={'seconds':round(observed_seconds,2),'decoded_frames':observed_frames,
                  'decoded_fps':round(observed_frames/observed_seconds,1),
                  'ui_loop_p95_ms':round(sorted(gaps)[int(len(gaps)*.95)],1),'ui_loop_max_ms':round(max(gaps),1)}
        assert measured['ui_loop_max_ms']<500,measured
        # Reserved local chord must exit fullscreen without sending F12 remotely.
        app.toggle_fullscreen();root.update()
        app.key(SimpleNamespace(keycode=123,keysym='F12',state=0x20005),True)
        root.update();assert not app.fullscreen
        app.toggle_fullscreen();root.update()
        sid=engine.sid;app.stop_session();wait(lambda:engine.closed.is_set())
        assert not app.fullscreen and app.header.winfo_ismapped()
        assert fixture.api('/api/remote/catalog')['sessions'][0]['status']=='closed'
        assert not engine.send({'type':'key','key':66,'down':True})
        assert app.image is None and not failures,failures
        app.close();root=None
        report={'passed':True,'version':__version__,'Pillow':pillow_version,'scope':'own Tk window, isolated loopback server, synthetic lossless PNG endpoint',
                'checks':['native login and endpoint selection from all-endpoint default grant without per-device grant','native 1920x1080 PNG display','drag / wheel / keyboard dispatch without SendInput',
                          'focus loss releases held input','100% pixels and scrolled pointer coordinates','fullscreen hides header/footer and fills client area',
                          'fullscreen toolbar hides, reveals at top edge and restores layout','local escape chord restores window without remote F12',
                          'stop exits fullscreen, clears image, closes server session and prevents later input'],
                'measurement':measured,'screen_capture_of_employee_desktop':False,'real_remote_input_sent':False,
                'company_agent_modified':False,'real_endpoint_and_Defender_acceptance':'pending'}
        (ROOT/'evidence/native-remote-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    finally:
        if root is not None:
            if app:app.close()
            else:root.destroy()
        stop.set()
        if thread:thread.join(5)
        fixture.tearDown()


if __name__=='__main__':run()
