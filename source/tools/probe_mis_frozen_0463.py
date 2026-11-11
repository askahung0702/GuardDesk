"""Frozen Server, real configured MIS EXE, compiled GUI with synthetic endpoint.

No employee desktop capture or physical input. Public CA stays local to client.
"""
import ctypes,hashlib,http.cookiejar,io,ipaddress,json,secrets,shutil,socket,sqlite3,subprocess,sys,tempfile,time,traceback,types,uuid,zipfile
from contextlib import closing,contextmanager
from pathlib import Path
from cryptography import x509
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from guarddesk.server_setup import secure_directory,certificates
from guarddesk.agent import Agent,enroll
from guarddesk.remote_client import RemoteClient
from guarddesk.mis_support import connection
from test_native_remote import frame
import urllib.request,urllib.error
from PyInstaller.archive.readers import CArchiveReader
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def main():
    uid=uuid.uuid4().hex;process=viewer=root_widget=gui=None
    report={'version':'0.4.63','probe_id':uid,'scope':'frozen_Server_and_MIS_package_owned_synthetic_consent',
      'passed':False,'company_changed':False,'desktop_captured':False,'physical_input_sent':False,'checks':[]}
    @contextmanager
    def owned():
        with tempfile.TemporaryDirectory(prefix='mis-onefile-frozen-',dir=ROOT/'runtime') as tmp:
            try:yield secure_directory(Path(tmp),allow_empty=True)
            finally:
                if gui is not None and not gui.closing.is_set():gui.close()
                if root_widget is not None:
                    try:root_widget.destroy()
                    except Exception:pass
                for child in (viewer,process):
                    if child is not None:
                        if child.poll() is None:child.terminate()
                        child.wait(timeout=15)
    try:
        with owned() as work:
            data=secure_directory(work/'data');database=data/'control.sqlite3';password=secrets.token_urlsafe(20)
            seed="import sys,json;sys.path.insert(0,sys.argv[1]);from guarddesk import __version__;from guarddesk.store import Store;s=json.load(sys.stdin);assert __version__=='0.4.62';Store(s['db']).add_user('fixture-mis',s['password'])"
            seeded=subprocess.run([sys.executable,'-c',seed,str(ROOT/'dist/GuardDesk-0.4.62-source.zip')],input=json.dumps({'db':str(database),'password':password}).encode(),cwd=work,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            assert seeded.returncode==0,'old schema seed'
            tls=data/'tls';tls.mkdir();certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
            endpoint_port,console_port=port(),port();assert endpoint_port!=console_port
            endpoint='https://127.0.0.1:'+str(endpoint_port);console='http://127.0.0.1:'+str(console_port)
            config=data/'server.json';config.write_text(json.dumps({'db':'control.sqlite3','host':'127.0.0.1','port':endpoint_port,'local_console_port':console_port,'cert':'tls/server.crt','key':'tls/server.key'}),encoding='utf-8')
            original_config=config.read_bytes();ca=(tls/'ca.pem').read_bytes()
            with zipfile.ZipFile(data/'Endpoint-Connection.zip','x') as z:
                z.writestr('GuardDesk-CA.pem',ca);z.writestr('endpoint-connection.json',json.dumps({'version':1,'server':endpoint,'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}))
            parent=secure_directory(work/'program');app=parent/'GuardDesk';shutil.copytree(ROOT/'dist/GuardDesk',app)
            serverlog=(work/'server.log').open('wb')
            try:process=subprocess.Popen([str(app/'GuardDesk.exe'),'serve','--config',str(config)],cwd=work,stdout=serverlog,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
            finally:serverlog.close()
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf=''
            def api(path,body=None):
                req=urllib.request.Request(console+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
                with opener.open(req,timeout=60 if path=='/api/mis-support-package' else 10) as response:
                    blob=response.read();return json.loads(blob) if 'application/json' in response.headers['Content-Type'] else blob
            for _ in range(150):
                assert process.poll() is None,'frozen server startup'
                try:
                    if api('/api/health')['version']=='0.4.63':break
                except urllib.error.URLError:pass
                time.sleep(.1)
            else:raise RuntimeError('startup timeout')
            csrf=api('/api/login',{'username':'fixture-mis','password':password})['csrf']
            deadline=time.monotonic()+120
            while True:
                status=api('/api/updates')['bundled_release']
                if status['status']=='ready':break
                assert status['status']=='preparing',status.get('code','unexpected publication status')
                assert time.monotonic()<deadline,'bundle timeout';time.sleep(.2)
            api('/api/remote/account',{'username':'fixture-helper','password':password})
            code=api('/api/enrollments',{})['token'];watch=work/'documents';watch.mkdir()
            aid=enroll(work/'agent/config.json',endpoint,code,watch,ca=str(tls/'ca.pem'),name='SYNTHETIC-ASSISTED-PC');agent=Agent(work/'agent/config.json')
            agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
            api('/api/remote/grant',{'username':'fixture-helper','device_id':aid,'enabled':True,'can_control':True,'days':1})
            # Actual admin UI download, not only a direct API call.
            from playwright.sync_api import sync_playwright
            page_errors=[]
            with sync_playwright() as pw:
                browser=pw.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,chromium_sandbox=True)
                try:
                    page=browser.new_page(viewport={'width':1500,'height':1050},locale='zh-TW',accept_downloads=True)
                    page.on('pageerror',lambda e:page_errors.append(str(e)))
                    page.goto(console);page.locator('[name=username]').fill('fixture-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    page.get_by_role('heading',name='安全總覽',exact=True).wait_for();page.locator('nav [data-page=remote]').click();page.locator('#download-mis-support').wait_for()
                    page.screenshot(path=str(ROOT/'evidence'/('mis-admin-'+uid+'.png')),full_page=True)
                    with page.expect_download(timeout=60000) as download:page.locator('#download-mis-support').click()
                    payload=work/'MIS測試工具.exe';download.value.save_as(payload);blob=payload.read_bytes()
                    assert not page_errors,page_errors
                finally:browser.close()
            report['admin_ui_page_errors']=page_errors
            report['checks'].append('actual frozen admin web page downloads configured MIS EXE with zero page errors')
            from guarddesk.mis_onefile import embedded
            from owned_onefile_window import exercise
            viewer_exe=payload
            public=embedded(viewer_exe);assert public['server']==endpoint
            assert set(public)=={'format','server','ca_pem','ca_sha256'}
            assert public['ca_pem'].encode()==ca
            assert code.encode() not in blob and b'PRIVATE KEY' not in public['ca_pem'].encode()
            server,ca_path=endpoint,str(tls/'ca.pem')
            viewer=subprocess.Popen([str(viewer_exe)],cwd=work,creationflags=subprocess.CREATE_NO_WINDOW)
            report['actual_onefile_lifecycle']=exercise(viewer,viewer_exe)
            report['checks'].append('actual downloaded configured single EXE starts from renamed Unicode path without sidecars; X hides, tray restores, tray exit ends own process')
            # Execute the exact GUI code embedded in that portable executable.
            pyz=CArchiveReader(str(viewer_exe)).open_embedded_archive('PYZ.pyz')
            module=types.ModuleType('guarddesk._owned_mis_gui');module.__package__='guarddesk';exec(pyz.extract('guarddesk.remote_viewer'),module.__dict__)
            import tkinter as tk
            root_widget=tk.Tk();gui=module.RemoteViewer(root_widget,server,workstation=True,ca=ca_path,tray=True)
            # A real desktop Agent renews readiness continuously. Package/UI
            # checks can take longer than the intentional 12-second lease.
            agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
            gui.user.set('fixture-helper');gui.password.set(password);gui.login()
            def pump(until,timeout=10):
                until_time=time.monotonic()+timeout
                while not until():
                    root_widget.update();time.sleep(.02)
                    assert time.monotonic()<until_time,'compiled GUI test timeout: '+gui.status.get()
            pump(lambda:gui.client is not None)
            assert len(gui.devices)==1 and gui.devices[0]['id']==aid
            agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
            gui.mode.set('檢視並控制');gui.reason.set('');gui.request()
            pump(lambda:gui.engine is not None);sid=gui.engine.sid;assert gui.image is None
            agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
            sent=time.monotonic();agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame()})
            pump(lambda:gui.image is not None)
            report['synthetic_frame_to_gui_ms']=round((time.monotonic()-sent)*1000,3)
            gui.window_close();pump(lambda:gui.engine is None and gui.hidden)
            pump(lambda:gui.client.call('/api/remote/session?id='+sid)['status']=='closed')
            gui.show_from_tray();assert not gui.hidden
            agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
            pump(lambda:not gui.busy);gui.request();pump(lambda:gui.engine is not None)
            sid=gui.engine.sid;assert gui.image is None
            api('/api/remote/grant',{'username':'fixture-helper','device_id':aid,'enabled':False,'can_control':False})
            pump(lambda:gui.engine is None and gui.image is None)
            gui.close();time.sleep(.3)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('SELECT status FROM remote_sessions WHERE id=?',(sid,)).fetchone()[0]=='closed'
                audit=[json.loads(r[0]) for r in db.execute("SELECT details FROM events WHERE kind='remote.requested'")]
                assert audit[-1]['operator_origin']=='mis_workstation'
            assert config.read_bytes()==original_config
            report['checks'].append('exact compiled workstation GUI logs in over TLS, lists only granted endpoint, has no image before consent, displays synthetic frame after approval and stops on tray hiding and after grant revocation; blank reason accepted while consent remains required')
            report.update(passed=True,exe_sha256=sha(app/'GuardDesk.exe'),viewer_sha256=sha(viewer_exe),configured_exe_sha256=hashlib.sha256(blob).hexdigest(),configured_exe_bytes=len(blob),original_config_unchanged=True)
    except Exception as exc:report.update(failure=type(exc).__name__+': '+str(exc)[:1200],failure_line=traceback.extract_tb(exc.__traceback__)[-1].lineno)
    finally:
        path=ROOT/'evidence'/('mis-onefile-frozen-'+uid+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({'evidence':str(path),**report},ensure_ascii=False))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
