"""Exercise the frozen executable, not Python imports, on Windows."""
import hashlib
import http.cookiejar
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


def run():
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    exe=root/'dist/GuardDesk/GuardDesk.exe'
    assert (exe.parent/'_internal/guarddesk/windows/install-usb.ps1').is_file()
    assert (exe.parent/'_internal/guarddesk/windows/applications.ps1').is_file()
    def cli(*args):
        result=subprocess.run([str(exe),*map(str,args)],cwd=root,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stderr.decode('utf-8',errors='replace')
        return result.stdout.decode('utf-8',errors='replace')
    from guarddesk import __version__
    assert json.loads(cli('component-info'))=={'version':__version__,'update_protocol':1,'architecture':'windows-x64'}
    assert '--device-id' in cli('updater-check','--help')
    # Own frozen Tk login window only: never starts a real remote session.
    viewer=exe.parent/'_internal/GuardDeskRemote.exe'
    assert viewer.is_file() and not (exe.parent/'GuardDeskRemote.exe').exists()
    from guarddesk.update_packages import safe_name
    assert all(safe_name(p.relative_to(exe.parent).as_posix()) for p in exe.parent.rglob('*') if p.is_file())
    native_viewer=subprocess.Popen([str(viewer)],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
    import ctypes
    from ctypes import wintypes as w
    api=ctypes.windll.user32
    api.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    api.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
    api.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
    callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);owned=[]
    def find_owned(hwnd,param):
        pid=w.DWORD();api.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if pid.value==native_viewer.pid:
            title=ctypes.create_unicode_buffer(256);api.GetWindowTextW(hwnd,title,256)
            if title.value=='GuardDesk 遠端協助':owned.append(hwnd)
        return True
    visit=callback(find_owned);api.EnumWindows.argtypes=[callback,w.LPARAM]
    try:
        for attempt in range(100):
            assert native_viewer.poll() is None,'Frozen native viewer exited before creating its window'
            api.EnumWindows(visit,0)
            if owned:break
            time.sleep(.1)
        else:raise AssertionError('Frozen native viewer did not create a Tk login window')
        api.PostMessageW(owned[0],0x0010,0,0)
        assert native_viewer.wait(timeout=10)==0
    finally:
        if native_viewer.poll() is None:native_viewer.terminate();native_viewer.wait(timeout=10)
    with tempfile.TemporaryDirectory(dir=root/'runtime') as temp:
        scratch=Path(temp)
        source,encrypted,restored,key=scratch/'source.txt',scratch/'sealed.gdesk',scratch/'restored.txt',scratch/'key'
        source.write_text('packaged encryption test',encoding='utf-8')
        cli('encrypt',source,encrypted,'--key',key)
        cli('decrypt',encrypted,restored,'--key',key)
        assert source.read_bytes()==restored.read_bytes()
        watch=scratch/'documents';watch.mkdir()
        config=scratch/'agent/config.json';config.parent.mkdir()
        config.write_text(json.dumps({'server':'http://127.0.0.1:1','token':'offline-test-token','device_id':'frozen-native-test','watch':str(watch)}),encoding='utf-8')
        assert '--once' in cli('usb-worker','--help')
        import ctypes
        def is_admin():return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if not is_admin():
            check=subprocess.run([str(exe),'updater-check','--device-id','a'*24],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
            assert check.returncode!=0 and 'MIS'.encode() in check.stderr
            denied=subprocess.run([str(exe),'usb-worker','--config',str(config),'--once'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
            assert denied.returncode!=0 and 'SYSTEM' in denied.stderr.decode('utf-8',errors='replace')
        message=json.dumps({'type':'navigation','url':'https://example.com/packaged-test','request_id':'frozen','event_id':'browser-frozen-test'}).encode()
        import struct
        native=subprocess.run([str(exe),'browser-host','--config',str(config)],input=struct.pack('<I',len(message))+message,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        assert native.returncode==0,native.stderr.decode('utf-8',errors='replace')
        size=struct.unpack('<I',native.stdout[:4])[0];reply=json.loads(native.stdout[4:4+size])
        assert reply['recorded'] and reply['request_id']=='frozen'
        # Real windowless entry point, isolated offline policy; no startup/task changes.
        from guarddesk.agent import Agent
        settings=json.loads(config.read_text());settings['remote_enabled']=False;config.write_text(json.dumps(settings))
        isolated=Agent(config)
        with isolated.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(json.dumps({'version':0,'body':{'file_audit':{'enabled':False,'scope':'managed','exclude_paths':[]},'application_audit':False,'browser_audit':False}}),))
        gui=exe.parent/'GuardDeskAgent.exe'
        # A disposable desktop probe must not claim the signed-in user's real
        # HKCU Native Host, even if no host was registered before the test.
        import winreg
        def host_snapshot():
            result=[]
            for key_name,value in ((r'Software\GuardDesk','AgentConfig'),(r'Software\Google\Chrome\NativeMessagingHosts\com.guarddesk.agent',''),(r'Software\Microsoft\Edge\NativeMessagingHosts\com.guarddesk.agent','')):
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key_name) as key:result.append(winreg.QueryValueEx(key,value))
                except FileNotFoundError:result.append(None)
            return result
        host_before=host_snapshot()
        background=subprocess.Popen([str(gui),'desktop-agent','--config',str(config)],cwd=scratch,creationflags=subprocess.CREATE_NO_WINDOW)
        status=config.parent/'desktop-status.json'
        try:
            for attempt in range(100):
                if status.is_file() and json.loads(status.read_text()).get('state')=='running':break
                assert background.poll() is None,'Windowless agent exited before ready'
                time.sleep(.1)
            else:raise AssertionError('Windowless agent did not report running')
            assert not json.loads(status.read_text())['console_attached']
            duplicate=subprocess.run([str(gui),'desktop-agent','--config',str(config)],cwd=scratch,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
            assert duplicate.returncode==0 and background.poll() is None
            (config.parent/'stop-user-agent').write_text('stop')
            assert background.wait(timeout=20)==0
            assert json.loads(status.read_text())['state']=='stopped'
        finally:
            if background.poll() is None:background.terminate();background.wait(timeout=10)
        assert host_snapshot()==host_before,'Frozen disposable desktop probe changed live Native Host registration'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        process=subprocess.Popen([str(exe),'serve','--db',str(scratch/'test.sqlite3'),'--port',str(port)],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for attempt in range(100):
                try:
                    with opener.open(f'http://127.0.0.1:{port}/api/health',timeout=1) as response:
                        assert json.load(response)['status']=='ok'
                    break
                except urllib.error.URLError:
                    time.sleep(.1)
            else:
                raise AssertionError('Frozen server did not start')
            for path,needle in [('/',b'GuardDesk'),('/app.js',b'function overview'),('/management.js',b'function syncSetModules'),('/audit_ui.js',b'function detailedAudit'),('/remote_ui.js',b'function remotePage'),('/style.css',b':root')]:
                with opener.open(f'http://127.0.0.1:{port}'+path,timeout=3) as response:
                    assert needle in response.read()
            # Actual compiled fallback scanner, synthetic files only. The
            # one-shot command does not start watchers or install OS auditing.
            from guarddesk.store import Store
            from guarddesk.agent import enroll
            scan_store=Store(scratch/'test.sqlite3');scan_watch=scratch/'scan-fixture';scan_watch.mkdir()
            startup_file=scan_watch/'Start Menu/Programs/Startup/test.lnk'
            startup_file.parent.mkdir(parents=True);startup_file.write_text('ignored startup fixture')
            ordinary=scan_watch/'report.docx';ordinary.write_text('ordinary business fixture')
            business_boot=scan_watch/'Documents/Boot/report.docx'
            business_boot.parent.mkdir(parents=True);business_boot.write_text('business folder named Boot')
            development_file=scan_watch/'node_modules/fixture/index.js'
            development_file.parent.mkdir(parents=True);development_file.write_text('excluded synthetic dependency')
            fixture_data=scan_watch/'programdata'
            fixture_health=fixture_data/'GuardDeskPilot/USBControl'/('a'*24)/'broker-health.json'
            fixture_health.parent.mkdir(parents=True);fixture_health.write_text('synthetic health only')
            for profile in ('DEV','user1'):
                user_file=scan_watch/'Profiles'/profile/'workspace/fixture.py'
                user_file.parent.mkdir(parents=True);user_file.write_text('synthetic development file')
            fixture_user_rule=str(scan_watch/'Profiles/{user}/workspace')
            from guarddesk.file_exclusions import DEVELOPMENT_RULE
            from guarddesk.store import canonical
            with scan_store.connect() as db:
                policy=Store.policy(db);policy['body']['file_audit']['exclude_paths']=[DEVELOPMENT_RULE,fixture_user_rule,r'D:\Users\{user}\workspace']
                policy['body']['application_audit_exclusions']=['conhost.exe','docker.exe',r'C:\Tools\worker.exe']
                db.execute('INSERT INTO policies VALUES (?,?,?,?)',(policy['version']+1,canonical(policy['body']),time.time(),'fixture'))
            from guarddesk.store import digest
            with scan_store.connect() as db:db.execute('INSERT INTO enrollments VALUES (?,?,0)',(digest('frozen-scan-fixture'),time.time()+300))
            scan_config=scratch/'scan-agent/config.json'
            scan_did=enroll(scan_config,f'http://127.0.0.1:{port}','frozen-scan-fixture',scan_watch)
            # Source filtering takes effect after the endpoint receives the
            # assignment. The legacy --once command scans before heartbeat.
            from guarddesk.agent import Agent
            Agent(scan_config).heartbeat()
            from unittest.mock import patch
            with patch.dict(os.environ,{'ProgramData':str(fixture_data)}):cli('agent','--config',scan_config,'--once')
            with scan_store.connect() as db:
                scanned=[json.loads(row[0])['path'] for row in db.execute("SELECT details FROM events WHERE device_id=? AND kind='file.created'",(scan_did,))]
            assert set(scanned)=={str(ordinary),str(business_boot)},scanned
            import sqlite3
            from contextlib import closing
            with closing(sqlite3.connect(scan_config.with_suffix('.sqlite3'))) as db:
                assert not db.execute("SELECT 1 FROM files WHERE path LIKE 'node_modules%'").fetchone()
                assert not db.execute("SELECT 1 FROM files WHERE path LIKE '%broker-health.json'").fetchone()
                assert not db.execute("SELECT 1 FROM files WHERE path LIKE 'Profiles%'").fetchone()
                packet=json.loads(db.execute("SELECT value FROM state WHERE key='policy'").fetchone()[0])
                assert 'application_audit_exclusions' not in packet['body']
                assert packet['audit_options']['application_exclusions']==['conhost.exe','docker.exe',r'C:\Tools\worker.exe']
            # Frozen 0.4.24 Agent stops new modifications; frozen Server also
            # filters legacy batches without rewriting already stored history.
            with scan_store.connect() as db:
                Store.event(db,scan_did,'file.modified','info',{'path':'historic-fixture'},'historic-modification')
                original=dict(db.execute('SELECT * FROM events WHERE event_id=?',('historic-modification',)).fetchone())
            ordinary.write_text('changed business fixture')
            with patch.dict(os.environ,{'ProgramData':str(fixture_data)}):cli('agent','--config',scan_config,'--once')
            from guarddesk.agent import Agent
            legacy=Agent(scan_config)
            legacy_batch=[{'event_id':'legacy-modification','kind':'file.modified','severity':'info','occurred':time.time(),'details':{'path':str(ordinary)}},
                          {'event_id':'legacy-rename','kind':'file.renamed','severity':'info','occurred':time.time(),'details':{'source_path':'old.docx','destination_path':'new.docx'}}]
            for _ in range(2):assert legacy.call('/api/agent/events',{'events':legacy_batch})['accepted']==[e['event_id'] for e in legacy_batch]
            development_batch=[{'event_id':'legacy-development-cache','kind':'file.created','severity':'info','occurred':time.time(),'details':{'path':str(development_file)}},
                               {'event_id':'development-security','kind':'application.blocked','severity':'warning','occurred':time.time(),'details':{'path':str(development_file)}}]
            for _ in range(2):assert legacy.call('/api/agent/events',{'events':development_batch})['accepted']==[e['event_id'] for e in development_batch]
            application_cases=[('skip-conhost','application.started','info',r'C:\Windows\System32\conhost.exe'),
                               ('skip-docker','application.stopped','info',r'C:\Tools\docker.exe'),
                               ('skip-custom','application.started','info',r'C:\Tools\worker.exe'),
                               ('keep-custom','application.started','info',r'C:\OtherTools\worker.exe'),
                               ('keep-block','application.blocked','warning',r'C:\Tools\docker.exe'),
                               ('keep-critical','application.started','critical',r'C:\Tools\docker.exe')]
            application_batch=[{'event_id':eid,'kind':kind,'severity':level,'occurred':time.time(),'details':{'path':path,'process':path}} for eid,kind,level,path in application_cases]
            for _ in range(2):assert legacy.call('/api/agent/events',{'events':application_batch})['accepted']==[e['event_id'] for e in application_batch]
            health_root='C:\\ProgramData\\GuardDeskPilot\\USBControl\\'+'a'*24+'\\'
            health_path=health_root+'broker-health.json';health_temp=health_root+'broker-health.new'
            health_cases=[('skip-health','file.created','info',{'path':health_path}),
                          ('skip-health-rename','file.renamed','info',{'source_path':health_temp,'destination_path':health_path}),
                          ('keep-health-warning','file.deleted','warning',{'path':health_path}),
                          ('keep-health-gap','agent.audit_gap','critical',{'path':health_path}),
                          ('keep-health-cross','file.moved','info',{'source_path':health_path,'destination_path':str(ordinary)}),
                          ('keep-health-document','file.created','info',{'path':r'C:\Documents\broker-health.json'})]
            with scan_store.connect() as db:
                Store.event(db,scan_did,'file.created','info',{'path':health_path},'historic-health')
                original_health=dict(db.execute("SELECT * FROM events WHERE event_id='historic-health'").fetchone())
            health_batch=[{'event_id':eid,'kind':kind,'severity':level,'occurred':time.time(),'details':details} for eid,kind,level,details in health_cases]
            for _ in range(2):assert legacy.call('/api/agent/events',{'events':health_batch})['accepted']==[e['event_id'] for e in health_batch]
            user_cases=[('skip-user-dev','file.created',{'path':r'D:\Users\dev\workspace\main.py'}),
                        ('skip-user-user1','file.opened',{'path':r'D:\Users\user1\workspace\main.py'}),
                        ('keep-user-doc','file.opened',{'path':r'D:\Users\user1\Documents\main.py'}),
                        ('keep-user-prefix','file.created',{'path':r'D:\Users\user1\workspace2\main.py'}),
                        ('keep-user-boundary','file.moved',{'source_path':r'D:\Users\user1\workspace\main.py','destination_path':r'D:\Users\user1\Documents\main.py'}),
                        ('keep-user-gap','agent.audit_gap',{'path':r'D:\Users\user1\workspace\main.py'})]
            user_batch=[{'event_id':eid,'kind':kind,'severity':'info','occurred':time.time(),'details':details} for eid,kind,details in user_cases]
            for _ in range(2):assert legacy.call('/api/agent/events',{'events':user_batch})['accepted']==[e['event_id'] for e in user_batch]
            extended=legacy.call('/api/agent/extended-policy',{})
            assert 'application_audit_exclusions' not in extended['body'] and extended['audit_options']['application_exclusions']==packet['audit_options']['application_exclusions']
            with scan_store.connect() as db:
                for eid,_,_,_ in health_cases:
                    assert db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0]==(0 if eid.startswith('skip-') else 1),eid
                assert dict(db.execute("SELECT * FROM events WHERE event_id='historic-health'").fetchone())==original_health
                for eid,_,_ in user_cases:
                    assert db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0]==(0 if eid.startswith('skip-') else 1),eid
                for eid,_,_,_ in application_cases:
                    count=db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0]
                    assert count==(0 if eid.startswith('skip-') else 1),(eid,count)
                assert not db.execute("SELECT 1 FROM events WHERE event_id='legacy-development-cache'").fetchone()
                assert db.execute("SELECT count(*) FROM events WHERE event_id='development-security'").fetchone()[0]==1
                assert db.execute("SELECT count(*) FROM events WHERE kind='file.modified'").fetchone()[0]==1
                assert dict(db.execute('SELECT * FROM events WHERE event_id=?',('historic-modification',)).fetchone())==original
                assert db.execute('SELECT count(*) FROM events WHERE event_id=?',('legacy-rename',)).fetchone()[0]==1
            assert scan_store.verify()['valid']
            backup=scratch/'migration.sqlite3'
            result=json.loads(cli('server-backup','--db',scratch/'test.sqlite3','--output',backup,'--migration'))
            assert result['migration'] and backup.is_file() and not result['source_modified']
            denied_opt=subprocess.run([str(exe),'optimize-storage','--db',str(scratch/'test.sqlite3')],cwd=root,capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
            assert denied_opt.returncode!=0,'Offline optimizer must reject the running Server lease'
        finally:
            process.terminate();process.communicate(timeout=10)
        with scan_store.connect() as db:before_opt=[dict(r) for r in db.execute('SELECT * FROM events ORDER BY id')]
        optimized=json.loads(cli('optimize-storage','--db',scratch/'test.sqlite3'))
        assert optimized['passed'] and optimized['moved']>0 and optimized['history_preserved']
        with scan_store.connect() as db:
            assert [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id')]==before_opt
            assert db.execute('SELECT count(*) FROM events_legacy').fetchone()[0]==0
        assert scan_store.verify()['valid']
        # Real frozen wizard, importing an isolated prior DB (no password on CLI).
        from guarddesk.store import Store
        database = scratch/'server data/control.sqlite3'
        Store(database).add_user('test-mis', '7')
        easy_root = scratch/'easy server data'
        easy_root.mkdir()  # Reproduce a user-precreated empty data folder.
        # The installer now checks the Server program permissions as well as
        # its manifest. Model an actual private MIS installation, not the
        # shared build workspace; these are exactly the tested frozen bytes.
        from guarddesk.server_setup import secure_directory
        private_program=secure_directory(scratch/'installed-program')
        installed_app=private_program/'GuardDesk';shutil.copytree(exe.parent,installed_app)
        installed_exe=installed_app/'GuardDesk.exe'
        wizard = subprocess.run([str(installed_exe),'server-setup','--root',str(easy_root)],
            input=f'guarddesk.test\n{database}\n'.encode(),cwd=scratch,capture_output=True,
            timeout=40,creationflags=subprocess.CREATE_NO_WINDOW)
        assert wizard.returncode==0,wizard.stderr.decode('utf-8',errors='replace')
        repeated=subprocess.run([str(installed_exe),'server-setup','--root',str(easy_root)],
            input=b'',cwd=scratch,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        assert repeated.returncode==0 and b'Start-Management.cmd' in repeated.stdout
        # The server-created installer is usable without the connection-only ZIP.
        installer_zip=easy_root/'GuardDesk-Endpoint.zip'
        assert installer_zip.is_file()
        with zipfile.ZipFile(installer_zip) as bundle:
            for name in ('Setup-Endpoint.cmd','Connect-Endpoint.cmd','GuardDesk/GuardDesk.exe','GuardDesk/GuardDeskAgent.exe','endpoint-files.json','update-trust.json'):
                assert name in bundle.namelist(), name
            assert bundle.read('Connect-Endpoint.cmd')==bundle.read('Setup-Endpoint.cmd')
            assert hashlib.sha256(bundle.read('GuardDesk/GuardDesk.exe')).hexdigest()==hashlib.sha256(exe.read_bytes()).hexdigest()
            assert not any(n.endswith(('.key','.sqlite3')) for n in bundle.namelist())
            from guarddesk.endpoint_package import REQUIRED
            payload=json.loads(bundle.read('endpoint-files.json'))
            assert payload['version']==__version__ and REQUIRED<=payload['files'].keys()
            assert all(hashlib.sha256(bundle.read('GuardDesk/'+name)).hexdigest()==digest for name,digest in payload['files'].items())
            assert '不需要手動執行 PS1' in bundle.read('README-Endpoint.txt').decode('utf-8')
        easy_config=easy_root/'server.json'
        easy_settings=json.loads(easy_config.read_text())
        with socket.socket() as one,socket.socket() as two:
            one.bind(('127.0.0.1',0));two.bind(('127.0.0.1',0))
            easy_settings.update(port=one.getsockname()[1],local_console_port=two.getsockname()[1])
        easy_config.write_text(json.dumps(easy_settings))
        with zipfile.ZipFile(easy_root/'Endpoint-Connection.zip') as bundle:
            assert not any(b'PRIVATE KEY' in bundle.read(p) for p in bundle.namelist())
            assert 'Connect-Endpoint.cmd' in bundle.namelist()
        assert '--open-console' in (easy_root/'Start-Management.cmd').read_text(encoding='utf-8')
        optimizer_cmd=(easy_root/'Optimize-Storage.cmd').read_bytes()
        assert b'optimize-storage --config' in optimizer_cmd and b'\n' not in optimizer_cmd.replace(b'\r\n',b'')
        assert str(installed_app/'_internal/GuardDeskRemote.exe') in (easy_root/'Start-Remote.cmd').read_text(encoding='utf-8')
        assert json.loads(cli('server-check','--config',easy_config))['passed']
        # Model a private MIS-installed program directory, not the shared build
        # workspace. Binary/runtime bytes are the exact tested frozen build.
        process=subprocess.Popen([str(installed_app/'GuardDesk.exe'),'serve','--config',str(easy_config)],cwd=scratch,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        from unittest.mock import patch
        original=socket.getaddrinfo
        def resolve(host,*args,**kwargs):return original('127.0.0.1' if host=='guarddesk.test' else host,*args,**kwargs)
        try:
            local=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            for attempt in range(100):
                try:
                    with local.open(f'http://127.0.0.1:{easy_settings["local_console_port"]}/',timeout=1) as response:
                        assert b'GuardDesk' in response.read()
                    break
                except urllib.error.URLError:time.sleep(.1)
            else:raise AssertionError('Frozen local-only management console did not start')
            console=f'http://127.0.0.1:{easy_settings["local_console_port"]}'
            login=urllib.request.Request(console+'/api/login',data=json.dumps({'username':'test-mis','password':'7'}).encode(),headers={'Content-Type':'application/json'})
            with local.open(login,timeout=3) as response:session=json.load(response)
            for attempt in range(600):
                with local.open(console+'/api/updates',timeout=5) as response:automatic=json.load(response)
                if automatic['bundled_release']['status']=='ready':break
                assert automatic['bundled_release']['status']=='preparing',automatic['bundled_release']
                time.sleep(.2)
            else:raise AssertionError('Frozen bundled release preparation did not finish')
            assert automatic['latest_release_id']==automatic['bundled_release']['release_id'] and not automatic['jobs']
            automatic_release_id=automatic['latest_release_id']
            create_support=urllib.request.Request(console+'/api/remote/account',
                data=json.dumps({'username':'short-support','password':'1'}).encode(),
                headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
            with local.open(create_support,timeout=3) as response:assert json.load(response)['ok']
            all_remote=urllib.request.Request(console+'/api/remote/grant',
                data=json.dumps({'username':'short-support','device_id':'*','enabled':True,'can_control':True,'days':0}).encode(),
                headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
            with local.open(all_remote,timeout=5) as response:assert json.load(response)['ok']
            package_request=urllib.request.Request(console+'/api/endpoint-package',data=b'{}',headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
            with local.open(package_request,timeout=30) as response:
                downloaded=scratch/'frozen-endpoint.zip';downloaded.write_bytes(response.read())
                assert response.headers['Cache-Control']=='no-store'
            with zipfile.ZipFile(downloaded) as bundle:
                assert 'Setup-Endpoint.cmd' in bundle.namelist()
                assert hashlib.sha256(bundle.read('GuardDesk/GuardDeskAgent.exe')).hexdigest()==hashlib.sha256(gui.read_bytes()).hexdigest()
                assert not any(name.endswith('.key') or 'runtime' in name.split('/') for name in bundle.namelist())
                shared_code=json.loads(bundle.read('endpoint-connection.json'))['deployment_code']
                pinned=json.loads(bundle.read('update-trust.json'))['public_key']
            # Import actual frozen application bytes, not mock executable fixtures.
            candidate=scratch/'update-release.zip';program_files={p.relative_to(exe.parent).as_posix():p for p in exe.parent.rglob('*') if p.is_file()}
            manifest_hashes={'GuardDesk/'+name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in program_files.items()}
            with zipfile.ZipFile(candidate,'w',zipfile.ZIP_DEFLATED) as bundle:
                for name,path in sorted(program_files.items()):bundle.write(path,'GuardDesk/'+name)
                bundle.writestr('MANIFEST-SHA256.json',json.dumps(manifest_hashes));bundle.writestr('build-info.json',json.dumps({'GuardDesk':__version__}))
            upload=urllib.request.Request(console+'/api/updates/import',data=candidate.read_bytes(),headers={'Content-Type':'application/zip','X-CSRF-Token':session['csrf'],'X-GuardDesk-Authorize':'update-release'})
            with local.open(upload,timeout=30) as response:release_id=json.load(response)['id']
            assert release_id==automatic_release_id,'Manual and bundled packages must use identical application bytes'
            with patch('socket.getaddrinfo',side_effect=resolve):
                endpoint=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(easy_root/'tls/ca.pem'))))
                url=f'https://guarddesk.test:{easy_settings["port"]}'
                with endpoint.open(url+'/api/health',timeout=3) as response:assert json.load(response)['status']=='ok'
                try:endpoint.open(url+'/',timeout=3)
                except urllib.error.HTTPError as denied:assert denied.code==403
                else:raise AssertionError('Agent-only listener exposed management UI')
                def register_shared(name):
                    payload=json.dumps({'token':shared_code,'name':name,'department':'frozen fixture'}).encode()
                    with endpoint.open(urllib.request.Request(url+'/api/agent/enroll',data=payload,headers={'Content-Type':'application/json'}),timeout=5) as response:return json.load(response)
                first=register_shared('first');second=register_shared('second')
                assert first['device_id']!=second['device_id'] and first['token']!=second['token']
                # Rule predates both enrollments; compiled Server expands it for
                # the standard protocol-2 viewer without individual grants.
                from guarddesk.remote_client import RemoteClient
                frozen_support=RemoteClient(console)
                try:
                    catalog=frozen_support.login('short-support','1')
                    assert {first['device_id'],second['device_id']} <= {d['id'] for d in catalog['devices']}
                    assert len(catalog['grant_rules'])==1 and catalog['grant_rules'][0]['permanent']
                    presence=urllib.request.Request(url+'/api/agent/remote/poll',data=b'{"account":"SIMULATED-USER","ready":true,"protocol":2}',headers={'Content-Type':'application/json','Authorization':'Bearer '+first['token']})
                    with endpoint.open(presence,timeout=5) as response:assert json.load(response)['session'] is None
                    requested=frozen_support.request(first['device_id'],'control','Frozen all-endpoint consent simulation')
                    assert requested['status']=='requested'
                    revoke_remote=urllib.request.Request(console+'/api/remote/grant',data=json.dumps({'username':'short-support','device_id':'*','enabled':False,'can_control':False}).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
                    with local.open(revoke_remote,timeout=5) as response:assert json.load(response)['ok']
                    assert frozen_support.call('/api/remote/session?id='+requested['id'])['status']=='closed'
                    assert frozen_support.catalog()['devices']==[]
                finally:frozen_support.logout()
                # Owned installer fixture: explicitly attest the one-device pilot;
                # this does not prove capacity on any company endpoint.
                scheduled=urllib.request.Request(console+'/api/updates/jobs',data=json.dumps({'release_id':release_id,'device_ids':[first['device_id']],'confirm':'deploy','legacy_preflight_confirmed':True}).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
                with local.open(scheduled,timeout=5) as response:jid=json.load(response)['job_ids'][0]
                # Real frozen server, verified TLS, own simulated endpoint:
                # notification carries no code and never runs an updater.
                import threading
                def wait_notice(cursor):
                    req=urllib.request.Request(url+'/api/agent/updates/wait',data=json.dumps({'role':'native','cursor':cursor}).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+first['token']})
                    with endpoint.open(req,timeout=12) as response:return json.load(response)
                initial=wait_notice(None);notices=[];notice_errors=[]
                def waiting_notice():
                    try:notices.append(wait_notice(initial['cursor']))
                    except Exception as exc:notice_errors.append(type(exc).__name__)
                listener=threading.Thread(target=waiting_notice);listener.start()
                for attempt in range(40):
                    with local.open(console+'/api/updates',timeout=5) as response:jobs=json.load(response)['jobs']
                    if next(j for j in jobs if j['id']==jid)['delivery']['connected']['native']:break
                    time.sleep(.05)
                else:raise AssertionError('Frozen notification channel did not become ready')
                nudge=urllib.request.Request(console+'/api/updates/notify',data=json.dumps({'job_id':jid}).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
                with local.open(nudge,timeout=5) as response:assert json.load(response)['connected_roles']==['native']
                listener.join(5);assert not listener.is_alive() and not notice_errors and notices[0]['changed']
                poll=urllib.request.Request(url+'/api/agent/updates/poll',data=json.dumps({'role':'native','version':__version__}).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+first['token']})
                with endpoint.open(poll,timeout=5) as response:packet=json.load(response)['job']
                from guarddesk.update_client import validate_job
                job,manifest=validate_job(packet,pinned,first['device_id'])
                package_request=urllib.request.Request(url+'/api/agent/updates/download?job_id='+jid,headers={'Authorization':'Bearer '+first['token']})
                with endpoint.open(package_request,timeout=30) as response:update_bytes=response.read()
                assert hashlib.sha256(update_bytes).hexdigest()==manifest['sha256']
                with zipfile.ZipFile(__import__('io').BytesIO(update_bytes)) as bundle:assert hashlib.sha256(bundle.read('GuardDeskAgent.exe')).hexdigest()==hashlib.sha256(gui.read_bytes()).hexdigest()
                # Simulated component completion, real frozen signed maintenance API.
                # No native task or program replacement occurs in this smoke.
                def agent_post(path,body):
                    req=urllib.request.Request(url+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+first['token']})
                    with endpoint.open(req,timeout=5) as response:return json.load(response)
                for role in ('native','main'):
                    agent_post('/api/agent/updates/status',{'job_id':jid,'role':role,'state':'healthy','version':__version__})
                maintenance=agent_post('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})['authorization']
                from guarddesk.updater_refresh import authorization
                from types import SimpleNamespace
                lease=authorization(maintenance,SimpleNamespace(config={'device_id':first['device_id'],'update_key':pinned}),job,manifest)
                assert agent_post('/api/agent/updates/poll',{'role':'native','version':__version__})['waiting_for']=='updater_refresh'
                agent_post('/api/agent/updater/complete',{'id':lease['id'],'state':'healthy'})
                with local.open(console+'/api/updates',timeout=5) as response:
                    assert json.load(response)['updater_refresh'][0]['state']=='healthy'
                revoke=urllib.request.Request(console+'/api/deployment/revoke',data=b'{"confirm":"revoke"}',headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
                with local.open(revoke,timeout=5) as response:assert not json.load(response)['active']
                try:register_shared('revoked')
                except urllib.error.HTTPError as denied:assert denied.code==401
                else:raise AssertionError('Frozen shared bootstrap remained valid after revocation')
                heartbeat=urllib.request.Request(url+'/api/agent/heartbeat',data=b'{"policy_version":0,"inventory":{}}',headers={'Content-Type':'application/json','Authorization':'Bearer '+first['token']})
                with endpoint.open(heartbeat,timeout=5) as response:assert 'policy' in json.load(response)
                # Exercise the final frozen 0.4.28 server, not source imports.
                def mis_json(path,body=None):
                    request=urllib.request.Request(console+path,data=json.dumps(body).encode() if body is not None else None,
                        headers={'Content-Type':'application/json','X-CSRF-Token':session['csrf']})
                    with local.open(request,timeout=15) as response:return json.load(response)
                assert mis_json('/api/state?compact=1&stats=0')['stats'] is None
                draft={'name':'Frozen narrow inheritance','overrides':{},'operations':[{'path':'file_audit.exclude_paths','op':'append','value':[r'C:\OwnedFrozen']}],'enabled':True}
                preview=mis_json('/api/policy-sets/preview',draft)
                saved=mis_json('/api/policy-sets',{**draft,'expected_generation':preview['generation']})
                assignment={'set_id':saved['id'],'target_type':'device','target_id':first['device_id']}
                compared=mis_json('/api/assignments/preview',assignment)
                assert compared['changed_count']==1
                mis_json('/api/assignments',{**assignment,'expected_generation':compared['generation']})
                detail=mis_json('/api/device-detail?device_id='+first['device_id'])
                assert r'C:\OwnedFrozen' in detail['effective_policy']['body']['file_audit']['exclude_paths']
                assert all(not row['hardware_tested'] for row in detail['device']['policy_progress'])
                mis_json('/api/audit/storage/enable',{'confirm':'enable_daily'})
                for _ in range(150):
                    storage=mis_json('/api/audit/storage')
                    if storage['mode']=='daily-v1' and storage['migration']['state']=='completed':break
                    time.sleep(.1)
                else:raise AssertionError('Frozen daily activation failed')
                cursor=mis_json('/api/events?cursor_mode=1&limit=2')
                assert cursor['total'] is None and cursor['has_more']
                from urllib.parse import quote
                next_page=mis_json('/api/events?cursor_mode=1&limit=2&cursor='+quote(cursor['next_cursor']))
                assert not {r['id'] for r in cursor['items']}&{r['id'] for r in next_page['items']}
                assert mis_json('/api/integrity')['valid']
                daily_backup=json.loads(cli('server-backup','--db',easy_root/'control.sqlite3','--output',scratch/'daily-backup.sqlite3'))
                assert daily_backup['event_day_files']
                assert json.loads(cli('server-check','--config',easy_config))['passed']
        finally:
            process.terminate();process.communicate(timeout=10)
        # Frozen deployment CLI: distinct program/config/data roots, unrelated CWD.
        from test_server_deployment import certificate
        cert, tls_key = certificate(scratch/'server config/tls')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        server_config = scratch/'server config/settings.json'
        server_config.write_text(json.dumps({'host':'0.0.0.0', 'port':port,
            'db':'../server data/control.sqlite3', 'cert':'tls/server.crt','key':'tls/server.key'}))
        checked = json.loads(cli('server-check','--config',server_config))
        assert checked['passed'] and checked['db']==str(database)
        rejected = subprocess.run([str(exe),'serve','--config',str(server_config),'--db',str(database)],
            cwd=scratch,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        assert rejected.returncode!=0
        process=subprocess.Popen([str(exe),'serve','--config',str(server_config)],cwd=scratch,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))))
            for attempt in range(100):
                try:
                    with opener.open(f'https://127.0.0.1:{port}/api/health',timeout=1) as response:
                        assert json.load(response)['status']=='ok'
                    break
                except urllib.error.URLError:time.sleep(.1)
            else:raise AssertionError('Frozen configured HTTPS server did not start')
            with opener.open(f'https://127.0.0.1:{port}/',timeout=3) as response:
                from guarddesk import __version__
                assert __version__.encode() in response.read()
        finally:
            process.terminate();process.communicate(timeout=10)
    report={'passed':True,'checks':['frozen exe starts','AES-GCM package roundtrip','SQLite server health','bundled HTML JS CSS served','frozen native browser host writes offline event','frozen server migration snapshot succeeds while source serves','frozen server-check validates separate data directory','frozen serve --config HTTPS health with trusted test CA and unrelated working directory','config/CLI override ambiguity rejected','USB installer bundled and worker CLI available','non-admin USB enforcement denied before apply' if not is_admin() else 'non-admin check skipped: elevated test account'],'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()}
    report['checks'].append('frozen Agent stops file modifications; frozen Server acknowledges filtered legacy batches, keeps rename replay idempotent and preserves historical hashes')
    report['gui_sha256']=hashlib.sha256(gui.read_bytes()).hexdigest()
    development_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen Agent skips development cache discovery/baseline; ordinary document and Boot business folder preserved','Frozen Server acknowledges and filters legacy cache events idempotently','Application security event retained once','Existing source event hashes unchanged'],
        'limitations':['Owned loopback synthetic fixture; no protected task or Windows policy changes','Not office Server, Windows 10 or company Defender acceptance']}
    (root/f'evidence/packaged-development-exclusions-{__version__}.json').write_text(json.dumps(development_report,indent=2),encoding='utf-8')
    application_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen Server excludes ordinary conhost/docker and exact custom path starts/stops, acknowledges replay','Different same-name path, blocks and critical starts retained once','Frozen Agent policy cache keeps legacy body and separate exclusion options','Frozen native extended-policy response uses the same legacy-compatible envelope'],
        'limitations':['Synthetic loopback fixture; no actual SYSTEM worker installation or Windows Security policy changes','Source collector and offline adapter verified separately in unit tests; company fleet/Defender not accepted']}
    (root/f'evidence/packaged-application-exclusions-{__version__}.json').write_text(json.dumps(application_report,indent=2),encoding='utf-8')
    report['checks'].extend(development_report['checks'])
    report['checks'].extend(application_report['checks'])
    health_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen Agent skips fixed health files before content reads/baseline with relocated fixture ProgramData',
                  'Frozen Server ACKs and filters old informational health create/rename batches on replay',
                  'Health warning, audit gap, same-name business document and crossing move retained once',
                  'Historic health event and original hashes unchanged; global chain verifies'],
        'limitations':['Synthetic loopback and owned files only; no live broker files, tasks or office Server changed',
                       'Company Defender/EDR, signing and physical fleet acceptance remain incomplete']}
    (root/f'evidence/packaged-internal-health-{__version__}.json').write_text(json.dumps(health_report,indent=2),encoding='utf-8')
    report['checks'].extend(health_report['checks'])
    user_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen Agent excludes two synthetic profile workspaces before baseline; ordinary documents retained',
                  'Frozen Server filters and ACKs old-format multi-user workspace batches idempotently',
                  'Same-prefix boundary, outside documents and gap remain; historic chain verifies'],
        'limitations':['Owned synthetic loopback only; no real profile enumeration or installed Agent changes',
                       'Old Agents need upgrade for source suppression; signing and company Defender remain unaccepted']}
    (root/f'evidence/packaged-user-path-{__version__}.json').write_text(json.dumps(user_report,indent=2),encoding='utf-8')
    report['checks'].extend(user_report['checks'])
    optimization_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen offline optimizer refuses running Server before mutation',
                  'Frozen optimizer creates backup, migrates history, verifies chain and compacts while retaining exact rows/IDs/hashes',
                  'Frozen setup produces CRLF Optimize-Storage.cmd; compact state skips global stats',
                  'Frozen daily WAL writes, cursor lists, full backup and preflight remain valid'],
        'limitations':['Owned small fixture and actual compiled EXE; large copy benchmark is recorded separately',
                       'No office Server, physical fleet or company Defender acceptance']}
    (root/f'evidence/packaged-storage-optimization-{__version__}.json').write_text(json.dumps(optimization_report,indent=2),encoding='utf-8')
    report['checks'].extend(optimization_report['checks'])
    improvement_report={'version':__version__,'passed':True,'exe_sha256':report['exe_sha256'],
        'checks':['Frozen field inheritance/append preview, publish and device assignment preserve unrelated settings',
                  'Frozen progress distinguishes receipt and untested enforcement',
                  'Frozen asynchronous daily activation retains global integrity and legacy/current query',
                  'Frozen signed cursor pages do not overlap',
                  'Frozen backup contains day files and server-check accepts the daily schema'],
        'limits':['Synthetic localhost; no office data migration, actual SYSTEM install or company Defender acceptance']}
    (root/f'evidence/packaged-improvements-{__version__}.json').write_text(json.dumps(improvement_report,indent=2),encoding='utf-8')
    report['checks'].extend(improvement_report['checks'])
    report['application_files']={p.relative_to(exe.parent).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in exe.parent.rglob('*') if p.is_file()}
    report['checks'].extend(['windowless GUI agent reports no console, rejects duplicate instance and stops gracefully with offline policy',
        'frozen one-shot fallback scanner excludes Startup files before upload, retains ordinary documents and business folders named Boot, without native watchers or OS policy changes',
        'frozen MIS all-endpoint rule covers future enrollments, expands legacy viewer catalog, preserves consent and closes pending remote on revocation without desktop capture or input',
        'frozen server in a private MIS program directory automatically verifies and signs its bundled Agent at startup, selects latest without upload, and creates no deployment job; optional manual import is idempotent',
        'frozen HTTPS server signs a fixed-purpose updater-maintenance lease after simulated component completion, freezes competing work and records completion without real SYSTEM modification',
        'frozen local admin updater-check CLI exposes required ID and refuses non-admin use; no actual protected install changed',
        'frozen agent-only verified HTTPS notification channel is woken by local MIS notify after commit without executing any payload',
        'frozen independent MIS viewer opens its own Tk login window and closes cleanly without a remote session',
        'viewer stays under _internal and application paths satisfy the existing updater whitelist; setup creates Start-Remote.cmd',
        'frozen version/update protocol probe succeeds; frozen server imports actual application bytes, signs a device-scoped job, and serves verified authenticated update bytes over HTTPS',
        'frozen shared package enrolls two independent endpoints over verified HTTPS; revoked code denied while existing endpoint heartbeat remains valid',
        'frozen authenticated management endpoint exports a single ZIP with the exact tested GUI binary with public CA and embedded reusable bootstrap',
        'frozen interactive server setup imports old fixture DB and creates private transport material',
        'frozen console accepts one-character MIS password and creates a one-character support password',
        'frozen wizard accepts a precreated empty folder and detects an existing installation without further prompts',
        'frozen local-only HTTP console and agent-only HTTPS run together; remote management UI denied',
        'exported endpoint ZIP contains no private keys; generated launcher targets the setup config'])
    (root/'evidence/packaged-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='application_files'}))


if __name__=='__main__':
    run()
