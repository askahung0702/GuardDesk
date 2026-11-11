"""Own private Server + exact frozen application: create, publish, download.

No real registry/UAC/profile/system trust or company Server access. Generated
fixture keys are private inside disposable roots and never saved in evidence.
"""
import hashlib,http.cookiejar,io,ipaddress,json,os,secrets,shutil,socket,ssl,subprocess,sys,tempfile,time,urllib.request,urllib.error,zipfile
from pathlib import Path
from cryptography import x509
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.server_setup import secure_directory,certificates
from guarddesk.store import Store


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe';expected=hashlib.sha256(exe.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='browser-publish-proof-',dir=ROOT/'runtime') as temporary:
        root=Path(temporary);program=root/'private-program';secure_directory(program)
        app=program/'GuardDesk';shutil.copytree(exe.parent,app)
        data=root/'private-data';secure_directory(data);tls=data/'tls';secure_directory(tls)
        ca=certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        store=Store(data/'control.sqlite3');password=secrets.token_urlsafe(24);store.add_user('fixture',password)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        base='https://127.0.0.1:'+str(port)
        connection={'version':1,'server':base,'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}
        with zipfile.ZipFile(data/'Endpoint-Connection.zip','w') as z:
            z.writestr('endpoint-connection.json',json.dumps(connection));z.writestr('GuardDesk-CA.pem',ca)
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=tls/'ca.pem')),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        process=subprocess.Popen([str(app/'GuardDesk.exe'),'serve','--db',str(store.path),'--host','127.0.0.1','--port',str(port),'--cert',str(tls/'server.crt'),'--key',str(tls/'server.key')],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            def call(path,body=None,headers=None):
                request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json',**(headers or {})})
                deadline=time.monotonic()+30
                while True:
                    try:
                        with client.open(request,timeout=45) as response:
                            raw=response.read();return json.loads(raw) if response.headers['Content-Type'].startswith('application/json') else raw
                    except urllib.error.HTTPError as error:
                        if error.code!=429 or time.monotonic()>=deadline:raise
                        time.sleep(.5)
            for _ in range(100):
                try:
                    if call('/api/health')['version']==__version__:break
                except (OSError,ConnectionError):pass
                assert process.poll() is None;time.sleep(.1)
            else:raise AssertionError('Owned frozen Server did not start')
            from guarddesk.store import digest
            with store.connect() as db:
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',('e'*24,digest('owned-dispatch-token'),'existing-fixture-endpoint','test',0))
            agent_headers={'Authorization':'Bearer owned-dispatch-token'}
            before=call('/api/agent/heartbeat',{'inventory':{},'policy_version':0},agent_headers)
            assert before['browser_dispatch']=={'status':'publication_required'}
            csrf=call('/api/login',{'username':'fixture','password':password})['csrf']
            headers={'X-CSRF-Token':csrf,'X-GuardDesk-Authorize':'browser-publication'}
            state=call('/api/browser-publication/create',{'base_url':base+'/browser-extension/','confirm_company_identity':True},headers)
            key=data/'BrowserSigner/extension-signing.pem';key_digest=hashlib.sha256(key.read_bytes()).hexdigest()
            again=call('/api/browser-publication/create',{'base_url':base+'/browser-extension/','confirm_company_identity':True},headers)
            assert state['extension_id']==again['extension_id'] and state['generation']==again['generation']
            assert hashlib.sha256(key.read_bytes()).hexdigest()==key_digest
            xml=call('/browser-extension/updates.xml');assert state['extension_id'].encode() in xml
            crx=call('/browser-extension/guarddesk-'+state['extension_version']+'.crx');assert crx.startswith(b'Cr24')
            bundle=call('/api/endpoint-package',{},headers)
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                manifest=json.loads(archive.read('endpoint-connection.json'))
                assert manifest['version']==3 and manifest['browser_deployment']==state['settings']
                from guarddesk.browser_deployment import verify_authorization
                trust=json.loads(archive.read('update-trust.json'))['public_key'];verify_authorization(manifest['browser_deployment'],manifest['browser_deployment_authorization'],trust)
                assert hashlib.sha256(archive.read('GuardDesk/GuardDesk.exe')).hexdigest()==expected
                status=json.loads(archive.read('browser-deployment-status.json'))
                assert status['status']=='policy_will_apply_during_uac' and status['browser_installation_verified'] is False
                assert not any(n.lower().endswith(('.key','.pfx')) or 'BrowserSigner' in n or 'signing.pem' in n for n in archive.namelist())
                assert b'PRIVATE KEY' not in archive.read('GuardDesk-CA.pem')
                assert '同一次 UAC' in archive.read('README-Browser.txt').decode('utf-8-sig')
            heartbeat=call('/api/agent/heartbeat',{'inventory':{},'policy_version':0},agent_headers)
            native=call('/api/agent/extended-policy',{},agent_headers)
            assert heartbeat['browser_dispatch']==native['browser_dispatch']
            dispatch=heartbeat['browser_dispatch'];assert dispatch['status']=='published'
            verify_authorization(dispatch['settings'],dispatch['authorization'],trust)
            from guarddesk.browser_dispatch import adopt
            from types import SimpleNamespace
            existing=root/'existing-agent-config.json'
            original={'device_id':'e'*24,'token':'owned-dispatch-token','update_key':trust,'audit_watch':str(root/'documents')}
            existing.write_text(json.dumps(original),encoding='utf-8')
            ordinary=SimpleNamespace(config=original,config_path=existing)
            adopt(ordinary,dispatch)
            assert all(ordinary.config[k]==v for k,v in original.items())
            assert ordinary.config['browser_deployment']==state['settings']
            # Corrupt publication must not fail the endpoint heartbeat.
            selector=data/'BrowserPublication/current.json';saved=selector.read_bytes();selector.write_bytes(b'corrupt fixture')
            try:
                damaged=call('/api/agent/heartbeat',{'inventory':{},'policy_version':0},agent_headers)
                assert damaged['browser_dispatch']=={'status':'publication_unavailable'}
                assert 'policy' in damaged
            finally:selector.write_bytes(saved)
            report={'passed':True,'version':__version__,'exe_sha256':expected,'frozen_server_used':True,'signed_crx_bytes':len(crx),'endpoint_zip_bytes':len(bundle),'checks':['Explicit company identity creation via authenticated frozen API','Same key and same generation retained across retry','Verified TLS public XML/CRX download','Actual authenticated endpoint ZIP contains matching company ID/public key/settings','Exact frozen binary in downloaded endpoint ZIP','No signing private key in public files or endpoint ZIP','Installer/browser-ready state remains distinct','Existing endpoint before publication reports publication_required','Frozen user and native policy projections carry identical organization-authorized settings','Existing config adopts descriptor without changing identity or update pin','Corrupt publication does not prevent heartbeat policy delivery'], 'office_changed':False,'real_uac_or_registry_changed':False,'actual_enterprise_installation_verified':False,'actual_ChatGPT_verified':False}
        finally:process.terminate();process.wait(20)
    (ROOT/f'evidence/browser-dispatch-frozen-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
