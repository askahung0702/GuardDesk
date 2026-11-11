"""Real old/new frozen Server, disposable prior schema and original config.

Only loopback, synthetic identities, private test TLS and exact owned Popen
handles. No Windows trust/policy/task changes or employee profiles.
"""
import copy,hashlib,http.cookiejar,io,ipaddress,json,os,re,secrets,shutil,socket,sqlite3,ssl,subprocess,sys,tempfile,time,traceback,uuid,zipfile
from contextlib import closing,contextmanager
from cryptography import x509
from pathlib import Path
import urllib.error,urllib.request
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.server_setup import secure_directory,certificates,server_name
from guarddesk.agent import Agent,enroll
from guarddesk.policy import DEFAULT_POLICY

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def free_port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def main():
    probe=uuid.uuid4().hex;report={'version':'0.4.62','probe_id':probe,'scope':'owned_old_0461_to_frozen_0462_original_config_https',
        'passed':False,'company_changed':False,'browser_policy_modified':False,'real_installed_agent':False,'checks':[]}
    new=ROOT/'dist/GuardDesk';old=ROOT/'runtime/pre0462-build-6092160f3039453e8c32ce429a29734e'
    process=None
    @contextmanager
    def workspace():
        with tempfile.TemporaryDirectory(prefix='upgrade0462-',dir=ROOT/'runtime') as tmp:
            try:yield tmp
            finally:
                if process is not None:
                    if process.poll() is None:process.terminate()
                    process.wait(timeout=15)
    try:
        with workspace() as tmp:
            work=secure_directory(Path(tmp),allow_empty=True);data=secure_directory(work/'data');database=data/'control.sqlite3'
            password=secrets.token_urlsafe(24)
            # Import exactly the sealed prior source to construct the old schema.
            seed="import sys,json;sys.path.insert(0,sys.argv[1]);from guarddesk import __version__;from guarddesk.store import Store;s=json.load(sys.stdin);assert __version__=='0.4.61';Store(s['db']).add_user('fixture-mis',s['password']);print(__version__)"
            seeded=subprocess.run([sys.executable,'-c',seed,str(ROOT/'dist/GuardDesk-0.4.61-source.zip')],
                input=json.dumps({'db':str(database),'password':password}).encode(),cwd=work,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            assert seeded.returncode==0,'Prior schema fixture seed failed'
            with closing(sqlite3.connect(database)) as db:
                assert db.execute("SELECT 1 FROM sqlite_master WHERE name='categories'").fetchone()
                assert 'category_refs' in [r[1] for r in db.execute('PRAGMA table_info(policy_sets)')]
            tls=data/'tls';tls.mkdir();certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
            port,console=free_port(),free_port();assert port!=console
            config=data/'server.json';config.write_text(json.dumps({'db':'control.sqlite3','host':'127.0.0.1','port':port,'local_console_port':console,'cert':'tls/server.crt','key':'tls/server.key'}),encoding='utf-8')
            original_config=config.read_bytes();url=f'http://127.0.0.1:{console}';endpoint=f'https://127.0.0.1:{port}'
            # Original public connection material is part of a real Server
            # data directory; a bare DB/config fixture must provide it too.
            ca=(tls/'ca.pem').read_bytes()
            with zipfile.ZipFile(data/'Endpoint-Connection.zip','x',zipfile.ZIP_DEFLATED) as z:
                z.writestr('GuardDesk-CA.pem',ca)
                z.writestr('endpoint-connection.json',json.dumps({'version':1,'server':endpoint,'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}))
            installed_parent=secure_directory(work/'program');installed=installed_parent/'GuardDesk';shutil.copytree(old,installed)
            client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            csrf=''
            def api(path,body=None):
                req=urllib.request.Request(url+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
                with client.open(req,timeout=45 if path=='/api/endpoint-package' else 10) as response:
                    blob=response.read();return json.loads(blob) if 'application/json' in response.headers['Content-Type'] else blob
            def start():
                nonlocal process
                log=(work/('server-'+uuid.uuid4().hex+'.log')).open('wb')
                try:process=subprocess.Popen([str(installed/'GuardDesk.exe'),'serve','--config',str(config)],cwd=work,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
                finally:log.close()
                for _ in range(150):
                    assert process.poll() is None,'Owned frozen Server exited before health'
                    try:
                        if api('/api/health')['status']=='ok':return
                    except (urllib.error.URLError,ConnectionError):pass
                    time.sleep(.1)
                raise RuntimeError('Owned frozen Server startup timeout')
            def stop():
                nonlocal process
                if process is not None:
                    if process.poll() is None:process.terminate()
                    process.wait(timeout=15);process=None
            def await_bundle(label):
                deadline=time.monotonic()+120
                while True:
                    publication=api('/api/updates')['bundled_release']
                    if publication['status']=='ready':return
                    if publication['status']!='preparing':raise RuntimeError('Owned '+label+' bundled release status: '+publication['status']+' / '+publication.get('code',''))
                    if time.monotonic()>=deadline:raise RuntimeError('Owned '+label+' bundled release preparation timeout')
                    time.sleep(.2)
            start();csrf=api('/api/login',{'username':'fixture-mis','password':password})['csrf']
            # An established prior installation has its organization signing
            # key already. Let the real old publisher prepare it before enroll.
            # Never manufacture replacement signing material after enrollment.
            await_bundle('old')
            previous_category=api('/api/categories/draft',{'kind':'website','draft':{'name':'Preserved prior category','description':'synthetic','parent_id':None,'members':[{'name':'prior.example','type':'domain','domain':'prior.example','include_subdomains':True,'scheme':'any'}]}})
            api('/api/categories/publish',{**previous_category,'expected_generation':api('/api/categories')['generation']})
            prior_category_snapshot=api('/api/categories?id='+previous_category['id'])['selected']['members']
            code=api('/api/enrollments',{})['token'];watch=work/'documents';watch.mkdir()
            agent_config=work/'agent/config.json';did=enroll(agent_config,endpoint,code,watch,name='OWNED-UPGRADE-FIXTURE',ca=str(tls/'ca.pem'))
            agent=Agent(agent_config);agent.heartbeat(refresh_inventory=False)
            with closing(sqlite3.connect(database)) as db:
                original_device=db.execute('SELECT id,token FROM devices WHERE id=?',(did,)).fetchone()
                original_policy=db.execute('SELECT body FROM policies ORDER BY version DESC LIMIT 1').fetchone()[0]
            preserved={str(p.relative_to(data)):sha(p) for p in data.rglob('*') if p.is_file() and (p.suffix in ('.key','.pem','.crt') or 'update-signing' in p.parts)}
            stop();saved=installed_parent/'old-GuardDesk'
            deadline=time.monotonic()+10
            while True:
                try:installed.rename(saved);break
                except OSError as exc:
                    if getattr(exc,'winerror',None) not in (5,32,33) or time.monotonic()>=deadline:raise
                    time.sleep(.2)
            shutil.copytree(new,installed)
            report['checks'].append('actual frozen 0.4.61 initialized prior schema and enrolled synthetic TLS endpoint')
            start();client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            csrf=api('/api/login',{'username':'fixture-mis','password':password})['csrf']
            assert config.read_bytes()==original_config
            assert all(sha(data/name)==value for name,value in preserved.items())
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('SELECT id,token FROM devices WHERE id=?',(did,)).fetchone()==original_device
                assert db.execute('SELECT body FROM policies ORDER BY version DESC LIMIT 1').fetchone()[0]==original_policy
                assert db.execute("SELECT 1 FROM sqlite_master WHERE name='categories'").fetchone()
                assert 'category_refs' in [r[1] for r in db.execute('PRAGMA table_info(policy_sets)')]
            agent.heartbeat(refresh_inventory=False)
            assert api('/api/categories?id='+previous_category['id'])['selected']['members']==prior_category_snapshot
            report['checks'].append('same original server.json, TLS/signing keys, prior policy and endpoint identity preserved across full program replacement')
            rows=[{'name':f'Site {i}','type':'domain','domain':f'*.s{i}.example.com','include_subdomains':True,'scheme':'any'} for i in range(51)]
            c=api('/api/categories/draft',{'kind':'website','draft':{'name':'Owned cloud fixture','description':'synthetic','parent_id':None,'members':rows}})
            preview=api('/api/categories/preview',{**c,'expected_generation':api('/api/categories')['generation']})
            c=api('/api/categories/publish',{**c,'expected_generation':preview['generation']})
            assert len(api('/api/categories?id='+c['id'])['selected']['members'])==50
            assert len(api('/api/categories?id='+c['id']+'&offset=50')['selected']['members'])==1
            p=api('/api/policy-sets',{'name':'Owned website block','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}},'category_refs':{'website_blocked':[{'id':c['id'],'include_descendants':False}]}})
            assignment={'set_id':p['id'],'target_type':'device','target_id':did,'enabled':True,'priority':100}
            preview=api('/api/assignments/preview',assignment);api('/api/assignments',{**assignment,'expected_generation':preview['generation']})
            policy=agent.heartbeat(refresh_inventory=False)
            assert set(policy['body']['website_control']['blocked'])=={f's{i}.example.com' for i in range(51)}
            report['checks'].append('frozen category draft, preview, publication, 50+1 members, policy reference and authenticated TLS heartbeat compile exact rules')
            broad=api('/api/categories/import',{'kind':'website','text':'*.dropbox.*\n*documentcloud*'})
            assert not broad['errors'] and all(m['type']=='host_glob' for m in broad['members'])
            check=api('/api/categories/match',{'members':broad['members'],'urls':['https://www.dropbox.com/','https://documentcloud.adobe.com/','https://example.test/documentcloud']})
            assert all(not hit['native_covered'] for row in check['results'] for hit in row['matches']) and not check['results'][2]['matches']
            assert check['results'][0]['matches'] and check['results'][1]['matches']
            from playwright.sync_api import sync_playwright,expect
            errors=[]
            with sync_playwright() as pw:
                browser=pw.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,chromium_sandbox=True)
                try:
                    page=browser.new_page(viewport={'width':1500,'height':1050},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(url);page.locator('[name=username]').fill('fixture-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    page.get_by_role('heading',name='安全總覽',exact=True).wait_for();page.locator('nav [data-page=categories]').click();page.locator('[data-category-id="'+c['id']+'"]').click()
                    expect(page.locator('#workspace tbody tr')).to_have_count(50)
                    page.locator('[data-category-action=match]').click();page.locator('#category-match [name=urls]').fill('https://s0.example.com/\nhttps://s0.example.com.evil.test/')
                    page.locator('#category-match button').click();expect(page.locator('#category-match-result')).to_contain_text('列入原生管制範圍');expect(page.locator('#category-match-result')).to_contain_text('未命中此類別')
                    page.screenshot(path=str(ROOT/'evidence'/('server-upgrade-0462-ui-'+probe+'.png')),full_page=True)
                    assert not errors,errors
                finally:browser.close()
            report['page_errors']=errors
            report['checks'].append('actual frozen category UI and matching API preserve wildcard input, exact host boundary and coverage without navigation or employee profile')
            # Real endpoint ZIP download, but never execute its installer.
            await_bundle('new')
            blob=api('/api/endpoint-package',{})
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                payload=json.loads(z.read('endpoint-files.json'));assert payload['version']=='0.4.62','downloaded endpoint version'
                assert sha(new/'GuardDesk.exe')==hashlib.sha256(z.read('GuardDesk/GuardDesk.exe')).hexdigest(),'downloaded EXE hash'
                assert all(hashlib.sha256(z.read('GuardDesk/'+name)).hexdigest()==value for name,value in payload['files'].items()),'downloaded runtime manifest'
                # Crypto libraries legitimately contain format-name strings.
                # Reject actual PEM payloads, not the words PRIVATE KEY alone.
                private_pem=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{100,}')
                assert not any(n.endswith(('.key','.sqlite3')) or private_pem.search(z.read(n)) for n in z.namelist() if not n.endswith('/')),'unexpected private key/database payload'
            assert b'function categoriesPage' in api('/category_library_ui.js')
            report['checks'].append('actual authenticated endpoint ZIP has 0.4.62 exact EXE/runtime hashes and no private key or database')
            report.update(passed=True,exe_sha256=sha(new/'GuardDesk.exe'),endpoint_zip_sha256=hashlib.sha256(blob).hexdigest(),endpoint_zip_bytes=len(blob),prior_version='0.4.61',original_config_unchanged=True)
            stop()
    except Exception as exc:
        report['failure']=type(exc).__name__+': '+str(exc)[:1500]
        report['failure_line']=traceback.extract_tb(exc.__traceback__)[-1].lineno
    finally:
        if process is not None and process.poll() is None:process.terminate();process.wait(timeout=15)
        path=ROOT/'evidence'/('server-upgrade-0462-'+probe+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'evidence':str(path),**report},ensure_ascii=False))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
