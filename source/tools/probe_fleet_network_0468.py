"""Real frozen Server + browser, synthetic inventory only; no installed Agent."""
import hashlib,json,secrets,socket,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.server_setup import secure_directory
from guarddesk.store import Store,canonical,digest
from playwright.sync_api import sync_playwright,expect


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe';target=ROOT/'evidence/fleet-network-frozen-0.4.68.json'
    assert not target.exists()
    info=subprocess.run([str(exe),'component-info'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    assert info.returncode==0 and json.loads(info.stdout)['version']=='0.4.68'
    report=dict(version='0.4.68',passed=False,company_changed=False,synthetic_endpoints=250,
        exe_sha256=sha(exe),queries=[],page_errors=[])
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='fleet-search-owned-') as tmp:
        root=Path(tmp);secure_directory(root,allow_empty=True)
        store=Store(root/'control.sqlite3');password=secrets.token_urlsafe(24);store.add_user('owned-search',password)
        with store.connect() as db:
            for i in range(250):
                assets={'user_accounts':['OWNED\\tester'],'network_addresses':[f'192.0.2.{i+1}','2001:db8::7'],
                    'mac_address':'AA:BB:CC:DD:EE:FF' if i==249 else f'02:00:00:00:00:{i:02X}'}
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory,last_address) VALUES (?,?,?,?,?,?,?)',
                    (f'owned-{i}',digest('owned-token-'+str(i)),f'Owned-{i:03d}','Owned lab',time.time(),canonical(assets),'198.51.100.9'))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        url=f'http://127.0.0.1:{port}';client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with (root/'server.log').open('w',encoding='utf-8') as log:
            server=subprocess.Popen([str(exe),'serve','--db',str(store.path),'--host','127.0.0.1','--port',str(port)],
                cwd=root,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            try:
                for attempt in range(150):
                    if server.poll() is not None:raise AssertionError('Owned frozen Server stopped')
                    try:
                        with client.open(url+'/api/health',timeout=1) as response:
                            if response.status==200:break
                    except OSError:time.sleep(.1)
                else:raise AssertionError('Owned frozen Server health timeout')
                with sync_playwright() as p:
                    browser=p.chromium.launch(channel='chromium',headless=True)
                    try:
                        page=browser.new_page(viewport={'width':1640,'height':1080},locale='zh-TW',timezone_id='Asia/Taipei')
                        page.on('pageerror',lambda error:report['page_errors'].append(str(error)))
                        page.goto(url);page.locator('[name=username]').fill('owned-search');page.locator('[name=password]').fill(password)
                        page.locator('#login-form button').click();page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
                        page.locator('nav [data-page=devices]').click();field=page.locator('#fleet-search');field.wait_for()
                        expect(field).to_have_attribute('placeholder','搜尋端點、部門、Windows 帳號、IP 或 MAC')
                        expect(page.locator('.fleet-table tbody tr')).to_have_count(50)
                        requests=[];page.on('request',lambda request:requests.append(urlsplit(request.url).path))
                        def search(query,total):
                            def matching(response):
                                return urlsplit(response.url).path=='/api/fleet' and parse_qs(urlsplit(response.url).query).get('q')==[query]
                            started=time.monotonic()
                            with page.expect_response(matching) as pending:field.fill(query)
                            response=pending.value;assert response.ok
                            packet=response.json();assert packet['total']==total,(query,packet['total'])
                            expect(page.locator('.fleet-table tbody tr')).to_have_count(min(50,total))
                            report['queries'].append({'query':query,'total':total,'milliseconds':round((time.monotonic()-started)*1000,2)})
                            return packet
                        for query in ('192.0.2.250','aa:bb:cc:dd:ee:ff','AA-BB-CC-DD-EE-FF','aabbccddeeff','aabb.ccdd.eeff','BB-CC-DD'):
                            packet=search(query,1);assert packet['items'][0]['id']=='owned-249'
                            expect(page.locator('.fleet-table')).to_contain_text('Owned-249')
                        screenshot=ROOT/'evidence/fleet-network-search-0.4.68.png';page.screenshot(path=str(screenshot),full_page=True)
                        first=search('192.0.2.',250)
                        with page.expect_response(lambda response:urlsplit(response.url).path=='/api/fleet' and parse_qs(urlsplit(response.url).query).get('offset')==['50']) as pending:
                            page.locator('[data-fleet-page="1"]').click()
                        second=pending.value.json();assert second['total']==250 and len(second['items'])==50
                        assert not {d['id'] for d in first['items']}&{d['id'] for d in second['items']}
                        search('2001:0DB8:0:0:0:0:0:7',250);search('198.51.100.9',250)
                        field.focus();node=field.element_handle();page.evaluate('async()=>await refresh({automatic:true})')
                        assert node.evaluate('node=>node.isConnected') and field.input_value()=='198.51.100.9'
                        assert '/api/events' not in requests and '/api/device-detail' not in requests,requests
                        assert not report['page_errors'],report['page_errors']
                        served=page.request.get(url+'/management.js');assert served.ok
                        report.update(passed=True,pages_do_not_overlap=True,search_draft_preserved=True,no_history_or_detail_fetch=True,
                            management_js_sha256=hashlib.sha256(served.body()).hexdigest(),screenshot=screenshot.relative_to(ROOT).as_posix(),
                            scope='Actual frozen Server and owned Chromium profile; synthetic 250 endpoint inventory, not company field acceptance')
                        assert report['management_js_sha256']==sha(ROOT/'guarddesk/static/management.js')
                    finally:browser.close()
            finally:
                if server.poll() is None:server.terminate()
                server.wait(timeout=15)
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
