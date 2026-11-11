"""Isolated Chromium profile + actual native EXE, with HKCU values restored.

Only this product's per-user native host keys are touched. Browser profiles and
credentials of the user's installed Chrome/Edge are never opened.
"""
import json
import os
import sys
import tempfile
import threading
import time
import hashlib
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.agent import Agent,private_write
from guarddesk import __version__
from guarddesk.browser_host import extension_id,HOST_NAME,register
from playwright.sync_api import sync_playwright
import winreg


def main():
    root=Path(__file__).resolve().parents[1]
    exe=root/'dist/GuardDesk/GuardDesk.exe'
    keys=[(r'Software\GuardDesk','AgentConfig'),(r'Software\Google\Chrome\NativeMessagingHosts'+'\\'+HOST_NAME,''),(r'Software\Microsoft\Edge\NativeMessagingHosts'+'\\'+HOST_NAME,'')]
    previous=[]
    for name,value in keys:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,name) as key:
                try:original=winreg.QueryValueEx(key,value)
                except FileNotFoundError:original=None
            previous.append((True,original))
        except FileNotFoundError:previous.append((False,None))
    if any(value is not None for existed,value in previous[1:]):
        raise OSError('An existing Chrome/Edge Native Host is registered; use a separate test account instead of replacing a live enrollment')
    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'<!doctype html><title>GuardDesk isolated navigation test</title><h1>Audit test</h1>'
            self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(*args):pass
    upstream=ThreadingHTTPServer(('127.0.0.1',0),Page)
    threading.Thread(target=upstream.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(dir=root/'runtime') as temporary:
            scratch=Path(temporary);watch=scratch/'documents';watch.mkdir()
            config=scratch/'runtime/agent/config.json'
            private_write(config,{'server':'http://127.0.0.1:1','token':'isolated-offline-token','device_id':'isolated-browser-test','watch':str(watch)})
            agent=Agent(config)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,keys[0][0]) as key:winreg.SetValueEx(key,'AgentConfig',0,winreg.REG_SZ,str(config))
            # Explicit test-account-only registration, not automatic startup.
            # Startup must reject uninstalled disposable configs.
            original=config.read_bytes()
            register(config,exe,enable_proxy=False)
            assert config.read_bytes()==original,'automatic registration changed proxy/config'
            with sync_playwright() as p:
                extension=str(root/'browser-extension')
                context=p.chromium.launch_persistent_context(str(scratch/'browser-profile'),channel='chromium',headless=True,args=['--disable-extensions-except='+extension,'--load-extension='+extension])
                try:
                    worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
                    assert extension_id() in worker.url,worker.url
                    # A Worker object exists before onInstalled/native handshake
                    # completes. Navigate only after this fresh install is ready.
                    ready_deadline=time.monotonic()+20
                    while time.monotonic()<ready_deadline:
                        status=worker.evaluate('async()=>globalThis.chrome?.storage?.local ? (await chrome.storage.local.get({host_status:{}})).host_status : {}')
                        if status.get('connected'):break
                        time.sleep(.1)
                    else:raise AssertionError('Native host startup did not complete: '+json.dumps(status))
                    page=context.new_page();page.goto(f'http://127.0.0.1:{upstream.server_port}/visited?offline=1')
                    deadline=time.monotonic()+20
                    rows=[]
                    while time.monotonic()<deadline:
                        with agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                        if any('/visited?offline=1' in row['details'].get('url','') for row in rows):break
                        time.sleep(.15)
                    if not any(row['kind']=='web.navigation' and '/visited?offline=1' in row['details'].get('url','') for row in rows):
                        diagnostic=worker.evaluate('async()=>await chrome.storage.local.get(null)')
                        raise AssertionError('Native navigation was not persisted: '+json.dumps(diagnostic))
                    assert Agent(config).queue_status()['pending']>0
                    from guarddesk.document_audit import browser_status
                    observed=browser_status(agent)
                    assert observed['status']=='connected_limited',observed
                    assert observed['browsers'][0]['extension_version']=='0.4.0',observed
                finally:context.close()
            report={'passed':True,'version':__version__,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'checks':['isolated Chromium loads unpacked extension','explicit test-account registration preserves config/proxy bytes','stable extension id matches native allowlist','real browser navigation reaches frozen native host','extension version handshake persisted with bounded readiness','URL and time persisted while server is offline','outbox survives Agent reopen','original Chrome/Edge/GuardDesk HKCU values restored in finally'],'extension_id':extension_id(),'limits':['Explicit test-account registration; automatic installed-only scope guard tested separately','Owned Chromium profile, not managed corporate extension installation']}
    finally:
        upstream.shutdown();upstream.server_close()
        for (name,value),(existed,original) in zip(keys,previous):
            if original is not None:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER,name) as key:winreg.SetValueEx(key,value,0,original[1],original[0])
            else:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,name,0,winreg.KEY_SET_VALUE) as key:winreg.DeleteValue(key,value)
                except FileNotFoundError:pass
            if not existed:
                try:winreg.DeleteKey(winreg.HKEY_CURRENT_USER,name)
                except FileNotFoundError:pass
    (root/f'evidence/extension-native-smoke-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()
