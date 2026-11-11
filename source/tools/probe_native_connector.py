"""Owned-profile Chrome connector interop probe; never changes machine policy.

Uses Chrome's local_user_agent TEST provider only inside a new disposable
profile. Not a production deployment or a substitute for provider registration.
Only self-generated non-sensitive fixture paths are accepted as requests.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ntpath
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guarddesk.native_connector import (ConnectorInbox, request_envelope,
    attachment_details, owned_browser_peer)


def fields(data):
    if len(data) > 32768:
        raise ValueError('Probe message exceeds bound')
    cursor = 0
    def varint():
        nonlocal cursor
        value = 0
        for shift in range(0, 70, 7):
            if cursor >= len(data):
                raise ValueError('Truncated protobuf varint')
            byte = data[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError('Invalid protobuf varint')
    output = {}
    count = 0
    while cursor < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not number or count >= 256:
            raise ValueError('Invalid protobuf fields')
        count += 1
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else 8 if wire == 1 else 4
            if length > len(data)-cursor:
                raise ValueError('Truncated protobuf field')
            value = data[cursor:cursor+length]
            cursor += length
        else:
            raise ValueError('Unsupported protobuf group')
        output.setdefault(number, []).append(value)
    return output


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def blob(number, value):
    return varint(number*8+2)+varint(len(value))+value


def allow(token):
    # AgentToChrome.response: token + successful dlp verdict, no blocking rule.
    result = blob(1, b'dlp') + varint(2*8) + varint(1)
    return blob(1, blob(1, token) + blob(4, result))


def release_owned_mouse():
    """Release the synthetic left button even if the owned OLE helper timed out."""
    class Mouse(ctypes.Structure):
        _fields_ = [('dx',w.LONG),('dy',w.LONG),('data',w.DWORD),
                    ('flags',w.DWORD),('time',w.DWORD),('extra',ctypes.c_size_t)]
    class Payload(ctypes.Union):
        _fields_ = [('mouse',Mouse),('padding',ctypes.c_byte*32)]
    class Input(ctypes.Structure):
        _fields_ = [('kind',w.DWORD),('payload',Payload)]
    user = ctypes.WinDLL('user32',use_last_error=True)
    user.SendInput.argtypes = [w.UINT,ctypes.POINTER(Input),ctypes.c_int]
    event = Input()
    event.payload.mouse.flags = 4  # MOUSEEVENTF_LEFTUP, paired with our helper.
    if user.SendInput(1,ctypes.byref(event),ctypes.sizeof(event)) != 1:
        raise ctypes.WinError(ctypes.get_last_error())


class Probe:
    def __init__(self, fixture):
        from guarddesk.document_context import token_sid, kernel_api
        self.kernel = kernel_api()
        adv = ctypes.WinDLL('advapi32', use_last_error=True)
        adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        token = w.HANDLE()
        if not adv.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid = token_sid(token)
        finally:
            self.kernel.CloseHandle(token)
        self.name = r'\\.\pipe\path_user.' + sid
        self.sid = sid
        self.fixture = str(fixture)
        self.allowed = set()
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.listening = threading.Event()
        self.records = []
        self.acks = 0
        self.connected = 0
        self.errors = []
        self.peer = None
        self.verify_peer = None
        self.inbox = ConnectorInbox()
        self.messages = 0
        self.cancel_messages = 0
        self.rejected_nonfixture = 0
        self.thread = threading.Thread(target=self.run, daemon=True, name='Owned connector probe')

    def pipe(self):
        class Security(ctypes.Structure):
            _fields_ = [('size', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
        adv = ctypes.WinDLL('advapi32', use_last_error=True)
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
        descriptor = w.LPVOID()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;GA;;;SY)(A;;GA;;;'+self.sid+')', 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            security = Security(ctypes.sizeof(Security), descriptor, False)
            # Duplex, overlapped, first instance; message-mode, reject remote.
            handle = self.kernel.CreateNamedPipeW(self.name, 3|0x40000000|0x80000, 4|2|8,
                                                 1, 32768, 32768, 0, ctypes.byref(security))
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            return handle
        finally:
            self.kernel.LocalFree(descriptor)

    def run(self):
        import _winapi
        from multiprocessing.connection import PipeConnection
        try:
            while not self.stop.is_set():
                handle = self.pipe()
                connection = None
                self.listening.set()
                try:
                    pending = _winapi.ConnectNamedPipe(handle, overlapped=True)
                    while _winapi.WaitForSingleObject(pending.event, 50) != 0:
                        if self.stop.is_set():
                            pending.cancel()
                            pending.GetOverlappedResult(True)
                            return
                    pending.GetOverlappedResult(True)
                    peer = w.ULONG()
                    if not self.kernel.GetNamedPipeClientProcessId(handle, ctypes.byref(peer)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    deadline = time.monotonic()+10
                    while not self.ready.wait(.05) and time.monotonic()<deadline:
                        if self.stop.is_set():
                            return
                    if not self.ready.is_set() or peer.value not in self.allowed:
                        raise OSError('Probe rejected client outside owned browser PID')
                    if self.verify_peer() != self.peer:
                        raise OSError('Owned browser process identity changed')
                    self.connected += 1
                    connection = PipeConnection(handle)
                    handle = None
                    for _ in range(256):
                        while not connection.poll(.05):
                            if self.stop.is_set():
                                return
                        raw = connection.recv_bytes(32768)
                        message = fields(raw)
                        self.messages += 1
                        if 3 in message:
                            self.cancel_messages += 1
                        if 2 in message:
                            self.acks += 1
                        request, verdict = request_envelope(raw)
                        if request is None:
                            continue
                        connection.send_bytes(verdict)
                        value = attachment_details(request,self.peer)
                        details = value[0]
                        if ntpath.normcase(ntpath.normpath(details['source_path'])) != ntpath.normcase(ntpath.normpath(self.fixture)):
                            self.rejected_nonfixture += 1
                            continue
                        self.inbox.offer(value)
                        self.records.append(details)
                except (EOFError, BrokenPipeError):
                    pass
                finally:
                    if connection:
                        connection.close()
                    if handle:
                        self.kernel.CloseHandle(handle)
        except BaseException as exc:
            self.errors.append(type(exc).__name__+': '+str(exc)[:200])
            self.listening.set()

    def close(self):
        self.stop.set()
        self.thread.join(3)
        if self.thread.is_alive():
            raise OSError('Owned probe thread failed to stop')


def main():
    import faulthandler
    trace = (ROOT/'runtime/native-connector-probe-stack.log').open('w',encoding='utf-8')
    faulthandler.dump_traceback_later(20, file=trace)
    def stage(value):
        print('PROBE_STAGE '+value, flush=True)
    from playwright.sync_api import sync_playwright
    from guarddesk.server_setup import secure_directory
    folder = ROOT/'runtime'/('native-connector-probe-'+uuid.uuid4().hex)
    stage('create_owned_profile')
    secure_directory(folder)
    profile = folder/'profile'
    (profile/'Default').mkdir(parents=True)
    fixture = folder/'owned-fixture.txt'
    fixture.write_text('GuardDesk synthetic, non-sensitive connector fixture\n', encoding='utf-8')
    preferences = {'enterprise_connectors': {'on_file_attached': [{'service_provider':'local_user_agent',
                    'enable':[{'url_list':['*'],'tags':['dlp']}], 'block_until_verdict':0,
                    'default_action':'allow', 'block_large_files':False, 'block_password_protected':False}]}}
    (profile/'Default/Preferences').write_text(json.dumps(preferences), encoding='utf-8')
    probe = Probe(fixture)
    probe.thread.start()
    if not probe.listening.wait(3) or probe.errors:
        raise OSError('Unable to start owned probe: '+str(probe.errors))
    result = {'scope':'isolated_profile_test_provider_only', 'employee_profile_modified':False,
              'registry_modified':False, 'production_provider_approved':False}
    mode = 'interactive' if '--interactive' in sys.argv else 'cdp_drag' if '--cdp-drag' in sys.argv else 'picker' if '--picker' in sys.argv else 'ole'
    result['mode'] = mode
    result['browser_family'] = 'edge' if '--edge' in sys.argv else 'chrome'
    helper_process = None
    helper_forced = False
    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'<style>body{margin:0;min-height:100vh;background:#eef8f7}input{font-size:22px}</style><h1>GuardDesk owned native connector test</h1><input type=file id=f><script>document.ondragover=e=>e.preventDefault();document.ondrop=e=>{e.preventDefault();window.received=[...e.dataTransfer.files].map(f=>f.name);document.title="Dropped "+e.dataTransfer.files.length};f.onchange=()=>document.title="Selected "+f.files.length</script>'
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self,*args):
            pass
    receiver = ThreadingHTTPServer(('127.0.0.1',0),Receiver)
    receiver.daemon_threads = True
    receiver_thread = threading.Thread(target=receiver.serve_forever,daemon=True)
    receiver_thread.start()
    receiver_url = 'http://127.0.0.1:'+str(receiver.server_port)+'/'
    result['receiver_url'] = receiver_url
    try:
        stage('start_test_driver')
        with sync_playwright() as pw:
            stage('start_owned_browser')
            executable = (Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe'
                          if '--edge' in sys.argv else Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'))
            stderr_log = (ROOT/'runtime/native-connector-owned-browser.stderr.log').open('wb')
            process = subprocess.Popen([str(executable), *(['--headless=new'] if '--cdp-drag' in sys.argv else []), '--remote-debugging-port=0',
                '--remote-debugging-address=127.0.0.1','--user-data-dir='+str(profile),
                '--disable-gpu','--force-renderer-accessibility','--window-position=30,30','--window-size=920,700','--no-first-run','--no-default-browser-check','about:blank'],
                stdout=subprocess.DEVNULL,stderr=stderr_log,creationflags=subprocess.CREATE_NO_WINDOW)
            browser = None
            try:
                stage('wait_owned_browser_transport')
                port_file = profile/'DevToolsActivePort'
                deadline = time.monotonic()+15
                while not port_file.is_file() and time.monotonic()<deadline:
                    if process.poll() is not None:
                        raise OSError('Owned Chrome exited before test transport')
                    time.sleep(.05)
                port, endpoint = port_file.read_text(encoding='utf-8').splitlines()[:2]
                browser = pw.chromium.connect_over_cdp('ws://127.0.0.1:'+port+endpoint)
                stage('owned_browser_connected')
                context = browser.contexts[0]
                stage('query_owned_browser_pid')
                # Chrome is launched directly with this fresh user-data-dir;
                # accept only its original OS process, never a name match.
                probe.allowed = {process.pid}
                probe.peer = owned_browser_peer(process._handle,process.pid,str(executable))
                probe.verify_peer = lambda:owned_browser_peer(process._handle,process.pid,str(executable))
                probe.ready.set()
                stage('create_owned_test_page')
                page = context.new_page()
                console = []
                page.on('console',lambda event:console.append({'type':event.type,'text':event.text[:300]}) if len(console)<16 else None)
                page.goto(receiver_url)
                page.bring_to_front()
                stage('prepare_synthetic_input')
                page.locator('#f').set_input_files(str(fixture))
                if '--read-control' in sys.argv:
                    # Explicitly read only our tiny, self-generated fixture in
                    # the test page to distinguish file I/O from attachment.
                    result['baseline_file_read_bytes'] = page.evaluate('f.files[0].arrayBuffer().then(data=>data.byteLength)')
                page.wait_for_timeout(500)
                result['automation_input_requests'] = len(probe.records)
                owned_pid = next(iter(probe.allowed))
                picker = '--picker' in sys.argv
                if mode == 'interactive':
                    page.locator('#f').set_input_files([])
                    page_cdp = context.new_cdp_session(page)
                    page_cdp.send('Page.setInterceptFileChooserDialog', {'enabled':False})
                    print('OWNED_FIXTURE '+str(fixture),flush=True)
                    print('OWNED_BROWSER_PID '+str(owned_pid),flush=True)
                    stage('wait_actual_desktop_file_input')
                    deadline = time.monotonic()+600
                    while not probe.records and not probe.errors and time.monotonic()<deadline:
                        page.wait_for_timeout(100)
                    page.wait_for_timeout(1000)
                    result.update(browser_version=browser.version,
                                  page_received=page.evaluate('[...f.files].map(f=>f.name)'),
                                  native_helper={'mode':'desktop_input','interception':False})
                    continue_probe = False
                elif '--cdp-drag' in sys.argv:
                    stage('browser_drag_input')
                    session = context.new_cdp_session(page)
                    payload = {'items':[], 'files':[str(fixture)], 'dragOperationsMask':1}
                    for kind in ['dragEnter','dragOver','drop']:
                        session.send('Input.dispatchDragEvent', {'type':kind,'x':300,'y':300,'data':payload})
                    page.wait_for_timeout(3000)
                    result.update(browser_version=browser.version, page_received=page.evaluate('window.received||[]'),
                                  native_helper={'mode':'owned_browser_drag_input','physical_input':False})
                    continue_probe = False
                else:
                    continue_probe = True
                if not continue_probe:
                    result.update(connected=probe.connected, requests=probe.records, acks=probe.acks, errors=probe.errors)
                    return result
                helper = ROOT/'runtime/file-handoff-build'/('GuardDeskOwnedFilePicker.exe' if picker else 'GuardDeskOwnedOleDrop.exe')
                dropped = subprocess.Popen([str(helper),str(owned_pid),str(fixture), *(['--cancel'] if '--cancel-drag' in sys.argv else [])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                helper_process = dropped
                stage('run_native_file_picker' if picker else 'run_real_ole_drag')
                if picker:
                    page.locator('#f').set_input_files([])
                    page_cdp = context.new_cdp_session(page)
                    page_cdp.send('Page.setInterceptFileChooserDialog', {'enabled':False})
                    page_cdp.send('Page.enable', {'enableFileChooserOpenedEvent':True})
                    result['chooser_events'] = []
                    page_cdp.on('Page.fileChooserOpened',lambda event:result['chooser_events'].append({'mode':event.get('mode')}))
                    page.locator('#f').click(timeout=3000)
                deadline = time.monotonic()+10
                while dropped.poll() is None and time.monotonic()<deadline:
                    page.wait_for_timeout(50)
                if dropped.poll() is None:
                    helper_forced = True
                    dropped.terminate()
                    dropped.wait(timeout=3)
                    out, err = dropped.communicate()
                    result['ole_timeout_diagnostic'] = err.decode(errors='replace')[:2400]
                    raise OSError('Owned OLE test exceeded deadline')
                stdout, stderr = dropped.communicate()
                result['native_helper'] = {'mode':'picker' if picker else 'ole', 'exit_code': dropped.returncode, 'result':stdout.decode(errors='replace')[:1000],
                                        'error':stderr.decode(errors='replace')[:200]}
                page.wait_for_timeout(3000)
                result['page_received'] = page.evaluate('[...document.querySelector("#f").files].map(f=>f.name)' if picker else 'window.received||[]')
                if '--discard-after-drop' in sys.argv or '--discard-after-attach' in sys.argv:
                    page.evaluate('window.received=[];document.querySelector("#f").value=""')
                    result['page_discarded_after_attachment'] = True
                result['browser_version'] = browser.version
                result['console'] = console
                result.update(connected=probe.connected, requests=probe.records, acks=probe.acks, errors=probe.errors)
            except Exception as exc:
                result['failure'] = type(exc).__name__+': '+str(exc)[:500]
                print('PROBE_FAILURE '+result['failure'],flush=True)
            finally:
                if helper_process is not None:
                    if helper_process.poll() is None:
                        helper_forced = True
                        helper_process.terminate()
                        helper_process.wait(timeout=3)
                    # Normal helper exit releases its own synthetic button.
                    # Do not send a redundant LEFTUP seconds later (or after a
                    # precondition refusal) when the user may be dragging.
                    if mode == 'ole' and helper_forced:
                        release_owned_mouse()
                        result['synthetic_mouse_released'] = True
                stage('close_owned_browser')
                # Connected-browser close in the installed Playwright version
                # can wait indefinitely after Chrome exits. Keep ownership on
                # the original Popen HANDLE and let the driver context stop.
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                stderr_log.close()
                result['owned_browser_exit'] = process.returncode
    finally:
        receiver.shutdown()
        receiver.server_close()
        receiver_thread.join(2)
        probe.close()
        result.update(connected=probe.connected, requests=probe.records, acks=probe.acks, errors=probe.errors)
        result.update(protocol_messages=probe.messages,cancel_messages=probe.cancel_messages,
                      rejected_nonfixture=probe.rejected_nonfixture)
        if '--bridge' in sys.argv:
            # Explicitly isolated Agent/center fixture; never employee config.
            sys.path.insert(0,str(ROOT/'tests'))
            import test_system
            from guarddesk.file_handoff import HandoffQueue
            from urllib.parse import urlencode
            case = test_system.SystemTest('runTest')
            case.setUp()
            agent = None
            try:
                agent,did,_ = case.make_agent()
                agent.heartbeat()
                agent.config['audit_watch'] = str(folder)
                queue = HandoffQueue(agent,experimental=True)
                result['bridge_admission'] = probe.inbox.drain(queue)
                queue.flush()
                agent.flush()
                events = case.api('/api/events?'+urlencode({'device':did,'category':'documents','kind':'file.web_handoff'}))
                result['bridge_center_events'] = events['total']
                result['bridge_exact_details'] = bool(probe.records) and sorted([e['details'] for e in events['items']],key=lambda d:d['request_token_hash']) == sorted(probe.records,key=lambda d:d['request_token_hash'])
            finally:
                if agent:agent.close_collectors()
                case.tearDown()
        faulthandler.cancel_dump_traceback_later()
        trace.close()
        result['capture_verified'] = bool(probe.records) and not result.get('failure') and not probe.errors
        result['canceled_before_drop'] = '--cancel-drag' in sys.argv
        result['case_passed'] = result['capture_verified'] if not result['canceled_before_drop'] else (
            probe.connected > 0 and not result.get('failure') and not probe.errors and not probe.records
            and not result.get('page_received') and result.get('native_helper',{}).get('exit_code') == 0)
        if '--bridge' in sys.argv:
            result['bridge_verified'] = bool(probe.records) and result.get('bridge_exact_details') is True and result.get('bridge_center_events') == len(probe.records)
            result['case_passed'] = result['case_passed'] and (result.get('bridge_center_events') == 0
                if result['canceled_before_drop'] else result['bridge_verified'])
        if '--read-control' in sys.argv:
            result['case_passed'] = result['case_passed'] and result.get('baseline_file_read_bytes',0) > 0 and result.get('automation_input_requests') == 0
        # Each run is immutable evidence; a handshake is never a capture pass.
        output = ROOT/'evidence'/('native-connector-'+mode+'-'+uuid.uuid4().hex+'.json')
        output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'evidence':str(output),'result':result},ensure_ascii=False),flush=True)
    return result


if __name__ == '__main__':
    sys.exit(0 if main().get('case_passed') else 2)
