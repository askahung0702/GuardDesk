"""Thread-specific native receiver research in a controller-owned browser only.

No SDK provider, extension, employee profile, machine policy or file upload.
CDP supplies test-page ground truth only; paths/origins must come from the DLL.
"""
import ctypes as c
from ctypes import wintypes as w
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mmap
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guarddesk.file_handoff import NativeHandoff
from guarddesk.native_connector import owned_browser_peer
from guarddesk.server_setup import secure_directory
from tools.probe_native_connector import release_owned_mouse


class Shared(c.Structure):
    _fields_ = [('magic',w.DWORD),('size',w.DWORD),('browser_pid',w.DWORD),
        ('controller_pid',w.DWORD),('browser_created',c.c_ulonglong),
        ('profile',w.WCHAR*1024),('fixture',w.WCHAR*4096),
        ('allowed_origins',(w.WCHAR*512)*2),
        *[(name,w.LONG) for name in ('state','error','attached','detached','count',
                                    'rejected','origin_failed','origin_stage')],
        ('callback_max_us',c.c_ulonglong),('enter_max_us',c.c_ulonglong),
        ('origin_max_us',c.c_ulonglong),('lost',c.c_ulonglong),
        ('records',NativeHandoff.Record*8)]


DROP_RECORDING_CONTRACT = {
    'version':'2026-10-28-accepted-drop',
    'product_action':'website_upload',
    'trigger':'browser_accepted_drop',
    'network_completion_required':False,
    'final_submit_required':False,
    'page_upload_handler_required':False,
    'remove_after_drop_retracts_record':False,
    'correct_source_path_and_receiving_origin_required':True,
}


def drop_case_passed(case_name, helper_exit, helper_stdout, records, received, *,
                     fixture_path, expected_origin, expected_pid, restored=False,
                     removal_preserved=True):
    """Evaluate the user's accepted-drop contract, never network completion.

    Page filenames are diagnostic ground truth, not a requirement for a drop
    into a page without an upload handler. Actual native acceptance, full path,
    receiving origin and receiver PID remain mandatory. This is test policy,
    not a deployable browser event source or source authentication boundary.
    """
    positive = {'accepted_drop','second_tab','cross_origin_iframe','aria_document_spoof',
                'normal_after_spoof','default_navigation_control','accepted_then_removed'}
    if case_name not in positive | {'cancel_before_drop','restored_receiver'}:
        raise ValueError('Unknown owned drop case')
    if helper_exit != 0:return False
    try:
        helper = json.loads(helper_stdout)
    except (ValueError,TypeError):return False
    if not isinstance(helper,dict) or helper.get('scope') != 'owned_real_ole_drag':return False
    if any(type(helper.get(key)) is not int for key in ('target_pid','hresult','effect')):return False
    if helper['target_pid'] != expected_pid:return False
    if case_name == 'cancel_before_drop':
        return helper['hresult'] == 262401 and helper['effect'] == 0 and not received and not records
    if helper['hresult'] != 262400 or not 1 <= helper['effect'] <= 7:return False
    if case_name == 'restored_receiver':
        return restored and received == [ntpath.basename(fixture_path)] and not records
    if len(records) != 1:return False
    row = records[0]
    matched = (row.get('path') == fixture_path and row.get('origin') == expected_origin and
               type(row.get('process_id')) is int and row['process_id'] == expected_pid and
               type(row.get('file_index')) is int and row['file_index'] == 0 and
               type(row.get('file_count')) is int and row['file_count'] == 1)
    return bool(matched and (case_name != 'accepted_then_removed' or removal_preserved))


def main():
    from playwright.sync_api import sync_playwright
    dll_path = ROOT/'runtime/owned-browser-drop-build/GuardDeskOwnedBrowserDrop.dll'
    build = json.loads((dll_path.parent/'build.json').read_text(encoding='utf-8'))
    for name,digest in build['sources'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('Stale research build source: '+name)
    for path,digest in ((dll_path,build['dll_sha256']),
            (dll_path.parent/'GuardDeskOwnedBrowserOleSource.exe',build['helper_sha256'])):
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:raise RuntimeError('Stale research artifact')
    probe_id = uuid.uuid4().hex
    work = ROOT/'runtime'/('owned-native-drop-'+probe_id)
    secure_directory(work)
    profile = work/'profile'
    profile.mkdir()
    fixture = work/'owned-fixture.txt'
    fixture.write_text('GuardDesk self-generated native receiver fixture.\n',encoding='utf-8')
    executable = (Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe'
                  if '--edge' in sys.argv else Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'))
    report = {'probe_id':probe_id,'scope':'owned_disposable_browser_native_drop_research',
        'evidence_semantics':'website_upload_at_browser_accepted_drop',
        'recording_contract':DROP_RECORDING_CONTRACT,
        'network_transfer_observed':False,
        'sdk_provider':False,'extension':False,'employee_profile_modified':False,
        'machine_policy_modified':False,'passed':False,'cases':[],
        'forced_accessibility':'--accessibility' in sys.argv,
        'dll_sha256':hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        'source_helper':'owned_large_window_click_source_only',
        'helper_sha256':hashlib.sha256((dll_path.parent/'GuardDeskOwnedBrowserOleSource.exe').read_bytes()).hexdigest()}
    user = c.WinDLL('user32',use_last_error=True)
    callback_type = c.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    user.EnumWindows.argtypes = [callback_type,w.LPARAM]
    user.EnumChildWindows.argtypes = [w.HWND,callback_type,w.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [w.HWND,c.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    user.IsWindowVisible.argtypes = [w.HWND]
    user.GetWindowRect.argtypes = [w.HWND,c.POINTER(w.RECT)]
    user.GetAncestor.argtypes = [w.HWND,w.UINT]
    user.GetAncestor.restype = w.HWND
    user.GetClassNameW.argtypes = [w.HWND,w.LPWSTR,c.c_int]
    user.GetWindowTextW.argtypes = [w.HWND,w.LPWSTR,c.c_int]
    user.GetPropW.argtypes = [w.HWND,w.LPCWSTR]
    user.GetPropW.restype = w.HANDLE
    user.SetWindowsHookExW.argtypes = [c.c_int,c.c_void_p,w.HINSTANCE,w.DWORD]
    user.SetWindowsHookExW.restype = w.HHOOK
    user.UnhookWindowsHookEx.argtypes = [w.HHOOK]
    user.RegisterWindowMessageW.argtypes = [w.LPCWSTR]
    user.RegisterWindowMessageW.restype = w.UINT
    user.SendMessageTimeoutW.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,c.POINTER(c.c_size_t)]
    user.SendMessageTimeoutW.restype = w.LPARAM
    kernel = c.WinDLL('kernel32',use_last_error=True)
    kernel.GlobalAddAtomW.argtypes = [w.LPCWSTR]
    kernel.GlobalAddAtomW.restype = w.ATOM
    kernel.GlobalDeleteAtom.argtypes = [w.ATOM]
    library = c.WinDLL(str(dll_path),winmode=0x1100)
    library.gd_owned_browser_shared_size.restype = w.DWORD
    report['shared_size'] = {'python':c.sizeof(Shared),'native':library.gd_owned_browser_shared_size()}
    if len(set(report['shared_size'].values())) != 1:
        raise RuntimeError('Research shared ABI mismatch')
    process = helper = mapping = hook = atom = target = None
    message = user.RegisterWindowMessageW('GuardDesk.OwnedBrowserDropProbe.v1')
    forced_helper = False
    second_origin = ''
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'<title>GuardDesk owned native drop test</title><style>body{margin:0;min-height:100vh;background:#eef8f7}</style><h1>GuardDesk owned native drop receiver</h1><p>Self-generated fixture only. No upload.</p><script>window.received=[];document.ondragover=e=>e.preventDefault();document.ondrop=e=>{e.preventDefault();received=[...e.dataTransfer.files].map(f=>f.name)}</script>'
            if self.path == '/framecontainer':
                body = ('<style>body{margin:0}iframe{width:100vw;height:100vh;border:0}</style><iframe src="'+second_origin+'/frame"></iframe>').encode()
            elif self.path == '/aria':
                body += b'<div role="document" aria-valuetext="http://untrusted.invalid/" style="position:fixed;inset:0">Owned ARIA document spoof control</div>'
            elif self.path == '/reject':
                body = b'<h1>Owned default browser navigation control</h1><p>No drop handler or file input.</p>'
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self,*args):pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    second_server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    second_server.daemon_threads = True
    threading.Thread(target=second_server.serve_forever,daemon=True).start()
    second_origin = 'http://127.0.0.1:'+str(second_server.server_port)
    origin = 'http://127.0.0.1:'+str(server.server_port)
    report['expected_origin'] = origin
    def snapshot():return Shared.from_buffer_copy(mapping[:])
    def status():
        value = snapshot()
        return {key:getattr(value,key) for key in ('state','error','attached','detached','count',
                    'rejected','origin_failed','origin_stage','callback_max_us','enter_max_us','origin_max_us','lost')}
    def send(command,argument=0):
        result = c.c_size_t()
        if not user.SendMessageTimeoutW(target,message,command,argument,2,2000,c.byref(result)):
            raise c.WinError(c.get_last_error())
    try:
        with (work/'browser.stderr.log').open('wb') as browser_log, sync_playwright() as pw:
            process = subprocess.Popen([str(executable),'--user-data-dir='+str(profile),
                '--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',
                '--disable-gpu','--no-first-run','--no-default-browser-check',
                '--window-position=30,30','--window-size=920,700',
                *(['--force-renderer-accessibility'] if '--accessibility' in sys.argv else []),
                'about:blank'],stdout=subprocess.DEVNULL,stderr=browser_log,
                creationflags=subprocess.CREATE_NO_WINDOW)
            port_file = profile/'DevToolsActivePort'
            deadline = time.monotonic()+15
            while not port_file.is_file() and time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Owned browser exited before CDP: '+str(process.returncode))
                time.sleep(.05)
            port, endpoint = port_file.read_text(encoding='utf-8').splitlines()[:2]
            browser = pw.chromium.connect_over_cdp('ws://127.0.0.1:'+port+endpoint)
            report['browser_version'] = browser.version
            peer = owned_browser_peer(process._handle,process.pid,str(executable))
            report['peer'] = {'pid':peer.pid,'created_filetime':peer.created_filetime,'session':peer.session,'image':peer.image}
            page = browser.contexts[0].pages[0]
            page.goto(origin+'/')
            page.bring_to_front()
            page.wait_for_timeout(500)
            if page.url != origin+'/':
                # Disposable Edge may surface its own sync/first-run page.
                # Never attach the receiver probe to a browser settings or
                # permission surface, and never dismiss that surface for it.
                raise RuntimeError('Owned test page changed before attachment: '+page.url)
            candidates = []
            @callback_type
            def visit(hwnd,_):
                pid = w.DWORD()
                tid = user.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value == process.pid and user.GetPropW(hwnd,'OleDropTargetInterface'):
                    candidates.append((hwnd,tid))
                return True
            roots = []
            @callback_type
            def root(hwnd,_):
                pid = w.DWORD()
                user.GetWindowThreadProcessId(hwnd,c.byref(pid))
                bounds = w.RECT()
                kind = c.create_unicode_buffer(128)
                user.GetClassNameW(hwnd,kind,len(kind))
                user.GetWindowRect(hwnd,c.byref(bounds))
                if (pid.value == process.pid and user.IsWindowVisible(hwnd) and
                    kind.value == 'Chrome_WidgetWin_1' and bounds.right-bounds.left >= 800
                    and bounds.bottom-bounds.top >= 600):roots.append(hwnd)
                return True
            user.EnumWindows(root,0)
            for hwnd in roots:
                visit(hwnd,0)
                user.EnumChildWindows(hwnd,visit,0)
            report['owned_drop_targets'] = len(candidates)
            if len(candidates) != 1:raise RuntimeError('Expected exactly one owned registered drop target')
            target, thread = candidates[0]
            name = 'Local\\GuardDesk-OwnedDrop-'+probe_id
            mapping = mmap.mmap(-1,c.sizeof(Shared),tagname=name)
            initial = Shared()
            initial.magic, initial.size = 0x47444f44,c.sizeof(Shared)
            initial.browser_pid, initial.controller_pid = process.pid,os.getpid()
            initial.browser_created = peer.created_filetime
            initial.profile, initial.fixture = str(profile),str(fixture)
            initial.allowed_origins[0].value = origin
            initial.allowed_origins[1].value = second_origin
            mapping[:] = bytes(initial)
            hook = user.SetWindowsHookExW(4,c.cast(library.gd_owned_browser_callwndproc,c.c_void_p),library._handle,thread)
            if not hook:raise c.WinError(c.get_last_error())
            atom = kernel.GlobalAddAtomW(name)
            if not atom:raise c.WinError(c.get_last_error())
            send(os.getpid(),atom)
            report['attached_status'] = status()
            if snapshot().state != 1:raise RuntimeError('Owned native target attachment failed')
            if '--inspect-hold' in sys.argv:
                # Only the exact roots already verified against our retained
                # Popen PID. Never inventory unrelated window contents.
                owned_windows=[]
                for hwnd in roots:
                    title=c.create_unicode_buffer(512)
                    user.GetWindowTextW(hwnd,title,len(title))
                    owned_windows.append({'hwnd':int(hwnd),'title':title.value})
                session_path=work/'owned-session.json'
                inspection={'scope':'owned_disposable_browser_native_drop_research','pid':process.pid,'continue_file':str(work/'continue-owned-test'),'origin':origin,'owned_windows':owned_windows,'attached_hwnd':int(target),'page_url':page.url}
                report['inspection']=inspection
                session_path.write_text(json.dumps(inspection),encoding='utf-8')
                print(json.dumps({'owned_session':str(session_path)}),flush=True)
                deadline=time.monotonic()+60
                while not (work/'continue-owned-test').exists() and time.monotonic()<deadline:
                    page.wait_for_timeout(100)
                if not (work/'continue-owned-test').exists():raise RuntimeError('Owned inspection interval ended without continuation')
            tests = [('cancel_before_drop',True,origin+'/',origin),('accepted_drop',False,origin+'/',origin)]
            if '--suite' in sys.argv:
                tests += [('accepted_then_removed',False,origin+'/',origin),
                          ('second_tab',False,second_origin+'/',second_origin),
                          ('cross_origin_iframe',False,origin+'/framecontainer',second_origin),
                          ('aria_document_spoof',False,origin+'/aria',origin),
                          ('normal_after_spoof',False,origin+'/',origin),
                          ('restored_receiver',False,origin+'/',origin)]
            if '--navigation-control' in sys.argv:
                tests = [('default_navigation_control',False,origin+'/reject',origin)]
            if '--case' in sys.argv:
                selected = sys.argv[sys.argv.index('--case')+1]
                tests = [item for item in tests if item[0] == selected]
                if not tests:raise ValueError('Unknown owned test case')
            for case_name,cancel,test_url,expected_origin in tests:
                if case_name == 'second_tab':page = browser.contexts[0].new_page()
                page.goto(test_url)
                page.bring_to_front()
                page.wait_for_timeout(700)
                if page.url != test_url:
                    raise RuntimeError('Owned test page changed before drop: '+page.url)
                received_frame = next((frame for frame in page.frames if frame.parent_frame),page.main_frame)
                received_frame.evaluate('window.received=[]')
                if case_name == 'restored_receiver':send(0)
                before = snapshot().count
                helper = subprocess.Popen([str(dll_path.parent/'GuardDeskOwnedBrowserOleSource.exe'),
                    str(process.pid),str(fixture),*(['--cancel'] if cancel else []),
                    '--target-window='+str(user.GetAncestor(target,2))],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
                deadline = time.monotonic()+12
                while helper.poll() is None and time.monotonic()<deadline:page.wait_for_timeout(50)
                if helper.poll() is None:
                    forced_helper = True
                    helper.terminate()
                    helper.wait(timeout=3)
                    raise RuntimeError('Owned OLE helper exceeded deadline')
                out,err = helper.communicate()
                page.wait_for_timeout(700)
                value = snapshot()
                records = [{'path':r.path,'origin':r.origin,'process_id':r.process_id,
                            'file_index':r.file_index,'file_count':r.file_count}
                           for r in value.records[before:min(value.count,8)]]
                navigated_to_fixture = page.url.startswith('file:')
                received = [] if navigated_to_fixture else received_frame.evaluate('window.received||[]')
                removal_preserved = True
                if case_name == 'accepted_then_removed':
                    received_frame.evaluate('window.received=[]')
                    page.wait_for_timeout(200)
                    after_remove = snapshot()
                    removal_preserved = (after_remove.count == value.count and
                        all(bytes(after_remove.records[i]) == bytes(value.records[i])
                            for i in range(before,min(value.count,8))))
                passed = drop_case_passed(case_name,helper.returncode,out.decode(errors='replace'),
                    records,received,fixture_path=str(fixture),expected_origin=expected_origin,
                    expected_pid=process.pid,restored=value.state==2,removal_preserved=removal_preserved)
                report['cases'].append({'case':case_name,'expected_origin':expected_origin,
                    'helper_exit':helper.returncode,'helper_stdout':out.decode(errors='replace')[:1000],
                    'helper_stderr':err.decode(errors='replace')[:1000], 'page_received':received,
                    'records':records,'native_status':status(),'passed':passed})
                report['cases'][-1]['default_navigation_to_fixture'] = navigated_to_fixture
                if case_name == 'accepted_then_removed':report['cases'][-1]['removal_preserved'] = removal_preserved
            send(0)
            report['detached_status'] = status()
            report['passed'] = all(case['passed'] for case in report['cases']) and snapshot().state == 2
    except Exception as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        if mapping:report['last_native_status'] = status()
    finally:
        if helper and helper.poll() is None:
            helper.terminate(); helper.wait(timeout=3); forced_helper=True
        if forced_helper:
            try:release_owned_mouse()
            except Exception as exc:report['mouse_cleanup_error']=type(exc).__name__
        if hook:
            if mapping and snapshot().state==1 and process and process.poll() is None:
                try:send(0); report['finally_detach']=status()
                except Exception as exc:report['detach_error']=str(exc)
            report['hook_removed'] = bool(user.UnhookWindowsHookEx(hook))
        if atom:kernel.GlobalDeleteAtom(atom)
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        if process:report['owned_browser_exit'] = process.returncode
        if mapping:mapping.close()
        server.shutdown();server.server_close()
        second_server.shutdown();second_server.server_close()
        report['field_deployment_complete'] = False
        evidence = ROOT/'evidence'/('owned-browser-native-drop-'+probe_id+'.json')
        evidence.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'evidence':str(evidence),'passed':report['passed'],
            'error':report.get('error'),'cases':report['cases']},ensure_ascii=False,indent=2),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
