"""Trace only our smoke-test failure, inspect only its own empty login window."""
import ctypes,hashlib,json,os,runpy,sys,time,psutil
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'));done=False


def trace(frame,event,arg):
    global done
    if done or event!='exception' or frame.f_code.co_name!='run' or not frame.f_code.co_filename.endswith('packaged_smoke.py') or not isinstance(arg[1],AssertionError) or 'Tk login window' not in str(arg[1]):return trace
    done=True;process=frame.f_locals['native_viewer'];report={'scope':'own_smoke_viewer_only','pid':process.pid,'original_api_type':str(type(frame.f_locals['api'])),'original_owned_count':len(frame.f_locals['owned']),'windows':[]}
    report['root']=str(frame.f_locals['root']);report['args']=process.args
    report['parent_tcl_env']={k:v for k,v in os.environ.items() if k in ('TCL_LIBRARY','TK_LIBRARY','TCLLIBPATH','_PYI_APPLICATION_HOME_DIR','_PYI_PARENT_PROCESS_LEVEL','_PYI_ARCHIVE_FILE')}
    env=psutil.Process(process.pid).environ();report['child_tcl_env']={k:v for k,v in env.items() if k in ('TCL_LIBRARY','TK_LIBRARY','TCLLIBPATH','_PYI_APPLICATION_HOME_DIR','_PYI_PARENT_PROCESS_LEVEL','_PYI_ARCHIVE_FILE')}
    report['tcl_modules']=[m.path for m in psutil.Process(process.pid).memory_maps() if any(n in m.path.lower() for n in ('tcl86','tk86'))]
    init=ROOT/'dist/GuardDesk/_internal/_tcl_data/init.tcl';report['init_tcl_sha256']=hashlib.sha256(init.read_bytes()).hexdigest()
    api=ctypes.WinDLL('user32',use_last_error=True);api.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)];api.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
    cb=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);api.EnumWindows.argtypes=[cb,w.LPARAM];api.EnumChildWindows.argtypes=[w.HWND,cb,w.LPARAM]
    api.SendMessageTimeoutW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,ctypes.POINTER(ctypes.c_size_t)];api.SendMessageTimeoutW.restype=w.LPARAM
    errors=[]
    def child(hwnd,param):
        text=ctypes.create_unicode_buffer(8192);result=ctypes.c_size_t();api.SendMessageTimeoutW(hwnd,0xD,len(text),ctypes.addressof(text),2,300,ctypes.byref(result))
        if text.value:errors.append(text.value)
        return True
    child_cb=cb(child)
    def window(hwnd,param):
        pid=w.DWORD();api.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if pid.value==process.pid:
            text=ctypes.create_unicode_buffer(256);api.GetWindowTextW(hwnd,text,len(text))
            if text.value and text.value not in report['windows']:report['windows'].append(text.value)
            if text.value=='Unhandled exception in script':api.EnumChildWindows(hwnd,child_cb,0)
        return True
    callback=cb(window);deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        api.EnumWindows(callback,0)
        if errors or 'GuardDesk 遠端協助' in report['windows']:break
        time.sleep(.1)
    report.update(exception_controls=errors,process_exit=process.poll(),company_changed=False)
    (ROOT/'evidence/maintenance/packaged-viewer-diagnosis-0.4.56.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report),flush=True)
    return trace


sys.settrace(trace)
runpy.run_path(str(ROOT/'tests/packaged_smoke.py'),run_name='__main__')
