"""Elevated, reversible OS-primitives check; never installs a real endpoint.

Only a unique ProgramData test directory and a DISABLED temporary task are
created, validated and removed. No PS policy, registry, native worker or mail.
"""
import ctypes,json,os,secrets,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import native_installer as ni
from guarddesk.installer_channel import Receiver,connect,send
from guarddesk.windows_controls import is_admin

def child(pipe):
    if not is_admin():raise PermissionError('OS primitive test requires explicit UAC')
    channel=connect(pipe);ops=ni.Windows();nonce=secrets.token_hex(12)
    base=ni.folder(35).parent;directory=base/('GuardDesk-InstallerCheck-'+nonce);task='GuardDesk-InstallerCheck-'+nonce
    created=False;checks=[];report={}
    try:
        ops.protect(directory,create=True);checks.append('atomic private directory with Admin/SYSTEM owner and DACL')
        sub=directory/'sub';ops.protect(sub,create=True)
        exe=sub/'GuardDesk.exe';ops.write(exe,b'NOT AN EXECUTABLE - DISABLED TEST ONLY')
        ops.tree(directory);checks.append('protected file writes and recursive ACL validation')
        config=directory/'fixture.json';ops.write(config,b'{}')
        raw=ni.task_body(exe,config,'native')
        root=ni.ET.fromstring(raw);ns={'t':ni.NS}
        root.find('t:Settings/t:Enabled',ns).text='false';root.find('t:Triggers/t:BootTrigger/t:Enabled',ns).text='false'
        raw=ni.ET.tostring(root,encoding='utf-16',xml_declaration=True)
        ops.register(task,raw,directory);created=True
        queried=ops.query(task);ni.verify_task(queried,exe,config,'native')
        actual=ni.ET.fromstring(queried.decode('oem') if b'\x00' not in queried else queried)
        assert actual.findtext('t:Settings/t:Enabled',namespaces=ns)=='false'
        checks.append('actual Task Scheduler XML registration, disabled task, strict identity verification')
        ops.stop(task,exe);checks.append('already stopped task handling with actual process handles')
        report={'passed':True,'checks':checks,'task_executed':False,'real_endpoint_installed':False,'execution_policy_changed':False}
    except Exception as exc:
        import traceback
        report={'passed':False,'checks':checks,'error':type(exc).__name__+': '+str(exc)[:1500],'trace':traceback.format_exc()[-5000:]}
    finally:
        cleanup=[]
        if created:
            try:ni.verify_task(ops.query(task),directory/'sub/GuardDesk.exe',directory/'fixture.json','native');ops.delete(task)
            except Exception as exc:cleanup.append(type(exc).__name__)
        try:
            if directory.exists():
                assert directory.parent==base and directory.name=='GuardDesk-InstallerCheck-'+nonce
                ops.tree(directory);shutil.rmtree(directory)
        except Exception as exc:cleanup.append(type(exc).__name__)
        report['cleanup_errors']=cleanup
        report['passed']=bool(report.get('passed')) and not cleanup
        try:send(channel,report)
        finally:channel[0].CloseHandle(channel[1])
    return 0 if report['passed'] else 1

def parent():
    from ctypes import wintypes as w
    receiver=Receiver()
    class Info(ctypes.Structure):
        _fields_=[('cbSize',w.DWORD),('fMask',w.ULONG),('hwnd',w.HWND),('lpVerb',w.LPCWSTR),('lpFile',w.LPCWSTR),('lpParameters',w.LPCWSTR),('lpDirectory',w.LPCWSTR),('nShow',ctypes.c_int),('hInstApp',w.HINSTANCE),('lpIDList',w.LPVOID),('lpClass',w.LPCWSTR),('hkeyClass',w.HKEY),('dwHotKey',w.DWORD),('hIcon',w.HANDLE),('hProcess',w.HANDLE)]
    shell=ctypes.WinDLL('shell32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    shell.ShellExecuteExW.argtypes=[ctypes.POINTER(Info)];shell.ShellExecuteExW.restype=w.BOOL
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
    kernel.CloseHandle.argtypes=[w.HANDLE]
    info=Info();info.cbSize=ctypes.sizeof(info);info.fMask=0x40;info.lpVerb='runas';info.lpFile=sys.executable
    info.lpParameters=subprocess.list2cmdline([str(Path(__file__).resolve()),'--child',receiver.name]);info.lpDirectory=str(ROOT);info.nShow=0
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
        deadline=time.monotonic()+180;report=None
        while time.monotonic()<deadline:
            if report is None:report=receiver.poll()
            if kernel.WaitForSingleObject(info.hProcess,200)==0:break
        if report is None:report=receiver.poll()
        if report is None:raise OSError('No test result; inspect the temporary test task before rerun')
        path=ROOT/'evidence/native-installer-os-primitives-0.4.41.json';path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report));return 0 if report['passed'] else 1
    finally:
        if info.hProcess:kernel.CloseHandle(info.hProcess)
        receiver.close()
if __name__=='__main__':raise SystemExit(child(sys.argv[2]) if len(sys.argv)==3 and sys.argv[1]=='--child' else parent())
