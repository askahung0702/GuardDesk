"""Disclosed temporary SYSTEM fixture, no endpoint/control/network changes."""
import ctypes,hashlib,json,os,secrets,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import native_installer as ni
from guarddesk.installer_channel import Receiver,connect,send
from guarddesk.windows_controls import is_admin

def inspect(pipe):
    import traceback
    if not is_admin():raise PermissionError('Explicit UAC required')
    channel=connect(pipe);ops=ni.Windows();nonce='ee8425dd2f561cfc86f57da7'
    base=ni.folder(35).parent;directory=base/('GuardDesk-HealthCheck-'+nonce);task='GuardDesk-HealthCheck-'+nonce
    report={'diagnosis_only':True,'directory':str(directory),'task':task}
    try:
        task_exists=True
        try:
            raw=ops.query(task);ni.verify_task(raw,directory/'GuardDesk.exe',directory/'fixture.json','native')
            report['xml']=raw.decode('oem') if b'\x00' not in raw else raw.decode('utf-16')
        except OSError as exc:report['task_query']=str(exc);task_exists=False
        report['files']=[p.name for p in directory.iterdir()]
        health=directory/'native-health.json'
        if health.exists():report['health']=ni.read_json(health)
        try:
            if task_exists:ops.stop(task,directory/'GuardDesk.exe');ops.delete(task)
            report['task_cleaned']=True
        except Exception:report['cleanup_error']=traceback.format_exc()
        if report.get('task_cleaned'):
            assert directory.parent==base and directory.name=='GuardDesk-HealthCheck-'+nonce
            ops.tree(directory);shutil.rmtree(directory);report['directory_cleaned']=True
    except Exception:report['error']=traceback.format_exc()
    try:send(channel,report)
    finally:channel[0].CloseHandle(channel[1])
    return 0

def child(pipe):
    if not is_admin():raise PermissionError('Explicit UAC required')
    channel=connect(pipe)
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(ROOT/'dist/GuardDesk/GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    compiled=archive.extract('guarddesk.native_installer')
    assert compiled==compile((ROOT/'guarddesk/native_installer.py').read_bytes(),str(ROOT/'guarddesk/native_installer.py'),'exec')
    exec(compiled,ni.__dict__)
    ops=ni.Windows();nonce=secrets.token_hex(12)
    base=ni.folder(35).parent;directory=base/('GuardDesk-HealthCheck-'+nonce);task='GuardDesk-HealthCheck-'+nonce
    created=False;checks=[];report={}
    try:
        checks.append('exact built installer module equals source and its compiled functions are used')
        ops.protect(directory,create=True)
        exe=directory/'GuardDesk.exe';config=directory/'fixture.json';ops.write(config,b'{}')
        code='''using System;using System.Diagnostics;using System.IO;using System.Threading;using System.Security.Principal;
class Program {static void Main(){string root=AppDomain.CurrentDomain.BaseDirectory;
string body="{\\"pid\\":"+Process.GetCurrentProcess().Id+",\\"time\\":"+((DateTime.UtcNow-new DateTime(1970,1,1)).TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture)+",\\"version\\":\\"0.4.41\\",\\"sid\\":\\""+WindowsIdentity.GetCurrent().User.Value+"\\"}";
File.WriteAllText(Path.Combine(root,"native-health.json"),body);Thread.Sleep(60000);}}'''
        source=directory/'fixture.cs';ops.write(source,code.encode('utf-8'))
        # Resolve the official Windows compiler; never execute user-supplied paths.
        compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(exe),str(source)],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise OSError((result.stdout+result.stderr).decode(errors='replace'))
        ops.protect(exe);ops.tree(directory);checks.append('protected fixture built with official compiler')
        root=ni.ET.fromstring(ni.task_body(exe,config,'native'));ns={'t':ni.NS}
        root.find('t:Triggers/t:BootTrigger/t:Enabled',ns).text='false'
        ops.register(task,ni.ET.tostring(root,encoding='utf-16',xml_declaration=True),directory);created=True
        ni.verify_task(ops.query(task),exe,config,'native');checks.append('same production task XML registered')
        started=time.time();ops.start(task);ops.health(directory/'native-health.json','0.4.41',exe,started)
        body=ni.read_json(directory/'native-health.json');assert body['sid']=='S-1-5-18'
        checks.append('actual SYSTEM process started and production health reader accepted exact PID/image/version/time')
        try:ni.process_image(body['pid']);checks.append('ordinary process query already permitted')
        except PermissionError as exc:
            assert exc.winerror==5
            checks.append('after health query: thread impersonation/privilege reverted; ordinary query remains denied')
        ops.stop(task,exe);checks.append('actual task stopped and precise image lock released')
        report={'passed':True,'checks':checks,'task_identity':body['sid'],'real_endpoint_installed':False,'policy_or_registry_changed':False}
    except Exception as exc:
        import traceback
        report={'passed':False,'checks':checks,'error':str(exc)[:1500],'trace':traceback.format_exc()[-5000:]}
        if (directory/'native-health.json').exists():
            try:
                report['health']=ni.read_json(directory/'native-health.json')
                report['process_image']=str(ni.process_image(report['health']['pid']))
            except Exception as diagnosis:report['diagnosis_error']=traceback.format_exc()[-3000:]
    finally:
        cleanup=[]
        if created:
            try:ni.verify_task(ops.query(task),directory/'GuardDesk.exe',directory/'fixture.json','native');ops.stop(task,directory/'GuardDesk.exe');ops.delete(task)
            except Exception as exc:cleanup.append(type(exc).__name__+': '+str(exc))
        try:
            if directory.exists() and not cleanup:
                assert directory.parent==base and directory.name=='GuardDesk-HealthCheck-'+nonce
                ops.tree(directory)
                for attempt in range(30):
                    try:shutil.rmtree(directory);break
                    except PermissionError:
                        if attempt==29:raise
                        time.sleep(.5)
        except Exception as exc:
            import traceback
            cleanup.append(traceback.format_exc())
        report['task']=task;report['directory']=str(directory)
        report['installer_source_sha256']=hashlib.sha256((ROOT/'guarddesk/native_installer.py').read_bytes()).hexdigest()
        report['compiled_exe_sha256']=hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        report['cleanup_errors']=cleanup;report['passed']=bool(report.get('passed')) and not cleanup
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
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD;kernel.CloseHandle.argtypes=[w.HANDLE]
    info=Info();info.cbSize=ctypes.sizeof(info);info.fMask=0x40;info.lpVerb='runas';info.lpFile=sys.executable
    info.lpParameters=subprocess.list2cmdline([str(Path(__file__).resolve()),'--child-inspect' if '--inspect' in sys.argv else '--child',receiver.name]);info.lpDirectory=str(ROOT);info.nShow=0
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
        deadline=time.monotonic()+150;report=None
        while time.monotonic()<deadline:
            if report is None:report=receiver.poll()
            if kernel.WaitForSingleObject(info.hProcess,200)==0:break
        if report is None:report=receiver.poll()
        if report is None:raise OSError('No fixture result; inspect temporary task before retry')
        name='native-worker-health-os-inspect-20261021.json' if '--inspect' in sys.argv else 'native-worker-health-os-20261021.json'
        (ROOT/'evidence'/name).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report));return 0 if report.get('passed',report.get('diagnosis_only')) else 1
    finally:
        if info.hProcess:kernel.CloseHandle(info.hProcess)
        receiver.close()
if __name__=='__main__':raise SystemExit(inspect(sys.argv[2]) if len(sys.argv)==3 and sys.argv[1]=='--child-inspect' else child(sys.argv[2]) if len(sys.argv)==3 and sys.argv[1]=='--child' else parent())
