"""Fixed remote service lifecycle; never accepts arbitrary service/command names."""
import ctypes
import json
import re
import subprocess
import time
from contextlib import contextmanager
from ctypes import wintypes as w
from pathlib import Path

NAME='GuardDeskRemote'

def description(executable,config):
    from .machine_service import image
    did=Path(config).parent.name
    if not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('Invalid service identity')
    return {'kind':'remote-service-v1','device_id':did,'binary':subprocess.list2cmdline([
        str(image(executable)),'--device-id',did])}

def verify(raw,executable,config,role):
    if role!='native' or raw!=description(executable,config):raise OSError('Remote service identity mismatch; preserve installation')

class Config(ctypes.Structure):
    _fields_=[('type',w.DWORD),('start',w.DWORD),('error',w.DWORD),('binary',w.LPWSTR),
        ('group',w.LPWSTR),('tag',w.DWORD),('dependencies',w.LPWSTR),('account',w.LPWSTR),('display',w.LPWSTR)]

class Status(ctypes.Structure):
    _fields_=[(name,w.DWORD) for name in ('type','state','accepted','exit','specific','checkpoint','hint','pid','flags')]

class Service:
    def __init__(self):
        self.api=ctypes.WinDLL('advapi32',use_last_error=True)
        declarations={
            'OpenSCManagerW':([w.LPCWSTR,w.LPCWSTR,w.DWORD],w.HANDLE),
            'OpenServiceW':([w.HANDLE,w.LPCWSTR,w.DWORD],w.HANDLE),
            'CloseServiceHandle':([w.HANDLE],w.BOOL),
            'QueryServiceConfigW':([w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)],w.BOOL),
            'QueryServiceStatusEx':([w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)],w.BOOL),
            'CreateServiceW':([w.HANDLE,w.LPCWSTR,w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.LPCWSTR,w.LPCWSTR,w.LPVOID,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR],w.HANDLE),
            'StartServiceW':([w.HANDLE,w.DWORD,w.LPVOID],w.BOOL),
            'ControlService':([w.HANDLE,w.DWORD,w.LPVOID],w.BOOL),
            'DeleteService':([w.HANDLE],w.BOOL),
            'SetServiceObjectSecurity':([w.HANDLE,w.DWORD,w.LPVOID],w.BOOL),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW':([w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID],w.BOOL),
            'QueryServiceObjectSecurity':([w.HANDLE,w.DWORD,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)],w.BOOL),
            'GetSecurityDescriptorOwner':([w.LPVOID,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)],w.BOOL),
            'GetSecurityDescriptorDacl':([w.LPVOID,ctypes.POINTER(w.BOOL),ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)],w.BOOL),
            'GetAce':([w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)],w.BOOL),
            'IsWellKnownSid':([w.LPVOID,ctypes.c_int],w.BOOL),
        }
        for name,(args,result) in declarations.items():
            fn=getattr(self.api,name);fn.argtypes=args;fn.restype=result

    @contextmanager
    def manager(self,create=False):
        value=self.api.OpenSCManagerW(None,None,3 if create else 1)
        if not value:raise ctypes.WinError(ctypes.get_last_error())
        try:yield value
        finally:self.api.CloseServiceHandle(value)

    @contextmanager
    def opened(self,access,missing=False):
        with self.manager() as manager:
            value=self.api.OpenServiceW(manager,NAME,access|0x20000)
            if not value and not (missing and ctypes.get_last_error()==1060):raise ctypes.WinError(ctypes.get_last_error())
            try:
                if value:self.protection(value)
                yield value
            finally:
                if value:self.api.CloseServiceHandle(value)

    def protection(self,handle):
        size=w.DWORD();self.api.QueryServiceObjectSecurity(handle,5,None,0,ctypes.byref(size))
        if not 0<size.value<=65536:raise OSError('Service security query failed')
        data=ctypes.create_string_buffer(size.value)
        if not self.api.QueryServiceObjectSecurity(handle,5,data,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        owner=w.LPVOID();default=w.BOOL();present=w.BOOL();dacl=w.LPVOID()
        def trusted(sid):return any(self.api.IsWellKnownSid(sid,kind) for kind in (22,26))
        if not self.api.GetSecurityDescriptorOwner(data,ctypes.byref(owner),ctypes.byref(default)) or not trusted(owner):raise PermissionError('Service owner untrusted')
        if not self.api.GetSecurityDescriptorDacl(data,ctypes.byref(present),ctypes.byref(dacl),ctypes.byref(default)) or not present or not dacl:raise PermissionError('Service DACL missing')
        count=ctypes.c_ushort.from_address(dacl.value+4).value
        if count>1024:raise PermissionError('Service ACL too large')
        for index in range(count):
            ace=w.LPVOID()
            if not self.api.GetAce(dacl,index,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
            kind=ctypes.c_ubyte.from_address(ace.value).value
            if kind==1:continue
            if kind!=0:raise PermissionError('Unknown service ACE')
            mask=ctypes.c_uint32.from_address(ace.value+4).value
            if mask & ~0x2008d and not trusted(ace.value+8):raise PermissionError('Service can be changed by untrusted identity')

    def read(self,handle):
        size=w.DWORD();self.api.QueryServiceConfigW(handle,None,0,ctypes.byref(size))
        if not 0<size.value<=65536:raise OSError('Service configuration query failed')
        data=ctypes.create_string_buffer(size.value)
        if not self.api.QueryServiceConfigW(handle,data,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        cfg=ctypes.cast(data,ctypes.POINTER(Config)).contents
        if cfg.type!=0x10 or cfg.start!=2 or cfg.account!='LocalSystem' or cfg.dependencies or cfg.group:
            raise PermissionError('Service type/account/start contract mismatch')
        match=re.fullmatch(r'(?:"[^"\r\n]+\\GuardDeskService\.exe"|[^\s"]+\\GuardDeskService\.exe) --device-id ([0-9a-f]{24})',cfg.binary or '')
        if not match:raise PermissionError('Service binary contract mismatch')
        return {'kind':'remote-service-v1','device_id':match[1],'binary':cfg.binary}

    def query(self):
        with self.opened(1,missing=True) as handle:return self.read(handle) if handle else None

    def state(self,handle):
        value=Status();size=w.DWORD()
        if not self.api.QueryServiceStatusEx(handle,0,ctypes.byref(value),ctypes.sizeof(value),ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        return value

    def create(self,expected):
        from .machine_service import enabled as full_service
        display='GuardDesk Endpoint Service (Internal Trial)' if full_service() else 'GuardDesk Remote Assistance (Internal Trial)'
        with self.manager(create=True) as manager:
            handle=self.api.CreateServiceW(manager,NAME,display,0xf01ff,
                0x10,2,1,expected['binary'],None,None,None,None,None)
            if not handle:raise ctypes.WinError(ctypes.get_last_error())
            try:
                # Only a newly created owned service. Standard users may query
                # status; they cannot start/stop/change configuration or DACLs.
                descriptor=w.LPVOID();kernel=ctypes.WinDLL('kernel32',use_last_error=True)
                kernel.LocalFree.argtypes=[w.LPVOID];kernel.LocalFree.restype=w.LPVOID
                if not self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)',1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if not self.api.SetServiceObjectSecurity(handle,5,descriptor):raise ctypes.WinError(ctypes.get_last_error())
                finally:kernel.LocalFree(descriptor)
                self.protection(handle)
                if self.read(handle)!=expected:raise PermissionError('Created service does not match expected identity')
            except BaseException:
                self.api.DeleteService(handle);raise
            finally:self.api.CloseServiceHandle(handle)

    def action(self,expected,action):
        access={'start':0x14,'stop':0x24,'delete':0x10004}[action]|1
        with self.opened(access) as handle:
            if self.read(handle)!=expected:raise PermissionError('Service changed before action')
            state=self.state(handle)
            if action=='start':
                if state.state==4:return
                if state.state!=1:raise OSError('Service transition is still in progress')
                if not self.api.StartServiceW(handle,0,None):raise ctypes.WinError(ctypes.get_last_error())
            elif action=='delete':
                if state.state!=1:raise OSError('Service is not stopped; preserving it')
                if not self.api.DeleteService(handle):raise ctypes.WinError(ctypes.get_last_error())
            else:
                if state.state==1:return
                if state.state!=3 and not self.api.ControlService(handle,1,ctypes.byref(Status())):raise ctypes.WinError(ctypes.get_last_error())
                deadline=time.monotonic()+55
                while time.monotonic()<deadline:
                    if self.state(handle).state==1:return
                    time.sleep(.2)
                raise TimeoutError('Service has not stopped; preserve transaction and files')

    def retire_self(self,expected):
        # Decommissioned worker reports its durable final ACK before exiting.
        # DeleteService only marks this running, fixed service for deletion.
        with self.opened(0x10001) as handle:
            if self.read(handle)!=expected:raise PermissionError('Service retirement identity mismatch')
            if not self.api.DeleteService(handle):raise ctypes.WinError(ctypes.get_last_error())


def platform():
    from .native_installer import Windows,verify_task,wait_image_unmapped
    from .machine_service import image
    class ServiceWindows(Windows):
        def __init__(self):self.service=Service();self.expected=None
        @staticmethod
        def native_name(name):return re.fullmatch(r'\\?GuardDesk-USBControl-[0-9a-f]{24}',name) is not None
        def names(self):
            names=super().names();current=self.service.query()
            if current:
                name='\\GuardDesk-USBControl-'+current['device_id']
                if name.casefold() in {n.casefold() for n in names}:raise OSError('Both service and legacy task exist; preserve installation')
                names.add(name)
            return names
        def body(self,executable,config,role):
            if role!='native':
                from .native_installer import task_body
                return task_body(executable,config,role)
            raw=description(executable,config);self.verify(raw,executable,config,role);return raw
        def verify(self,raw,executable,config,role):
            if role!='native':return verify_task(raw,executable,config,role)
            self.expected=description(executable,config)
            self.executable=executable;self.config=config
            if isinstance(raw,dict):verify(raw,executable,config,role)
            else:verify_task(raw,executable,config,role)
        def query(self,name):return (self.service.query() if self.native_name(name) else None) or super().query(name)
        def start(self,name):
            if self.native_name(name) and self.service.query():self.service.action(self.expected,'start')
            else:super().start(name)
        def stop(self,name,executable):
            if self.native_name(name) and self.service.query():
                self.service.action(self.expected,'stop')
                wait_image_unmapped(executable);wait_image_unmapped(image(executable))
            else:super().stop(name,executable)
        def delete(self,name):
            if not self.native_name(name):return super().delete(name)
            if self.native_name(name) and self.service.query():self.service.action(self.expected,'delete')
            elif ('\\'+name).casefold() in {n.casefold() for n in super().names()}:super().delete(name)
        def register(self,name,raw,directory):
            if not self.native_name(name):return super().register(name,raw,directory)
            if isinstance(raw,dict):
                if raw!=self.expected:raise PermissionError('Unexpected new service')
                existing=self.service.query()
                if existing:
                    if existing!=raw:raise PermissionError('Foreign service preserved')
                    return
                if ('\\'+name).casefold() in {n.casefold() for n in super().names()}:
                    # Already verified and stopped by the transaction.
                    verify_task(super().query(name),self.executable,self.config,'native')
                    super().delete(name)
                self.service.create(raw)
            else:
                # Original task XML is retained by transaction; restore only it.
                if self.service.query():self.service.action(self.expected,'delete')
                super().register(name,raw,directory)
    return ServiceWindows()
