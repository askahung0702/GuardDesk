"""Limited-access process image attribution; no command lines or user guessing."""
import collections
import ctypes
import time
from ctypes import wintypes as w


class ProcessResolver:
    def __init__(self):self.cache=collections.OrderedDict();self.window=0;self.queries=0

    @staticmethod
    def descriptor(value):
        result={'process_identity_status':'creation_time_checked'}
        result['process_created']=value['born']
        if value.get('image'):result['process']=value['image']
        if type(value.get('session')) is int:result['process_session_id']=value['session']
        return result

    def resolve(self,event):
        pid=event['pid'];occurred=event.get('occurred',0);now=time.time()
        while self.cache and now-next(iter(self.cache.values()))['queried']>5:self.cache.popitem(last=False)
        saved=self.cache.get(pid)
        # A PID alone is not an identity. Cache entries apply only to events
        # before the query and after that process's creation; later events
        # require another handle query to rule out PID reuse.
        if saved and saved['born']<=occurred<=saved['queried']:
            return self.descriptor(saved)
        stamp=time.monotonic()
        if stamp-self.window>=1:self.window=stamp;self.queries=0
        if self.queries>=64:return {'process_identity_status':'query_budget_reached'}
        self.queries+=1
        try:value=self.query(pid)
        except OSError:value=None
        if value and value['born']<=occurred<=value['queried']:
            self.cache.pop(pid,None);self.cache[pid]=value
            while len(self.cache)>4096:self.cache.popitem(last=False)
            return self.descriptor(value)
        return {'process_identity_status':'unavailable_or_process_replaced'}

    @staticmethod
    def query(pid):
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
        api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle.restype=w.BOOL
        api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];api.GetProcessTimes.restype=w.BOOL
        api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];api.QueryFullProcessImageNameW.restype=w.BOOL
        api.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)];api.ProcessIdToSessionId.restype=w.BOOL
        handle=api.OpenProcess(0x1000,False,pid)
        if not handle:return None
        try:
            born,exited,kernel,user=(w.FILETIME() for _ in range(4));size=w.DWORD(32768);image=ctypes.create_unicode_buffer(size.value)
            if not api.GetProcessTimes(handle,ctypes.byref(born),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user)):return None
            image_ok=api.QueryFullProcessImageNameW(handle,0,image,ctypes.byref(size))
            session=w.DWORD();session_ok=api.ProcessIdToSessionId(pid,ctypes.byref(session))
            if not image_ok and not session_ok:return None
            return {'born':((born.dwHighDateTime<<32)|born.dwLowDateTime)/10000000-11644473600,'queried':time.time(),'image':image.value if image_ok else None,'session':session.value if session_ok else None}
        finally:api.CloseHandle(handle)
