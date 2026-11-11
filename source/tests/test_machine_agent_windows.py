"""Owned random pipes only. Transport fixtures do NOT certify SYSTEM/WTS install."""
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch, Mock
from guarddesk import machine_agent_windows as windows
from guarddesk.machine_agent import Router,MAX_MESSAGE
from guarddesk.native_connector_pipe import _api,_IO
from guarddesk.native_browser_identity import _snapshot,_process_sid


@unittest.skipUnless(os.name=='nt','Windows named pipes required')
class WindowsTransportTest(unittest.TestCase):
    @contextmanager
    def listener(self):
        api=_api();api.GetCurrentProcess.restype=w.HANDLE
        process=api.GetCurrentProcess();_,_,session,image=_snapshot(api,process);sid=_process_sid(process)
        agent=SimpleNamespace(config={'server':'https://fixture.example.test','device_id':'a'*24},cached_policy=lambda:{'version':0,'body':{}})
        states={session:{'sid':sid,'logon':100,'account':'FIXTURE\\owned','active':True,'locked':False}}
        calls=[]
        router=Router(agent,lambda:states,lambda path,body:(calls.append((path,body)) or {'ok':True}))
        name=r'\\.\pipe\GuardDesk-MachineAgent-fixture-'+uuid.uuid4().hex
        # The actual Python PID/SID/session are checked by the production
        # process lease. Only immutable image location/ACL are substituted.
        # Windows venv sys.executable can be a redirector, not the process image.
        # Pin the owned test process observed by Win32; production stays fixed.
        with (patch.object(windows,'PIPE',name),patch.object(windows,'installed_image',return_value=Path(image).resolve()),
              patch.object(windows,'PIPE_SECURITY',windows.PIPE_SECURITY.replace('O:SY','O:'+sid)),
              patch('guarddesk.update_native.protected_tree')):
            # This owned transport fixture cannot create SYSTEM-owned objects.
            # Validate its real owner, then translate ONLY the constructor check.
            # Raw/client checks below still read the actual non-SYSTEM owner.
            original_owner=windows.pipe_owner
            def owned_constructor_owner(api,handle):
                owner=original_owner(api,handle)
                self.assertEqual(owner,sid)
                return 'S-1-5-18'
            with patch.object(windows,'pipe_owner',side_effect=owned_constructor_owner):
                listener=windows.Listener(router)
            try:yield listener,router,states,calls,session
            finally:listener.close()

    def raw(self,path,body,generation=None):
        api=_api()
        api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];api.CreateFileW.restype=w.HANDLE
        api.SetNamedPipeHandleState.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD),w.LPVOID,w.LPVOID]
        handle=api.CreateFileW(windows.PIPE,0xc0000000,0,None,3,0x40000000|0x100000|0x10000,None)
        if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        try:
            mode=w.DWORD(2)
            if not api.SetNamedPipeHandleState(handle,ctypes.byref(mode),None,None):raise ctypes.WinError(ctypes.get_last_error())
            io=_IO(api,handle,threading.Event(),MAX_MESSAGE)
            owner=windows.pipe_owner(api,handle)
            request={'path':path,'body':body}
            if generation is not None:request['generation']=generation
            io.operation('write',json.dumps(request).encode(),timeout=2)
            result=json.loads(io.operation('read',timeout=2))
            if result.get('ok'):io.operation('write',b'{}',timeout=1)
            return result,owner
        finally:api.CloseHandle(handle)

    def test_actual_pipe_owner_is_readable_and_unprivileged_server_is_rejected(self):
        with self.listener():
            reply,owner=self.raw('/local/status',{})
            self.assertTrue(reply['ok']);self.assertNotEqual(owner,'S-1-5-18')
            with self.assertRaises(PermissionError):windows.request('/local/status',{},timeout=1)

    def test_actual_pid_sid_session_authenticated_and_old_generation_rejected(self):
        with self.listener() as (listener,router,states,calls,session):
            reply,_=self.raw('/local/bootstrap',{})
            self.assertTrue(reply['ok']);self.assertEqual(reply['result']['session'],session)
            reply,_=self.raw('/api/agent/custom-settings',{'protocol':2},router.generation)
            self.assertTrue(reply['ok']);self.assertEqual(len(calls),1)
            reply,_=self.raw('/api/agent/custom-settings',{'protocol':2},'0'*32)
            self.assertFalse(reply['ok']);self.assertEqual(len(calls),1)
            states[session]['sid']='S-1-5-21-999'
            reply,_=self.raw('/local/bootstrap',{})
            self.assertFalse(reply['ok'])

    def test_actual_authenticated_remote_bootstrap_needs_no_user_profile(self):
        with self.listener() as (listener,router,states,calls,session):
            reply,_=self.raw('/local/remote-bootstrap',{})
            self.assertTrue(reply['ok']);self.assertEqual(reply['result']['session'],session)
            self.assertEqual(reply['result']['sid'],states[session]['sid'])
            self.assertEqual(reply['result']['device_id'],'a'*24)
            self.assertNotIn('config',reply['result']);self.assertNotIn('token',reply['result'])
            self.assertEqual(calls,[])

    def test_rejected_generation_reply_is_delivered_before_pipe_disconnect(self):
        with self.listener() as (_,router,_,calls,_):
            for _ in range(40):
                reply,_=self.raw('/api/agent/custom-settings',{'protocol':2},'0'*32)
                self.assertFalse(reply['ok'])
            self.assertEqual(calls,[])

    def test_non_installed_image_and_privileged_routes_are_rejected(self):
        with self.listener() as (listener,router,states,calls,session):
            with patch.object(windows,'installed_image',return_value=Path(sys.executable).with_name('not-this-process.exe')):
                reply,_=self.raw('/local/bootstrap',{})
                self.assertFalse(reply['ok'])
            reply,_=self.raw('/api/agent/updates/poll',{'role':'native'},router.generation)
            self.assertFalse(reply['ok']);self.assertEqual(calls,[])

    def test_concurrent_fixed_pipe_instances_cancel_cleanly_and_latency_is_bounded(self):
        with self.listener() as (listener,router,states,calls,session):
            values=[]
            for _ in range(40):
                start=time.perf_counter();reply,_=self.raw('/local/status',{});values.append(time.perf_counter()-start)
                self.assertTrue(reply['ok'])
            self.assertEqual(len(listener.handles),8)
            self.assertLess(sorted(values)[37],.25)
            self.assertEqual(calls,[])

    def test_production_descriptor_explicit_system_owner_and_unchanged_dacl(self):
        self.assertEqual(windows.PIPE_SECURITY,'O:SYD:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;IU)')
        # Execute real Windows SDDL conversion in Listener.pipe; only object
        # creation is substituted. This does NOT certify SYSTEM service startup.
        api=_api();seen=[]
        adv=ctypes.WinDLL('advapi32',use_last_error=True)
        adv.GetSecurityDescriptorOwner.argtypes=[w.LPVOID,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)]
        adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)]
        def create(*args):
            descriptor=ctypes.cast(args[-1],ctypes.POINTER(windows._Security)).contents.descriptor
            owner=w.LPVOID();defaulted=w.BOOL();value=w.LPWSTR()
            self.assertTrue(adv.GetSecurityDescriptorOwner(descriptor,ctypes.byref(owner),ctypes.byref(defaulted)))
            self.assertTrue(adv.ConvertSidToStringSidW(owner,ctypes.byref(value)))
            try:seen.append(value.value)
            finally:api.LocalFree(value)
            self.assertFalse(defaulted.value)
            self.assertEqual(args[2],4|2|8) # local only, message mode
            return 123
        listener=object.__new__(windows.Listener)
        listener.api=SimpleNamespace(CreateNamedPipeW=create,LocalFree=api.LocalFree,CloseHandle=Mock())
        with patch.object(windows,'pipe_owner',return_value='S-1-5-18'):
            self.assertEqual(listener.pipe(True),123)
        self.assertEqual(seen,['S-1-5-18'])
        listener.api.CloseHandle.assert_not_called()
        # The field BA owner is rejected at creation and the new handle closed.
        with patch.object(windows,'pipe_owner',return_value='S-1-5-32-544'):
            with self.assertRaisesRegex(PermissionError,'owner mismatch at creation'):listener.pipe(True)
        listener.api.CloseHandle.assert_called_once_with(123)


if __name__=='__main__':unittest.main()
