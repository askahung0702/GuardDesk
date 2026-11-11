"""Own-window metadata and local focus routing; no remote input/capture."""
import ctypes,os,unittest
from ctypes import wintypes as w
from types import SimpleNamespace
from unittest.mock import Mock,patch
from guarddesk import mis_window
from guarddesk.remote_viewer import RemoteViewer

class User:
    def __init__(self):
        self.windows={10:(12,34,mis_window.CLASS_NAME),20:(12,35,'OwnedMain'),30:(99,88,'OtherApp')};self.foreground=20;self.focus=0;self.shown=[];self.zoomed=False;self.iconic=False
    def EnumThreadWindows(self,thread,visit,unused):
        return all(visit(hwnd,0) for hwnd,info in self.windows.items() if info[1]==thread)
    def GetWindowThreadProcessId(self,hwnd,pid):
        row=self.windows.get(hwnd,(0,0,''));ctypes.cast(pid,ctypes.POINTER(w.DWORD)).contents.value=row[0];return row[1]
    def GetClassNameW(self,hwnd,text,size):text.value=self.windows[hwnd][2];return len(text.value)
    def GetForegroundWindow(self):return self.foreground
    def GetFocus(self):return self.focus
    def SetForegroundWindow(self,hwnd):self.foreground=hwnd;return True
    def SetFocus(self,hwnd):self.focus=hwnd
    def IsIconic(self,hwnd):return self.iconic
    def IsZoomed(self,hwnd):return self.zoomed
    def ShowWindow(self,hwnd,action):self.shown.append((hwnd,action));self.zoomed=action==3;self.iconic=False

class FocusPolicyTest(unittest.TestCase):
    def setUp(self):
        self.user=User();self.kernel=SimpleNamespace(GetCurrentProcessId=lambda:12,GetCurrentThreadId=lambda:34)
        self.patch=patch.object(mis_window,'api',return_value=(self.user,self.kernel,lambda f:f));self.patch.start();self.addCleanup(self.patch.stop)
    def test_activate_only_current_UI_thread_fixed_class_and_process(self):
        self.assertTrue(mis_window.activate());self.assertEqual(self.user.focus,10);self.assertEqual(self.user.foreground,10)
    def test_other_application_foreground_is_never_stolen(self):
        self.user.foreground=30;self.assertFalse(mis_window.activate(True));self.assertEqual(self.user.focus,0);self.assertEqual(self.user.shown,[])
    def test_missing_wrong_identity_or_ambiguous_target_is_rejected(self):
        for row in ((99,34,mis_window.CLASS_NAME),(12,34,'Different'),(12,99,mis_window.CLASS_NAME)):
            self.user.windows[10]=row;self.assertFalse(mis_window.activate())
        self.user.windows[10]=(12,34,mis_window.CLASS_NAME);self.user.windows[11]=self.user.windows[10];self.assertFalse(mis_window.activate())
    def test_maximize_restore_and_minimize_restore_use_actual_window_state(self):
        self.assertTrue(mis_window.activate(True));self.assertTrue(mis_window.activate(True));self.user.iconic=True
        self.assertTrue(mis_window.activate());self.assertEqual(self.user.shown,[(10,3),(10,9),(10,9)])
    def test_invalid_local_action_is_rejected(self):
        with self.assertRaises(ValueError):mis_window.activate('arbitrary')

class ShellRoutingTest(unittest.TestCase):
    def test_stop_after_logout_ignores_destroyed_workspace_controls(self):
        app=RemoteViewer.__new__(RemoteViewer);app.engine=None;app.fullscreen=False;app.clear_frame=Mock();app.metric=Mock();app.status=Mock()
        for name in ('native_window_button','fullscreen_button','display_box','native_actions'):
            widget=Mock();widget.winfo_exists.return_value=False;setattr(app,name,widget)
        app.stop_session()
        app.native_window_button.configure.assert_not_called();app.fullscreen_button.configure.assert_not_called();app.display_box.configure.assert_not_called();app.native_actions.pack_forget.assert_not_called()
    def test_stop_restores_legacy_fullscreen_without_activating_stopping_native_window(self):
        app=RemoteViewer.__new__(RemoteViewer);app.engine=SimpleNamespace(native_media=True,activate_window=Mock(),stop=Mock());engine=app.engine
        app.fullscreen=True;app._toggle_canvas_fullscreen=Mock();app.clear_frame=Mock();app.metric=Mock();app.status=Mock()
        app.stop_session();app._toggle_canvas_fullscreen.assert_called_once();engine.stop.assert_called_once();engine.activate_window.assert_not_called();self.assertIsNone(app.engine)
    def test_native_fullscreen_button_routes_to_native_window_not_Tk_canvas(self):
        app=RemoteViewer.__new__(RemoteViewer);app.engine=SimpleNamespace(native_media=True,activate_window=Mock(return_value=True));app.status=Mock();app.root=Mock();app.fullscreen=False
        self.assertEqual(app.toggle_fullscreen(),'break');app.engine.activate_window.assert_called_once_with(True)
        app.root.attributes.assert_not_called();self.assertFalse(app.fullscreen)
    def test_native_window_unavailable_is_not_claimed_ready(self):
        app=RemoteViewer.__new__(RemoteViewer);app.engine=SimpleNamespace(native_media=True,activate_window=Mock(return_value=False));app.status=Mock()
        self.assertFalse(app.activate_native_window());self.assertIn('仍在建立',app.status.set.call_args.args[0])

@unittest.skipUnless(os.name=='nt','Windows metadata only')
class OwnedMetadataTest(unittest.TestCase):
    def test_real_hidden_owned_window_thread_pid_class_and_duplicate_rejection(self):
        user,kernel,callback=mis_window.api();user.CreateWindowExW.argtypes=[w.DWORD,w.LPCWSTR,w.LPCWSTR,w.DWORD,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,w.HWND,w.HMENU,w.HINSTANCE,w.LPVOID];user.CreateWindowExW.restype=w.HWND
        user.DestroyWindow.argtypes=[w.HWND];user.DestroyWindow.restype=w.BOOL
        windows=[]
        try:
            with patch.object(mis_window,'CLASS_NAME','Static'):
                for _ in range(2):
                    hwnd=user.CreateWindowExW(0,'STATIC','GuardDesk owned hidden metadata',0,0,0,40,40,None,None,None,None);self.assertTrue(hwnd);windows.append(hwnd)
                    found=mis_window.find_owned_window(user,kernel,callback)
                    self.assertEqual(found,hwnd if len(windows)==1 else None)
        finally:
            for hwnd in windows:self.assertTrue(user.DestroyWindow(hwnd))
