"""Own-window metadata and local focus routing; no remote input/capture."""
import ctypes,os,unittest
from ctypes import wintypes as w
from types import SimpleNamespace
from unittest.mock import Mock,patch
from guarddesk import mis_window
from guarddesk.remote_viewer import DEVICE_RESULT_LIMIT, RemoteViewer

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

class EndpointSearchTest(unittest.TestCase):
    def setUp(self):
        self.app = app = RemoteViewer.__new__(RemoteViewer)
        app.engine = app.native_root = app.selected_device_id = None
        app.busy = False
        app.closing = Mock()
        app.closing.is_set.return_value = False
        app.username = 'operator'
        app.devices = {}
        for name in ('device_results','device_results_frame','device_entry','device_query','device_hint',
                     'mode_box','quality_box','connect_button','status','reason','mode','quality','background','client'):
            setattr(app, name, Mock())
        self.rows = {}
        app.device_results.get_children.side_effect = lambda: tuple(self.rows)
        app.device_results.delete.side_effect = lambda *ids: self.rows.clear()
        app.device_results.insert.side_effect = lambda *args, iid, values: self.rows.update({iid:values})
        app.device_results.exists.side_effect = self.rows.__contains__
        app.device_results.focus.return_value = ''
        app.device_query.get.return_value = ''
        app.device_query.set.side_effect = self.search
        app.reason.get.return_value = ''
        app.mode.get.return_value = '僅檢視'
        app.quality.get.return_value = '順暢 · 最高 8 FPS'
        clock = patch('guarddesk.remote_viewer.time.time', return_value=10)
        self.now = clock.start()
        self.addCleanup(clock.stop)

    @staticmethod
    def endpoint(number, name, account=None, **changes):
        return {'id':f'{number:024x}','name':name,'account':account,'ready':True,'protocol':6,**changes}

    def load_catalog(self, rows, *, absent=(), expired=()):
        grants = [{'device_id':row['id'],'username':'other' if index in absent else 'operator',
                   'expires':9 if index in expired else 20,'can_control':False}
                  for index, row in enumerate(rows)]
        self.app.catalog_data = {'devices':rows,'grants':grants}
        self.app.update_devices()

    def search(self, text):
        self.app.device_query.get.return_value = text
        self.app.device_query_changed()
        return tuple(self.rows)

    def test_search_limits_results_and_only_matches_authorized_devices(self):
        rows = [self.endpoint(i,f'PC-{i:03}') for i in range(40)]
        chosen = self.endpoint(90,'PC',r'EXAMPLE\測試員',registered_name='OLD-LABEL')
        hidden = self.endpoint(91,'Hidden',r'EXAMPLE\測試員')
        expired = self.endpoint(92,'Expired',r'EXAMPLE\測試員')
        self.load_catalog([*rows,chosen,hidden,expired],absent=(41,),expired=(42,))
        self.assertFalse(self.rows)
        matches = self.search(' pC ')
        self.assertEqual(len(matches), DEVICE_RESULT_LIMIT)
        self.assertEqual(matches[0], chosen['id'])
        self.assertIn('41', self.app.device_hint.set.call_args.args[0])
        self.assertEqual(self.search(r'example\測'), (chosen['id'],))
        self.assertEqual(self.search(chosen['id']), (chosen['id'],))
        self.assertEqual(self.search('old-label'), (chosen['id'],))
        self.assertEqual(self.search('hidden'), ())
        self.assertEqual(self.search('expired'), ())

    def test_keyboard_focus_and_exact_text_require_explicit_selection(self):
        row = self.endpoint(1,'DEV-01')
        self.load_catalog([row])
        self.search('DEV-01')
        self.assertEqual(self.app.focus_device_results(), 'break')
        self.app.device_results.selection_set.assert_called_with(row['id'])
        self.app.request()
        self.app.background.assert_not_called()
        self.app.select_device(row['id'])
        self.assertEqual(self.app.selected_device()['id'], row['id'])
        self.app.request()
        work, done = self.app.background.call_args.args
        self.app.device_entry.configure.assert_called_with(state='disabled')
        work()
        self.app.client.request.assert_called_once_with(row['id'],'view','','balanced')
        done(None,'fixture failure')
        self.app.device_entry.configure.assert_called_with(state='normal')

    def test_catalog_refresh_keeps_same_id_and_never_picks_same_name_replacement(self):
        first, second = self.endpoint(1,'DEV'), self.endpoint(2,'DEV')
        self.load_catalog([first,second])
        self.assertEqual(self.search('dev'), (first['id'],second['id']))
        self.app.select_device(second['id'])
        self.load_catalog([{**second,'name':'DEV NEW'},first])
        self.assertEqual(self.app.selected_device()['id'],second['id'])
        self.assertEqual(self.app.device_query.get(),'DEV NEW')
        self.load_catalog([{**first,'name':'DEV NEW'}])
        self.assertIsNone(self.app.selected_device())
        self.assertEqual(tuple(self.rows), (first['id'],))
        self.app.request()
        self.app.background.assert_not_called()

    def test_editing_search_unselects_and_unready_or_expired_device_cannot_connect(self):
        row = self.endpoint(1,'DEV-01')
        self.load_catalog([row])
        self.search('DEV')
        self.app.select_device(row['id'])
        self.assertIsNotNone(self.app.selected_device())
        self.search('DEV-')
        self.assertIsNone(self.app.selected_device())
        self.load_catalog([{**row,'ready':False}])
        self.app.select_device(row['id'])
        self.app.connect_button.configure.assert_called_with(state='disabled')
        self.app.request()
        self.now.return_value = 20
        self.assertIsNone(self.app.selected_device())
        self.app.request()
        self.app.background.assert_not_called()


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
