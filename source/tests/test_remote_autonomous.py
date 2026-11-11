"""Offline lifetime and scheduler contracts; no center, capture or OS input."""
import ast
from pathlib import Path
import unittest
from guarddesk.remote_lifetime import NO_SESSION_DEADLINE,consent_tick
from guarddesk.remote_native_broker import NativeJob,lease_deadline
from test_remote_native_broker import Library,REQUEST,PEER,APPROVAL,reply

class AutonomousContracts(unittest.TestCase):
    def test_unlimited_consent_is_not_unlimited_input_authority(self):
        self.assertEqual(consent_tick(None,1000),NO_SESSION_DEADLINE)
        job=NativeJob(Library(),lambda *a:None,REQUEST,PEER,{**APPROVAL,'session_lifetime':'until_stopped'})
        self.assertEqual(job.spec.consent_tick_deadline,NO_SESSION_DEADLINE)
        self.assertEqual(lease_deadline(reply(),1000,1001,NO_SESSION_DEADLINE,can_control=True,administrator=True),6000)
        self.assertEqual(lease_deadline(reply(),1000,6000,NO_SESSION_DEADLINE,can_control=True,administrator=True),0)
        with self.assertRaises(ValueError):
            lease_deadline({**reply(),'lease_seconds':600},1000,1001,NO_SESSION_DEADLINE,can_control=True,administrator=True)

    def test_finite_compatibility_and_invalid_lifetimes(self):
        self.assertEqual(consent_tick(10,1000),11000)
        for value in (True,-1,0,601,float('inf'),float('nan'),'unlimited'):
            with self.subTest(value=value),self.assertRaises(ValueError):consent_tick(value,1000)

    def test_python_ui_has_one_native_run_and_no_per_frame_loop(self):
        from guarddesk import mis_native_media
        tree=ast.parse(Path(mis_native_media.__file__).read_text(encoding='utf-8'))
        controller=next(x for x in tree.body if isinstance(x,ast.ClassDef) and x.name=='NativeMisController')
        ui=next(x for x in controller.body if isinstance(x,ast.FunctionDef) and x.name=='_ui')
        self.assertFalse(any(isinstance(x,(ast.For,ast.While)) for x in ast.walk(ui)))
        calls=[x.func.attr for x in ast.walk(ui) if isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute)]
        self.assertEqual(calls.count('run'),1)
        self.assertNotIn('pump',calls);self.assertNotIn('wait',calls)
