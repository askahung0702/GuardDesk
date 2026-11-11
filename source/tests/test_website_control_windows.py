"""Real Win32 registry operations, redirected only to a unique owned HKCU tree.

This tests the OS driver and recovery, not protected SYSTEM ACLs, browser policy
precedence or real navigation. It never writes Chrome/Edge company policy keys.
"""
import copy
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from guarddesk import website_control as wc
from guarddesk.category_rules import WEBSITE_DEFAULT


@unittest.skipUnless(os.name=='nt','Win32 registry required')
class WindowsRegistryTest(unittest.TestCase):
    def test_owned_hkcu_real_driver_apply_readback_change_and_restore(self):
        import winreg as w
        own=r'Software\GuardDeskOwnedTests\WebsiteControl'+'\\'+uuid.uuid4().hex
        roots={b:own+'\\'+b for b in wc.ROOTS}
        class FixtureDriver:
            # Explicit fixture boundary: real registry operations, without
            # claiming this user-owned directory passed SYSTEM protection.
            def __init__(self):self.raw=wc.Registry()
            def read(self,*a):return self.raw.read(*a)
            def read_value(self,*a):return self.raw.read_value(*a)
            def value(self,*a):return self.raw.value(*a)
            def prune(self,*a):return self.raw.prune(*a)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(wc.ROOTS,roots),patch.object(w,'HKEY_LOCAL_MACHINE',w.HKEY_CURRENT_USER):
            worker=wc.WebsiteController(Path(tmp),FixtureDriver())
            control={**copy.deepcopy(WEBSITE_DEFAULT),'enabled':True,'blocked':[f's{i}.example.com' for i in range(1000)],'allowed':['.approved.example.com']}
            try:
                started=time.perf_counter();result=worker.apply(control);elapsed=time.perf_counter()-started
                self.assertEqual(result['browsers']['chrome']['state'],'registry_verified',result)
                self.assertEqual(len(worker.registry.read('edge')['URLBlocklist']),1000)
                worker.apply({**control,'blocked':['next.example.com']})
                self.assertEqual(worker.registry.read('chrome')['URLBlocklist'],{'1':'next.example.com'})
                worker.restore();self.assertEqual(worker.registry.read('chrome'),wc.EMPTY)
                print('owned HKCU 1000-rules apply seconds='+str(round(elapsed,4)))
            finally:
                worker.restore()
                # Exact generated keys only. DeleteKey refuses nonempty keys.
                self.assertTrue(own.startswith('Software\\GuardDeskOwnedTests\\WebsiteControl\\'))
                for path in reversed(list(roots.values())):
                    try:w.DeleteKeyEx(w.HKEY_CURRENT_USER,path,w.KEY_WOW64_64KEY)
                    except FileNotFoundError:pass
                try:w.DeleteKeyEx(w.HKEY_CURRENT_USER,own,w.KEY_WOW64_64KEY)
                except FileNotFoundError:pass


if __name__=='__main__':unittest.main()
