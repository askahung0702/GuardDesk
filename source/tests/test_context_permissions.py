import ctypes
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from guarddesk import context_permissions as cp
from guarddesk import document_context as dc


class ContextPermissionTest(unittest.TestCase):
    def test_fixed_code_only_validated_before_any_grant(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);native=root/'USBControl';native.mkdir()
            (native/'GuardDesk.exe').write_bytes(b'fixture')
            (native/'_internal').mkdir();(native/'_internal/own.dll').write_bytes(b'fixture')
            (root/'Updater').mkdir();(root/'Updater/secret.json').write_bytes(b'not-code')
            events=[]
            with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree',side_effect=lambda p,**kw:events.append(('validate',p))),patch.object(cp,'grant_read_execute',side_effect=lambda p:events.append(('grant',p)) or True):
                result=cp.repair_installed_runtime()
            grants=[p for action,p in events if action=='grant']
            self.assertEqual(result['checked'],5)
            self.assertEqual(set(grants),{root,native,native/'GuardDesk.exe',native/'_internal',native/'_internal/own.dll'})
            first=next(i for i,e in enumerate(events) if e[0]=='grant')
            self.assertEqual(first,5)

    def test_untrusted_or_private_tree_never_granted(self):
        for name in ('_internal/secret.key','config.json'):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);native=root/'USBControl';native.mkdir()
                (native/'GuardDesk.exe').write_bytes(b'fixture')
                bad=native/name;bad.parent.mkdir(exist_ok=True);bad.write_bytes(b'private')
                with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree'),patch.object(cp,'grant_read_execute') as grant:
                    with self.assertRaises(ValueError):cp.repair_installed_runtime()
                    grant.assert_not_called()
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch.object(cp,'grant_read_execute') as grant:
            with self.assertRaises(PermissionError):cp.repair_installed_runtime()
            grant.assert_not_called()

    def test_permission_validation_failure_precedes_any_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);native=root/'USBControl';native.mkdir();(native/'GuardDesk.exe').write_bytes(b'fixture')
            with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree',side_effect=PermissionError('fixture')),patch.object(cp,'grant_read_execute') as grant:
                with self.assertRaises(PermissionError):cp.repair_installed_runtime()
                grant.assert_not_called()

    def test_startup_cache_only_after_success(self):
        with patch.object(cp,'_ready',False),patch.object(cp,'repair_installed_runtime',side_effect=[OSError('retry'),{}]) as repair:
            with self.assertRaises(OSError):cp.ensure_installed_runtime()
            cp.ensure_installed_runtime();cp.ensure_installed_runtime()
            self.assertEqual(repair.call_count,2)

    @unittest.skipUnless(os.name=='nt','Windows DACL boundary')
    def test_actual_win32_merge_owner_preserved_no_write_granted_idempotent(self):
        from guarddesk.source_permissions import WindowsSecurity,WRITE_SOURCE
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'owned-fixture.bin';path.write_bytes(b'fixture')
            security=WindowsSecurity();before=security.descriptor(path)
            self.assertTrue(cp.grant_read_execute(path));after=security.descriptor(path)
            self.assertEqual(before[0],after[0])
            grants=[mask for kind,flags,mask,sid in after[1] if kind==0 and not flags&8 and sid==cp.USERS]
            self.assertTrue(any(mask&cp.READ_EXECUTE==cp.READ_EXECUTE for mask in grants))
            self.assertFalse(any(mask&WRITE_SOURCE for mask in grants))
            self.assertFalse(cp.grant_read_execute(path))

    def test_bounded_launch_failure_metadata(self):
        c=dc.Context();exc=ctypes.WinError(5);exc.context_stage='create_user_process'
        c.failure('launch',exc)
        status=c.status();self.assertEqual(status['errors'],1)
        self.assertEqual(status['last_error']['operation'],'create_user_process')
        self.assertEqual(status['last_error']['winerror'],5)
        self.assertNotIn('message',status['last_error'])

    def test_listener_does_not_poison_valid_active_session(self):
        with patch('guarddesk.custom_windows.session_information',return_value={'locked':False,'logon':10,'idle':0}) as query:
            states=dc.user_session_states([(0,4),(2,0),(65536,6)])
            self.assertEqual(set(states),{2});query.assert_called_once_with(2)

    def test_real_session_failure_is_unknown_and_other_session_survives(self):
        with patch('guarddesk.custom_windows.session_information',side_effect=[ctypes.WinError(5),{'locked':False,'logon':10,'idle':0}]):
            states=dc.user_session_states([(1,0),(2,0)])
        c=dc.Context();c.states=states
        self.assertTrue(states[1]['query_failed']);self.assertFalse(states[2].get('query_failed'))
        self.assertEqual(c.status()['active_sessions'],2);self.assertEqual(c.status()['session_query_failures'],1)
        why,_=c.classify({'process_session_id':1,'process_identity_status':'creation_time_checked'},0,30)
        self.assertEqual(why,'context_unavailable')


if __name__=='__main__':unittest.main()
