import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import source_permissions as source

USER='S-1-5-21-1-2-3-1001'
OTHER='S-1-5-32-545'
ALLOWED={USER,source.SYSTEM,source.ADMINISTRATORS,source.TRUSTED_INSTALLER}


class SourcePermissionsTest(unittest.TestCase):
    def test_windows_root_create_folder_and_inherit_only_are_not_replacement(self):
        aces=[(0,0,4,OTHER),(0,8,0xE0010000,OTHER),(0,0,0x1f01ff,source.SYSTEM)]
        source.validate_descriptor('C:\\',source.TRUSTED_INSTALLER,aces,ALLOWED,ancestor=True)
        with self.assertRaises(source.SourcePermissionError):source.validate_descriptor('application',USER,aces,ALLOWED)

    def test_parent_delete_child_write_dacl_owner_or_generic_write_are_blocked(self):
        for right in (0x10,0x100,0x40,0x10000,0x40000,0x80000,0x40000000,0x10000000,2):
            with self.subTest(right=right),self.assertRaises(source.SourcePermissionError):
                source.validate_descriptor('ancestor',USER,[(0,0,right,OTHER)],ALLOWED,ancestor=True)

    def test_source_other_user_modification_is_still_blocked(self):
        for right in (2,4,0x10,0x40,0x100,0x10000,0x1301bf):
            with self.subTest(right=right),self.assertRaises(source.SourcePermissionError):
                source.validate_descriptor('application',USER,[(0,0,right,OTHER)],ALLOWED)

    def test_untrusted_owner_is_blocked_even_with_read_only_dacl(self):
        with self.assertRaises(source.SourcePermissionError) as exc:
            source.validate_descriptor('application',OTHER,[(0,0,0x1200a9,OTHER)],ALLOWED)
        self.assertEqual(exc.exception.reason,'untrusted_owner')

    def test_inherit_only_deny_and_read_entries_do_not_grant_writes(self):
        source.validate_descriptor('application',USER,[(0,8,0x1f01ff,OTHER),(1,0,0x1f01ff,None),(0,0,0x1200a9,OTHER)],ALLOWED)
        with self.assertRaises(source.SourcePermissionError):
            source.validate_descriptor('child',USER,[(0,16,2,OTHER)],ALLOWED)

    def test_unsupported_write_grant_remains_fail_closed(self):
        with self.assertRaises(source.SourcePermissionError):
            source.validate_descriptor('application',USER,[(9,0,2,None)],ALLOWED)

    def test_tree_checks_actual_children_and_direct_parent_with_location(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'source';root.mkdir();child=root/'unsafe.dll';child.write_bytes(b'synthetic')
            visited=[]
            def descriptor(path):
                visited.append(path)
                return USER,[(0,0,2,OTHER)] if path==child else []
            with patch.object(source,'WindowsSecurity') as native:
                native.return_value.current_user.return_value=USER
                native.return_value.descriptor.side_effect=descriptor
                with self.assertRaises(source.SourcePermissionError) as error:source.check_source(root,threading.Event())
            self.assertEqual(error.exception.path,str(child));self.assertEqual(error.exception.reason,'untrusted_write')
            self.assertIn(root.parent,visited);self.assertEqual(visited[0],root.parent)

    def test_cancel_stops_without_scanning_or_registration(self):
        stop=threading.Event();stop.set()
        with patch.object(source,'WindowsSecurity') as native:
            native.return_value.current_user.return_value=USER
            with self.assertRaises(InterruptedError):source.check_source(Path.cwd(),stop)
            native.return_value.descriptor.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows ACL readback')
    def test_real_system_drive_read_only_check_does_not_require_private_root(self):
        api=source.WindowsSecurity();root=Path.cwd().parents[-1]
        owner,aces=api.descriptor(root)
        # Validate the same real descriptor twice; the API only reads security.
        before=(owner,aces)
        source.validate_descriptor(root,owner,aces,{*ALLOWED,api.current_user()},ancestor=True)
        self.assertEqual(api.descriptor(root),before)
