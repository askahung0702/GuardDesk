"""Owned package trees and child fixture only; no installed endpoint update."""
from pathlib import Path
import tempfile
import time
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from guarddesk.remote_components import validate_layout,installed_images,REMOTE_FILES,COHORT_MANIFEST,cohort_manifest
from guarddesk.update_packages import file_hash
from guarddesk.update_native import NativeAdapter
from test_update_windows import WindowsExitTest


def write_owned_cohort(root,worker_bytes=b'owned fixture'):
    remote=Path(root)/'_internal/remote';remote.mkdir(parents=True,exist_ok=True)
    for name in REMOTE_FILES:(remote/name).write_bytes(worker_bytes)
    manifest=cohort_manifest({name:file_hash(remote/name) for name in REMOTE_FILES},build_id='f'*64)
    (remote/COHORT_MANIFEST).write_text(json.dumps(manifest),encoding='utf-8')
    return remote


class ComponentLayoutTest(unittest.TestCase):
    def test_top_level_sidecar_is_rejected_instead_of_silently_omitted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'GuardDeskRemoteWorker.exe').write_bytes(b'owned fixture')
            with self.assertRaises(ValueError):validate_layout(root)

    def test_fixed_internal_components_are_included_and_caller_names_are_not_supported(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);remote=write_owned_cohort(root)
            worker=remote/'GuardDeskRemoteWorker.exe'
            (remote/'untrusted.exe').write_bytes(b'not a launchable component')
            self.assertEqual(installed_images(root),[root/'GuardDesk.exe',worker,remote/'GuardDeskRemoteMedia.exe'])
            self.assertEqual(len(validate_layout(root)),4)

    def test_partial_missing_tampered_or_claimed_accepted_cohort_is_refused(self):
        for fault in ('missing','tampered','accepted','no_manifest'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);remote=write_owned_cohort(root)
                if fault=='missing':(remote/'GuardDeskRemoteMedia.exe').unlink()
                if fault=='tampered':(remote/'GuardDeskRemoteBridge.dll').write_bytes(b'other build')
                if fault=='no_manifest':(remote/COHORT_MANIFEST).unlink()
                if fault=='accepted':
                    value=json.loads((remote/COHORT_MANIFEST).read_text());value['state']='field_accepted'
                    (remote/COHORT_MANIFEST).write_text(json.dumps(value))
                with self.assertRaises(ValueError):validate_layout(root)

    def test_legacy_without_remote_components_remains_valid(self):
        with tempfile.TemporaryDirectory() as folder:self.assertEqual(validate_layout(Path(folder)),[])


class SidecarExitTest(WindowsExitTest):
    def test_waits_for_owned_sidecar_after_main_worker_exits(self):
        root=self.root/'remote-sidecar';remote=write_owned_cohort(root,self.exe.read_bytes())
        worker=remote/'GuardDeskRemoteWorker.exe'
        child=self.child(900,exe=worker)
        adapter=NativeAdapter.__new__(NativeAdapter);adapter.native=root
        adapter.agent=SimpleNamespace(config={'device_id':'a'*24})
        from guarddesk.update_windows import image_processes
        def owned_processes(image):
            # Main image is represented by our uniquely named fixture, never
            # inspect an installed company's SYSTEM GuardDesk process.
            return image_processes(self.exe if image==root/'GuardDesk.exe' else image)
        with patch.object(adapter,'_validate_task'),patch('guarddesk.update_native.task_command') as task,patch('guarddesk.update_windows.image_processes',side_effect=owned_processes):
            adapter.stop();task.assert_not_called()
        self.assertIsNotNone(child.poll())


if __name__=='__main__':unittest.main()
