"""Update safety fixtures only; no installed tasks/configs or remote endpoints."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from guarddesk.update_windows import image_processes, rename_protected
from guarddesk.update_native import NativeAdapter


class RenameSafetyTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        (self.source/'keep').write_bytes(b'old');self.target=self.root/'target'

    def test_destination_and_foreign_parent_are_never_overwritten(self):
        self.target.mkdir();(self.target/'keep').write_bytes(b'existing')
        with patch('guarddesk.update_native.protected_tree'),self.assertRaises(FileExistsError):
            rename_protected(self.source,self.target)
        self.assertEqual((self.target/'keep').read_bytes(),b'existing')
        with self.assertRaises(ValueError):rename_protected(self.source,self.root/'other/target')

    def test_only_transient_windows_errors_retry_and_revalidate(self):
        error=PermissionError('sensitive text must not be logged');error.winerror=32
        with patch('guarddesk.update_native.protected_tree') as guard, \
             patch.object(Path,'rename',side_effect=[error,None]) as rename, \
             patch('guarddesk.update_windows.time.sleep'):
            rename_protected(self.source,self.target)
            self.assertEqual(rename.call_count,2);self.assertEqual(guard.call_count,4)
        with patch('guarddesk.update_native.protected_tree'), \
             patch.object(Path,'rename',side_effect=FileNotFoundError('missing')) as rename:
            with self.assertRaises(FileNotFoundError):rename_protected(self.source,self.target)
            self.assertEqual(rename.call_count,1)

    def test_timeout_retains_original_windows_code_and_old_files(self):
        error=PermissionError('locked');error.winerror=32
        with patch('guarddesk.update_native.protected_tree'), \
             patch.object(Path,'rename',side_effect=error) as rename:
            with self.assertRaises(PermissionError) as caught:
                rename_protected(self.source,self.target,timeout=0)
            self.assertEqual(caught.exception.winerror,32);self.assertEqual(rename.call_count,1)
        self.assertEqual((self.source/'keep').read_bytes(),b'old')

    def test_lost_trust_on_retry_stops_before_another_rename(self):
        error=PermissionError('locked');error.winerror=32
        with patch('guarddesk.update_native.protected_tree',side_effect=[None,None,OSError('ACL changed')]), \
             patch.object(Path,'rename',side_effect=error) as rename, \
             patch('guarddesk.update_windows.time.sleep'):
            with self.assertRaises(OSError):rename_protected(self.source,self.target)
            self.assertEqual(rename.call_count,1)


@unittest.skipUnless(os.name=='nt','Windows process handles and directory sharing')
class WindowsExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.name='UpdateFixture'+uuid.uuid4().hex+'.exe'
        cls.exe=cls.root/cls.name;source=cls.root/'fixture.cs'
        source.write_text('using System;using System.Threading;class Fixture {'
                         'static void Main(string[] args){Console.WriteLine("ready");'
                         'Thread.Sleep(int.Parse(args[0]));}}',encoding='ascii')
        compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(cls.exe),str(source)],capture_output=True,timeout=30)
        if result.returncode:cls.temp.cleanup();raise AssertionError(result.stdout+result.stderr)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def child(self,milliseconds=700,exe=None,cwd=None):
        process=subprocess.Popen([str(exe or self.exe),str(milliseconds)],cwd=cwd,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(process.stdout.readline().strip(),'ready')
        self.addCleanup(lambda:process.communicate(timeout=10))
        return process

    def test_exact_path_handles_wait_for_exit_and_ignore_same_name_elsewhere(self):
        other=self.root/'other';other.mkdir(exist_ok=True)
        other_exe=other/self.name;other_exe.write_bytes(self.exe.read_bytes())
        first=self.child(700);second=self.child(2500,exe=other_exe)
        with image_processes(self.exe) as wait:
            with self.assertRaises(OSError) as caught:wait(time.monotonic())
            self.assertEqual(caught.exception.winerror,1460)
            wait(time.monotonic()+5)
        self.assertIsNotNone(first.poll());self.assertIsNone(second.poll())

    def test_stop_waits_for_process_after_worker_mutex_is_already_free(self):
        directory=self.root/'stop';directory.mkdir(exist_ok=True)
        exe=directory/self.name;exe.write_bytes(self.exe.read_bytes())
        child=self.child(700,exe=exe,cwd=directory)
        adapter=NativeAdapter.__new__(NativeAdapter);adapter.native=directory
        adapter.agent=SimpleNamespace(config={'device_id':uuid.uuid4().hex[:24]})
        def capture(expected):
            self.assertEqual(expected,directory/'GuardDesk.exe')
            return image_processes(exe)
        with patch.object(adapter,'_validate_task'),patch('guarddesk.update_native.task_command') as command, \
             patch('guarddesk.update_windows.image_processes',side_effect=capture):
            adapter.stop();command.assert_not_called()
        self.assertIsNotNone(child.poll())

    def test_real_locked_directory_is_retried_then_switched(self):
        source=self.root/('native-'+uuid.uuid4().hex);source.mkdir()
        (source/'keep').write_bytes(b'old');target=source.with_name(source.name+'-backup')
        child=self.child(700,cwd=source)
        with patch('guarddesk.update_native.protected_tree'):
            rename_protected(source,target,timeout=4)
        self.assertIsNotNone(child.poll());self.assertFalse(source.exists())
        self.assertEqual((target/'keep').read_bytes(),b'old')


class StopOrderTest(unittest.TestCase):
    def test_both_workers_capture_before_end_and_wait_before_return(self):
        from guarddesk.updater_refresh import WindowsAdapter
        for kind in ('native','updater'):
            events=[]
            @contextmanager
            def capture(path):
                events.append('capture');yield lambda deadline:events.append('wait')
            adapter=(NativeAdapter if kind=='native' else WindowsAdapter).__new__(NativeAdapter if kind=='native' else WindowsAdapter)
            adapter.agent=SimpleNamespace(config={'device_id':'f'*24});adapter.name='fixture'
            adapter.native=adapter.current=Path('fixed')
            validator='_validate_task' if kind=='native' else 'validate_task'
            @contextmanager
            def mutex(*args):
                events.append('mutex')
                if events.count('mutex')==1 and kind=='native':raise OSError('running')
                yield
            with patch.object(adapter,validator),patch('guarddesk.update_windows.image_processes',capture), \
                 patch('guarddesk.single_instance.machine_instance',mutex), \
                 patch('guarddesk.update_native.task_command',side_effect=lambda *args:events.append('end')):
                adapter.stop()
            self.assertEqual(events[0],'capture');self.assertEqual(events[-1],'wait')
            self.assertIn('end',events)


if __name__=='__main__':unittest.main()
