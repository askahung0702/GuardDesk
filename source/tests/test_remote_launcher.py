"""CMD startup regression, no company Agent, login or remote session."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class RemoteLauncherTest(unittest.TestCase):
    def test_windows_entry_points_use_crlf(self):
        for name in (p.name for p in ROOT.glob('*.cmd')):
            data=(ROOT/name).read_bytes()
            self.assertNotIn(b'\n',data.replace(b'\r\n',b''),name)
            self.assertGreater(data.count(b'\r\n'),5)

    @unittest.skipUnless(os.name=='nt','Windows CMD required')
    def test_missing_runtime_message_survives_real_cmd_from_other_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as temp:
            folder=Path(temp)/'啟動檔 中文與空白';folder.mkdir()
            for name,needle in (('Start-Remote.cmd','完整 GuardDesk'),('Diagnose-Remote.cmd','找不到 GuardDesk')):
                path=folder/name;path.write_bytes((ROOT/name).read_bytes())
                result=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(path)],cwd=ROOT,
                    input=b'\r\n',capture_output=True,timeout=10)
                self.assertEqual(result.returncode,2)
                self.assertIn(needle,result.stdout.decode('utf-8',errors='replace'))
                self.assertEqual(result.stderr,b'')
