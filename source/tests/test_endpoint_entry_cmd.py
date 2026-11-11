"""Actual CMD with owned argument-only EXE; no Agent, center or UAC is run."""
import base64,json,os,subprocess,tempfile,unittest
from pathlib import Path
from guarddesk.endpoint_package import SETUP,UPGRADE


class EndpointEntryCmdTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.addClassCleanup(cls.tmp.cleanup)
        code=cls.root/'OwnedArguments.cs';cls.stub=cls.root/'OwnedArguments.exe'
        code.write_text('using System; using System.Text; class OwnedArguments { static int Main(string[] args) { Console.WriteLine("ARGS64="+Convert.ToBase64String(Encoding.UTF8.GetBytes(String.Join("\\n",args)))); return Int32.Parse(Environment.GetEnvironmentVariable("OWNED_ENTRY_EXIT_CODE") ?? "0"); } }',encoding='utf-8')
        result=subprocess.run(['C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe','/nologo','/target:exe','/out:'+str(cls.stub),str(code)],capture_output=True,timeout=30)
        if result.returncode:raise AssertionError(result.stdout)

    def fixture(self,raw,missing=None):
        root=self.root/('中文 路徑 (測試) '+str(len(list(self.root.iterdir()))));root.mkdir()
        for name in ('GuardDesk/GuardDesk.exe','GuardDesk/GuardDeskAgent.exe',
                'GuardDesk/_internal/agent-release.json','endpoint-files.json','endpoint-connection.json','update-trust.json'):
            file=root/name;file.parent.mkdir(parents=True,exist_ok=True)
            file.write_bytes(self.stub.read_bytes() if name=='GuardDesk/GuardDesk.exe' else b'owned nonexecuted fixture')
        if missing:(root/missing).unlink()
        (root/'Entry.cmd').write_bytes(raw)
        return root

    def run_entry(self,root,page=950,code=0):
        parent=root/'Owned-Launch.cmd'
        parent.write_bytes(('@echo off\r\nchcp '+str(page)+' >nul\r\ncall "%~dp0Entry.cmd"\r\n'
            'set "owned_result=%errorlevel%"\r\nchcp 65001 >nul\r\nexit /b %owned_result%\r\n').encode('ascii'))
        env=os.environ.copy();env['OWNED_ENTRY_EXIT_CODE']=str(code)
        result=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(parent)],input=b'\r\n',capture_output=True,timeout=15,cwd=self.root,env=env)
        output=result.stdout+result.stderr
        self.assertNotIn(b'is not recognized',output);self.assertNotIn(b'Syntax error',output)
        return result.returncode,output

    def test_control_files_are_ascii_crlf_without_code_page_transition(self):
        for raw in (SETUP,UPGRADE):
            raw.decode('ascii');self.assertNotIn(b'chcp',raw.lower());self.assertNotIn(b'\n',raw.replace(b'\r\n',b''))
            self.assertNotIn(b'\xef\xbb\xbf',raw)

    def test_complete_entries_preserve_exact_argv_for_three_parent_code_pages(self):
        for raw,upgrade in ((SETUP,False),(UPGRADE,True)):
            root=self.fixture(raw)
            for page in (437,950,65001):
                with self.subTest(upgrade=upgrade,page=page):
                    code,output=self.run_entry(root,page);self.assertEqual(code,0)
                    encoded=next(n for n in output.splitlines() if n.startswith(b'ARGS64='))[7:]
                    args=base64.b64decode(encoded).decode('utf-8').split('\n')
                    expected=['endpoint-setup']+(['--upgrade-existing'] if upgrade else [])+['--connection',str(root/'endpoint-connection.json')]
                    self.assertEqual(args,expected);self.assertIn(b'ExitCode=0',output)

    def test_every_missing_prerequisite_names_exact_path_without_launching(self):
        for raw in (SETUP,UPGRADE):
            for name in ('GuardDesk/GuardDesk.exe','GuardDesk/GuardDeskAgent.exe','GuardDesk/_internal/agent-release.json',
                    'endpoint-files.json','endpoint-connection.json','update-trust.json'):
                root=self.fixture(raw,name)
                with self.subTest(upgrade=raw==UPGRADE,missing=name):
                    code,output=self.run_entry(root);self.assertEqual(code,2);self.assertNotIn(b'ARGS64=',output)
                    self.assertIn(name.replace('/','\\').encode('ascii'),output)
                    self.assertIn(b'ExitCode=2',output)

    def test_backend_failure_code_is_not_replaced_by_pause_or_echo(self):
        for raw in (SETUP,UPGRADE):
            root=self.fixture(raw);code,output=self.run_entry(root,code=17)
            self.assertEqual(code,17);self.assertIn(b'ExitCode=17',output)

    def test_connection_only_directory_is_rejected_without_creating_runtime(self):
        root=self.root/'只有連線';root.mkdir();(root/'endpoint-connection.json').write_text('{}')
        (root/'Entry.cmd').write_bytes(UPGRADE)
        code,output=self.run_entry(root);self.assertEqual(code,2)
        self.assertIn(b'GuardDesk\\GuardDesk.exe',output);self.assertNotIn(b'ARGS64=',output)
        self.assertFalse((root/'runtime').exists())
