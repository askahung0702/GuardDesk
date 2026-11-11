"""Fresh-process role checks; no installed Agent, elevation or network access."""
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


SOURCE = Path(__file__).resolve().parents[1]
GUARD = '''
import importlib.abc
import sys
from unittest.mock import Mock, patch
class NoCenter(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'guarddesk.server' or fullname.startswith('guarddesk.server.'):
            raise AssertionError('Endpoint attempted to load center: '+fullname)
sys.meta_path.insert(0, NoCenter())
import guarddesk.__main__ as cli
assert 'guarddesk.server' not in sys.modules
'''


class CliRoleImportsTest(unittest.TestCase):
    def fresh(self, code):
        # A separate interpreter prevents a previous server test from hiding an
        # accidental import through sys.modules. All relative writes stay here.
        runtime = SOURCE / 'runtime'
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            script = 'import sys\nsys.path.insert(0, '+repr(str(SOURCE))+')\n'+GUARD+textwrap.dedent(code)
            result = subprocess.run([sys.executable, '-B', '-X', 'utf8', '-c', script],
                                    cwd=directory, capture_output=True, text=True,
                                    encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+'\n'+result.stderr)
        return result.stdout

    def test_import_does_not_load_center(self):
        self.fresh('')

    def test_component_info_without_center(self):
        output = self.fresh('''
            sys.argv = ['GuardDesk', 'component-info']
            cli.main()
            assert 'guarddesk.server' not in sys.modules
        ''')
        import json
        self.assertIsInstance(json.loads(output), dict)

    def test_standard_worker_dispatch_without_center(self):
        self.fresh('''
            import types
            from guarddesk import remote_trial
            remote_trial.ENABLED = False
            worker = Mock()
            module = types.ModuleType('guarddesk.native_usb')
            module.UsbWorker = Mock(return_value=worker)
            sys.modules[module.__name__] = module
            sys.argv = ['GuardDesk', 'usb-worker', '--config', 'owned-config', '--extended']
            cli.main()
            module.UsbWorker.assert_called_once_with('owned-config')
            worker.run.assert_called_once()
            assert worker.run.call_args.kwargs == {'extended': True}
            assert 'guarddesk.server' not in sys.modules
        ''')

    def test_trial_worker_dispatch_without_center(self):
        self.fresh('''
            from guarddesk import remote_trial
            sys.argv = ['GuardDesk', 'usb-worker', '--config', 'owned-config', '--once']
            with patch.object(remote_trial, 'ENABLED', True), patch.object(remote_trial, 'worker', return_value=None) as worker:
                cli.main()
                worker.assert_called_once()
                assert worker.call_args.args[0] == 'owned-config'
                assert worker.call_args.kwargs == {'once': True, 'restore': False}
            assert 'guarddesk.server' not in sys.modules
        ''')

    def test_explicit_serve_still_dispatches(self):
        self.fresh('''
            import types
            module = types.ModuleType('guarddesk.server')
            module.serve = Mock(return_value=object())
            sys.modules[module.__name__] = module
            sys.argv = ['GuardDesk', 'serve', '--db', 'owned.sqlite3', '--host', '127.0.0.1', '--port', '12345']
            with patch.object(cli, 'run_server') as run:
                cli.main()
            module.serve.assert_called_once_with('owned.sqlite3', '127.0.0.1', 12345, None, None)
            run.assert_called_once()
            assert run.call_args.args[0] is module.serve.return_value
        ''')

    def test_existing_config_serve_preserves_startup(self):
        self.fresh('''
            import types
            from pathlib import Path
            config = types.ModuleType('guarddesk.server_config')
            config.load = Mock(return_value={'db':'owned.sqlite3', 'local_console_port':12345})
            config.start = Mock(return_value=[object()])
            setup = types.ModuleType('guarddesk.server_setup')
            setup.maintenance_launcher = Mock()
            sys.modules[config.__name__] = config
            sys.modules[setup.__name__] = setup
            sys.argv = ['GuardDesk', 'serve', '--config', 'existing/server.json', '--open-console']
            with patch.object(cli, 'run_servers') as run:
                cli.main()
            config.load.assert_called_once_with('existing/server.json')
            config.start.assert_called_once_with(config.load.return_value)
            setup.maintenance_launcher.assert_called_once_with(Path('existing').resolve(), Path(sys.executable))
            run.assert_called_once()
            assert run.call_args.args[0] is config.start.return_value
            assert run.call_args.args[2] == 'http://127.0.0.1:12345'
        ''')

    def test_add_user_keeps_store_behavior_without_center(self):
        self.fresh('''
            import guarddesk.store as store
            sys.argv = ['GuardDesk', 'add-user', 'owned-user', '--db', 'owned.sqlite3', '--role', 'support']
            with patch.object(store, 'Store') as factory, patch.object(cli.getpass, 'getpass', return_value='test-only'):
                cli.main()
                factory.assert_called_once_with('owned.sqlite3')
                factory.return_value.add_user.assert_called_once_with('owned-user', 'test-only', 'support')
            assert 'guarddesk.server' not in sys.modules
        ''')

    def test_demo_keeps_local_store_digest_and_server(self):
        self.fresh('''
            import threading, types
            from pathlib import Path
            from guarddesk.store import Store
            module = types.ModuleType('guarddesk.server')
            server = Mock()
            module.serve = Mock(return_value=server)
            sys.modules[module.__name__] = module
            stop = threading.Event()
            stop.set()
            def enroll_owned(config, *args, **kwargs):
                config.parent.mkdir(parents=True)
                config.write_text('{}', encoding='utf-8')
            with patch.object(cli, 'enroll', side_effect=enroll_owned), patch.object(cli, 'Agent'):
                cli.demo(stop)
            dbpath = Path('runtime/control.sqlite3').resolve()
            module.serve.assert_called_once_with(dbpath)
            server.shutdown.assert_called_once()
            server.server_close.assert_called_once()
            with Store(dbpath).connect() as db:
                row = db.execute('SELECT token FROM enrollments').fetchone()
                assert row and len(row[0]) == 64
        ''')
