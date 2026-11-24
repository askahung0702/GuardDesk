"""Real owned Win32 mutexes and actual Worker; no installed Agent/installer."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock,patch
import test_software_deployment as fixture
from guarddesk import software_client as client,software_msi as msi,update_packages as packages
from guarddesk.single_instance import machine_instance
from guarddesk.update_native import broker_scope
from guarddesk.update_native import installation_scope
from guarddesk.update_client import Transaction
import test_updates as updates
import threading

class IdleUpdaterMSITest(TestCase):
    def setUp(self):
        self.fixture=fixture.Worker();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.did=uuid.uuid4().hex[:24];self.agent=self.fixture.agent
        self.agent.config['device_id']=self.did;self.agent.config_path=self.fixture.root/'config.json'
        self.fixture.packet['device_id']=self.did
        self.agent.call=Mock(side_effect=lambda path,body:{'job':packages.sign(self.fixture.key,self.fixture.packet),'state':'downloading'} if path.endswith('/poll') else {'authorized':True})
        self.worker=client.Worker(self.agent,self.fixture.worker.stop,self.fixture.root)
    def owned_lock(self,kind,did):
        # Remap the machine-wide installation lock into a unique owned test name.
        return machine_instance(kind,self.did if kind=='native-installer-machine' else did)
    def prepare(self):
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(msi,'installed_version',side_effect=[None,'1.2.3']))
        stack.enter_context(patch.object(msi,'inspect',return_value=fixture.manifest()))
        stack.enter_context(patch.object(client,'download',side_effect=lambda a,j,p,s:p.write_bytes(b'owned fixture')))
        stack.enter_context(patch('guarddesk.native_browser_identity.signed_publisher',return_value='Owned Test'))
        stack.enter_context(patch('guarddesk.update_native.protected_tree'))
        stack.enter_context(patch.object(packages,'file_hash',return_value=fixture.PID))
        stack.enter_context(patch('guarddesk.single_instance.machine_instance',side_effect=self.owned_lock))
        stack.enter_context(patch.object(client.shutil,'disk_usage',return_value=SimpleNamespace(free=10*fixture.contract.GIB)))
        stack.enter_context(patch('guarddesk.performance.background_work'))
        return stack.enter_context(patch.object(client.subprocess,'Popen',return_value=SimpleNamespace(poll=lambda:0,returncode=0)))
    def test_idle_updater_remains_singleton_but_does_not_block_msi(self):
        launch=self.prepare()
        with broker_scope(self.agent):
            with self.assertRaises(OSError):
                with machine_instance('update',self.did):pass
            self.worker.cycle()
        result=json.loads(self.worker.journal.read_text(encoding='utf-8'))['result']
        self.assertEqual(result,{'job_id':fixture.JID,'state':'succeeded','error':'','exit_code':0})
        launch.assert_called_once()
    def test_actual_installation_lock_still_blocks_msi_before_launch(self):
        launch=self.prepare()
        with machine_instance('native-installer-machine',self.did):self.worker.cycle()
        result=json.loads(self.worker.journal.read_text(encoding='utf-8'))['result']
        self.assertEqual(result['state'],'failed');self.assertIn('INSTALL_LOCK',result['error'])
        launch.assert_not_called()

    def test_old_broker_defers_before_intent_then_resumes_same_job_once(self):
        launch=self.prepare()
        with patch.object(msi,'installed_version',side_effect=[None,None,'1.2.3']):
            with patch.object(client,'updater_coordinated',return_value=False):
                waiting=self.worker.cycle()
            self.assertEqual(waiting,{'state':'waiting_for_agent_update','protocol':1})
            self.assertEqual(json.loads(self.worker.journal.read_text(encoding='utf-8'))['phase'],'download')
            self.assertFalse(self.worker.payload.exists());launch.assert_not_called()
            self.worker.cycle()
        result=json.loads(self.worker.journal.read_text(encoding='utf-8'))['result']
        self.assertEqual(result['state'],'succeeded');launch.assert_called_once()

    def test_missing_new_broker_does_not_delay_existing_intent_review(self):
        launch=self.prepare();client.save(self.worker.journal,{'id':fixture.JID,'phase':'intent'})
        with patch.object(client,'updater_coordinated',return_value=False) as ready:self.worker.cycle()
        ready.assert_not_called();launch.assert_not_called()
        self.assertEqual(json.loads(self.worker.journal.read_text(encoding='utf-8'))['result']['state'],'review_required')

    def test_waiting_for_new_broker_still_allows_safe_preintent_cancellation(self):
        launch=self.prepare()
        with patch.object(client,'updater_coordinated',return_value=False):
            self.worker.cycle()
            self.agent.call=Mock(side_effect=lambda path,body:{'job':None} if path.endswith('/poll') else {'state':'cancelled'})
            self.worker.cycle()
        record=json.loads(self.worker.journal.read_text(encoding='utf-8'))
        self.assertEqual(record['result']['state'],'cancelled');self.assertTrue(record['acknowledged']);launch.assert_not_called()


class NativeUpdateCoordinationTest(TestCase):
    setUp=updates.UpdateTransactionTest.setUp

    def prepare(self,**adapter_options):
        self.owned=uuid.uuid4().hex[:24]
        def owned_lock(kind,did):
            return machine_instance(kind,self.owned if kind=='native-installer-machine' else did)
        context=patch('guarddesk.single_instance.machine_instance',side_effect=owned_lock);context.start();self.addCleanup(context.stop)
        adapter=updates.Adapter(self.root,**adapter_options)
        return adapter,Transaction(self.agent,'native',adapter,coordination=installation_scope)
    def assert_install_locked(self):
        with self.assertRaises(OSError):
            with machine_instance('native-installer-machine',self.owned):pass
    def assert_released(self):
        with machine_instance('native-installer-machine',self.owned):pass

    def test_apply_holds_shared_install_lock_at_program_stop_switch_and_start(self):
        adapter,tx=self.prepare();checked=[]
        for name in ('stop','switch','start'):
            original=getattr(adapter,name)
            def check(*args,_original=original,_name=name,**kwargs):
                self.assert_install_locked();checked.append(_name);return _original(*args,**kwargs)
            setattr(adapter,name,check)
        tx.apply(self.envelope)
        self.assertEqual(checked,['stop','switch','start']);self.assertEqual(adapter.value,'0.4.12')
        self.assertEqual(self.agent.config_path.read_bytes(),self.original);self.assertEqual(self.agent.queue_status()['pending'],1)
        self.assert_released()

    def test_install_lock_collision_prevents_update_journal_or_program_changes(self):
        adapter,tx=self.prepare()
        with machine_instance('native-installer-machine',self.owned):
            with self.assertRaises(OSError):tx.apply(self.envelope)
        self.assertFalse(tx.journal.exists());self.assertEqual(adapter.stops,0)
        self.assertEqual(adapter.value,'0.4.11');self.assertEqual(self.agent.config_path.read_bytes(),self.original)
        self.assert_released()

    def test_rollback_retains_shared_lock_and_releases_after_failed_health(self):
        adapter,tx=self.prepare(fail=True);original=adapter.rollback
        def rollback(state):self.assert_install_locked();return original(state)
        adapter.rollback=Mock(side_effect=rollback);tx.apply(self.envelope)
        adapter.rollback.assert_called_once();self.assertEqual(adapter.value,'0.4.11')
        self.assertEqual(json.loads(tx.journal.read_text(encoding='utf-8'))['phase'],'rolled_back');self.assert_released()

    def test_interrupted_recovery_cannot_rollback_while_msi_holds_install_lock(self):
        adapter,tx=self.prepare();adapter.value='broken'
        tx.write({'job':self.payload,'phase':'old_moved','old_version':'0.4.11','target':'0.4.12','started':0})
        before=tx.journal.read_bytes();original=adapter.rollback
        def rollback(state):self.assert_install_locked();return original(state)
        adapter.rollback=Mock(side_effect=rollback)
        with machine_instance('native-installer-machine',self.owned):
            with self.assertRaises(OSError):tx.recover()
        adapter.rollback.assert_not_called();self.assertEqual(tx.journal.read_bytes(),before)
        tx.recover();adapter.rollback.assert_called_once();self.assertEqual(adapter.value,'0.4.11');self.assert_released()

    def test_terminal_or_absent_recovery_does_not_acquire_install_lock(self):
        adapter,tx=self.prepare();tx.coordination=Mock(side_effect=AssertionError('Idle recovery must not block installation'))
        tx.recover()
        for phase in ('healthy','rolled_back','failed','downloading','prepared'):
            with self.subTest(phase=phase),patch.object(tx,'receipt'):
                tx.write({'job':self.payload,'phase':phase,'version':'0.4.11','reported':True});tx.recover()
        tx.coordination.assert_not_called()

    def test_native_broker_explicitly_wires_transaction_coordination(self):
        from guarddesk.update_native import run
        self.owned=uuid.uuid4().hex[:24];self.agent.config['device_id']=self.owned
        stop=threading.Event()
        def poll(path,body,**kwargs):stop.set();return {'job':None}
        self.agent.call=Mock(side_effect=poll)
        adapter=Mock();adapter.current.return_value='0.4.112'
        with patch('guarddesk.agent.Agent',return_value=self.agent),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.decommission.saved',return_value=None),patch('guarddesk.update_native.NativeAdapter',return_value=adapter),patch('guarddesk.update_native.Transaction') as factory,patch('guarddesk.updater_refresh.pending',return_value=False),patch('guarddesk.update_notify.Waiter'):
            run(self.agent.config_path,stop)
        factory.assert_called_once_with(self.agent,'native',adapter,coordination=installation_scope)
        factory.return_value.recover.assert_called_once()
        health=json.loads((self.agent.config_path.parent/'broker-health.json').read_text(encoding='utf-8'))
        self.assertEqual(health['install_coordination'],1)


class BrokerReadinessTest(TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'Software';self.root.mkdir();self.path=self.root.parent/'broker-health.json'
        self.health={'install_coordination':1,'version':'0.4.113','time':990,'pid':123}
        clock=patch.object(client.time,'time',return_value=1000);clock.start();self.addCleanup(clock.stop)
        acl=patch('guarddesk.update_native.protected_tree');acl.start();self.addCleanup(acl.stop);self.acl=acl
    def check(self,health):
        self.path.write_text(json.dumps(health),encoding='utf-8')
        with patch.object(client,'broker_process_alive',return_value=True) as process:
            ready=client.updater_coordinated(self.root)
        return ready,process
    def test_only_fresh_supported_broker_health_can_authorize_new_coordination(self):
        ready,process=self.check(self.health);self.assertTrue(ready);process.assert_called_once()
        for changes in ({'install_coordination':True},{'install_coordination':0},{'install_coordination':2},{'version':'0.4.112'},{'version':'invalid'},{'time':909},{'time':1001},{'time':True},{'time':float('nan')},{'time':float('inf')}):
            with self.subTest(changes=changes):
                ready,process=self.check({**self.health,**changes});self.assertFalse(ready);process.assert_not_called()
        legacy={k:v for k,v in self.health.items() if k!='install_coordination'}
        self.assertFalse(self.check(legacy)[0])
    def test_untrusted_missing_malformed_or_oversized_health_never_enables_install(self):
        self.assertFalse(client.updater_coordinated(self.root))
        for raw in ('{bad','[]','x'*4097):
            self.path.write_text(raw,encoding='utf-8');self.assertFalse(client.updater_coordinated(self.root))
        self.path.write_text(json.dumps(self.health),encoding='utf-8')
        with patch('guarddesk.update_native.protected_tree',side_effect=PermissionError('owned rejected ACL')):
            self.assertFalse(client.updater_coordinated(self.root))
        with patch.object(client,'broker_process_alive',return_value=False):self.assertFalse(client.updater_coordinated(self.root))
    def test_real_process_image_and_creation_time_reject_stale_pid_identity(self):
        # Only this owned test interpreter is queried; no installed broker access.
        # Windows venv python.exe is a redirector; the live image is the base
        # interpreter. Frozen Updater uses its actual fixed GuardDesk.exe path.
        expected=Path(getattr(sys,'_base_executable',sys.executable))
        # The deterministic health clock above is intentionally not a process timestamp.
        from datetime import datetime,timezone
        real_now=datetime.now(timezone.utc).timestamp()
        self.assertTrue(client.broker_process_alive(os.getpid(),real_now,expected))
        self.assertFalse(client.broker_process_alive(os.getpid(),0,expected))
        self.assertFalse(client.broker_process_alive(os.getpid(),real_now,expected.with_name('wrong-owned.exe')))
        self.assertFalse(client.broker_process_alive(True,real_now,expected))
        self.assertFalse(client.broker_process_alive(0,real_now,expected))
