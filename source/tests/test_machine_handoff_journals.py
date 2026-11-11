"""Large completed journals must not deadlock the machine-session handoff."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from guarddesk import __version__
from guarddesk.native_installer import assert_quiescent,read_json
from guarddesk.machine_agent_windows import Platform
from guarddesk.machine_agent import Supervisor
from guarddesk import update_packages as packages
import test_system
import test_updates


def full_journal(phase='healthy'):
    files={f'_internal/runtime/module-{i:04}.dll':'a'*64 for i in range(1055)}
    return {'phase':phase,'reported':True,'version':__version__,
            'job':{'release':{'payload':{'files':files},'signature':'owned-fixture'}}}


class JournalSizeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'updates').mkdir()

    def write(self,phase='healthy',name='transaction-native.json'):
        p=self.root/'updates'/name;p.write_text(json.dumps(full_journal(phase)),encoding='utf-8')
        self.assertGreater(p.stat().st_size,65536)
        return p

    def test_realistic_completed_manifest_allows_platform_launch(self):
        for name in ['transaction-native.json','updater-refresh.json']:
            with self.subTest(name=name):
                self.write(name=name)
                self.assertTrue(Platform.can_launch(SimpleNamespace(agent=SimpleNamespace(config_path=self.root/'config.json'))))

    def test_large_in_progress_and_unknown_journals_remain_blocked(self):
        for phase in ['downloading','prepared','switching','restarting','unexpected']:
            with self.subTest(phase=phase):
                self.write(phase)
                with self.assertRaises(OSError):assert_quiescent(self.root)

    def test_legacy_manifest_size_and_config_bound_are_independent(self):
        p=self.write();raw=p.read_bytes()
        with self.assertRaises(ValueError):read_json(p)  # config reader remains 64 KiB
        p.write_bytes(raw+b' '*(600*1024-len(raw)))
        assert_quiescent(self.root)
        p.write_bytes(p.read_bytes()+b' ')
        assert_quiescent(self.root)  # legacy phase no longer depends on 600 KiB
        p.write_bytes(b'{invalid')
        with self.assertRaises(OSError):assert_quiescent(self.root)


class HandoffCompletionTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_updates.UpdateServerTest.make_agent
    upload=test_updates.UpdateServerTest.upload

    def test_large_journal_session_heartbeat_completes_real_signed_job(self):
        self.handoff(False)

    def test_small_control_session_heartbeat_completes_real_signed_job(self):
        self.handoff(True)

    def handoff(self,new_format):
        info=self.upload(test_updates.release(self.root/'owned.zip',version=__version__))
        agent,did,_=self.make_agent()
        jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','legacy_preflight_confirmed':True})['job_ids'][0]
        agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.60'})
        agent.call('/api/agent/updates/status',{'job_id':jid,'role':'native','state':'healthy','version':__version__})
        with self.store.connect() as db:
            db.execute('INSERT INTO extended_status VALUES (?,?,?)',(did,json.dumps({'machine_agent':{'scope':'machine','version':__version__,'helpers':0,'errors':1}}),time.time()))
        blocked=agent.call('/api/agent/updates/poll',{'role':'main','version':'0.4.60'})
        self.assertEqual(blocked.get('waiting_for'),'machine_agent_handoff')
        waiting=self.api('/api/updates')['jobs'][0]
        self.assertEqual(waiting['delivery']['code'],'machine_agent_handoff')
        self.assertEqual(waiting['status'],'pending')
        updates=agent.config_path.parent/'updates';updates.mkdir()
        p=updates/'transaction-native.json'
        if new_format:
            from guarddesk.update_client import save
            save(p,full_journal())
        else:p.write_text(json.dumps(full_journal()),encoding='utf-8')
        self.assertGreater(p.stat().st_size,65536)
        originals={agent.config_path:agent.config_path.read_bytes(),p:p.read_bytes()}
        agent.queue('web.navigation',{'fixture':'preserve offline event'},event_id='owned-handoff-event')
        states={1:{'sid':'S-1-5-21-11','account':'EXAMPLE\\A','logon':10,'active':True,'locked':False}}
        platform=SimpleNamespace(sessions=lambda:states,launch=Mock(return_value=SimpleNamespace(alive=lambda:True,close=Mock())),
                                 agent=agent)
        platform.can_launch=lambda:Platform.can_launch(platform)
        supervisor=Supervisor(agent,threading.Event(),platform)
        supervisor.tick();self.assertEqual(platform.launch.call_count,1)
        supervisor.report_main_update()
        self.assertEqual(self.api('/api/updates')['jobs'][0]['status'],'pending')
        agent.config['update_key']=packages.public_key(packages.signer(self.root))
        supervisor.router.dispatch({'path':'/api/agent/heartbeat','body':{'inventory':{'agent_version':__version__}}},
                                   {'session':1,'sid':states[1]['sid'],'logon':10})
        supervisor.report_main_update()
        job=self.api('/api/updates')['jobs'][0]
        self.assertEqual(job['status'],'completed')
        self.assertEqual(job['components']['main']['state'],'healthy')
        self.assertEqual(agent.queue_status()['pending'],1)
        for path,body in originals.items():self.assertEqual(path.read_bytes(),body)


if __name__=='__main__':unittest.main()

