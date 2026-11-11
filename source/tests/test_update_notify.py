"""Isolated notification channels, simulated update jobs; no real Windows tasks."""
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error

import test_system
import test_updates
from guarddesk.update_notify import Signals,Waiter


class UpdateNotifyTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp;tearDown=test_system.SystemTest.tearDown;api=test_system.SystemTest.api
    make_agent=test_updates.UpdateServerTest.make_agent;upload=test_updates.UpdateServerTest.upload;prepare=test_updates.UpdateServerTest.prepare
    poll=test_updates.UpdateServerTest.poll;report=test_updates.UpdateServerTest.report

    def waiting(self,agent,role='native'):
        cursor=agent.call('/api/agent/updates/wait',{'role':role,'cursor':None})['cursor']
        result=[];errors=[]
        def wait():
            try:result.append(agent.call('/api/agent/updates/wait',{'role':role,'cursor':cursor},timeout=5))
            except (OSError,ConnectionError) as exc:errors.append(str(exc))
        thread=threading.Thread(target=wait);thread.start()
        deadline=time.monotonic()+2
        while not self.server.update_signals.connected(agent.config['device_id'],role) and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(self.server.update_signals.connected(agent.config['device_id'],role))
        return thread,result,errors

    def test_create_job_wakes_waiter_after_commit_without_holding_database(self):
        info=self.upload(test_updates.release(self.root/'fixture.zip'));agent,did,_=self.make_agent();thread,result,errors=self.waiting(agent)
        try:
            self.api('/api/groups',{'name':'write while long poll','parent_id':None})
            start=time.monotonic();jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy'})['job_ids'][0]
            thread.join(2);self.assertFalse(thread.is_alive());self.assertFalse(errors)
            self.assertTrue(result[0]['changed']);self.assertLess(time.monotonic()-start,2)
            self.assertEqual(self.poll(agent)['job']['payload']['id'],jid)
        finally:self.server.update_signals.notify([did]);thread.join(5)

    def test_notice_is_device_scoped_and_native_completion_wakes_main(self):
        info,agent,did,jid=self.prepare();thread,result,errors=self.waiting(agent,'main')
        try:
            self.server.update_signals.notify(['f'*24]);time.sleep(.05);self.assertTrue(thread.is_alive())
            self.assertEqual(self.poll(agent,'main')['waiting_for'],'native')
            self.poll(agent);self.report(agent,jid,'native','healthy')
            thread.join(2);self.assertFalse(thread.is_alive());self.assertFalse(errors)
            self.assertIsNotNone(self.poll(agent,'main')['job'])
        finally:self.server.update_signals.notify([did]);thread.join(5)

    def test_admin_nudge_preserves_future_schedule_and_requires_csrf(self):
        info,agent,did,jid=self.prepare()
        with self.store.connect() as db:db.execute('UPDATE update_jobs SET not_before=? WHERE id=?',(time.time()+600,jid))
        thread,result,errors=self.waiting(agent)
        try:
            for bad in ({'job_id':[]},{'job_id':'bad'},{'job_id':jid,'shell':'bad'}):
                with self.assertRaises(urllib.error.HTTPError) as malformed:self.api('/api/updates/notify',bad)
                self.assertEqual(malformed.exception.code,400)
            with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/updates/notify',{'job_id':jid},csrf=False)
            self.assertEqual(exc.exception.code,403)
            reply=self.api('/api/updates/notify',{'job_id':jid});self.assertEqual(reply['connected_roles'],['native'])
            thread.join(2);self.assertTrue(result[0]['changed']);self.assertFalse(errors)
            self.assertIsNone(self.poll(agent)['job']);self.assertEqual(self.api('/api/updates')['jobs'][0]['delivery']['code'],'scheduled')
            with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/updates/notify',{'job_id':jid})
            self.assertEqual(exc.exception.code,429)
        finally:self.server.update_signals.notify([did]);thread.join(5)

    def test_revoked_credentials_cannot_receive_notification(self):
        agent,did,_=self.make_agent();thread,result,errors=self.waiting(agent)
        self.api('/api/devices/revoke',{'device_id':did});self.server.update_signals.notify([did]);thread.join(2)
        self.assertFalse(result);self.assertTrue(errors);self.assertIn('HTTP 401',errors[0])
        for body in ({'role':'system','cursor':None},{'role':'native','cursor':'bad'},{'role':'native','cursor':None,'shell':'bad'}):
            other,_,_=self.make_agent()
            with self.assertRaises(ConnectionError):other.call('/api/agent/updates/wait',body)

    def test_delivery_distinguishes_missing_broker_diagnostics_legacy_and_remote(self):
        info,agent,did,jid=self.prepare();agent.heartbeat(refresh_inventory=False)
        self.assertEqual(self.api('/api/updates')['jobs'][0]['delivery']['code'],'native_unreported')
        agent.call('/api/agent/updates/diagnostic',{'role':'native','version':'0.4.15','code':'initialization_failed'})
        self.assertEqual(self.api('/api/updates')['jobs'][0]['delivery']['code'],'initialization_failed')
        with self.assertRaises(ConnectionError):agent.call('/api/agent/updates/diagnostic',{'role':'native','version':'0.4.15','code':'secret exception text'})
        with self.store.connect() as db:db.execute('DELETE FROM update_diagnostics')
        self.poll(agent)
        self.assertEqual(self.api('/api/updates')['jobs'][0]['delivery']['code'],'updating')
        # Connected channel status must not masquerade as healthy/completed.
        with self.store.connect() as db:db.execute("UPDATE update_status SET state='queued' WHERE job_id=?",(jid,))
        thread,result,errors=self.waiting(agent)
        try:
            job=self.api('/api/updates')['jobs'][0];self.assertEqual(job['delivery']['code'],'notified');self.assertEqual(job['status'],'pending')
        finally:self.server.update_signals.notify([did]);thread.join(5)

    def test_verified_https_channel_and_bad_ca_rejected(self):
        import json
        from test_server_deployment import certificate
        from guarddesk.server import serve
        from guarddesk.agent import Agent
        cert,key=certificate(self.root/'tls');server=serve(self.db,port=0,cert=cert,key=key,surface='agent',shared=self.server)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            agent,did,_=self.make_agent();settings={**agent.config,'server':f'https://127.0.0.1:{server.server_port}','ca':str(cert)}
            agent.config_path.write_text(json.dumps(settings),encoding='utf-8');secure=Agent(agent.config_path)
            self.assertEqual(secure.call('/api/agent/updates/wait',{'role':'native','cursor':None})['notification_protocol'],1)
            other_cert,_=certificate(self.root/'wrong-tls');settings['ca']=str(other_cert)
            agent.config_path.write_text(json.dumps(settings),encoding='utf-8')
            with self.assertRaises(ConnectionError):Agent(agent.config_path).call('/api/agent/updates/wait',{'role':'native','cursor':None})
        finally:server.shutdown();server.server_close();thread.join(5)


class UpdateNotifyPureTest(unittest.TestCase):
    def test_local_check_requires_admin_and_never_starts_a_transaction(self):
        from guarddesk.update_native import check_installed
        from pathlib import Path
        import json
        import tempfile
        with patch('guarddesk.windows_privilege.is_admin',return_value=False):
            with self.assertRaises(PermissionError):check_installed('a'*24)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);did='a'*24;config=root/'USBControl'/did/'config.json';config.parent.mkdir(parents=True)
            config.write_text(json.dumps({'device_id':did,'token':'sensitive fixture token'}))
            with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree'),patch('guarddesk.update_native.NativeAdapter') as adapter,patch('guarddesk.update_native.task_command') as task,patch('guarddesk.update_native.Transaction') as transaction:
                adapter.return_value.current.return_value='0.4.13';result=check_installed(did)
                self.assertTrue(result['passed']);self.assertNotIn('sensitive',str(result));self.assertTrue(adapter.call_args.kwargs['check_only'])
                task.assert_not_called();transaction.assert_not_called()
                with self.assertRaises(ValueError):check_installed('../bad')

    def test_mutex_startup_failure_is_reported_before_exit(self):
        from guarddesk.update_native import run
        from pathlib import Path
        import tempfile
        calls=[]
        class FakeAgent:
            config={'device_id':'a'*24}
            def __init__(self,path):self.config_path=Path(path)
            def call(self,path,body,**kwargs):calls.append(body);return {'ok':True}
        with tempfile.TemporaryDirectory() as temp,patch('guarddesk.agent.Agent',FakeAgent),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.single_instance.machine_instance',side_effect=OSError('private mutex diagnostic')):
            with self.assertRaises(OSError):run(Path(temp)/'config.json',threading.Event())
        self.assertEqual(calls[0]['code'],'initialization_failed');self.assertNotIn('private mutex',str(calls))

    def test_bounded_slots_targeting_and_shutdown(self):
        from guarddesk.management import ManagementError
        signals=Signals(maximum=1,wait_seconds=2);cursor=signals.wait('device','native',None)['cursor'];received=[]
        thread=threading.Thread(target=lambda:received.append(signals.wait('device','native',cursor)));thread.start()
        deadline=time.monotonic()+1
        while not signals.connected('device','native') and time.monotonic()<deadline:time.sleep(.01)
        with self.assertRaises(ManagementError):signals.wait('other','main',None)
        signals.notify(['other']);time.sleep(.03);self.assertTrue(thread.is_alive());signals.close();thread.join(1)
        self.assertEqual(received[0]['retry_after'],5)
        for i in range(1100):signals.notify([str(i)])
        self.assertLessEqual(len(signals.revisions),1024)

    def test_old_server_falls_back_without_busy_loop(self):
        class Agent:
            calls=0
            def call(self,*args,**kwargs):self.calls+=1;raise ConnectionError('管理中心拒絕請求：HTTP 404')
        class Stop:
            delays=[]
            def is_set(self):return False
            def wait(self,seconds):self.delays.append(seconds)
        agent=Agent();stop=Stop();waiter=Waiter('native');waiter.wait(agent,stop);waiter.wait(agent,stop)
        self.assertEqual(agent.calls,1);self.assertEqual(stop.delays,[30,30])

    def test_native_initialization_failure_is_reported_and_retried_without_update(self):
        from contextlib import nullcontext
        from guarddesk.update_native import run
        from pathlib import Path
        import tempfile
        stop=threading.Event();calls=[]
        class FakeAgent:
            config={'device_id':'a'*24}
            def __init__(self,path):self.config_path=Path(path)
            def call(self,path,body,**kwargs):calls.append((path,body));stop.set();return {'ok':True}
        with tempfile.TemporaryDirectory() as temp,patch('guarddesk.agent.Agent',FakeAgent),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.single_instance.machine_instance',return_value=nullcontext()),patch('guarddesk.decommission.saved',return_value=None),patch('guarddesk.update_native.NativeAdapter',side_effect=RuntimeError('private detail not uploaded')):
            run(Path(temp)/'config.json',stop)
        self.assertEqual(calls[0][1]['code'],'initialization_failed');self.assertNotIn('private detail',str(calls))
