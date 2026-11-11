import copy
import json
import sqlite3
import urllib.error
import unittest
from contextlib import closing
from unittest.mock import patch
import test_system
from guarddesk.agent import Agent
from guarddesk import decommission
from guarddesk.server_backup import snapshot


class RemovalTest(unittest.TestCase):
    def setUp(self):
        test_system.SystemTest.setUp(self)
        # These fixtures use temporary configs, never the signed-in user's
        # actual Native Host / Run entries or installed SYSTEM tasks.
        for name in ('guarddesk.browser_host.unregister_owned',
                     'guarddesk.endpoint_setup.remove_autostart_for_config',
                     'guarddesk.update_native.remove_broker_task'):
            boundary=patch(name);boundary.start();self.addCleanup(boundary.stop)
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def prepare(self):
        agent,did,_=self.make_agent();agent.heartbeat()
        packet=agent.call('/api/agent/native-usb-policy',{})
        agent.call('/api/agent/native-usb-status',{**packet,'status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':0},'worker_version':'0.4.4'})
        return agent,did,{'device_id':did,'confirm_name':'test-endpoint','reason':'isolated uninstall test'}

    def test_permission_name_version_scope_and_no_premature_revoke(self):
        agent,did,body=self.prepare()
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/devices/uninstall',body,csrf=False)
        self.assertEqual(denied.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/devices/uninstall',{**body,'confirm_name':'wrong'})
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/devices/uninstall',body)
        self.assertEqual(denied.exception.code,403)
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        job=self.api('/api/devices/uninstall',body)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/devices/uninstall',body)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/devices/revoke',{'device_id':did})
        with self.assertRaises(ConnectionError):agent.call('/api/agent/uninstall/status',{'job_id':job['id'],'role':'native','state':'ready'})
        with self.assertRaises(ConnectionError):agent.call('/api/agent/uninstall/status',{'job_id':'another-device-job','role':'main','state':'working'})
        for role in ('main','native'):agent.call('/api/agent/uninstall/status',{'job_id':job['id'],'role':role,'state':'ready'})
        self.assertEqual(self.api('/api/device-detail?device_id='+did)['device']['uninstall']['status'],'completed')
        self.api('/api/devices/revoke',{'device_id':did})

    def test_old_worker_rejected_and_queued_job_expires_without_execution(self):
        agent,did,body=self.prepare()
        with self.store.connect() as db:
            db.execute('UPDATE native_usb_status SET body=? WHERE device_id=?',(json.dumps({'worker_version':'0.4.3'}),did))
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/devices/uninstall',body)
        with self.store.connect() as db:db.execute('UPDATE native_usb_status SET body=? WHERE device_id=?',(json.dumps({'worker_version':'0.4.4'}),did))
        self.api('/api/devices/uninstall',body)
        with self.store.connect() as db:db.execute('UPDATE endpoint_removals SET expires=0')
        self.assertIsNone(agent.call('/api/agent/uninstall/poll',{'role':'main'})['job'])
        self.assertFalse(decommission.main_step(agent));self.assertIsNone(decommission.saved(agent))

    def test_main_drains_then_native_restores_with_fixed_operations_and_retries_ack(self):
        agent,did,body=self.prepare();job=self.api('/api/devices/uninstall',body)
        agent.queue('file.created',{'path':'test.txt'})
        self.assertTrue(decommission.main_step(agent));self.assertTrue(agent.decommissioned)
        restored=Agent(agent.config_path)
        self.assertTrue(decommission.main_step(restored))
        # Separate database models the separately protected SYSTEM outbox.
        directory=self.root/'protected';directory.mkdir();config=directory/'config.json';config.write_text(agent.config_path.read_text())
        class Worker:
            def __init__(self):self.agent=Agent(config)
            def restore(self):return {'status':'restored'}
        worker=Worker();worker.agent.queue('application.started',{'process':'test.exe'})
        original=worker.agent.call
        failed=[False]
        def lose_ack(path,packet):
            result=original(path,packet)
            if path.endswith('/status') and packet['state']=='ready' and not failed[0]:
                failed[0]=True;self.api('/api/devices/revoke',{'device_id':did});raise ConnectionError('lost ACK')
            return result
        with patch('guarddesk.application_control.ExtendedWorker.restore',return_value={'status':'restored'}) as restore,patch.object(worker,'restore',wraps=worker.restore) as usb,patch('guarddesk.decommission.remove_task') as task,patch.object(worker.agent,'call',side_effect=lose_ack):
            self.assertEqual(decommission.native_step(worker),'pending')
            self.assertEqual(decommission.native_step(worker),'done')
            restore.assert_called_once();usb.assert_called_once();task.assert_called_once_with(worker.agent)
        self.assertEqual(self.api('/api/device-detail?device_id='+did)['device']['uninstall']['status'],'completed')
        self.assertTrue(config.exists());self.assertTrue(worker.agent.state.exists())

    def test_proxy_preflight_and_restore_conflict_do_not_fake_success(self):
        agent,did,body=self.prepare();self.api('/api/devices/uninstall',body)
        agent.config_path.write_text(json.dumps({**agent.config,'proxy_enabled':True}))
        with patch.object(agent,'close_collectors') as close:
            self.assertFalse(decommission.main_step(agent));close.assert_not_called();self.assertIsNone(decommission.saved(agent))
        agent.config_path.write_text(json.dumps(agent.config));self.assertTrue(decommission.main_step(agent))
        config=self.root/'native.json';config.write_text(agent.config_path.read_text())
        class Worker:
            def __init__(self):self.agent=Agent(config)
            def restore(self):raise OSError('company policy conflict')
        worker=Worker()
        with patch('guarddesk.application_control.ExtendedWorker.restore'),patch('guarddesk.decommission.remove_task') as task:
            self.assertEqual(decommission.native_step(worker),'pending');task.assert_not_called()
        self.assertEqual(self.api('/api/device-detail?device_id='+did)['device']['uninstall']['status'],'failed')

    def test_task_identity_rejects_foreign_actions_and_config(self):
        exe=r'C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe';config=r'C:\ProgramData\GuardDeskPilot\USBControl\test\config.json'
        xml='<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>'+exe+'</Command><Arguments>usb-worker --extended --config "'+config+'"</Arguments></Exec></Actions></Task>'
        decommission.validate_task(xml,exe,config)
        for other in (xml.replace('usb-worker','other'),xml.replace(config,config+'.other'),xml.replace('GuardDesk.exe','other.exe'),xml.replace('</Actions>','<ComHandler/></Actions>'),'bad xml'):
            with self.assertRaises(OSError):decommission.validate_task(other,exe,config)

    def test_migration_snapshot_preserves_business_data_and_does_not_modify_source(self):
        agent,did,body=self.prepare();self.api('/api/devices/uninstall',body)
        target=self.root/'migration.sqlite3';result=snapshot(self.db,target,True)
        self.assertTrue(result['migration']);self.assertFalse(result['source_modified'])
        with closing(sqlite3.connect(target)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(db.execute('SELECT id FROM devices').fetchone()[0],did)
            self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM endpoint_removals').fetchone()[0],1)
        with self.store.connect() as db:self.assertGreater(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
        with self.assertRaises(FileExistsError):snapshot(self.db,target)
        self.assertEqual(self.api('/api/state')['devices'][0]['id'],did)


if __name__=='__main__':unittest.main()
