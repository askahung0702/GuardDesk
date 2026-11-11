"""Fixed-scope maintenance tests; never touch real protected files or tasks."""
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import test_system
import test_updates
from guarddesk import __version__,updater_refresh as refresh,update_packages as packages


class RefreshServerTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp;tearDown=test_system.SystemTest.tearDown;api=test_system.SystemTest.api
    make_agent=test_updates.UpdateServerTest.make_agent;upload=test_updates.UpdateServerTest.upload
    poll=test_updates.UpdateServerTest.poll;report=test_updates.UpdateServerTest.report
    def prepare(self):
        info=self.upload(test_updates.release(self.root/'refresh.zip',version=__version__))
        agent,did,_=self.make_agent()
        jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','legacy_preflight_confirmed':True})['job_ids'][0]
        self.poll(agent);self.report(agent,jid,'native','healthy',__version__)
        return info,agent,did,jid
    def ready(self):
        info,agent,did,jid=self.prepare();self.poll(agent,'main');self.report(agent,jid,'main','healthy',__version__)
        return info,agent,did,jid
    def test_native_then_main_completion_required_before_maintenance(self):
        info,agent,did,jid=self.prepare()
        result=agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})
        self.assertEqual(result['waiting_for'],'main_component')
        self.poll(agent,'main');self.report(agent,jid,'main','healthy',__version__)
        result=agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})
        lease=packages.verify(result['authorization'],packages.public_key(packages.signer(self.root)))
        self.assertEqual(lease['device_id'],did);self.assertEqual(lease['release_id'],info['id'])
        self.assertEqual(lease['operation'],'refresh_guarddesk_updater')
        self.assertLessEqual(lease['expires']-lease['created'],300)
        self.assertNotIn('path',lease);self.assertNotIn('command',lease)
    def test_lease_blocks_updates_cancellation_and_removal_until_completion(self):
        info,agent,did,jid=self.ready()
        lease=agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})['authorization']['payload']
        self.assertEqual(self.poll(agent)['waiting_for'],'updater_refresh')
        for path,body in [('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','legacy_preflight_confirmed':True}),('/api/updates/cancel',{'job_id':jid}),('/api/devices/uninstall',{'device_id':did})]:
            with self.assertRaises(urllib.error.HTTPError) as denied:self.api(path,body)
            self.assertEqual(denied.exception.code,409)
        self.assertIsNone(agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})['authorization'])
        agent.call('/api/agent/updater/complete',{'id':lease['id'],'state':'healthy'})
        agent.call('/api/agent/updater/complete',{'id':lease['id'],'state':'healthy'})
        catalog=self.api('/api/updates');self.assertEqual(catalog['updater_refresh'][0]['state'],'healthy')
        self.assertTrue(self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','legacy_preflight_confirmed':True})['job_ids'])
    def test_wrong_device_extra_fields_expiry_and_revocation(self):
        info,agent,did,jid=self.ready();other,_,_=self.make_agent()
        for caller,body in [(other,{'job_id':jid,'version':__version__}),(agent,{'job_id':jid,'version':__version__,'command':'cmd'})]:
            with self.assertRaises(ConnectionError):caller.call('/api/agent/updater/prepare',body)
        packet=agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})
        with self.store.connect() as db:db.execute('UPDATE updater_refresh SET expires=0 WHERE device_id=?',(did,))
        self.assertNotEqual(self.poll(agent).get('waiting_for'),'updater_refresh')
        with self.assertRaises(ConnectionError):other.call('/api/agent/updater/complete',{'id':packet['authorization']['payload']['id'],'state':'healthy'})
        with self.store.connect() as db:db.execute('UPDATE devices SET revoked=1 WHERE id=?',(did,))
        with self.assertRaises(ConnectionError):agent.call('/api/agent/updater/observed',{})
    def test_maintenance_progress_does_not_relabel_historical_jobs(self):
        info,agent,did,old=self.ready()
        jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','legacy_preflight_confirmed':True})['job_ids'][0]
        for role in ('native','main'):self.report(agent,jid,role,'healthy',__version__)
        agent.call('/api/agent/updater/prepare',{'job_id':jid,'version':__version__})
        jobs={j['id']:j for j in self.api('/api/updates')['jobs']}
        self.assertEqual(jobs[jid]['delivery']['code'],'updater_refresh')
        self.assertEqual(jobs[old]['delivery']['code'],'finished')


class RefreshTransactionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.key=Ed25519PrivateKey.generate();self.did='1'*24;self.jid='2'*32
        self.manifest={'format':1,'version':__version__,'architecture':'windows-x64','sha256':'3'*64,'bytes':123,
                       'files':{'GuardDesk.exe':'4'*64,'GuardDeskAgent.exe':'5'*64,'_internal/lib.dll':'6'*64}}
        self.job={'id':self.jid,'device_id':self.did,'release_id':self.manifest['sha256'],'release':packages.sign(self.key,self.manifest)}
        (self.root/'transaction-native.json').write_text(json.dumps({'phase':'healthy','reported':True,'version':__version__,'job':self.job}))
        self.events=[];self.health=True;self.stage_error=False
        owner=self
        class Adapter:
            root=owner.root
            def version(self):owner.events.append('version');return '0.4.16'
            def baseline(self):return {'GuardDesk.exe':'oldhash'}
            def cleanup(self,jid):owner.events.append('cleanup')
            def stage(self,job,manifest):
                owner.events.append('stage')
                if owner.stage_error:raise ValueError('tampered bytes')
            def stop(self):owner.events.append('stop')
            def switch(self,state):owner.events.append('switch')
            def start(self):owner.events.append('start')
            def health(self,*args):owner.events.append('health');return owner.health
            def rollback(self,state):owner.events.append('rollback')
        self.adapter=Adapter()
        self.agent=SimpleNamespace(config={'device_id':self.did,'update_key':packages.public_key(self.key)},config_path=self.root/'config.json',call=self.call)
        self.client=refresh.Refresh(self.agent,self.adapter)
        now=time.time();self.lease={'format':1,'operation':'refresh_guarddesk_updater','id':'7'*32,'device_id':self.did,'job_id':self.jid,'release_id':self.manifest['sha256'],'version':__version__,'created':now,'expires':now+300}
        self.offline=False
    def call(self,path,body):
        if path.endswith('/prepare'):self.events.append('authorization');return {'authorization':packages.sign(self.key,self.lease)}
        self.events.append('complete:'+body['state'])
        if self.offline:raise ConnectionError('offline')
        return {'ok':True}
    def test_handoff_order_success_and_no_repeated_probes(self):
        self.client.step()
        self.assertEqual(self.events,['version','authorization','cleanup','stage','stop','switch','start','health','complete:healthy'])
        self.assertFalse(refresh.pending(self.agent));self.events.clear();self.client.step();self.assertEqual(self.events,[])
    def test_signature_scope_time_and_operation_rejected_before_stop(self):
        for field,value in [('device_id','9'*24),('operation','run_shell'),('expires',time.time()-1),('version','0.4.99'),('release_id','0'*64),('expires',float('inf'))]:
            lease={**self.lease,field:value}
            with self.assertRaises(ValueError):
                if value==float('inf'):packages.sign(self.key,lease)
                else:refresh.authorization(packages.sign(self.key,lease),self.agent,self.job,self.manifest)
        packet=packages.sign(Ed25519PrivateKey.generate(),self.lease)
        with self.assertRaises(ValueError):refresh.authorization(packet,self.agent,self.job,self.manifest)
        self.assertNotIn('stop',self.events)
    def test_stage_failure_keeps_running_broker(self):
        self.stage_error=True
        with self.assertRaises(ValueError):self.client.step()
        self.assertNotIn('stop',self.events);self.assertEqual(refresh.read(self.client.state)['phase'],'failed')
    def test_baseline_failure_releases_lease_without_stopping_broker(self):
        with patch.object(self.adapter,'baseline',side_effect=OSError('untrusted ACL')):
            with self.assertRaises(OSError):self.client.step()
        self.assertNotIn('stop',self.events);self.assertIn('complete:failed',self.events)
    def test_health_failure_restores_and_marks_rollback(self):
        self.health=False;self.client.step()
        self.assertIn('rollback',self.events);self.assertEqual(refresh.read(self.client.state)['phase'],'rolled_back')
        self.assertFalse(refresh.pending(self.agent))
    def test_switch_error_keeps_safe_diagnostic_and_restores_broker(self):
        error=PermissionError('password=secret private path');error.winerror=32
        with patch.object(self.adapter,'switch',side_effect=error):self.client.step()
        state=refresh.read(self.client.state)
        self.assertEqual(state['failure'],{'stage':'switching','type':'PermissionError','winerror':32})
        self.assertEqual(state['phase'],'rolled_back');self.assertIn('rollback',self.events)
        self.assertNotIn('secret',self.client.state.read_text())
    def test_crash_recovery_is_local_and_offline_completion_is_durable(self):
        refresh.save(self.client.state,{'phase':'switching','job_id':self.jid,'lease_id':'7'*32,'old_version':'0.4.16','old_files':{}})
        self.offline=True;self.client.recover();state=refresh.read(self.client.state)
        self.assertEqual(state['phase'],'rolled_back');self.assertFalse(state['reported']);self.assertIn('rollback',self.events)
        self.offline=False;self.client.recover();self.assertTrue(refresh.read(self.client.state)['reported'])
    def test_newer_installed_broker_is_not_downgraded(self):
        self.adapter.version=lambda:'9.0.0';self.client.step();self.assertEqual(self.events,[])
    def test_partial_native_transaction_never_starts_handoff(self):
        record=refresh.read(self.root/'transaction-native.json');record['phase']='restarting'
        refresh.save(self.root/'transaction-native.json',record);self.client.step();self.assertEqual(self.events,[])


class ProtectedStageTest(unittest.TestCase):
    def test_windows_process_identity_uses_real_current_process(self):
        if os.name!='nt':self.skipTest('Windows API')
        from guarddesk.update_native import process_image
        # A venv's sys.executable can be a redirector; compare with the actual
        # current process module, not its launcher path. No product guard changes.
        import ctypes
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.GetModuleFileNameW.argtypes=[w.HMODULE,w.LPWSTR,w.DWORD];api.GetModuleFileNameW.restype=w.DWORD
        buffer=ctypes.create_unicode_buffer(32768)
        size=api.GetModuleFileNameW(None,buffer,len(buffer));self.assertTrue(0<size<len(buffer))
        self.assertEqual(process_image(os.getpid()),Path(buffer.value).resolve())

    def test_real_directory_switch_restore_and_interrupted_rename(self):
        for interrupted in (False,True):
            with self.subTest(interrupted=interrupted),tempfile.TemporaryDirectory() as temp:
                adapter=object.__new__(refresh.WindowsAdapter);adapter.program=Path(temp);adapter.current=adapter.program/'Updater'
                adapter.current.mkdir();(adapter.current/'GuardDesk.exe').write_bytes(b'old')
                jid='2'*32;stage,backup,failed=adapter.paths(jid)
                if not interrupted:stage.mkdir();(stage/'GuardDesk.exe').write_bytes(b'new')
                state={'job_id':jid,'old_version':__version__,'old_files':{'GuardDesk.exe':hashlib.sha256(b'old').hexdigest()}}
                with patch('guarddesk.update_native.protected_tree'),patch.object(adapter,'stop'),patch.object(adapter,'start'),patch.object(adapter,'version',return_value=__version__),patch.object(adapter,'health',return_value=True):
                    if interrupted:
                        with self.assertRaises(FileNotFoundError):adapter.switch(state)
                    else:
                        adapter.switch(state);self.assertEqual((adapter.current/'GuardDesk.exe').read_bytes(),b'new')
                    adapter.rollback(state)
                    self.assertEqual((adapter.current/'GuardDesk.exe').read_bytes(),b'old');self.assertFalse(backup.exists())
                    if not interrupted:self.assertEqual((failed/'GuardDesk.exe').read_bytes(),b'new')

    def test_corrupt_backup_is_preserved_and_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            adapter=object.__new__(refresh.WindowsAdapter);adapter.program=Path(temp);adapter.current=adapter.program/'Updater'
            _,backup,_=adapter.paths('2'*32);backup.mkdir();(backup/'GuardDesk.exe').write_bytes(b'tampered')
            with patch('guarddesk.update_native.protected_tree'),patch.object(adapter,'stop'),patch.object(adapter,'start') as start:
                with self.assertRaises(OSError):adapter.rollback({'job_id':'2'*32,'old_files':{'GuardDesk.exe':'0'*64}})
                start.assert_not_called();self.assertTrue(backup.exists())

    def test_stale_health_or_wrong_process_does_not_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);adapter=object.__new__(refresh.WindowsAdapter);adapter.current=root/'Updater'
            adapter.agent=SimpleNamespace(config_path=root/'config.json')
            now=time.time();record={'version':__version__,'native_version':__version__,'pid':os.getpid(),'time':now}
            refresh.save(root/'broker-health.json',record)
            with patch('guarddesk.update_native.process_image',return_value=root/'other.exe'):
                self.assertFalse(adapter.health(__version__,now-1,timeout=0))
            record['time']=now-100;refresh.save(root/'broker-health.json',record)
            with patch('guarddesk.update_native.process_image',return_value=adapter.current/'GuardDesk.exe'):
                self.assertFalse(adapter.health(__version__,now-1,timeout=0))

    def test_system_task_export_accepts_implicit_service_logon_and_rejects_foreign_identity(self):
        adapter=object.__new__(refresh.WindowsAdapter)
        adapter.current=Path(r'C:\Program Files\GuardDeskPilot\Updater')
        adapter.agent=SimpleNamespace(config_path=Path(r'C:\ProgramData\GuardDeskPilot\USBControl\111111111111111111111111\config.json'))
        adapter.name='GuardDesk-AgentUpdater-'+'1'*24
        xml=('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals>'
             '<Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
             '<Actions Context="Author"><Exec><Command>'+str(adapter.current/'GuardDesk.exe')+'</Command>'
             '<Arguments>update-service --config "'+str(adapter.agent.config_path)+'"</Arguments></Exec></Actions></Task>')
        for document in (xml,xml.replace('</UserId>','</UserId><LogonType>ServiceAccount</LogonType>')):
            with patch('guarddesk.update_native.task_xml',return_value=document):adapter.validate_task()
        for document in (xml.replace('S-1-5-18','S-1-5-19'),xml.replace('HighestAvailable','LeastPrivilege'),
                         xml.replace('</UserId>','</UserId><LogonType>InteractiveToken</LogonType>'),
                         xml.replace('Context="Author"','Context="Other"'),xml.replace('update-service','other'),
                         xml.replace('</Actions>','<ComHandler/></Actions>')):
            with patch('guarddesk.update_native.task_xml',return_value=document),self.assertRaises(OSError):adapter.validate_task()

    def test_real_extraction_and_hash_validation_before_any_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);native=root/'USBControl';native.mkdir();data=root/'data';data.mkdir();jid='2'*32;(data/jid).mkdir()
            contents={'GuardDesk.exe':b'console','GuardDeskAgent.exe':b'gui','_internal/lib.dll':b'lib'}
            for name,blob in contents.items():p=native/name;p.parent.mkdir(exist_ok=True);p.write_bytes(blob)
            archive=data/jid/'package.zip'
            with zipfile.ZipFile(archive,'w') as package:
                for name,blob in contents.items():package.writestr(name,blob)
            manifest={'format':1,'version':__version__,'architecture':'windows-x64','sha256':packages.file_hash(archive),'bytes':archive.stat().st_size,'files':{n:hashlib.sha256(b).hexdigest() for n,b in contents.items()}}
            adapter=object.__new__(refresh.WindowsAdapter);adapter.program=root;adapter.root=data;adapter.native=native
            with patch('guarddesk.update_native.protected_tree'),patch('guarddesk.updater_refresh.probe',return_value=__version__) as probe:
                adapter.stage({'id':jid},manifest);probe.assert_called_once()
                (native/'GuardDesk.exe').write_bytes(b'tampered')
                with self.assertRaises(ValueError):adapter.stage({'id':jid},manifest)
                self.assertEqual(probe.call_count,1)


if __name__=='__main__':unittest.main()

