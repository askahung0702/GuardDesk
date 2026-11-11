"""No UAC, real scheduled tasks, native replacement or real desktop changes."""
import hashlib
import io
import json
import shutil
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch
import test_system
from guarddesk import update_packages as packages
from guarddesk.agent import Agent,enroll
from guarddesk.update_client import Transaction,validate_job,remove_managed


def release(path,version='0.4.12',contents=None):
    contents=contents or {'GuardDesk/GuardDesk.exe':b'fixture console not executable','GuardDesk/GuardDeskAgent.exe':b'fixture GUI not executable','GuardDesk/_internal/runtime.dll':b'fixture runtime'}
    hashes={n:hashlib.sha256(v).hexdigest() for n,v in contents.items()}
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
        for n,v in contents.items():archive.writestr(n,v)
        archive.writestr('MANIFEST-SHA256.json',json.dumps(hashes));archive.writestr('build-info.json',json.dumps({'GuardDesk':version}))
    return path


class UpdateServerTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp;tearDown=test_system.SystemTest.tearDown;api=test_system.SystemTest.api
    def make_agent(self):
        count=getattr(self,'agent_count',0);self.agent_count=count+1
        token=self.api('/api/enrollments',{})['token'];config=self.root/f'agent{count}/config.json'
        did=enroll(config,self.url,token,self.watch,name='fixture'+str(count))
        return Agent(config),did,token

    def upload(self,path,csrf=True):
        headers={'Content-Type':'application/zip','X-GuardDesk-Authorize':'update-release'}
        if csrf:headers['X-CSRF-Token']=self.csrf
        with self.client.open(urllib.request.Request(self.url+'/api/updates/import',data=path.read_bytes(),headers=headers),timeout=10) as response:return json.load(response)

    def prepare(self):
        info=self.upload(release(self.root/'fixture.zip'));agent,did,_=self.make_agent()
        job=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy'})['job_ids'][0]
        return info,agent,did,job

    def poll(self,agent,role='native',version='0.4.11'):return agent.call('/api/agent/updates/poll',{'role':role,'version':version})
    def report(self,agent,jid,role,state,version='0.4.12'):return agent.call('/api/agent/updates/status',{'job_id':jid,'role':role,'state':state,'version':version})

    def test_signed_release_native_then_main_identity_and_durable_queue(self):
        info,agent,did,jid=self.prepare();agent.queue('file.created',{'fixture':True});config_before=agent.config_path.read_bytes()
        self.assertIsNone(self.poll(agent,'main')['job'])
        envelope=self.poll(agent)['job'];pinned=packages.public_key(packages.signer(self.root));job,manifest=validate_job(envelope,pinned,did)
        self.assertEqual(job['id'],jid);self.assertEqual(manifest['version'],'0.4.12')
        raw=urllib.request.Request(self.url+'/api/agent/updates/download?job_id='+jid,headers={'Authorization':'Bearer '+agent.config['token']})
        with urllib.request.urlopen(raw) as response:self.assertEqual(hashlib.sha256(response.read()).hexdigest(),manifest['sha256'])
        self.report(agent,jid,'native','applying','0.4.11');self.report(agent,jid,'native','healthy')
        self.assertIsNotNone(self.poll(agent,'main')['job']);self.report(agent,jid,'main','healthy')
        self.report(agent,jid,'main','healthy')  # Lost completion ACK is idempotent.
        result=self.api('/api/updates');self.assertEqual(result['jobs'][0]['status'],'completed')
        self.assertEqual(agent.config_path.read_bytes(),config_before);self.assertEqual(agent.queue_status()['pending'],1)

    def test_signature_device_scope_tamper_and_revoked_download(self):
        info,agent,did,jid=self.prepare();packet=self.poll(agent)['job'];key=packages.public_key(packages.signer(self.root))
        with self.assertRaises(ValueError):validate_job(packet,key,'f'*24)
        modified=json.loads(json.dumps(packet));modified['payload']['allow_downgrade']=1
        with self.assertRaises(ValueError):validate_job(modified,key,did)
        other,_,_=self.make_agent()
        request=urllib.request.Request(self.url+'/api/agent/updates/download?job_id='+jid,headers={'Authorization':'Bearer '+other.config['token']})
        with self.assertRaises(urllib.error.HTTPError) as denied:urllib.request.urlopen(request)
        self.assertEqual(denied.exception.code,409)
        self.api('/api/devices/revoke',{'device_id':did})
        request=urllib.request.Request(self.url+'/api/agent/updates/download?job_id='+jid,headers={'Authorization':'Bearer '+agent.config['token']})
        with self.assertRaises(urllib.error.HTTPError) as denied:urllib.request.urlopen(request)
        self.assertEqual(denied.exception.code,401)

    def test_roles_csrf_cancel_expiry_and_no_rollback_without_authority(self):
        path=release(self.root/'fixture.zip')
        with self.assertRaises(urllib.error.HTTPError) as denied:self.upload(path,csrf=False)
        self.assertEqual(denied.exception.code,403)
        info,agent,did,jid=self.prepare()
        self.api('/api/updates/cancel',{'job_id':jid});self.assertIsNone(self.poll(agent)['job'])
        with self.assertRaises(ConnectionError):self.report(agent,jid,'native','applying','0.4.11')
        jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy'})['job_ids'][0]
        self.poll(agent);self.report(agent,jid,'native','applying','0.4.11')
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/cancel',{'job_id':jid})
        self.assertEqual(denied.exception.code,409)
        with self.store.connect() as db:db.execute('UPDATE update_jobs SET expires=? WHERE id=?',(time.time()-1,jid))
        self.assertIsNone(self.poll(agent)['job'])
        import http.cookiejar
        reader=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.api('/api/login',{'username':'reader','password':self.password},client=reader)
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates',client=reader)
        self.assertEqual(denied.exception.code,403)

    def test_group_schedule_and_batch_limit_with_rollback_failure_status(self):
        info=self.upload(release(self.root/'fixture.zip'));agents=[self.make_agent()[0] for _ in range(3)]
        group=self.api('/api/groups',{'name':'update fixture','parent_id':None})
        child=self.api('/api/groups',{'name':'child','parent_id':group['id']})
        ids=[a.config['device_id'] for a in agents]
        for index,did in enumerate(ids):self.api('/api/devices/move',{'device_id':did,'group_id':child['id'] if index else group['id'],'revision':1})
        result=self.api('/api/updates/jobs',{'release_id':info['id'],'group_id':group['id'],'confirm':'deploy'})
        self.assertEqual(len(result['job_ids']),3)
        by_device={r['device_id']:r['id'] for r in self.api('/api/updates')['jobs']}
        self.assertIsNotNone(self.poll(agents[0])['job']);self.assertIsNotNone(self.poll(agents[1])['job'])
        self.assertEqual(self.poll(agents[2])['waiting_for'],'batch_slot')
        self.report(agents[0],by_device[ids[0]],'native','rolled_back','0.4.11')
        self.assertIsNotNone(self.poll(agents[2])['job'])
        self.assertEqual(next(j for j in self.api('/api/updates')['jobs'] if j['device_id']==ids[0])['status'],'failed')
    def test_future_schedule_waits_and_active_remote_session_defers_update(self):
        info=self.upload(release(self.root/'fixture.zip'));agent,did,_=self.make_agent()
        jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy','not_before':time.time()+3600})['job_ids'][0]
        self.assertIsNone(self.poll(agent)['job'])
        with self.store.connect() as db:db.execute('UPDATE update_jobs SET not_before=? WHERE id=?',(time.time()-1,jid))
        agent.call('/api/agent/remote/poll',{'account':'fixture','ready':True})
        grant=self.api('/api/remote/grant',{'username':'admin','device_id':did,'enabled':True,'can_control':True,'days':1})
        session=self.api('/api/remote/request',{'device_id':did,'mode':'view','reason':'update defer fixture'})
        agent.call('/api/agent/remote/update',{'session_id':session['id'],'action':'approve','account':'fixture'})
        self.assertEqual(self.poll(agent)['waiting_for'],'remote_assistance')

    def test_import_rejects_traversal_duplicate_version_and_secret(self):
        self.upload(release(self.root/'good.zip'))
        with self.assertRaises(urllib.error.HTTPError):self.upload(release(self.root/'changed.zip',contents={'GuardDesk/GuardDesk.exe':b'new','GuardDesk/GuardDeskAgent.exe':b'gui','GuardDesk/_internal/lib.dll':b'lib'}))
        for index,bad in enumerate(['GuardDesk/_internal/../../outside.exe','GuardDesk/_internal/secret.key','GuardDesk/_internal/CON.txt']):
            contents={'GuardDesk/GuardDesk.exe':b'a','GuardDesk/GuardDeskAgent.exe':b'b',bad:b'bad'}
            with self.assertRaises(urllib.error.HTTPError):self.upload(release(self.root/f'bad{index}.zip',contents=contents))
        self.assertEqual(len(self.api('/api/updates')['releases']),1)
        self.assertFalse((self.root/'outside.exe').exists())
        self.assertEqual(list(self.root.glob('update-import-*')),[])


class Adapter:
    def __init__(self,root,fail=False,crash=False):self.root=root;self.value='0.4.11';self.fail=fail;self.crash=crash;self.stops=0;self.switches=0
    def current(self):return self.value
    def probe(self,path):return '0.4.12'
    def stage(self,job):return self.root/('stage-'+job['id'])
    def validate_stage(self,path):pass
    def budget(self,incoming):pass
    def stop(self):self.stops+=1
    def switch(self,state,write):
        state['phase']='old_moved';write(state);self.switches+=1;self.value=state['target']
        if self.crash:raise OSError('simulated switch failure')
    def start(self,state,rollback):pass
    def health(self,version,started,timeout):return self.value==version and not (self.fail and version=='0.4.12')
    def rollback(self,state):self.value=state['old_version']
    def cleanup(self,state):pass


class UpdateTransactionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        (self.root/'docs').mkdir();cfg=self.root/'agent/config.json';cfg.parent.mkdir()
        self.private=packages.signer(self.root);key=packages.public_key(self.private)
        cfg.write_text(json.dumps({'server':'http://127.0.0.1:1','device_id':'a'*24,'token':'isolated-only','watch':str(self.root/'docs'),'update_key':key}))
        self.agent=Agent(cfg);self.agent.queue('file.created',{'fixture':True});self.original=cfg.read_bytes()
        self.staging=self.root/'import';self.staging.mkdir();manifest,self.archive=packages.import_release(release(self.root/'fixture.zip'),self.staging)
        now=time.time();self.payload={'id':'b'*32,'device_id':'a'*24,'release_id':manifest['sha256'],'created':now,'not_before':now,'expires':now+86400,'allow_downgrade':0,'release':packages.sign(self.private,manifest)}
        self.envelope=packages.sign(self.private,self.payload);self.reports=[]
        self.agent.call=lambda path,body:self.reports.append(body) or {'ok':True}
        self.download=patch('guarddesk.update_client.download',side_effect=lambda agent,job,manifest,target:shutil.copyfile(self.archive,target));self.download.start();self.addCleanup(self.download.stop)
    def test_success_preserves_identity_queue_and_verifies_before_stop(self):
        adapter=Adapter(self.root);tx=Transaction(self.agent,'native',adapter);tx.apply(self.envelope)
        self.assertEqual(adapter.value,'0.4.12');self.assertEqual(tx.journal.read_text(encoding='utf-8').count('healthy'),1)
        self.assertEqual(self.agent.config_path.read_bytes(),self.original);self.assertEqual(self.agent.queue_status()['pending'],1)
        before=adapter.stops;tx.apply(self.envelope);self.assertEqual(adapter.stops,before)
    def test_failed_health_and_failed_switch_restore_old_version(self):
        for index,kwargs in enumerate([{'fail':True},{'crash':True}]):
            payload={**self.payload,'id':str(index)*32,'created':time.time()};adapter=Adapter(self.root,**kwargs);tx=Transaction(self.agent,'native',adapter)
            tx.apply(packages.sign(self.private,payload));self.assertEqual(adapter.value,'0.4.11')
            self.assertEqual(json.loads(tx.journal.read_text(encoding='utf-8'))['phase'],'rolled_back')
    def test_safe_failure_stage_code_survives_rollback_and_server_report(self):
        adapter=Adapter(self.root);tx=Transaction(self.agent,'native',adapter)
        error=PermissionError('token=secret example private path');error.winerror=32
        with patch.object(adapter,'switch',side_effect=error):tx.apply(self.envelope)
        state=json.loads(tx.journal.read_text(encoding='utf-8'))
        self.assertEqual(state['failure'],{'stage':'switching','type':'PermissionError','winerror':32})
        self.assertEqual(state['phase'],'rolled_back')
        self.assertIn('程式目錄切換失敗（Windows 32）',self.reports[-1]['error'])
        self.assertNotIn('secret',tx.journal.read_text(encoding='utf-8'))
        self.assertNotIn('private path',json.dumps(self.reports))
    def test_rollback_failure_is_not_reported_as_rolled_back_or_healthy(self):
        adapter=Adapter(self.root,crash=True);tx=Transaction(self.agent,'native',adapter)
        with patch.object(adapter,'rollback',side_effect=OSError('private rollback text')):
            with self.assertRaises(OSError):tx.apply(self.envelope)
        state=json.loads(tx.journal.read_text(encoding='utf-8'))
        self.assertEqual(state['failure']['stage'],'switching')
        self.assertEqual(state['rollback_failure']['type'],'OSError')
        self.assertNotIn(state['phase'],('healthy','rolled_back'))
        self.assertNotIn('private rollback text',tx.journal.read_text(encoding='utf-8'))
    def test_failed_diagnostic_write_still_attempts_rollback(self):
        adapter=Adapter(self.root,crash=True);tx=Transaction(self.agent,'native',adapter)
        original=tx.write
        def write(state):
            if 'failure' in state and state['phase']!='rolled_back':raise OSError('disk write failed')
            original(state)
        with patch.object(tx,'write',side_effect=write):tx.apply(self.envelope)
        self.assertEqual(adapter.value,'0.4.11')
        self.assertEqual(json.loads(tx.journal.read_text(encoding='utf-8'))['phase'],'rolled_back')
    def test_download_tamper_and_wrong_binary_version_leave_old_running(self):
        adapter=Adapter(self.root);tx=Transaction(self.agent,'native',adapter)
        self.archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError):tx.apply(self.envelope)
        self.assertEqual(adapter.stops,0);self.assertEqual(adapter.value,'0.4.11')
    def test_wrong_probe_offline_download_and_explicit_downgrade(self):
        adapter=Adapter(self.root);adapter.probe=lambda path:'0.4.99';tx=Transaction(self.agent,'native',adapter)
        with self.assertRaises(ValueError):tx.apply(self.envelope)
        self.assertEqual(adapter.stops,0)
        payload={**self.payload,'id':'c'*32,'created':time.time()};envelope=packages.sign(self.private,payload)
        with patch('guarddesk.update_client.download',side_effect=ConnectionError('offline')):
            with self.assertRaises(ConnectionError):tx.apply(envelope)
        self.assertEqual(adapter.stops,0)
        manifest={**packages.verify(payload['release'],self.agent.config['update_key']),'version':'0.4.11'}
        adapter.value='0.4.12'
        payload.update(id='d'*32,created=time.time(),release=packages.sign(self.private,manifest))
        with self.assertRaises(ValueError):tx.apply(packages.sign(self.private,payload))
        payload.update(allow_downgrade=1);adapter.probe=lambda path:'0.4.11'
        tx.apply(packages.sign(self.private,payload));self.assertEqual(adapter.value,'0.4.11')
    def test_crash_journal_recovers_before_new_job_and_replay_is_rejected(self):
        adapter=Adapter(self.root);tx=Transaction(self.agent,'native',adapter)
        tx.write({'job':self.payload,'phase':'old_moved','old_version':'0.4.11','target':'0.4.12','started':time.time()})
        adapter.value='broken';tx.recover();self.assertEqual(adapter.value,'0.4.11')
        stale={**self.payload,'id':'c'*32,'created':self.payload['created']-10}
        with self.assertRaises(ValueError):tx.apply(packages.sign(self.private,stale))
    def test_cleanup_refuses_outside_scope_and_privileged_acl_requires_protected_owner(self):
        outside=self.root/'keep';outside.mkdir();(outside/'data').write_text('keep')
        with self.assertRaises(ValueError):remove_managed(self.root/'agent',outside,'.*')
        self.assertEqual((outside/'data').read_text(encoding='utf-8'),'keep')
        if __import__('os').name=='nt':
            from guarddesk.update_native import protected_tree
            with self.assertRaises(OSError):protected_tree(outside)
    def test_interrupted_stream_is_retryable_and_removes_partial_download(self):
        self.download.stop()  # Exercise the real streaming function, not the transaction fixture copy.
        from guarddesk.update_client import download,RetryUpdate
        from unittest.mock import MagicMock
        manifest=packages.verify(self.payload['release'],self.agent.config['update_key'])
        response=MagicMock();response.__enter__.return_value=response;response.headers={'Content-Length':str(manifest['bytes'])};response.read.side_effect=ConnectionResetError('fixture reset')
        opener=MagicMock();opener.open.return_value=response;target=self.root/'download.zip'
        with patch('guarddesk.update_client.transport',return_value=opener):
            with self.assertRaises(RetryUpdate):download(self.agent,self.payload,manifest,target)
        self.assertFalse(target.exists());self.assertFalse(target.with_suffix('.part').exists())
        self.assertEqual(self.agent.queue_status()['pending'],1)
