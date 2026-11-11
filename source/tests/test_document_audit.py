import copy
import io
import json
import tempfile
import time
import unittest
import urllib.error
import zipfile
from pathlib import Path
from urllib.parse import urlencode
import test_system
from guarddesk import document_audit as docs
from guarddesk.browser_host import handle_message,extension_id
from guarddesk.browser_deployment import artifact,changes,execute,KEYS
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import Store


class DocumentAuditTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_unified_documents_preserve_original_ids_legacy_filter_and_csv(self):
        agent,did,_=self.make_agent()
        try:
            with self.store.connect() as db:
                for kind in ('file.opened','file.created','file.moved','web.upload_started','web.upload_response','web.upload_failed','web.navigation','application.started'):
                    Store.event(db,did,kind,'info',{'source_path':r'C:\owned\report.txt','url':'https://example.test/upload'},occurred=time.time()-1)
            def fetch(**q):return self.api('/api/events?'+urlencode({'device':did,**q}))
            originals=fetch(limit=200)['items']
            expected=[r for r in originals if r['kind'].startswith(('file.','web.upload_'))]
            result=fetch(category='documents',limit=200)
            self.assertEqual([r['id'] for r in result['items']],[r['id'] for r in expected])
            self.assertEqual([r['hash'] for r in result['items']],[r['hash'] for r in expected])
            self.assertEqual(fetch(category='files')['total'],3)
            first=fetch(category='documents',limit=2,cursor_mode=1)
            second=fetch(category='documents',limit=2,cursor_mode=1,cursor=first['next_cursor'])
            self.assertFalse({r['id'] for r in first['items']} & {r['id'] for r in second['items']})
            csv=self.api('/api/events.csv?'+urlencode({'device':did,'category':'documents'})).decode('utf-8-sig')
            self.assertIn('web.upload_response',csv);self.assertIn('file.opened',csv);self.assertNotIn('web.navigation',csv)
        finally:agent.close_collectors()

    def test_handshake_ttl_legacy_and_disabled_policy_do_not_fabricate_uploads(self):
        agent,did,_=self.make_agent()
        try:
            handle_message(agent,{'type':'status'})
            self.assertEqual(docs.browser_status(agent)['status'],'awaiting_extension')
            with self.assertRaises(ValueError):handle_message(agent,{'type':'status','browser':'chrome','extension_version':'<script>'})
            message={'type':'status','browser':'chrome','extension_version':'0.4.0'}
            handle_message(agent,message)
            self.assertEqual(docs.browser_status(agent)['browsers'][0]['status'],'connected_limited')
            self.assertEqual(docs.browser_status(agent)['browsers'][1]['status'],'not_observed')
            with agent.db() as db:
                saved=json.loads(db.execute('SELECT value FROM state WHERE key=?',(docs.SESSION_KEY,)).fetchone()[0])
                self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],0)
            docs.browser_handshake(agent,message,now=saved['chrome']['seen']+1)
            with agent.db() as db:self.assertEqual(json.loads(db.execute('SELECT value FROM state WHERE key=?',(docs.SESSION_KEY,)).fetchone()[0]),saved)
            self.assertEqual(docs.browser_status(agent,now=saved['chrome']['seen']+181)['status'],'awaiting_extension')
            self.assertEqual(docs.browser_status(agent,False)['status'],'disabled')
            agent.heartbeat()
            detail=self.api('/api/device-detail?device_id='+did)['device']['document_audit']
            self.assertEqual(detail['upload']['status'],'connected_limited')
            self.assertEqual(detail['copy']['status'],'worker_not_reported')
            self.assertEqual(detail['read']['status'],'worker_not_reported')
            self.assertEqual(detail['configuration']['status'],'general_policy_enabled')
            self.assertEqual(detail['configuration']['read_roots'],0)
        finally:agent.close_collectors()

    def test_desired_scope_never_claims_observed_read_and_keeps_collector_failure(self):
        from guarddesk.document_settings import packet
        policy=copy.deepcopy(DEFAULT_POLICY);now=time.time()
        device={'extended_status':{'received':now,'document_read':{'status':'collector_failed'},
                                  'document_provisioning':{'status':'monitoring_periodic','managed_objects':3}},'inventory':{}}
        scope=packet([{'path':r'C:\Company\Documents','recursive':True,'read':True,'copy':False}])
        value=docs.readiness(device,policy,now=now,documents=scope)
        self.assertEqual(value['configuration']['read_roots'],1)
        self.assertEqual(value['read']['collector_status'],'collector_failed')
        self.assertNotIn('last_read_observed',value['read'])
        self.assertEqual(value['upload']['status'],'agent_not_reported')

    def test_general_read_worker_queue_reaches_center_without_custom_assignment(self):
        from guarddesk.document_worker import DocumentWorker
        from unittest.mock import patch
        from test_general_file_audit import Trace
        agent,did,_=self.make_agent()
        try:
            agent.heartbeat();agent.config['audit_watch']=r'C:\Owned'
            worker=DocumentWorker(agent,agent.config_path.parent);worker.trusted=True
            worker.policy=copy.deepcopy(DEFAULT_POLICY)
            worker.policy['file_audit']={'enabled':True,'scope':'managed','exclude_paths':[r'C:\Owned\excluded']}
            now=time.time()
            worker.context.states={1:{'active':True,'locked':False,'logon':10,'time':now}}
            worker.context.samples={1:[{'session':1,'time':now,'idle_ms':1000,'input_tick':100,'foreground_pid':123,'desktop':True}]}
            identity={'process_identity_status':'creation_time_checked','process_session_id':1,'process_created':now-60,'process':r'C:\Apps\editor.exe'}
            with patch('guarddesk.document_io.NativeTrace',Trace),patch.object(worker.context,'poll'),patch('guarddesk.document_process.ProcessResolver.resolve',return_value=identity),patch('guarddesk.document_sacl.Manager',side_effect=AssertionError('No SACL for general audit')):
                worker.cycle()
                base={'pid':123,'op':'read','bytes':32,'offset':0,'status':0,'open_id':1,'occurred':now}
                worker.trace.events=[{**base,'path':r'C:\Owned\x.txt'},{**base,'path':r'C:\Owned\excluded\hidden.txt'}]
                worker.cycle()
            agent.flush()
            rows=self.api('/api/events?'+urlencode({'device':did,'kind':'file.opened'}))['items']
            self.assertEqual(len(rows),1);self.assertEqual(rows[0]['details']['evidence'],'completed_native_read')
            self.assertEqual(rows[0]['details']['path'],r'C:\Owned\x.txt')
            self.assertEqual(rows[0]['details']['interaction'],'recent_input_foreground')
        finally:agent.close_collectors()

    def test_package_requires_admin_and_has_no_private_signing_key(self):
        payload=self.api('/api/browser-deployment-package',{})
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            settings=json.loads(archive.read('browser-deployment.json'))
            self.assertEqual(settings['extension_id'],extension_id());self.assertEqual(settings['chrome_update_url'],'')
            status=json.loads(archive.read('deployment-status.json'))
            self.assertFalse(status['signed_crx_included'])
            with zipfile.ZipFile(io.BytesIO(archive.read('extension-source.zip'))) as source:
                self.assertFalse(any(n.endswith(('.pem','.key','.pfx')) for n in source.namelist()))
                self.assertEqual(json.loads(source.read('manifest.json'))['version'],'0.5.0')
        with self.assertRaises(urllib.error.HTTPError) as context:self.api('/api/browser-deployment-package',{},csrf=False)
        self.assertEqual(context.exception.code,403)
        self.api('/api/login',{'username':'reader','password':self.password})
        with self.assertRaises(urllib.error.HTTPError) as context:self.api('/api/browser-deployment-package',{})
        self.assertEqual(context.exception.code,403)

    def test_automatic_audit_host_does_not_route_traffic_to_unconfigured_proxy(self):
        agent,did,_=self.make_agent()
        try:
            policy=copy.deepcopy(DEFAULT_POLICY)
            policy['upload_rules']=[{'type':'domain','target':'example.com','rate_kbps':1000}]
            with agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(json.dumps({'version':1,'body':policy}),))
            status=handle_message(agent,{'type':'status'})
            self.assertFalse(status['proxy_required'])
            self.assertEqual(status['proxy_policy_state'],'proxy_not_configured')
            agent.config['proxy_enabled']=True
            status=handle_message(agent,{'type':'status'})
            self.assertTrue(status['proxy_required'])
            self.assertEqual(status['proxy_policy_state'],'configured_requires_runtime_check')
        finally:agent.close_collectors()


class RegistryFixture:
    def __init__(self):self.values={browser:{'1':'existing-company-extension;https://company.test/update.xml'} for browser in KEYS};self.fail=False
    def read(self,browser):return self.values[browser].copy()
    def write(self,item,value):
        if self.fail and item['browser']=='edge' and value is not None:raise OSError('simulated failure')
        current=self.values[item['browser']].get(item['name'])
        if current not in (item['before'],item['after']):raise OSError('external conflict')
        if value is None:self.values[item['browser']].pop(item['name'],None)
        else:self.values[item['browser']][item['name']]=value


class DeploymentTest(unittest.TestCase):
    def settings(self):return {'extension_id':extension_id(),'chrome_update_url':'https://company.test/chrome.xml','edge_update_url':'https://company.test/edge.xml'}

    def test_additive_plan_apply_restore_and_external_conflict(self):
        registry=RegistryFixture();baseline=copy.deepcopy(registry.values)
        with tempfile.TemporaryDirectory() as temp:
            planned=execute(self.settings(),'plan',temp,registry)
            self.assertEqual(registry.values,baseline);self.assertTrue(all(i['name']=='2' for i in planned['changes']))
            result=execute(self.settings(),'apply',temp,registry)
            self.assertFalse(result['browser_installation_verified'])
            registry.values['chrome']['2']='external replacement'
            with self.assertRaises(OSError):execute(None,'restore',temp,registry)
            self.assertTrue((Path(temp)/'browser-policy-owned.json').exists())
            self.assertIn('2',registry.values['edge']) # preflight before any mutation
            registry.values['chrome']['2']=planned['changes'][0]['after']
            execute(None,'restore',temp,registry)
            self.assertEqual(registry.values,baseline)

    def test_partial_failure_rollback_journal_recovery_and_same_existing_entry(self):
        registry=RegistryFixture();baseline=copy.deepcopy(registry.values);registry.fail=True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(OSError):execute(self.settings(),'apply',temp,registry)
            self.assertEqual(registry.values,baseline)
            self.assertTrue((Path(temp)/'browser-policy-owned.json').exists())
            registry.fail=False;execute(None,'restore',temp,registry)
            execute(self.settings(),'apply',temp,registry)
            self.assertEqual(changes(self.settings(),registry.values),[])
            self.assertEqual(execute(self.settings(),'apply',temp,registry)['status'],'policy_written_await_browser')

    def test_untrusted_sources_and_occupied_nonstring_slots_are_rejected_or_preserved(self):
        settings=self.settings()
        for value in ('','http://company.test/update','https://user:pass@company.test/update','https://company.test/update?token=secret','https://company.test:0/update','https://company.test/update#secret'):
            with self.subTest(value=value),self.assertRaises(ValueError):changes({**settings,'chrome_update_url':value},{})
        with self.assertRaises(ValueError):changes({**settings,'extension_id':'a'*32},{})
        planned=changes(settings,{'chrome':{'1':{'registry_type':4}}})
        self.assertEqual(planned[0]['name'],'2')
        with self.assertRaises(ValueError):changes(settings,{'chrome':{'1':extension_id()+';https://external.test/update'}})

    def test_readiness_rejects_malformed_or_expired_client_status(self):
        for status in ('bad',{'checked_at':'bad'},{'checked_at':float('nan')},{'checked_at':time.time()+300}):
            result=docs.readiness({'inventory':{'collectors':{'document_upload':status}}},DEFAULT_POLICY)
            self.assertNotEqual(result['upload']['status'],'connected_limited')
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['enabled']=False;policy['browser_audit']=False
        result=docs.readiness({},policy)
        self.assertEqual(result['read']['status'],'disabled');self.assertEqual(result['upload']['status'],'disabled')


if __name__=='__main__':unittest.main()
