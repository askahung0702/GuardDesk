import copy,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import file_access as access
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy,normalize_policy


class FileAccessTest(unittest.TestCase):
    def test_versioned_options_use_unchanged_legacy_body_and_groups(self):
        policy=copy.deepcopy(DEFAULT_POLICY)
        rules=[r'C:\Users\{user}\AppData',access.PROCESS+'OneDrive.exe',access.SERVICES]
        policy['file_audit']['exclude_paths']=rules
        wire=agent_policy_wire({'body':policy})
        self.assertEqual(set(wire['body']['file_audit']),{'enabled','scope','exclude_paths'})
        self.assertEqual(decode_agent_policy(wire)['body'],policy)
        self.assertEqual(access.options(rules),{'exclude_services':False,'exclude_processes':['OneDrive.exe'],'mode':'interactive','interaction_seconds':30})
        for rule in (access.PROCESS+'*.exe',access.PREFIX+'typo',access.PROCESS+'OneDrive.exe\n',access.PROCESS+r'C:\Users\{user}\agent.exe'):
            policy['file_audit']['exclude_paths']=[rule]
            with self.assertRaises(ValueError):normalize_policy(policy)

    def test_confirmed_services_filter_without_guessing_unknown_or_human(self):
        item={'path':r'C:\Owned\x.txt','process_session_id':0,'process_identity_status':'creation_time_checked'}
        self.assertTrue(access.excluded_event('file.opened','info',item,[]))
        for changes in ({'process_session_id':1},{'process_session_id':False},{'process_identity_status':'unavailable_or_process_replaced'}):
            self.assertFalse(access.excluded_event('file.opened','info',{**item,**changes},[]))
        self.assertFalse(access.excluded_event('file.opened','info',item,[access.SERVICES]))
        for kind in ('file.created','file.deleted','file.copy_candidate','web.upload_started','application.started','agent.audit_gap'):
            self.assertFalse(access.excluded_event(kind,'info',item,[]))
        self.assertFalse(access.excluded_event('file.opened','warning',item,[]))

    def test_exact_process_rules_do_not_filter_unknown_or_rename_other_events(self):
        item={'path':r'C:\Owned\x.txt','process':r'C:\Apps\OneDrive.exe','process_identity_status':'creation_time_checked'}
        self.assertTrue(access.excluded_event('file.opened','info',item,[access.PROCESS+'onedrive.exe']))
        self.assertFalse(access.excluded_event('file.opened','info',item,[access.PROCESS+r'D:\Apps\OneDrive.exe']))
        self.assertFalse(access.excluded_event('file.opened','info',{**item,'process_identity_status':'unknown'},[access.PROCESS+'onedrive.exe']))
        self.assertFalse(access.excluded_event('file.opened','info',{},[]))

    def test_root_directories_and_short_directory_aliases_are_not_documents(self):
        f=access.Filter();item={'process_id':123456,'path':'C:\\','evidence':'completed_native_open'}
        with patch('guarddesk.file_access.attributes',side_effect=AssertionError('root needs no I/O')):
            self.assertEqual(f.check(item,[]),'directory')
        with patch('guarddesk.file_access.attributes',return_value=0x10) as query:
            item['path']=r'C:\Users\user1\DOCUME~1'
            self.assertEqual(f.check(item,[]),'directory');self.assertEqual(f.check(item,[]),'directory');self.assertEqual(query.call_count,1)

    def test_empty_files_and_native_non_directory_evidence_remain(self):
        f=access.Filter();item={'path':r'C:\Owned\empty.txt','process_id':123456,'evidence':'completed_native_open'}
        with patch('guarddesk.file_access.attributes',return_value=0x80):
            self.assertIsNone(f.check(item,[]));self.assertEqual(item['object_type'],'file')
        with patch('guarddesk.file_access.attributes',side_effect=AssertionError('known type must not query')):
            self.assertIsNone(f.check({**item,'object_type':'file'},[]))
            self.assertIsNone(f.check({**item,'path':r'C:\Owned\deleted.txt','evidence':'completed_native_read'},[]))
        self.assertEqual(f.check({**item,'process_id':os.getpid()},[]),'collector_self')

    def test_unknown_types_and_budget_are_explicit_and_bounded(self):
        f=access.Filter();item={'path':r'C:\Owned\gone.txt','process_id':123456,'evidence':'completed_native_open'}
        with patch('guarddesk.file_access.attributes',return_value=None),patch('guarddesk.file_access.time.monotonic',return_value=100):
            self.assertEqual(f.check(item,[]),'object_type_unconfirmed')
            for i in range(100):f.check({**item,'path':'C:\\Owned\\'+str(i)},[])
            self.assertLessEqual(len(f.cache),512)
            self.assertEqual(f.check({**item,'path':r'C:\Owned\last'},[]),'type_query_budget')

    def test_old_native_receipt_does_not_claim_background_filter_applied(self):
        from guarddesk.policy_progress import progress
        policy=copy.deepcopy(DEFAULT_POLICY);now=time.time()
        effective={'body':policy,'version':1,'field_sources':{k:{'name':'base'} for k in policy}}
        device={'last_seen':now,'policy_received':True,'inventory':{},'extended_status':{'received':now,'worker_version':'0.4.52','document_native_read':{'status':'collecting_native_reads'}}}
        row=next(r for r in progress(device,effective) if r['key']=='file_access_filter')
        self.assertEqual(row['state'],'pending')
        device['extended_status']['document_native_read'].update(filter_minimum_version='0.4.54',file_access_filter=access.options([]))
        self.assertEqual(next(r for r in progress(device,effective) if r['key']=='file_access_filter')['state'],'reported')
        policy['file_audit']['exclude_paths']=[access.PROCESS+'background.exe']
        self.assertEqual(next(r for r in progress(device,effective) if r['key']=='file_access_filter')['state'],'pending')


class FileAccessApiTest(unittest.TestCase):
    from test_system import SystemTest
    setUp=SystemTest.setUp;tearDown=SystemTest.tearDown;api=SystemTest.api;make_agent=SystemTest.make_agent

    def test_inherited_rules_acknowledge_old_queue_preserve_warning_upload_and_immutable_history(self):
        import test_management
        from guarddesk.agent import Agent,enroll
        agent,did,_=self.make_agent()
        token=self.api('/api/enrollments',{})['token'];config=self.root/'other'/'config.json'
        other_id=enroll(config,self.url,token,self.watch,name='other');other=Agent(config)
        details={'path':r'C:\Owned\x.txt','process':r'C:\Apps\background.exe','process_identity_status':'creation_time_checked'}
        agent.queue('file.opened',details);agent.flush()
        with self.store.connect() as db:old=dict(db.execute("SELECT id,hash FROM events WHERE device_id=? AND kind='file.opened'",(did,)).fetchone())
        group=test_management.ManagementTest.group(self,'MIS')
        test_management.ManagementTest.move(self,did,group['id'])
        policy=test_management.ManagementTest.policy(self,'background',{'file_audit':{'enabled':True,'scope':'all_local','exclude_paths':[access.PROCESS+'background.exe']}})
        test_management.ManagementTest.assign(self,policy,'group',group['id'])
        agent.queue('file.opened',details);agent.queue('file.opened',details,'warning');agent.queue('web.upload_started',details)
        agent.flush();other.queue('file.opened',details);other.flush()
        with self.store.connect() as db:
            rows=db.execute("SELECT device_id,kind,severity FROM events WHERE kind IN ('file.opened','web.upload_started')").fetchall()
        self.assertEqual(len([r for r in rows if r['device_id']==did]),3)
        self.assertEqual(len([r for r in rows if r['device_id']==other_id]),1)
        self.assertEqual(agent.queue_status()['pending'],0)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT hash FROM events WHERE id=?',(old['id'],)).fetchone()[0],old['hash'])
        agent.close_collectors();other.close_collectors()
