"""No HTTP server, installed Agent, SYSTEM task or real endpoint is started."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from guarddesk import removal,removal_full as full,remote_removal as runtime
from guarddesk.management import ManagementError

DID='a'*24
SECRET='b'*64

class Center(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        self.addCleanup(self.db.close)
        # Use the product's actual schema statement, not a divergent copy.
        from guarddesk.store import Store
        source=next(c for c in Store.__init__.__code__.co_consts if isinstance(c,str) and 'CREATE TABLE IF NOT EXISTS endpoint_file_removals(' in c)
        create=next(line.strip() for line in source.splitlines() if 'CREATE TABLE IF NOT EXISTS endpoint_file_removals(' in line)
        self.db.executescript('''CREATE TABLE devices(id TEXT PRIMARY KEY,name TEXT,revoked INTEGER,inventory TEXT);
          CREATE TABLE native_usb_status(device_id TEXT,body TEXT);
          CREATE TABLE endpoint_removals(id TEXT PRIMARY KEY,device_id TEXT,actor TEXT,reason TEXT,created REAL,expires REAL,status TEXT,main TEXT,native TEXT,error TEXT);
          CREATE TABLE update_jobs(device_id TEXT,status TEXT,expires REAL);'''+create)
        self.db.execute('INSERT INTO devices VALUES(?,?,0,?)',(DID,'owned-test',json.dumps({'capabilities':['remote_uninstall_v1',full.CAPABILITY]})))
        from guarddesk.software import SCHEMA
        self.db.executescript(SCHEMA)
        self.db.execute('INSERT INTO native_usb_status VALUES(?,?)',(DID,json.dumps({'worker_version':'0.4.97'})))
        for name in ('guarddesk.updater_maintenance.active','guarddesk.custom_settings.action_leased'):
            p=patch(name,return_value=False);p.start();self.addCleanup(p.stop)
        self.events=[];p=patch('guarddesk.store.Store.event',side_effect=lambda *a,**k:self.events.append(a));p.start();self.addCleanup(p.stop)
        self.body={'device_id':DID,'confirm_name':'owned-test','reason':'explicit test','mode':full.MODE,'acknowledge_no_backup':True}
        self.user={'role':'admin','username':'test-admin'};self.device={'id':DID}
    def create(self):
        self.job=removal.request(self.db,self.user,self.body);return self.job
    def prepare(self):
        self.create();full.prepare(self.db,self.device,{'job_id':self.job['id'],'secret':SECRET})
    def result(self,phase,**kwargs):return full.result(self.db,SECRET,{'job_id':self.job['id'],'phase':phase,**kwargs})
    def test_explicit_ack_and_admin_required(self):
        for user,body in (({'role':'support'},self.body),(self.user,{**self.body,'acknowledge_no_backup':False}),(self.user,{**self.body,'confirm_name':'wrong'})):
            with self.assertRaises(ManagementError):removal.request(self.db,user,body)
        self.assertEqual(self.db.execute('SELECT count(*) FROM endpoint_removals').fetchone()[0],0)
    def test_old_native_and_capability_refused(self):
        self.db.execute('UPDATE native_usb_status SET body=?',(json.dumps({'worker_version':'0.4.96'}),))
        with self.assertRaises(ManagementError):self.create()
        self.db.execute('UPDATE native_usb_status SET body=?',(json.dumps({'worker_version':'0.4.97'}),))
        self.db.execute('UPDATE devices SET inventory=?',(json.dumps({'capabilities':['remote_uninstall_v1']}),))
        with self.assertRaises(ManagementError):self.create()
    def test_legacy_workflow_unchanged(self):
        self.body={'device_id':DID,'confirm_name':'owned-test','reason':'legacy'};self.create()
        for role in ('main','native'):removal.agent_route(self.db,self.device,'/api/agent/uninstall/status',{'job_id':self.job['id'],'role':role,'state':'ready'})
        self.assertEqual(removal.latest(self.db,DID)['status'],'completed')
        self.assertNotIn('mode',removal.latest(self.db,DID))
    def test_full_cannot_be_completed_by_legacy_ack(self):
        self.create()
        with self.assertRaises(ManagementError):removal.agent_route(self.db,self.device,'/api/agent/uninstall/status',{'job_id':self.job['id'],'role':'native','state':'ready'})
        self.assertEqual(removal.latest(self.db,DID)['status'],'queued')
    def test_lost_prepare_response_is_idempotent_and_token_not_public(self):
        self.prepare();full.prepare(self.db,self.device,{'job_id':self.job['id'],'secret':SECRET})
        with self.assertRaises(ManagementError):full.prepare(self.db,self.device,{'job_id':self.job['id'],'secret':'c'*64})
        shown=json.dumps(removal.latest(self.db,DID));self.assertNotIn(SECRET,shown);self.assertNotIn('token_hash',shown)
    def test_other_device_and_wrong_secret_refused(self):
        self.prepare()
        with self.assertRaises(ManagementError):full.prepare(self.db,{'id':'f'*24},{'job_id':self.job['id'],'secret':SECRET})
        with self.assertRaises(ManagementError):full.result(self.db,'c'*64,{'job_id':self.job['id'],'phase':'authorize'})
    def test_expired_unstarted_job_not_claimed(self):
        self.create();self.db.execute('UPDATE endpoint_removals SET expires=0')
        with self.assertRaises(ManagementError):full.prepare(self.db,self.device,{'job_id':self.job['id'],'secret':SECRET})
        self.assertEqual(removal.latest(self.db,DID)['status'],'expired')
    def test_revoke_blocks_new_deletion_but_accepts_final_result(self):
        self.prepare();self.assertTrue(self.result('authorize')['authorized'])
        self.result('deleting');self.db.execute('UPDATE devices SET revoked=1')
        self.assertFalse(self.result('authorize')['authorized'])
        self.result('complete');self.assertEqual(removal.latest(self.db,DID)['status'],'completed')
    def test_authorize_does_not_consume_or_claim_completion(self):
        self.prepare();self.result('authorize');self.result('authorize')
        self.assertEqual(removal.latest(self.db,DID)['status'],'running')
        with self.assertRaises(ManagementError):self.result('complete')
    def test_final_ack_retry_and_maintenance_cleanup(self):
        self.prepare();self.result('deleting');self.result('complete');self.result('complete')
        self.result('complete',helper_cleanup='reboot_pending')
        self.assertEqual(removal.latest(self.db,DID)['cleanup']['helper_cleanup'],'reboot_pending')
        with self.assertRaises(ManagementError):self.result('review_required',error_code='LATE_FAILURE')
    def test_error_is_bounded_and_no_command_or_path_accepted(self):
        self.prepare()
        for extra in ({'path':'C:\\'},{'command':'delete'},{'error_code':'contains secret / path'},{'winerror':True}):
            with self.assertRaises(ManagementError):self.result('review_required',**extra)
    def test_report_expiry(self):
        self.prepare();self.db.execute('UPDATE endpoint_file_removals SET report_until=0')
        with self.assertRaises(ManagementError):self.result('authorize')
    def test_preparation_failure_shown_without_false_completion(self):
        self.create();full.preparation_error(self.db,self.device,{'job_id':self.job['id'],'winerror':5})
        j=removal.latest(self.db,DID);self.assertEqual(j['status'],'failed');self.assertEqual(j['cleanup']['winerror'],5)
    def test_ui_has_separate_full_cleanup_and_retained_files(self):
        text=Path(full.__file__).with_name('static').joinpath('management.js').read_text(encoding='utf-8')
        for value in ('remove_files_v1','retain_files','acknowledge_no_backup','reboot_pending','端點離線不代表完成'):
            self.assertIn(value,text)

class Lifecycle(unittest.TestCase):
    def setUp(self):self.result=None;self.calls=[];self.state={'restored':True}
    def save(self,x):self.result=dict(x);self.calls.append('save:'+x['phase'])
    def post(self,x):self.calls.append('post:'+x['phase'])
    def execute(self,remove=None,authorize=None,post=None):
        return runtime.execute_job(self.state,lambda:self.result,self.save,authorize or (lambda:{'authorized':True}),
            remove or (lambda:{'result':'AGENT_REMOVED_NO_BACKUP'}),post or self.post)
    def test_delete_once_then_report_only(self):
        count=[]
        self.execute(lambda:count.append(1) or {'result':'AGENT_REMOVED_NO_BACKUP'})
        self.execute(lambda:self.fail('Deletion replayed'))
        self.assertEqual(len(count),1);self.assertEqual(self.result['phase'],'complete')
    def test_before_delete_requires_restoration_and_center_authorization(self):
        with self.assertRaises(PermissionError):self.execute(authorize=lambda:{'authorized':False})
        self.assertIsNone(self.result)
        self.state['restored']=False
        with self.assertRaises(PermissionError):self.execute()
    def test_power_failure_does_not_replay(self):
        def crash():raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(crash)
        self.assertEqual(self.result['phase'],'deleting')
        self.execute(lambda:self.fail('Deletion replayed'))
        self.assertEqual(self.result['error_code'],'INTERRUPTED_REMOVAL_REVIEW_REQUIRED')
    def test_lost_final_ack_does_not_replay(self):
        def offline(body):raise ConnectionError('offline')
        with self.assertRaises(ConnectionError):self.execute(post=offline)
        self.assertEqual(self.result['phase'],'complete')
        self.execute(lambda:self.fail('Deletion replayed'))
    def test_os_error_never_says_complete(self):
        def fail():
            e=OSError('private path');e.winerror=32;raise e
        self.execute(fail);self.assertEqual(self.result['winerror'],32)
        self.assertNotIn('private',json.dumps(self.result));self.assertEqual(self.result['phase'],'review_required')
    def test_non_success_engine_result_rejected(self):
        self.execute(lambda:{'result':'REMOVAL_PREVIEW'})
        self.assertEqual(self.result['phase'],'review_required')
    def test_fixed_task_and_reject_foreign_program(self):
        with patch('guarddesk.remote_removal.folder',return_value=Path('C:/ProgramData/GuardDeskPilot')):
            exe=runtime.job_root('a'*32)/'program/GuardDesk.exe'
            raw=runtime.task_body(exe,'a'*32);runtime.verify_task(raw,exe,'a'*32)
            for altered in (raw.decode('utf-16').replace('S-1-5-18','S-1-5-32-544'),raw.decode('utf-16').replace('endpoint-remove-job','serve')):
                with self.assertRaises(PermissionError):runtime.verify_task(altered,exe,'a'*32)
            with self.assertRaises(ValueError):runtime.job_root('../escape')
    def test_restored_scope_does_not_exempt_other_identity_or_user(self):
        from tools.endpoint_remove_direct import control_changes
        with tempfile.TemporaryDirectory() as t:
            data=Path(t)/'GuardDeskPilot';root=data/'USBControl'/DID;root.mkdir(parents=True)
            (root/'windows').mkdir();(root/'windows/usb-original.json').write_text('{}')
            p=SimpleNamespace(data=data)
            control_changes(p,[],{},restored_root=root)
            other=data/'USBControl'/('c'*24);(other/'windows').mkdir(parents=True);(other/'windows/usb-original.json').write_text('{}')
            with self.assertRaisesRegex(OSError,'OWNED_CONTROL_RESTORE_REQUIRED'):control_changes(p,[],{},restored_root=root)
    def test_new_enrollment_or_different_center_cannot_be_erased_by_old_job(self):
        state={'device_id':DID,'server':'https://center.invalid'}
        marker={**state,'version':'0.4.97','ca_sha256':'abc'}
        runtime.check_identity(state,state,marker,'0.4.97','abc')
        for changes in ({'device_id':'f'*24},{'server':'https://other.invalid'},{'version':'0.4.98'},{'ca_sha256':'other'}):
            with self.assertRaises(PermissionError):runtime.check_identity(state,state,{**marker,**changes},'0.4.97','abc')

if __name__=='__main__':unittest.main()
