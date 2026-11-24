"""No HTTP server, installed Agent, SYSTEM task or real endpoint is started."""
import hashlib
import json
from contextlib import ExitStack,nullcontext
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock,patch
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
          CREATE TABLE native_usb_status(device_id TEXT PRIMARY KEY,body TEXT,received REAL);
          CREATE TABLE endpoint_removals(id TEXT PRIMARY KEY,device_id TEXT,actor TEXT,reason TEXT,created REAL,expires REAL,status TEXT,main TEXT,native TEXT,error TEXT);
          CREATE TABLE update_jobs(id TEXT PRIMARY KEY,device_id TEXT,status TEXT,expires REAL);
          CREATE TABLE update_status(job_id TEXT,role TEXT,state TEXT,PRIMARY KEY(job_id,role));'''+create)
        self.db.execute('INSERT INTO devices VALUES(?,?,0,?)',(DID,'owned-test',json.dumps({'capabilities':['remote_uninstall_v1',full.CAPABILITY]})))
        from guarddesk.software import SCHEMA
        self.db.executescript(SCHEMA)
        self.db.execute('INSERT INTO native_usb_status(device_id,body) VALUES(?,?)',(DID,json.dumps({'worker_version':'0.4.97'})))
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

    def test_company_audit_choice_requires_capable_native_and_matching_handshake(self):
        from guarddesk import native_usb
        self.body['keep_process_audit']=True
        with self.assertRaises(ManagementError):self.create()
        native_usb.accept_status(self.db,self.device,{'worker_version':'0.4.121','version':1,'usb_mode':'allow','status':'configured_replug_required','registry':{'Deny_Read':None,'Deny_Write':None},'removal_keep_process_audit':True})
        self.assertTrue(native_usb.snapshot(self.db,DID,'allow')['removal_keep_process_audit'])
        job=self.create()
        self.assertTrue(job['cleanup']['keep_process_audit'])
        poll='/api/agent/uninstall/poll'
        self.assertIsNone(removal.agent_route(self.db,self.device,poll,{'role':'native'})['job'])
        self.assertEqual(removal.agent_route(self.db,self.device,poll,{'role':'native','removal_keep_process_audit':True})['job']['id'],job['id'])
        packet={'job_id':job['id'],'secret':SECRET}
        with self.assertRaises(ManagementError):full.prepare(self.db,self.device,packet)
        self.assertEqual(full.get(self.db,job['id'])['phase'],'queued')
        self.assertTrue(full.prepare(self.db,self.device,{**packet,'keep_process_audit':True})['keep_process_audit'])
        self.result('deleting');self.result('complete')
        self.assertTrue(removal.latest(self.db,DID)['cleanup']['keep_process_audit'])

    def test_checked_legacy_conflict_can_close_before_upgrade_without_replay(self):
        from guarddesk.update_dispatch import activity_conflict
        self.prepare()
        jid=self.job['id']
        full.preparation_error(self.db,self.device,{'job_id':jid,'winerror':None})
        self.assertTrue(activity_conflict(self.db,DID))
        close={'device_id':DID,'job_id':jid,'confirm_name':'owned-test','verified_audit_conflict':True}
        for bad in ({'verified_audit_conflict':False},{'confirm_name':'wrong'},{'job_id':'c'*32}):
            with self.assertRaises(ManagementError):removal.close_audit_conflict(self.db,self.user,{**close,**bad})
        with self.assertRaises(ManagementError):removal.close_audit_conflict(self.db,{'role':'support'},close)
        closed=removal.close_audit_conflict(self.db,self.user,close)
        self.assertEqual(closed['status'],'closed')
        self.assertEqual(closed['error'],'PREPARATION_FAILED')
        self.assertFalse(activity_conflict(self.db,DID))
        self.assertIsNone(removal.agent_route(self.db,self.device,'/api/agent/uninstall/poll',{'role':'native'})['job'])
        with self.assertRaises(ManagementError):self.result('authorize')
        with self.assertRaises(ManagementError):full.prepare(self.db,self.device,{'job_id':jid,'secret':SECRET})
        with self.assertRaises(ManagementError):removal.close_audit_conflict(self.db,self.user,close)
        self.assertNotEqual(self.create()['id'],jid)

    def test_started_cleanup_cannot_be_closed_as_a_prepare_conflict(self):
        self.prepare();self.result('deleting');self.result('review_required',error_code='PROCESS_AUDIT_CONFLICT')
        job=removal.latest(self.db,DID)
        self.assertFalse(job['cleanup']['can_close_audit_conflict'])
        with self.assertRaises(ManagementError):
            removal.close_audit_conflict(self.db,self.user,{'device_id':DID,'job_id':job['id'],'confirm_name':'owned-test','verified_audit_conflict':True})

    def test_authorized_helper_without_deleting_ack_blocks_manual_close(self):
        self.prepare();self.assertTrue(self.result('authorize')['authorized'])
        full.preparation_error(self.db,self.device,{'job_id':self.job['id'],'winerror':None})
        self.assertFalse(removal.latest(self.db,DID)['cleanup']['can_close_audit_conflict'])

    def test_separate_agent_port_accepts_only_authenticated_result_post(self):
        from guarddesk.server import Handler
        self.prepare()
        handler=Handler.__new__(Handler)
        handler.connection=Mock()
        handler.server=SimpleNamespace(surface='agent',server_address=('127.0.0.1',1),tls=True,
                                       store=SimpleNamespace(connect=lambda **kw:nullcontext(self.db)))
        handler.headers={'Host':'127.0.0.1','Authorization':'Bearer '+SECRET}
        handler.path='/api/removal-result'
        handler.body=lambda:{'job_id':self.job['id'],'phase':'authorize'}
        handler.send=Mock()
        self.db.commit()
        handler.handle_request('POST')
        self.assertEqual(handler.send.call_args.args[:2],(200,{'authorized':True,'phase':'prepared'}))
        self.db.commit()
        handler.headers.pop('Authorization')
        handler.handle_request('POST')
        self.assertIn(handler.send.call_args.args[0],(400,401))
        handler.handle_request('GET')
        self.assertEqual(handler.send.call_args.args[0],403)
        handler.path='/api/devices/uninstall/close-audit-conflict'
        handler.handle_request('POST')
        self.assertEqual(handler.send.call_args.args[0],403)

    def test_native_prepare_uses_mis_choice_before_starting_cleanup(self):
        from guarddesk.process_audit import IDS
        self.db.execute('UPDATE native_usb_status SET body=?',(json.dumps({'worker_version':'0.4.121','removal_keep_process_audit':True}),))
        self.body['keep_process_audit']=True
        job=self.create()
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root=Path(temp)
            data=root/'data'/'GuardDeskPilot';program=root/'program'/'GuardDeskPilot'
            work=root/'job';work.mkdir()
            config_path=data/'USBControl'/DID/'config.json'
            audit=config_path.parent/'applications';audit.mkdir(parents=True)
            baseline=audit/'process-audit-original.json';baseline.write_text(json.dumps(dict.fromkeys(IDS,0)))
            state_path=work/'handoff.json'
            state_path.write_text(json.dumps({'device_id':DID,'job_id':job['id'],'secret':SECRET,'restored':False,'launched':False}))
            io=Mock()
            io.names.return_value=[]
            io.write.side_effect=lambda path,raw:path.write_bytes(raw)
            io.query.side_effect=lambda name:io.register.call_args.args[1]
            stack.enter_context(patch.object(runtime,'require_system'))
            stack.enter_context(patch.object(runtime,'folder',side_effect={35:data,38:program}.__getitem__))
            stack.enter_context(patch.object(runtime,'job_root',return_value=work))
            stack.enter_context(patch.object(runtime.sys,'frozen',True,create=True))
            stack.enter_context(patch.object(runtime.sys,'executable',str(program/'USBControl'/'GuardDesk.exe')))
            stack.enter_context(patch.object(runtime,'assert_quiescent'))
            stack.enter_context(patch.object(runtime,'protected_tree'))
            stack.enter_context(patch('guarddesk.native_installer.Windows',return_value=io))
            stack.enter_context(patch('guarddesk.single_instance.machine_instance',return_value=nullcontext()))
            stack.enter_context(patch('guarddesk.process_audit.read_flags',return_value=dict(zip(IDS,(3,1)))))
            write=stack.enter_context(patch('guarddesk.process_audit.auditpol'))
            agent=SimpleNamespace(config_path=config_path,config={'device_id':DID},call=Mock(return_value={'prepared':True}))
            worker=SimpleNamespace(agent=agent,restore=Mock(return_value={'status':'restored'}))
            with self.assertRaisesRegex(ValueError,'CHOICE_NOT_CONFIRMED'):
                runtime.prepare(worker,job)
            worker.restore.assert_not_called();io.start.assert_not_called()
            def handshake(path,body):
                self.assertEqual(path,'/api/agent/uninstall/prepare-files')
                return full.prepare(self.db,self.device,body)
            agent.call.side_effect=handshake
            runtime.prepare(worker,job)
            write.assert_not_called()
            self.assertTrue(baseline.exists())
            self.assertTrue(json.loads(state_path.read_text())['restored'])
            worker.restore.assert_called_once()
            io.start.assert_called_once()

    def test_legacy_schema_migrates_without_enabling_keep_for_existing_work(self):
        from contextlib import closing
        from guarddesk.store import Store
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'synthetic.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE endpoint_file_removals(job_id TEXT PRIMARY KEY,device_id TEXT,phase TEXT,token_hash TEXT,updated REAL,report_until REAL,error_code TEXT,winerror INTEGER,helper_cleanup TEXT)")
                db.execute("INSERT INTO endpoint_file_removals VALUES('old','owned','review_required','hash',1,2,'PREPARATION_FAILED',NULL,'not_scheduled')")
                db.commit()
            Store(path)
            with Store(path).connect() as db:
                row=full.get(db,'old')
                self.assertFalse(full.public(row)['keep_process_audit'])
                self.assertEqual((row['error_code'],row['token_hash']),('PREPARATION_FAILED','hash'))

class StagingDiagnostics(unittest.TestCase):
    def setUp(self):
        from guarddesk import decommission
        self.run_step = decommission.native_step
        stack = self.enterContext(ExitStack())
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        data, installed = root/'data'/'GuardDeskPilot', root/'installed'/'GuardDeskPilot'
        source = installed/'USBControl'
        source.mkdir(parents=True)
        exe = source/'GuardDesk.exe'
        exe.write_bytes(b'fixture')
        config = data/'USBControl'/DID/'config.json'
        config.parent.mkdir(parents=True)
        self.ca = config.with_name('company-ca.pem')
        self.ca.write_bytes(b'test public CA')
        self.work = root/'job'
        self.marker = config.with_name('removal-prepare-error.json')
        self.job = {'id':'c'*32, 'mode':full.MODE, 'cleanup':{'keep_process_audit':True}}
        self.reports = []
        def call(path, body):
            if path.endswith('/poll'):
                return {'job':self.job}
            self.assertEqual(path, '/api/agent/uninstall/files-error')
            self.reports.append(body)
            raise ConnectionError('offline')
        self.agent = SimpleNamespace(config_path=config, config={'device_id':DID, 'ca':str(self.ca),
                                     'server':'https://center.invalid'}, call=call)
        self.worker = SimpleNamespace(agent=self.agent, restore=Mock())
        self.io = Mock()
        self.io.protect.side_effect = lambda path, create: path.mkdir(exist_ok=True, parents=True)
        self.io.write.side_effect = lambda path, raw: path.write_bytes(raw)
        self.tree = stack.enter_context(patch.object(runtime, 'protected_tree'))
        for name, value in [('require_system', Mock()), ('assert_quiescent', Mock()),
                            ('folder', {35:data, 38:installed}.__getitem__), ('job_root', lambda jid:self.work)]:
            stack.enter_context(patch.object(runtime, name, value))
        stack.enter_context(patch.object(runtime.sys, 'frozen', True, create=True))
        stack.enter_context(patch.object(runtime.sys, 'executable', str(exe)))
        stack.enter_context(patch.object(decommission, 'saved', return_value=None))
        stack.enter_context(patch('guarddesk.single_instance.machine_instance', return_value=nullcontext()))
        stack.enter_context(patch('guarddesk.native_installer.Windows', return_value=self.io))
        stack.enter_context(patch('guarddesk.native_installer.source_files',
                                  return_value=({'GuardDesk.exe': hashlib.sha256(b'fixture').hexdigest()}, 7)))
        self.marker_write = stack.enter_context(patch('guarddesk.protected_files.ProtectedFiles.write',
                                                      side_effect=lambda path, raw: path.write_bytes(raw)))

    def observe(self, step, error_type='OSError', winerror=None):
        self.assertEqual(self.run_step(self.worker), 'pending')
        self.assertEqual(json.loads(self.marker.read_bytes()),
                         {'job_id':self.job['id'], 'step':step, 'error_type':error_type, 'winerror':winerror})
        self.assertEqual(self.reports[-1], {'job_id':self.job['id'], 'winerror':winerror})
        self.assertFalse((self.work/'handoff.json').exists())
        self.worker.restore.assert_not_called()
        self.io.start.assert_not_called()

    def test_ca_write_failure_survives_offline_report_and_populated_stage_retry(self):
        def fail_ca_write(path, raw):
            self.assertEqual(path, self.work/'center-ca.pem')
            raise OSError('private detail excluded')
        self.io.write.side_effect = fail_ca_write
        self.observe('write_staged_ca')
        self.observe('write_staged_ca')
        self.io.write.assert_called_once()
        self.marker_write.assert_called_once()

    def test_existing_stage_distinguishes_jobs_and_old_markers(self):
        stage = self.work/'program'
        stage.mkdir(parents=True)
        (stage/'GuardDesk.exe').write_bytes(b'preserve this evidence')
        for old in ({'job_id':self.job['id'], 'error_type':'OSError', 'winerror':None},
                    {'job_id':'d'*32, 'step':'read_ca'}):
            with self.subTest(old=old):
                self.marker.write_text(json.dumps(old))
                self.observe('existing_staging_without_handoff')
                self.assertEqual((stage/'GuardDesk.exe').read_bytes(), b'preserve this evidence')
                self.io.write.assert_not_called()

    def test_program_acl_failure_has_own_step(self):
        def check(path, **unused):
            if path == self.work/'program':
                raise OSError('untrusted fixture owner')
        self.tree.side_effect = check
        self.observe('verify_staged_permissions')

    def test_source_ca_read_failure_and_handoff_write_are_distinct(self):
        self.ca.unlink()
        self.assertEqual(self.run_step(self.worker), 'pending')
        self.assertEqual(json.loads(self.marker.read_bytes())['step'], 'read_ca')
        self.assertFalse((self.work/'center-ca.pem').exists())
        # A separate job proceeds past the CA and fails while saving its handoff.
        self.job['id'] = 'e'*32
        self.work = self.work.with_name('second-job')
        self.ca.write_bytes(b'public CA')
        def write(path, raw):
            if path.name == 'handoff.json':
                error = OSError('private handoff information')
                error.winerror = 5
                raise error
            path.write_bytes(raw)
        self.io.write.side_effect = write
        self.observe('write_handoff', winerror=5)
        self.assertEqual((self.work/'center-ca.pem').read_bytes(), self.ca.read_bytes())

    def test_unwritable_local_diagnostic_still_reports_to_center(self):
        self.ca.unlink()
        self.marker_write.side_effect = OSError('marker cannot be written')
        with self.assertRaisesRegex(OSError, 'marker cannot be written'):
            self.run_step(self.worker)
        self.assertEqual(len(self.reports), 1)
        self.worker.restore.assert_not_called()


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
