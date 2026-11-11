"""Offline only: real MSI read-only APIs, in-memory SQL and installer doubles.

No center listener, installed Agent, SYSTEM worker or third-party installer.
"""
import ctypes
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guarddesk import software as server,software_contract as contract,software_msi as msi,software_client as client,update_packages as packages
from guarddesk.management import ManagementError

DID='a'*24;PID='b'*64;JID='c'*32;CODE='{11223344-1111-2222-3333-123456789012}'
def manifest():return {'purpose':contract.PURPOSE,'sha256':PID,'bytes':1024,'name':'Owned test MSI','version':'1.2.3','product_code':CODE,'install_bytes':4096,'publisher':'Owned Test'}
def job():return {'purpose':contract.PURPOSE,'id':JID,'device_id':DID,'expires':time.time()+86400,'package':manifest()}

class Contract(unittest.TestCase):
    def test_manifest_over_512_mib_supported(self):
        m=manifest();m.update(bytes=2*contract.GIB,install_bytes=4*contract.GIB);contract.manifest(m)
    def test_reject_other_protocol_and_arbitrary_commands(self):
        for change in ({'purpose':'guarddesk-update-v1'},{'command':'cmd.exe'},{'bytes':True},{'bytes':65*contract.GIB},{'product_code':'/quiet'},{'version':'1.2.999999'}):
            with self.assertRaises(ValueError):contract.manifest({**manifest(),**change})
    def test_signed_endpoint_binding_expiry_and_tamper(self):
        key=Ed25519PrivateKey.generate();pinned=packages.public_key(key);body=job();envelope=packages.sign(key,body)
        contract.job(packages.verify(envelope,pinned),DID,time.time())
        with self.assertRaises(ValueError):contract.job(body,'f'*24,time.time())
        with self.assertRaises(ValueError):contract.job(body,DID,time.time()+2*86400)
        body['package']['bytes']=2048
        with self.assertRaises(ValueError):packages.verify(envelope,pinned)
    def test_exit_codes_require_detection(self):
        self.assertEqual(contract.outcome(0,'1.2.3','1.2.3')[0],'succeeded')
        self.assertEqual(contract.outcome(3010,'1.2.3','1.2.3')[0],'reboot_required')
        self.assertEqual(contract.outcome(0,None,'1.2.3')[0],'review_required')
        self.assertEqual(contract.outcome(1641,'1.2.3','1.2.3')[0],'review_required')
        self.assertEqual(contract.outcome(1618,None,'1.2.3'),('failed','MSI_EXIT_1618'))
    def test_fixed_arguments_and_no_shell(self):
        args=client.command(Path('C:/owned space/package.msi'),Path('C:/Windows/System32'))
        self.assertIn('/qn',args);self.assertIn('/norestart',args);self.assertIn('REBOOT=ReallySuppress',args)
        self.assertNotIn('cmd.exe',str(args));self.assertEqual(len(args),7)

class Center(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row;self.addCleanup(self.db.close)
        self.db.executescript(server.SCHEMA+'''CREATE TABLE devices(id TEXT PRIMARY KEY,name TEXT,revoked INTEGER);
        CREATE TABLE update_jobs(device_id TEXT,status TEXT,expires REAL);
        CREATE TABLE endpoint_removals(device_id TEXT,status TEXT);''')
        self.db.execute('INSERT INTO devices VALUES (?,?,0)',(DID,'owned'))
        self.db.execute('INSERT INTO software_packages VALUES (?,?,?,?)',(PID,json.dumps(manifest()),'admin',time.time()))
        self.db.execute('INSERT INTO software_presence VALUES (?,?,?)',(DID,'0.4.98',time.time()))
        for name in ('guarddesk.updater_maintenance.active','guarddesk.custom_settings.action_leased'):
            p=patch(name,return_value=False);p.start();self.addCleanup(p.stop)
        p=patch('guarddesk.store.Store.event');self.events=p.start();self.addCleanup(p.stop)
        self.key=Ed25519PrivateKey.generate();p=patch('guarddesk.update_packages.signer',return_value=self.key);p.start();self.addCleanup(p.stop)
        self.store=SimpleNamespace(path=Path('owned.db'));self.admin={'role':'admin','username':'admin'};self.device={'id':DID}
    def create(self):return server.create_jobs(self.db,self.admin,{'package_id':PID,'device_ids':[DID],'confirm':'install-msi-machine'})['job_ids'][0]
    def poll(self):return server.agent_route(self.store,self.db,self.device,'/poll',{'protocol':1,'version':'0.4.98'})
    def test_admin_and_capability_required(self):
        with self.assertRaises(ManagementError):server.create_jobs(self.db,{'role':'support'},{})
        self.db.execute('DELETE FROM software_presence')
        with self.assertRaises(ManagementError):self.create()
    def test_conflicts_and_double_dispatch(self):
        jid=self.create();self.assertTrue(server.active(self.db,DID))
        with self.assertRaises(ManagementError):self.create()
        server.cancel(self.db,self.admin,{'job_id':jid});self.assertFalse(server.active(self.db,DID))
        self.db.execute('INSERT INTO update_jobs VALUES (?,?,?)',(DID,'pending',time.time()+100))
        with self.assertRaises(ManagementError):self.create()
    def test_cancel_download_blocks_start(self):
        jid=self.create();self.poll();server.cancel(self.db,self.admin,{'job_id':jid})
        with self.assertRaises(ManagementError):server.agent_route(self.store,self.db,self.device,'/authorize',{'job_id':jid})
    def test_authorization_is_not_replayed(self):
        jid=self.create();packet=self.poll();contract.job(packages.verify(packet['job'],packages.public_key(self.key)),DID,time.time())
        server.agent_route(self.store,self.db,self.device,'/authorize',{'job_id':jid})
        with self.assertRaises(ManagementError):server.agent_route(self.store,self.db,self.device,'/authorize',{'job_id':jid})
        with self.assertRaises(ManagementError):server.cancel(self.db,self.admin,{'job_id':jid})
    def test_cross_endpoint_result_refused(self):
        jid=self.create()
        with self.assertRaises(ManagementError):server.valid(self.db,{'id':'d'*24},jid)
    def test_result_idempotent_and_bounded(self):
        jid=self.create();self.poll();server.agent_route(self.store,self.db,self.device,'/authorize',{'job_id':jid})
        body={'job_id':jid,'state':'succeeded','error':'','exit_code':0}
        for _ in range(2):self.assertTrue(server.agent_route(self.store,self.db,self.device,'/result',body)['ok'])
        self.assertFalse(server.active(self.db,DID))
        with self.assertRaises(ValueError):server.agent_route(self.store,self.db,self.device,'/result',{**body,'error':'C:/secret'})
    def test_interrupted_job_remains_busy_after_expiry(self):
        jid=self.create();self.poll();server.agent_route(self.store,self.db,self.device,'/authorize',{'job_id':jid})
        self.db.execute('UPDATE software_jobs SET expires=0');self.assertTrue(server.active(self.db,DID))
    def test_queued_expiry_is_safe(self):
        self.create();self.db.execute('UPDATE software_jobs SET expires=0');self.assertFalse(server.active(self.db,DID));self.assertIsNone(self.poll()['job'])
    def test_late_failure_after_cancel_is_acknowledged_without_reopening(self):
        jid=self.create();self.poll();server.cancel(self.db,self.admin,{'job_id':jid})
        result=server.agent_route(self.store,self.db,self.device,'/result',{'job_id':jid,'state':'failed','error':'MSI_VALIDATION_FAILED','exit_code':None})
        self.assertTrue(result['ok']);self.assertEqual(result['terminal_state'],'cancelled')
        self.assertEqual(server.valid(self.db,self.device,jid)['state'],'cancelled');self.assertFalse(server.active(self.db,DID))
    def test_configurable_quota(self):
        self.assertEqual(server.limits(self.db)['package_bytes'],8*contract.GIB)
        q={'package_bytes':16*contract.GIB,'library_bytes':128*contract.GIB}
        server.set_limits(self.db,self.admin,q);self.assertEqual(server.limits(self.db)['package_bytes'],q['package_bytes'])
        with self.assertRaises(ValueError):server.set_limits(self.db,self.admin,{**q,'package_bytes':65*contract.GIB})
    def test_review_close_requires_explicit_verification_and_not_success(self):
        jid=self.create();self.db.execute("UPDATE software_jobs SET state='review_required'")
        with self.assertRaises(ValueError):server.close_review(self.db,self.admin,{'job_id':jid})
        server.close_review(self.db,self.admin,{'job_id':jid,'confirm':'installer-stopped-and-result-reviewed'})
        self.assertFalse(server.active(self.db,DID));self.assertEqual(server.valid(self.db,self.device,jid)['state'],'failed')
    def test_running_package_cannot_be_deleted(self):
        self.create()
        with self.assertRaises(ManagementError):server.delete_package(self.store,self.db,self.admin,{'package_id':PID})
    def test_center_routes_require_admin_and_csrf(self):
        from guarddesk.server import Handler
        handler=object.__new__(Handler);handler.server=SimpleNamespace(store=self.store);handler.session=Mock(return_value=self.admin)
        Handler.route(handler,self.db,'GET','/api/software',{})
        handler.session.assert_called_with(self.db,mutate=False,admin=True)
        Handler.route(handler,self.db,'POST','/api/software/jobs',{'package_id':PID,'device_ids':[DID],'confirm':'install-msi-machine'})
        handler.session.assert_called_with(self.db,mutate=True,admin=True)
    def test_user_session_cannot_forward_installer_routes(self):
        from guarddesk.machine_agent import USER_PATHS
        for path in ('/api/agent/software/poll','/api/agent/software/authorize','/api/agent/software/result'):
            self.assertNotIn(path,USER_PATHS)

class Worker(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.key=Ed25519PrivateKey.generate();self.packet=job()
        self.agent=SimpleNamespace(config={'device_id':DID,'update_key':packages.public_key(self.key)},call=Mock(return_value={'job':packages.sign(self.key,self.packet),'state':'downloading'}))
        self.worker=client.Worker(self.agent,threading.Event(),self.root)
    def test_crash_intent_never_relaunches(self):
        client.save(self.worker.journal,{'id':JID,'phase':'intent'})
        with patch('guarddesk.software_client.subprocess.Popen') as launch:self.worker.cycle();launch.assert_not_called()
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['state'],'review_required')
    def test_lost_result_ack_only_resends(self):
        record={'id':JID,'phase':'result','result':{'job_id':JID,'state':'succeeded','error':'','exit_code':0}}
        client.save(self.worker.journal,record)
        with patch('guarddesk.software_client.subprocess.Popen') as launch:self.worker.cycle();launch.assert_not_called()
        self.agent.call.assert_called_once_with('/api/agent/software/result',record['result'])
    def test_existing_version_not_reinstalled(self):
        with patch.object(msi,'installed_version',return_value='1.2.3'),patch('guarddesk.software_client.subprocess.Popen') as launch:
            self.worker.cycle();launch.assert_not_called()
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['state'],'already_installed')
    def test_other_version_not_overwritten(self):
        with patch.object(msi,'installed_version',return_value='1.2.0'),patch('guarddesk.software_client.subprocess.Popen') as launch:
            self.worker.cycle();launch.assert_not_called()
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['error'],'SAME_PRODUCT_CODE_OTHER_VERSION')
    def test_insufficient_disk_never_downloads(self):
        with patch.object(msi,'installed_version',return_value=None),patch('guarddesk.software_client.shutil.disk_usage',return_value=SimpleNamespace(free=0)),patch.object(client,'download') as download:
            self.worker.cycle();download.assert_not_called()
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['error'],'INSUFFICIENT_INSTALL_SPACE')
    def test_stream_resume_and_hash(self):
        data=b'owned MSI bytes';target=self.root/'package.msi';target.with_suffix('.part').write_bytes(data[:4])
        j=job();j['package'].update(bytes=len(data),sha256=__import__('hashlib').sha256(data).hexdigest())
        response=io.BytesIO(data[4:]);response.status=206;response.headers={'Content-Length':str(len(data)-4),'Content-Range':f'bytes 4-{len(data)-1}/{len(data)}'}
        self.agent.config.update(server='https://owned.invalid',token='owned-test')
        with patch.object(client,'transport',return_value=SimpleNamespace(open=lambda *a,**k:response)):
            client.download(self.agent,j,target,threading.Event())
        self.assertEqual(target.read_bytes(),data)
    def test_broken_download_retains_partial_and_hash_mismatch_removes_it(self):
        target=self.root/'package.msi';j=job();j['package']['bytes']=10
        self.agent.config.update(server='https://owned.invalid',token='owned-test')
        response=io.BytesIO(b'ab');response.status=200;response.headers={'Content-Length':'10'}
        with patch.object(client,'transport',return_value=SimpleNamespace(open=lambda *a,**k:response)):
            with self.assertRaises(ConnectionError):client.download(self.agent,j,target,threading.Event())
        self.assertEqual(target.with_suffix('.part').read_bytes(),b'ab')
        target.with_suffix('.part').write_bytes(b'x'*10)
        with self.assertRaises(ValueError):client.download(self.agent,j,target,threading.Event())
        self.assertFalse(target.with_suffix('.part').exists())
    def test_actual_worker_sequence_with_process_double(self):
        calls=[];self.agent.call=Mock(side_effect=lambda path,body:(calls.append(path) or ({'job':packages.sign(self.key,self.packet),'state':'downloading'} if path.endswith('/poll') else {'authorized':True})))
        def downloaded(agent,job,path,stop):path.write_bytes(b'owned')
        from contextlib import nullcontext
        process=SimpleNamespace(poll=lambda:0,returncode=0)
        with patch.object(msi,'installed_version',side_effect=[None,'1.2.3']),patch.object(msi,'inspect',return_value=manifest()),patch.object(client,'download',side_effect=downloaded),patch('guarddesk.native_browser_identity.signed_publisher',return_value='Owned Test'),patch('guarddesk.update_native.protected_tree'),patch.object(packages,'file_hash',return_value=PID),patch('guarddesk.single_instance.machine_instance',side_effect=lambda *a:nullcontext()),patch.object(client.shutil,'disk_usage',return_value=SimpleNamespace(free=10*contract.GIB)),patch.object(client.subprocess,'Popen',return_value=process) as launch:
            self.worker.cycle()
        self.assertEqual(calls,['/api/agent/software/poll','/api/agent/software/authorize','/api/agent/software/result'])
        launch.assert_called_once();self.assertNotIn('shell',launch.call_args.kwargs)
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['state'],'succeeded')
    def test_intent_persisted_before_process_launch_failure(self):
        self.agent.call=Mock(side_effect=lambda path,body:{'job':packages.sign(self.key,self.packet),'state':'downloading'} if path.endswith('/poll') else {'authorized':True})
        from contextlib import nullcontext
        def launch(*a,**k):
            self.assertEqual(json.loads(self.worker.journal.read_text())['phase'],'intent')
            raise OSError(5,'owned failure')
        with patch.object(msi,'installed_version',return_value=None),patch.object(msi,'inspect',return_value=manifest()),patch.object(client,'download',side_effect=lambda a,j,p,s:p.write_bytes(b'owned')),patch('guarddesk.native_browser_identity.signed_publisher',return_value='Owned Test'),patch('guarddesk.update_native.protected_tree'),patch.object(packages,'file_hash',return_value=PID),patch('guarddesk.single_instance.machine_instance',side_effect=lambda *a:nullcontext()),patch.object(client.shutil,'disk_usage',return_value=SimpleNamespace(free=10*contract.GIB)),patch.object(client.subprocess,'Popen',side_effect=launch):
            self.worker.cycle()
        self.assertEqual(json.loads(self.worker.journal.read_text())['result']['state'],'review_required')

class WindowsMetadata(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'中文 owned.msi'
    def make(self,allusers='1',external=False):
        dll=msi.api();dll.MsiDatabaseCommit.argtypes=[ctypes.wintypes.UINT]
        # Own minimal MSI metadata database, never installed or executed.
        with msi.handle(dll,dll.MsiOpenDatabaseW,str(self.path),ctypes.cast(ctypes.c_void_p(3),ctypes.wintypes.LPCWSTR)) as db:
            sql=['CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)',
                 'CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `Cabinet` CHAR(255) PRIMARY KEY `DiskId`)',
                 'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `FileSize` LONG NOT NULL, `Attributes` SHORT PRIMARY KEY `File`)']
            props={'ProductCode':CODE,'ProductVersion':'1.2.3','ProductName':'Owned MSI','ALLUSERS':allusers}
            sql += [f"INSERT INTO `Property` (`Property`,`Value`) VALUES ('{k}','{v}')" for k,v in props.items()]
            sql += ["INSERT INTO `Media` (`DiskId`,`Cabinet`) VALUES (1,'"+('external.cab' if external else '#embedded')+"')"]
            for query in sql:
                with msi.handle(dll,dll.MsiDatabaseOpenViewW,db,query) as view:msi.check(dll.MsiViewExecute(view,0))
            msi.check(dll.MsiDatabaseCommit(db))
    def test_real_windows_msi_read_only(self):
        self.make();before=self.path.read_bytes();result=msi.inspect(self.path)
        self.assertEqual(result['product_code'],CODE);self.assertEqual(self.path.read_bytes(),before)
    def test_external_cab_refused(self):
        self.make(external=True)
        with self.assertRaises(ValueError):msi.inspect(self.path)
    def test_per_user_refused(self):
        self.make(allusers='')
        with self.assertRaises(ValueError):msi.inspect(self.path)
    def test_renamed_executable_refused(self):
        self.path.write_bytes(b'MZ'+bytes(200))
        with self.assertRaises(ValueError):msi.inspect(self.path)

if __name__=='__main__':unittest.main()
