"""Center link retry, role reachability and worker fault trace.

Pure logic with a synthetic clock and temporary private files: no center,
no network, no installed Agent, no service or registry access.
"""
import contextlib
import faulthandler
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import policy_progress,remote_service_worker,transport_errors
from guarddesk.agent import Agent
from guarddesk.store import Store
from guarddesk.transport_errors import Backoff,CenterTransportError,link_state,link_retry_floor


class Clock:
    def __init__(self):self.now=1000.0
    def __call__(self):return self.now


class BackoffTest(unittest.TestCase):
    def test_bounded_doubling_and_reset(self):
        clock=Clock();gate=Backoff(5,30,clock=clock,jitter=lambda:0)
        self.assertTrue(gate.ready())
        self.assertEqual([gate.failure() for _ in range(6)],[5,10,20,30,30,30])
        self.assertFalse(gate.ready());clock.now+=30;self.assertTrue(gate.ready())
        gate.success();self.assertEqual((gate.delay,gate.failures,gate.at),(5,0,0))

    def test_jitter_is_bounded_and_floor_is_capped(self):
        for value,expected in ((1,7.5),(99,7.5),(-5,5)):
            self.assertEqual(Backoff(5,30,clock=Clock(),jitter=lambda v=value:v).failure(),expected)
        self.assertEqual(Backoff(5,30,clock=Clock(),jitter=lambda:0).failure(300),300)
        self.assertEqual(Backoff(5,30,clock=Clock(),jitter=lambda:0).failure(10**9),3600)
        with self.assertRaises(ValueError):Backoff(0,30)
        with self.assertRaises(ValueError):Backoff(60,30)


class LinkStateTest(unittest.TestCase):
    def test_fixed_reasons_never_carry_exception_text(self):
        secret='https://center.example.test/?token=SECRET C:\\Users\\a\\file'
        cases=[(CenterTransportError('http',http_status=401),'center_rejected_identity'),
            (CenterTransportError('http',http_status=403),'center_rejected_identity'),
            (CenterTransportError('http',http_status=429),'center_busy'),
            (CenterTransportError('http',http_status=503),'center_unavailable'),
            (CenterTransportError('http',http_status=400),'center_http_error'),
            (CenterTransportError('tls'),'tls_failed'),
            (CenterTransportError('temporary_network'),'network_temporary'),
            (CenterTransportError('network_unclassified'),'network_unclassified'),
            (TimeoutError(secret),'local_timeout'),(PermissionError(secret),'local_rejected'),
            (ConnectionError(secret),'center_reply_invalid'),(OSError(secret),'local_error'),
            (ValueError(secret),'invalid_reply')]
        for error,expected in cases:
            state=link_state(error)
            self.assertEqual(state['state'],expected)
            self.assertLessEqual(set(state),{'state','http_status','winerror'})
            self.assertNotIn('SECRET',json.dumps(state))

    def test_only_identity_and_certificate_rejection_retry_slowly(self):
        self.assertEqual(link_retry_floor({'state':'center_rejected_identity'}),300)
        self.assertEqual(link_retry_floor({'state':'tls_failed'}),300)
        for state in ('network_temporary','center_unavailable','local_timeout','local_error'):
            self.assertEqual(link_retry_floor({'state':state}),0)


class AgentFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);watch=root/'watch';watch.mkdir()
        self.config=root/'config.json'
        self.config.write_text(json.dumps({'server':'https://center.example.test:8787','device_id':'a'*24,
            'token':'FIXTURE-TOKEN-NEVER-SENT','watch':str(watch)}))
        self.agent=Agent(self.config);self.clock=Clock()
        monotonic=patch('time.monotonic',self.clock);monotonic.start();self.addCleanup(monotonic.stop)
        jitter=patch('random.random',lambda:0);jitter.start();self.addCleanup(jitter.stop)
        spacing=patch('random.uniform',lambda low,high:low);spacing.start();self.addCleanup(spacing.stop)


class AgentLinkStepTest(AgentFixture):
    def drive(self,seconds,heartbeat,flush,step=5):
        beats=[];uploads=[]
        def beat(*args,**kwargs):beats.append(self.clock.now);return heartbeat(self.clock.now)
        def upload(*args,**kwargs):uploads.append(self.clock.now);return flush(self.clock.now)
        gate=Backoff(5,30);deadline=0;end=self.clock.now+seconds
        with patch.object(self.agent,'heartbeat',beat),patch.object(self.agent,'flush',upload):
            while self.clock.now<end:
                deadline=self.agent._link_step(threading.Event(),gate,deadline)
                self.clock.now+=step
        return beats,uploads

    def test_stuck_upload_never_stretches_heartbeat(self):
        # Regression for the shared retry: the old loop let a failing upload
        # push the heartbeat to a 60 second cadence against a 90 second limit.
        def flush(now):raise ConnectionError('center did not acknowledge the batch')
        beats,uploads=self.drive(600,lambda now:{},flush)
        gaps=[b-a for a,b in zip(beats,beats[1:])]
        self.assertGreaterEqual(len(beats),19);self.assertLessEqual(max(gaps),35)
        upload_gaps=[b-a for a,b in zip(uploads,uploads[1:])]
        self.assertLessEqual(max(upload_gaps),65);self.assertLess(len(uploads),20)
        self.assertEqual(self.agent.feature_status['center_link'],{'state':'connected'})

    def test_failed_heartbeat_backs_off_and_upload_lane_continues(self):
        def heartbeat(now):raise CenterTransportError('temporary_network')
        beats,uploads=self.drive(120,heartbeat,lambda now:{'sent':0,'pending':False})
        self.assertEqual([b-beats[0] for b in beats[:5]],[0,5,15,35,65])
        self.assertEqual(uploads,[beats[0]+60])
        self.assertEqual(self.agent.feature_status['center_link'],{'state':'network_temporary'})

    def test_recovery_reports_last_reason_once_connected(self):
        down=self.clock.now+60
        def heartbeat(now):
            if now<down:raise CenterTransportError('http',http_status=503)
            return {}
        beats,_=self.drive(200,heartbeat,lambda now:{'pending':False})
        self.assertEqual(self.agent.feature_status['center_link'],{'state':'connected','last_failure':'center_unavailable'})
        recovered=[b for b in beats if b>=down]
        self.assertLessEqual(recovered[0]-down,35)
        self.assertLessEqual(max(b-a for a,b in zip(recovered,recovered[1:])),35)

    def test_revoked_identity_retries_slowly_without_reenrollment(self):
        def heartbeat(now):raise CenterTransportError('http',http_status=401)
        before=self.config.read_bytes()
        beats,_=self.drive(900,heartbeat,lambda now:{'pending':False})
        self.assertEqual([b-beats[0] for b in beats],[0,300,600])
        self.assertEqual(self.agent.feature_status['center_link'],{'state':'center_rejected_identity','http_status':401})
        self.assertEqual(self.config.read_bytes(),before)


class FakeCompanion:
    policy=None
    def __init__(self,owner):self.owner=owner;self.polls=[];self.configured=0
    def configure(self):
        self.configured+=1
        if self.owner.offline():raise CenterTransportError('temporary_network')
    def poll(self,online=True):self.polls.append((self.owner.clock.now,online))
    def close(self):pass


class NativeWorkerRetryTest(AgentFixture):
    def offline(self):return self.clock.now<self.restore

    def run_worker(self,seconds):
        from guarddesk.native_usb import UsbWorker
        worker=UsbWorker(self.config);cycles=[];end=self.clock.now+seconds;companion=FakeCompanion(self)
        class Stop:
            def is_set(inner):return self.clock.now>=end
            def wait(inner,timeout=None):self.clock.now+=timeout;return self.clock.now>=end
            def set(inner):pass
        def cycle(*args,**kwargs):cycles.append(self.clock.now);return {}
        patches=[patch('guarddesk.native_usb.is_admin',return_value=True),
            patch('guarddesk.single_instance.machine_instance',lambda *a:contextlib.nullcontext()),
            patch('guarddesk.native_usb.background_work',lambda:contextlib.nullcontext()),
            patch('guarddesk.software_client.start',lambda *a:None),
            patch('guarddesk.custom_client.CustomClient',side_effect=OSError('fixture has no protected native root')),
            patch('guarddesk.application_control.ExtendedWorker',lambda agent:companion),
            patch('guarddesk.machine_agent.eligible',return_value=False),
            patch('guarddesk.decommission.native_step',return_value=None),
            patch.object(worker,'cycle',cycle)]
        with contextlib.ExitStack() as stack:
            for item in patches:stack.enter_context(item)
            worker.run(Stop(),extended=True)
        return worker,cycles,companion

    def test_offline_center_is_not_retried_every_round(self):
        # Old loop: one full failed sync every 5 seconds for the whole outage.
        self.restore=self.clock.now+10**6
        worker,cycles,companion=self.run_worker(300)
        self.assertEqual([c-cycles[0] for c in cycles[:5]],[0,5,15,35,65])
        self.assertLessEqual(len(cycles),13)
        self.assertLessEqual(max(b-a for a,b in zip(cycles,cycles[1:])),35)
        # Local collection continues every round; nothing is sent while backing off.
        self.assertGreaterEqual(len(companion.polls),40)
        self.assertFalse(any(online for _,online in companion.polls))
        with worker.agent.db() as db:
            self.assertTrue(db.execute("SELECT 1 FROM state WHERE key='native_usb_error'").fetchone())

    def test_recovered_center_returns_to_normal_cadence(self):
        self.restore=self.clock.now+100
        _,cycles,companion=self.run_worker(400)
        after=[c for c in cycles if c>=self.restore]
        self.assertLessEqual(after[0]-self.restore,35)
        self.assertTrue(all(25<=b-a<=35 for a,b in zip(after,after[1:])))
        self.assertTrue(any(online for now,online in companion.polls if now>after[0]))


class StatusReportThrottleTest(AgentFixture):
    def test_status_goes_out_on_change_or_every_thirty_seconds(self):
        from guarddesk.application_control import ExtendedWorker,STATUS_REPORT_SECONDS
        self.assertEqual(STATUS_REPORT_SECONDS,30)
        self.assertLess(STATUS_REPORT_SECONDS*3,120)  # center freshness window
        worker=ExtendedWorker(self.agent,start_documents=False)
        worker.policy={'application_publishers':[],'application_audit':False,'file_audit':{'enabled':False},
            'application_control':{'enabled':False}}
        worker.status={'status':'configured'};calls=[];flushes=[]
        def call(path,body,timeout=10):calls.append((self.clock.now,path,body.get('status')));return {'ok':True}
        with patch.object(worker,'configure_documents'),patch('guarddesk.custom_client.effective_body',return_value={'software':[]}),\
             patch('guarddesk.custom_settings.compatible_policy',side_effect=lambda policy,*a:policy),\
             patch.object(self.agent,'call',call),patch.object(self.agent,'flush',lambda **k:flushes.append(self.clock.now) or {'pending':False}):
            for _ in range(24):worker.poll();self.clock.now+=5
            self.assertEqual([c[0]-calls[0][0] for c in calls],[0,30,60,90])
            self.assertEqual(flushes,[calls[0][0]+60])
            worker.status={'status':'failed','error':'fixture'};worker.poll()
            self.assertEqual(calls[-1][2],'failed');self.assertEqual(len(calls),5)
            before=len(calls);flushed=len(flushes)
            report=worker.poll(online=False)
            self.assertEqual((len(calls),len(flushes)),(before,flushed));self.assertEqual(report['status'],'failed')
        self.assertTrue(all(path=='/api/agent/extended-status' for _,path,_ in calls))


class AvailabilityTest(unittest.TestCase):
    def device(self,seen,contact=0,revoked=0):return {'revoked':revoked,'last_seen':seen,'last_contact':contact}

    def test_partial_is_separate_from_ordinary_heartbeat_status(self):
        now=10000.0;check=policy_progress.availability
        self.assertEqual(check(self.device(now-10),now),'online')
        self.assertEqual(check(self.device(now-500,now-10),now),'partial')
        self.assertEqual(check(self.device(now-500,now-90),now),'offline')
        self.assertEqual(check(self.device(now-500),now),'offline')
        self.assertEqual(check(self.device(now-1,now-1,1),now),'revoked')
        # Older rows/Servers without the column and bad values never look reachable.
        self.assertEqual(check({'revoked':0,'last_seen':now-500},now),'offline')
        self.assertEqual(check(self.device(now-500,float('nan')),now),'offline')
        self.assertEqual(check(self.device(now+500,now+500),now),'offline')

    def test_contact_column_migrates_and_writes_are_throttled(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'control.sqlite3';store=Store(path);Store(path)  # idempotent re-open
            with store.connect() as db:
                self.assertIn('last_contact',{r[1] for r in db.execute('PRAGMA table_info(devices)')})
                db.execute("INSERT INTO devices(id,token,name,department,last_seen,enrolled_at,last_address) VALUES ('d','t','n','x',0,0,'')")
                row=lambda:db.execute("SELECT * FROM devices WHERE id='d'").fetchone()
                self.assertEqual(row()['last_contact'],0)
                self.assertEqual(policy_progress.availability(dict(row()),5000),'offline')
                policy_progress.touch(db,row(),5000);self.assertEqual(row()['last_contact'],5000)
                policy_progress.touch(db,row(),5010);self.assertEqual(row()['last_contact'],5000)
                policy_progress.touch(db,row(),5015);self.assertEqual(row()['last_contact'],5015)
                policy_progress.touch(db,row(),100);self.assertEqual(row()['last_contact'],100)  # clock moved back
                self.assertEqual(row()['last_seen'],0)
                self.assertEqual(policy_progress.availability(dict(row()),150),'partial')


class WorkerFaultTraceTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.was_enabled=faulthandler.is_enabled()
        self.addCleanup(lambda:faulthandler.enable() if self.was_enabled else faulthandler.disable())

    def test_trace_is_enabled_bounded_and_closed(self):
        stream=remote_service_worker.fault_trace(self.root)
        self.assertIsNotNone(stream);self.assertTrue(faulthandler.is_enabled())
        self.assertIs(remote_service_worker.fault_bounded(stream),stream)
        stream.write('x'*(remote_service_worker.FAULT_LIMIT+1));stream.flush()
        self.assertIsNone(remote_service_worker.fault_bounded(stream))
        self.assertFalse(faulthandler.is_enabled());self.assertTrue(stream.closed)
        remote_service_worker.fault_close(None)
        # The next start keeps one previous file and begins a new bounded one.
        again=remote_service_worker.fault_trace(self.root);remote_service_worker.fault_close(again)
        log=self.root/remote_service_worker.FAULT_LOG
        self.assertTrue(log.with_suffix('.previous.log').exists())
        text=log.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('worker_start version='));self.assertLess(len(text),200)

    def test_unavailable_directory_never_blocks_the_worker(self):
        self.assertIsNone(remote_service_worker.fault_trace(self.root/'missing'))
        remote_service_worker.exit_evidence(self.root/'missing',OSError('ignored'))

    def test_exit_evidence_has_fixed_fields_only(self):
        error=OSError('C:\\Users\\a\\secret token=SECRET');error.winerror=5
        remote_service_worker.exit_evidence(self.root,error)
        body=json.loads((self.root/remote_service_worker.EXIT_EVIDENCE).read_text(encoding='utf-8'))
        self.assertEqual(set(body),{'format','version','time','type','winerror'})
        self.assertEqual((body['type'],body['winerror']),('OSError',5))
        self.assertNotIn('SECRET',json.dumps(body))


if __name__=='__main__':unittest.main()
