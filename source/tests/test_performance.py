"""Prevent content rereads, unbounded batches and false deletes during sliced scans."""
import copy
import json
import io
import os
import tempfile
import socket
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.agent import Agent,private_write
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import canonical
from guarddesk.upload_proxy import GuardProxy
from guarddesk.windows_controls import WindowsControls


class PerformanceTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.watch=self.root/'documents';self.watch.mkdir()
        self.config=self.root/'agent/config.json'
        private_write(self.config,{'server':'http://127.0.0.1:1','token':'performance-test','device_id':'test','watch':str(self.watch)})
        self.agent=Agent(self.config)

    def tearDown(self):self.agent.close_collectors();self.temp.cleanup()

    def drain_scan(self,entries=2):
        for _ in range(100):
            result=self.agent.scan(max_entries=entries,time_budget=1)
            if not result['in_progress']:return result
        self.fail('Scan never completed')

    def queued(self):
        with self.agent.db() as db:return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox ORDER BY created')]

    def test_existing_files_skip_content_even_after_edit_and_old_verify_deadline(self):
        file=self.watch/'one.txt';file.write_text('alpha');self.drain_scan()
        with patch.object(Path,'open',side_effect=AssertionError('Unchanged content reread')):self.drain_scan()
        before=file.stat();file.write_text('bravo');os.utime(file,ns=(before.st_atime_ns,before.st_mtime_ns))
        # Legacy verification deadlines must not restart content hashing.
        with self.agent.db() as db:
            row=json.loads(db.execute('SELECT signature FROM files').fetchone()[0]);row['verified_at']=0
            db.execute('UPDATE files SET signature=?',(canonical(row),))
        with patch.object(Path,'open',side_effect=AssertionError('Existing content reread')):
            self.drain_scan()
            file.touch();self.drain_scan()
        self.assertEqual([e['kind'] for e in self.queued()],['file.created'])

    def test_scan_slices_never_delete_unvisited_files_and_restart_is_safe(self):
        for n in range(9):(self.watch/f'{n}.txt').write_text('hello')
        first=self.agent.scan(max_entries=2,time_budget=1)
        self.assertTrue(first['in_progress']);self.assertEqual(first['entries_this_slice'],2)
        self.agent.close_collectors();self.agent=Agent(self.config);self.drain_scan()
        (self.watch/'8.txt').unlink()
        result=self.agent.scan(max_entries=1,time_budget=1)
        self.assertTrue(result['in_progress']);self.assertFalse(any(e['kind']=='file.deleted' for e in self.queued()))
        self.drain_scan()
        deleted=[e for e in self.queued() if e['kind']=='file.deleted'];self.assertEqual(len(deleted),1);self.assertEqual(deleted[0]['details']['path'],str(self.agent.root/'8.txt'));self.assertEqual(deleted[0]['details']['relative_path'],'8.txt')

    def test_unreadable_traversal_preserves_old_files(self):
        (self.watch/'old.txt').write_text('one');self.drain_scan()
        with patch('guarddesk.snapshot.os.scandir',side_effect=PermissionError('access denied')):
            self.assertTrue(self.drain_scan()['partial'])
        self.assertFalse(any(e['kind']=='file.deleted' for e in self.queued()))
        self.assertEqual(self.queued()[-1]['kind'],'agent.scan_partial')

    def test_changed_large_file_uses_bounded_python_memory(self):
        (self.watch/'large.bin').write_bytes(b'x'*(8*1024*1024))
        tracemalloc.start()
        try:
            self.drain_scan();_,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertLess(peak,1024*1024,'Hashing must not allocate the entire document')
        self.assertEqual(len(self.queued()[0]['details']['sha256']),64)

    def test_background_flush_keeps_unsent_rows_and_retries_lost_ack(self):
        with self.agent.db() as db:
            for n in range(240):self.agent.queue('test.event',{'n':n},db=db)
        def accept(path,body):return {'accepted':[e['event_id'] for e in body['events']]}
        with patch.object(self.agent,'call',side_effect=accept) as send:
            result=self.agent.flush(max_batches=1,require_empty=False)
            self.assertEqual(result,{'sent':100,'pending':True});self.assertEqual(send.call_count,1)
        self.assertEqual(self.agent.queue_status()['pending'],140)
        with patch.object(self.agent,'call',return_value={'accepted':[]}):
            with self.assertRaises(ConnectionError):self.agent.flush(max_batches=1,require_empty=False)
        self.assertEqual(Agent(self.config).queue_status()['pending'],140)
        with patch.object(self.agent,'call',side_effect=accept):self.agent.flush()
        self.assertEqual(self.agent.queue_status()['pending'],0)

    def test_fresh_web_events_bypass_backlog_without_starving_older_files(self):
        with self.agent.db() as db:
            for n in range(300):self.agent.queue('file.created',{'n':n},db=db)
            for n in range(40):self.agent.queue('web.navigation',{'url':'https://example.com/'+str(n)},db=db)
        batches=[]
        def accept(path,body):batches.append(body['events']);return {'accepted':[e['event_id'] for e in body['events']]}
        with patch.object(self.agent,'call',side_effect=accept):self.agent.flush(max_batches=1,require_empty=False)
        self.assertEqual(sum(e['kind']=='web.navigation' for e in batches[0]),25)
        self.assertEqual(sum(e['kind']=='file.created' for e in batches[0]),75)
        self.assertEqual(self.agent.queue_status()['pending'],240)
        with patch.object(self.agent,'call',return_value={'accepted':[]}):
            with self.assertRaises(ConnectionError):self.agent.flush(max_batches=1,require_empty=False)
        reopened=Agent(self.config)
        with reopened.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox_priority').fetchone()[0],15)
        with patch.object(reopened,'call',side_effect=accept):reopened.flush()
        self.assertEqual(reopened.queue_status()['pending'],0)
        with reopened.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM outbox_priority').fetchone()[0],0)

    def test_worker_wal_session_preserves_committed_events_for_other_connections(self):
        with self.agent.wal_session():
            self.agent.queue('test.committed',{'value':1})
            self.assertTrue(Path(str(self.agent.state)+'-wal').exists())
            reopened=Agent(self.config)
            try:self.assertEqual(reopened.queue_status()['pending'],1)
            finally:reopened.close_collectors()
        self.assertEqual(Agent(self.config).queue_status()['pending'],1)

    def test_serialization_batch_is_byte_bounded(self):
        with self.agent.db() as db:
            for n in range(30):self.agent.queue('test.large',{'data':'x'*40000},db=db)
        sizes=[]
        def accept(path,body):
            sizes.append(len(canonical(body).encode()));return {'accepted':[e['event_id'] for e in body['events']]}
        with patch.object(self.agent,'call',side_effect=accept):self.agent.flush()
        self.assertGreater(len(sizes),1);self.assertLess(max(sizes),263000)

    def test_software_inventory_cached_while_policy_always_refreshes(self):
        policy={'version':1,'body':copy.deepcopy(DEFAULT_POLICY)}
        with patch('guarddesk.agent.inventory',return_value={'software':['Application'],'software_coverage':'test','user_accounts':['TEST\\user']}) as collect,patch.object(self.agent,'call',return_value={'policy':policy}) as call:
            self.agent.heartbeat();self.agent.heartbeat()
            self.assertEqual(collect.call_count,1);self.assertEqual(call.call_count,2)
            self.agent._next_inventory=0;self.agent.heartbeat()
            self.assertEqual(collect.call_count,2);self.assertEqual(collect.call_args.kwargs,{'include_software':False})
            self.agent._next_inventory=0;self.agent._next_software=0;self.agent.heartbeat()
            self.assertEqual(collect.call_count,3);self.assertEqual(collect.call_args.kwargs,{})

    def test_proxy_hot_path_avoids_sqlite_per_payload_chunk(self):
        proxy=GuardProxy(('127.0.0.1',0),self.agent)
        try:
            with patch.object(self.agent,'cached_policy',wraps=self.agent.cached_policy) as read:
                for _ in range(1000):proxy.rules()
                self.assertEqual(read.call_count,1)
                proxy._rules_until=0;proxy.rules();self.assertEqual(read.call_count,2)
        finally:proxy.server_close()

    def test_process_sample_reports_real_memory_and_explicit_cpu_interval(self):
        from guarddesk.performance import ProcessSampler
        sampler=ProcessSampler();first=sampler.sample()
        self.assertIsNone(first['cpu_machine_percent'])
        second=sampler.sample();self.assertGreaterEqual(second['cpu_machine_percent'],0)
        if os.name=='nt':
            self.assertGreater(second['working_set_bytes'],0);self.assertGreater(second['private_bytes'],0)

    def test_transport_is_reused_and_loopback_does_not_load_tls_roots(self):
        class Opener:
            def open(self,*args,**kwargs):return io.BytesIO(b'{"ok":true}')
        with patch('guarddesk.agent.urllib.request.build_opener',return_value=Opener()) as build,patch('guarddesk.agent.ssl.create_default_context') as tls:
            self.assertTrue(self.agent.call('/api/test',{})['ok']);self.agent.call('/api/test',{})
            self.assertEqual(build.call_count,1);tls.assert_not_called()

    def test_proxy_overload_is_bounded_and_slot_released_on_disconnect(self):
        proxy=GuardProxy(('127.0.0.1',0),self.agent,max_connections=1)
        thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
        try:
            with socket.create_connection(proxy.server_address,timeout=2) as first:
                first.sendall(b'GET ');time.sleep(.1)
                with socket.create_connection(proxy.server_address,timeout=2) as second:
                    self.assertIn(b'503',second.recv(4096))
            deadline=time.monotonic()+2
            while True:
                with socket.create_connection(proxy.server_address,timeout=2) as third:
                    third.sendall(b'invalid\r\n\r\n');reply=third.recv(4096)
                if b'502' in reply:break
                if time.monotonic()>deadline:self.fail('Proxy capacity did not recover')
                time.sleep(.05)
        finally:proxy.close();thread.join(3)

    def test_healthy_native_controls_do_not_spawn_powershell_each_minute(self):
        controls=WindowsControls(self.agent);controls.directory.mkdir()
        policy=copy.deepcopy(DEFAULT_POLICY)
        controls.manifest.write_text(canonical({'audit_settings':policy['file_audit'],'audit_checked_at':time.time(),'file_audit':{'status':'configured'}}))
        (controls.directory/'qos-status.json').write_text(canonical({'rules':[],'checked_at':time.time(),'report':{'status':'no_rules'}}))
        with patch('guarddesk.windows_controls.is_admin',return_value=True),patch('guarddesk.windows_controls.powershell',return_value={'status':'configured'}) as shell,patch.object(controls,'apply_usb',return_value={'status':'configured'}),patch.object(controls,'install') as install:
            self.assertEqual(controls.apply(policy)['status'],'configured');controls.apply(policy)
            install.assert_not_called();self.assertEqual(shell.call_count,1) # Validate ActiveStore once on each process start.
            policy['file_audit']['exclude_paths']=[r'C:\\Excluded'];controls.apply(policy);self.assertEqual(install.call_count,1)
            policy['upload_rules']=[{'type':'app','target':'upload.exe','rate_kbps':100}];controls.apply(policy);self.assertEqual(shell.call_count,2)
            restarted=Agent(self.config)
            try:WindowsControls(restarted).apply(policy);self.assertEqual(shell.call_count,3)
            finally:restarted.close_collectors()


if __name__=='__main__':unittest.main()
