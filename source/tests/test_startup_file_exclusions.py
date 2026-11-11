"""Synthetic system paths and private fixture files only; never touch real hives."""
import copy
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from guarddesk.store import canonical
from guarddesk.windows_events import SecurityCollector,excluded
from guarddesk.windows_watch import DirectoryMonitor
import test_endpoint_controls as fixtures


class StartupExclusionTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued
    save_policy=fixtures.EndpointTest.save_policy

    def drain(self):
        for _ in range(100):
            result=self.agent.scan(max_entries=2,time_budget=1)
            if not result['in_progress']:return result
        self.fail('scan did not finish')

    def test_system_startup_hive_paths_and_document_boundaries(self):
        for path in (r'C:\Windows\Prefetch\APP.pf',r'C:\Boot',r'D:\EFI',r'C:\Recovery\system.wim',
                     r'\\?\C:\Windows\System32\x.dll',r'\??\C:\Boot\BCD',
                     r'C:\pagefile.sys',r'D:\hiberfil.sys',r'C:\swapfile.sys',r'C:\bootmgr',
                     r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\agent.lnk',
                     r'C:\Users\alice\NTUSER.DAT',r'C:\Users\alice\NTUSER.DAT.LOG1',
                     r'C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2',
                     r'C:\Users\alice\NTUSER.DAT{12345678-abcd-1234-abcd-123456789012}.TM.blf'):
            with self.subTest(path=path):self.assertTrue(excluded(path))
        for path in (r'C:\Users\alice\Documents\budget.xlsx',r'C:\Users\alice\Documents\NTUSER.DAT',
                     r'C:\Users\alice\Documents\UsrClass.dat',r'C:\Users\alice\NTUSER.DAT-notes.txt',
                     r'C:\Users\alice\AppData\Local\Microsoft\Windows\business.docx',
                     r'C:\Users\alice\Documents\Boot\brief.docx',
                     r'\\server\share\Boot\brief.docx',
                     r'C:\Users\alice\Start Menu\Programs\StartupReports\report.docx'):
            with self.subTest(path=path):self.assertFalse(excluded(path))
        with patch.dict(os.environ,{'PUBLIC':r'D:\Profiles\Public','USERPROFILE':r'E:\MovedProfile\alice'}):
            self.assertTrue(excluded(r'D:\Profiles\bob\NTUSER.DAT'))
            self.assertTrue(excluded(r'E:\MovedProfile\alice\AppData\Local\Microsoft\Windows\UsrClass.dat'))

    def test_security_excluded_delete_marker_has_no_path_or_false_warning(self):
        collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(10,4656,path=r'C:\Users\alice\NTUSER.DAT'),self.policy)
            marker=db.execute('SELECT payload FROM audit_handles').fetchone()[0]
            self.assertEqual(json.loads(marker),{'_excluded':True})
            collector.ingest(db,fixtures.event(11,4663,path=r'C:\Users\alice\NTUSER.DAT'),self.policy)
            collector.ingest(db,fixtures.event(12,4660),self.policy)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_handles').fetchone()[0],0)
        self.assertEqual(self.queued(),[])
        # File opened by a startup/system process is still audited by path.
        e=fixtures.event(13,4663,path=r'C:\Users\alice\Documents\auto-opened.xlsx',mask='0x3')
        e['data']['ProcessName']=r'C:\Windows\System32\winlogon.exe'
        with self.agent.db() as db:collector.ingest(db,e,self.policy)
        self.assertEqual([e['kind'] for e in self.queued()],['file.opened'])

    def test_unknown_delete_still_warns_and_excluded_handle_close_cleans_up(self):
        collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4660),self.policy)
            collector.ingest(db,fixtures.event(2,4656,path=r'C:\Windows\System32\x.dll'),self.policy)
            collector.ingest(db,fixtures.event(3,4658),self.policy)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_handles').fetchone()[0],0)
        self.assertEqual([e['kind'] for e in self.queued()],['agent.audit_unresolved_delete'])

    def test_snapshot_prunes_system_directories_without_opening_excluded_files(self):
        ignored=[]
        for relative in ('Windows/System32/x.dll','Boot/BCD','EFI/boot.bin','Recovery/state.bin',
                         'Start Menu/Programs/Startup/start.lnk','Users/alice/NTUSER.DAT','custom/cache.bin'):
            path=self.watch/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture only');ignored.append(path)
        doc=self.watch/'report.docx';doc.write_text('business document')
        # Owned fixture dirs stand in for volume-root assets; actual volume
        # roots are checked by synthetic string tests, never written here.
        self.policy['file_audit']['exclude_paths']=[str(self.watch/part) for part in ('custom','Boot','EFI','Recovery')];self.save_policy()
        original_open=Path.open;original_scandir=os.scandir;opened=[];visited=[]
        def checked_open(path,*args,**kwargs):opened.append(path);return original_open(path,*args,**kwargs)
        def checked_scandir(path):visited.append(Path(path));return original_scandir(path)
        with patch.dict(os.environ,{'SystemRoot':str(self.watch/'Windows'),'PUBLIC':str(self.watch/'Users/Public')}),\
             patch.object(Path,'open',checked_open),patch('guarddesk.snapshot.os.scandir',side_effect=checked_scandir):
            result=self.drain()
        self.assertEqual(result['files'],1);self.assertEqual(opened,[doc])
        self.assertFalse(any(self.watch/part in visited for part in ('Windows','Boot','EFI','Recovery','custom')))
        self.assertEqual([e['details']['path'] for e in self.queued()],[str(doc)])

    def test_old_excluded_metadata_does_not_generate_fake_delete_or_clear_logs(self):
        self.agent.queue('file.opened',{'path':'historical event stays'})
        with self.agent.db() as db:
            for relative in ('Start Menu/Programs/Startup/old.lnk','missing-business.docx'):db.execute('INSERT INTO files VALUES (?,?)',(relative,canonical({})))
        self.drain()
        rows=self.queued();self.assertEqual(rows[0]['details']['path'],'historical event stays')
        self.assertEqual([r['details']['relative_path'] for r in rows if r['kind']=='file.deleted'],['missing-business.docx'])
        with self.agent.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM files').fetchone()[0],0)

    def test_policy_change_restarts_sliced_scan_with_new_exclusions(self):
        for number in range(5):(self.watch/f'{number}.docx').write_text('fixture')
        cache=self.watch/'custom';cache.mkdir();(cache/'x.bin').write_text('fixture')
        first=self.agent.scan(max_entries=1,time_budget=1);self.assertTrue(first['in_progress']);old=self.agent._snapshot
        self.policy['file_audit']['exclude_paths']=[str(cache)];self.save_policy()
        second=self.agent.scan(max_entries=1,time_budget=1);self.assertTrue(second['in_progress']);self.assertIsNot(self.agent._snapshot,old)
        self.drain()
        self.assertFalse(any(e['kind']=='file.deleted' for e in self.queued()))

    @unittest.skipUnless(os.name=='nt','Windows directory API')
    def test_native_directory_notifications_ignore_boot_churn_keep_documents(self):
        boot=self.watch/'Start Menu/Programs/Startup';boot.mkdir(parents=True)
        monitor=DirectoryMonitor(self.agent,{**self.policy,'file_audit':{**self.policy['file_audit'],'scope':'managed'}})
        try:
            self.assertEqual(monitor.start()['active'],1);time.sleep(.1)
            (boot/'fixture.bin').write_text('ignored fixture');doc=self.watch/'report.docx';doc.write_text('recorded')
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                if any(e['details'].get('path')==str(doc) for e in self.queued()):break
                time.sleep(.05)
            rows=self.queued();self.assertTrue(any(e['details'].get('path')==str(doc) for e in rows))
            self.assertFalse(any('fixture.bin' in e['details'].get('path','') for e in rows))
        finally:monitor.close()
