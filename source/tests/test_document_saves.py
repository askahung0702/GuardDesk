"""Replay directory notifications and completed writes through the durable endpoint uploader."""
import csv
import io
import json
import ntpath
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from guarddesk import document_saves
from guarddesk.agent import Agent, private_write
from guarddesk.audit_reports import ACTIONS
from guarddesk.file_exclusions import TMP_FILE_RULE, excluded_activity
from guarddesk.windows_watch import DirectoryMonitor, FileIdMoves, RenamePairs, consolidate_moves, decode_extended


class DocumentSaveTest(unittest.TestCase):
    folder = r'C:\Users\example\OneDrive\Docs'
    temp = r'C:\Users\example\AppData\Local\Temp\{097FDF78-E487-4C9D-AB3B-3967896833C9}.tmp'

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.config = Path(directory.name)/'agent.json'
        private_write(self.config, {'watch':directory.name, 'device_id':'owned-test'})
        self.agent = Agent(self.config)
        self.received = []
        self.pairs = RenamePairs()
        self.moves = FileIdMoves()
        self.clock = patch('time.time',return_value=100).start()
        self.addCleanup(patch.stopall)
        self.agent.call = self.accept

    def accept(self, path, body):
        self.assertEqual(path,'/api/agent/events')
        self.received.extend(body['events'])
        return {'accepted':[e['event_id'] for e in body['events']]}

    def notify(self, when, *entries):
        self.clock.return_value = when
        decoded = []
        for action,path,ref,size in entries:
            encoded = path.encode('utf-16-le')
            header = bytearray(84)
            struct.pack_into('<I',header,4,action)
            struct.pack_into('<qI',header,48,size,0x20)
            struct.pack_into('<Q',header,64,ref)
            struct.pack_into('<I',header,80,len(encoded))
            decoded.extend(decode_extended(header+encoded))
        pairs = self.pairs.consume([(a,p,attrs,ref,size) for a,p,ref,attrs,size in decoded],now=when)
        moves = self.moves.consume([(a,p,ref,attrs) for a,p,ref,attrs,size in decoded],now=when)
        for kind,details in consolidate_moves(pairs+moves):
            details.pop('_path_attributes',None)
            self.agent.queue(kind,{**details,'source':'ReadDirectoryChangesW'},occurred=when)

    def write(self, when, path, program='editor.exe', **changes):
        self.agent.queue('file.written',dict({
            'source':'windows_etw_file_io','path':path,'process_id':171,'process_created':12,
            'process_identity_status':'creation_time_checked','process':program,
            'written_bytes':14001,'user':None},**changes),occurred=when)

    def test_same_buffer_file_id_move_once_and_ambiguous_names_kept(self):
        src,dst=self.folder+r'\a.txt',self.folder+r'\archive\a.txt'
        self.notify(100,(2,src,31,10),(1,dst,31,10))
        self.assertEqual(self.drain(),[('file.moved',src)])
        self.assertEqual(self.received[0]['details']['destination_path'],dst)
        self.received.clear()
        self.notify(101,(2,src,32,10),(1,dst,33,10))
        self.assertCountEqual(self.drain(),[('file.deleted',src),('file.created',dst)])

    def swap(self, final, stage, backup, new=False, cleanup=True, process='editor.exe', placeholder_bytes=0):
        if new:
            self.notify(100,(1,final,1,0),(2,final,1,placeholder_bytes))
            # An upload between the initial placeholder and the final rename.
            self.assertTrue(self.agent.flush(require_empty=False)['pending'])
            self.notify(102,(1,final,2,0))
        self.notify(102,(1,stage,3,0))
        self.write(102,stage,process)
        self.notify(102,(4,final,2,0),(5,backup,2,0))
        self.notify(102,(4,stage,3,14001),(5,final,3,14001))
        if cleanup:
            self.notify(102,(2,backup,2,0),(1,self.temp,2,0))

    def drain(self):
        self.clock.return_value = 140
        result = self.agent.flush(require_empty=False)
        self.assertFalse(result['pending'])
        return [(e['kind'],e['details']['path']) for e in self.received if 'path' in e['details']]

    def test_reported_new_file_nine_visible_observations_are_one(self):
        final = self.folder+r'\report.docx'
        backup = self.folder+r'\{42685A46-F8B5-4ECE-86A1-7D79F8C7E0C7}.tmp'
        self.swap(final,self.folder+r'\~$report.tmp',backup,True,False,'WINWORD.EXE')
        # An excluded Temp destination has no separate create notification; the
        # volume-ID move still describes crossing into Temp in the field report.
        self.notify(102,(2,backup,2,0))
        self.agent.queue('file.moved',{'source':'ReadDirectoryChangesW','path':backup,'file_id':'2',
                         'source_path':backup,'destination_path':self.temp,'correlation':'same_volume_file_id_remove_add'})
        self.assertEqual(self.agent.queue_status()['pending'],9)
        self.assertEqual(self.drain(),[('file.created',final)])
        result = self.received[0]['details']
        self.assertEqual((result['observations'],result['process']),(9,'WINWORD.EXE'))
        self.assertNotIn('.tmp',json.dumps(self.received))
        self.assertNotIn('_save_object',json.dumps(self.received))

    def test_arbitrary_document_and_staging_names_and_editors(self):
        for index,(file,program) in enumerate([('budget.xlsx','EXCEL.EXE'),('talk.pptx','POWERPNT.EXE'),
                                               ('notes.txt','editor.exe'),('README','other.exe'),('data.custom','tool.exe')]):
            with self.subTest(file=file):
                self.received.clear()
                folder = self.folder+str(index)
                final = ntpath.join(folder,file)
                self.swap(final,folder+r'\randomstage',folder+r'\old-buffer',process=program)
                self.assertEqual(self.drain(),[('file.saved',final)])
                self.assertEqual(self.received[0]['details']['observations'],7)
                self.assertEqual(self.received[0]['details']['process'],program)

    def test_new_temp_publication_and_unlink_then_replace(self):
        for existing in (False,True):
            with self.subTest(existing=existing):
                self.received.clear()
                stage, final = self.folder+r'\Cedd4100', self.folder+r'\report.xlsx'
                self.notify(100,(1,stage,3,0))
                self.write(101,stage,'EXCEL.EXE')
                if existing:
                    self.notify(102,(2,final,2,301))
                self.notify(102,(4,stage,3,555),(5,final,3,555))
                self.assertEqual(self.drain(),[('file.saved',final)])
                self.assertEqual(self.received[0]['details']['evidence'],
                                 'same_directory_replacement' if existing else 'temporary_file_published')

    def test_true_delete_write_ordinary_tmp_and_upload_are_independent(self):
        tmp, final = self.folder+r'\independent.tmp', self.folder+r'\README'
        self.notify(100,(1,tmp,10,0),(2,final,20,12))
        self.write(101,final)
        self.agent.queue('web.upload_started',{'source':'browser_webrequest','path':tmp,'upload_id':'request'})
        self.agent.queue('agent.audit_gap',{'reason':'fixture'},'warning')
        self.agent.flush(require_empty=False)
        self.assertEqual({e['kind'] for e in self.received},{'web.upload_started','agent.audit_gap','file.written'})
        self.drain()
        self.assertCountEqual([e['kind'] for e in self.received],
                              ['agent.audit_gap','web.upload_started','file.created','file.deleted','file.written'])

    def test_nonempty_deleted_file_is_never_folded_as_an_empty_placeholder(self):
        final = self.folder+r'\file.any'
        self.swap(final,self.folder+r'\stage.tmp',self.folder+r'\old.tmp',True,placeholder_bytes=23)
        kinds = self.drain()
        self.assertCountEqual(kinds,[('file.created',final),('file.deleted',final),('file.created',final)])

    def test_unconfirmed_names_writers_and_out_of_scope_moves(self):
        final, stage = self.folder+r'\report.pdf', self.folder+r'\save.tmp'
        self.notify(100,(1,stage,50,0))
        self.write(101,stage)
        self.write(101,stage,'other.exe',process_id=172)
        self.notify(102,(4,stage,50,12),(5,final,50,12))
        self.notify(102,(4,final,70,10),(5,self.folder+r'\other',81,10))
        self.notify(102,(4,self.folder+r'\transfer.tmp',28,10),(5,r'E:\report.pdf',28,10))
        self.assertCountEqual([k for k,_ in self.drain()],
                              ['file.created','file.written','file.written','file.renamed','file.renamed','file.moved'])

    def test_incomplete_move_preserves_original_evidence(self):
        src = self.folder+r'\given-name.tmp'
        self.agent.queue('file.moved',{'source':'ReadDirectoryChangesW','path':src,'file_id':'18'})
        self.assertEqual(self.drain(),[('file.moved',src)])

    def test_explicit_drain_includes_candidate_arriving_between_batches(self):
        self.agent.queue('file.created',{'path':'already queued'})
        settle = document_saves.settle
        def collect_during_drain(db,force=False):
            settle(db,force)
            if len(self.received) == 1 and not self.agent.queue_status()['pending']:
                self.notify(105,(1,self.folder+r'\newfile',12,0))
        with patch.object(document_saves,'settle',side_effect=collect_during_drain):
            result = self.agent.flush()
        self.assertEqual(result,{'sent':2,'pending':False})

    def test_unrelated_directory_and_outside_time_window_are_not_correlated(self):
        stage = self.folder+r'\same.tmp'
        final = self.folder+r'\final'
        self.notify(100,(1,stage,51,0))
        self.write(100,self.folder+r'\other\same.tmp')
        self.write(100,stage)
        self.notify(110,(4,stage,51,12),(5,final,51,12))
        self.assertCountEqual([k for k,_ in self.drain()],['file.created','file.written','file.written','file.renamed'])

    def test_simultaneous_same_names_in_two_folders_remain_two_saves(self):
        results = []
        for ref,folder in enumerate((self.folder,self.folder+r'\other'),1):
            stage,final = folder+r'\buffer.tmp',folder+r'\report'
            self.notify(101,(1,stage,ref,0))
            self.write(101,stage)
            self.notify(102,(4,stage,ref,55),(5,final,ref,55))
            results.append(('file.saved',final))
        self.assertCountEqual(self.drain(),results)

    def test_delete_after_publish_at_identical_timestamp_stays_separate(self):
        stage, final = self.folder+r'\stage.tmp',self.folder+r'\draft'
        self.notify(100,(1,stage,11,0))
        self.write(101,stage)
        self.notify(102,(4,stage,11,20),(5,final,11,20),(2,final,11,20))
        self.assertCountEqual(self.drain(),[('file.saved',final),('file.deleted',final)])

    def test_restart_and_ack_loss_send_identical_summary(self):
        final = self.folder+r'\chart.bin'
        self.swap(final,self.folder+r'\stage.tmp',self.folder+r'\backup.tmp')
        self.agent = Agent(self.config)
        self.clock.return_value = 140
        def lose(path,body):
            self.accept(path,body)
            return {'accepted':[]}
        self.agent.call = lose
        with self.assertRaises(ConnectionError):
            self.agent.flush(require_empty=False)
        self.agent = Agent(self.config)
        self.agent.call = self.accept
        self.agent.flush(require_empty=False)
        self.assertEqual(len(self.received),2)
        self.assertEqual(self.received[0],self.received[1])
        self.assertEqual(self.received[0]['kind'],'file.saved')
        self.assertEqual(self.agent.queue_status()['pending'],0)

    def test_summary_is_queryable_exportable_and_counted_once(self):
        from guarddesk.audit_reports import index_batch
        from guarddesk.server import Handler
        from guarddesk.store import Store, digest
        store = Store(self.config.parent/'fixture-center.sqlite3')
        handler = Handler.__new__(Handler)
        handler.headers = {'Authorization':'Bearer fixture'}
        handler.server = SimpleNamespace()
        final = self.folder+r'\table.xlsx'
        self.swap(final,self.folder+r'\stage.tmp',self.folder+r'\old.tmp')
        self.drain()
        with store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                       ('fixture',digest('fixture'),'Owned','Owned',102))
            for _ in range(2):
                ack,_,_ = handler.route(db,'POST','/api/agent/events',{'events':self.received})
                self.assertEqual(ack['accepted'],[self.received[0]['event_id']])
        index_batch(store)
        with store.connect() as db, patch.object(handler,'session',return_value={'role':'admin','username':'owned'}):
            for route in ('/api/events','/api/events.csv'):
                handler.path = route+'?category=documents&kind=file.saved&file_action=written'
                result,_,_ = handler.route(db,'GET',route,{})
                if route.endswith('csv'):
                    rows = list(csv.DictReader(io.StringIO(result.decode('utf-8-sig'))))
                    self.assertEqual([(r['kind'],r['source_path']) for r in rows],[('file.saved',final)])
                    self.assertNotIn('.tmp',rows[0]['details'])
                else:
                    self.assertEqual(result['total'],1)
                    self.assertEqual(result['items'][0]['details']['path'],final)
        self.assertTrue(store.verify()['valid'])

    def test_pressure_forwards_uncombined_events_and_old_backlog_drains(self):
        with patch.object(document_saves,'LIMIT',3):
            for i in range(8):
                self.notify(101,(1,self.folder+str(i),i+1,0))
        with self.agent.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM document_save_pending').fetchone()[0],3)
            legacy = {'kind':'file.created','severity':'info','event_id':'legacy','occurred':80,'details':{'path':'old'}}
            db.execute('INSERT INTO outbox VALUES (?,?,?)',('legacy',json.dumps(legacy),80))
        self.assertEqual(len(self.drain()),9)
        self.assertEqual(ACTIONS['file.saved'],'written')
        self.assertTrue(excluded_activity('file.saved',{'path':self.folder+r'\notes'},[self.folder]))

    @unittest.skipUnless(os.name == 'nt','Windows directory notifications required')
    def test_owned_new_document_when_all_tmp_files_are_excluded(self):
        with tempfile.TemporaryDirectory() as owned:
            self.agent.root = Path(owned)
            final = Path(owned)/'test.xlsx'
            stage, backup = Path(owned)/'draft.TMP', Path(owned)/'original.tmp'
            monitor = DirectoryMonitor(self.agent,{'file_audit':{'scope':'managed','exclude_paths':[TMP_FILE_RULE]}})
            try:
                self.assertEqual(monitor.start()['active'],1)
                time.sleep(.15)
                final.touch()
                final.unlink()
                final.touch()
                stage.write_bytes(b'owned spreadsheet fixture')
                final.rename(backup)
                stage.rename(final)
                backup.unlink()
                deadline = time.monotonic()+4
                while self.agent.queue_status()['pending'] < 5 and time.monotonic() < deadline:
                    time.sleep(.05)
            finally:
                monitor.close()
            with self.agent.db() as db:
                events = [json.loads(row[0]) for row in db.execute('SELECT payload FROM outbox')]
            self.assertCountEqual([e['kind'] for e in events],
                                  ['file.created','file.deleted','file.created','file.renamed','file.renamed'])
            self.assertEqual(self.drain(),[('file.created',str(final))])
            self.assertNotIn('.tmp',json.dumps(self.received).lower())

    @unittest.skipUnless(os.name == 'nt','Windows directory notifications required')
    def test_owned_directory_replacement_through_windows_monitor(self):
        with tempfile.TemporaryDirectory() as owned:
            self.agent.root = Path(owned)
            final = Path(owned)/'README'
            final.write_bytes(b'original')
            stage, backup = Path(owned)/'new.tmp',Path(owned)/'old.tmp'
            monitor = DirectoryMonitor(self.agent,{'file_audit':{'scope':'managed','exclude_paths':[]}})
            try:
                self.assertEqual(monitor.start()['active'],1)
                time.sleep(.15)
                stage.write_bytes(b'new contents')
                final.rename(backup)
                stage.rename(final)
                backup.unlink()
                deadline = time.monotonic()+4
                while self.agent.queue_status()['pending'] < 4 and time.monotonic() < deadline:
                    time.sleep(.05)
            finally:
                monitor.close()
            self.assertEqual(self.drain(),[('file.saved',str(final))])
