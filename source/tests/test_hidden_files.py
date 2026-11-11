"""Hidden metadata boundaries, real owned Windows folders, legacy replay."""
import copy
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import test_endpoint_controls as fixtures
import test_management
from guarddesk.file_exclusions import excluded,excluded_activity,excluded_installer_activity,installer_rollback_path,normalized_path
from guarddesk.hidden_files import HIDDEN_RULE,HiddenPaths
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy,validate_policy
from guarddesk.store import Store
from guarddesk.windows_events import SecurityCollector
from guarddesk.windows_watch import DirectoryMonitor,RenamePairs,FileIdMoves


class Metadata:
    def __init__(self,values=None):self.values=values or {};self.calls=[];self.fixed_calls=[]
    def attributes(self,path):self.calls.append(path);return self.values.get(path,0x20)
    def fixed(self,path):self.fixed_calls.append(path);return True


class HiddenMetadataTest(unittest.TestCase):
    def test_each_notification_keeps_its_own_attributes_across_reused_names(self):
        path=r'C:\Owned\reused.txt'
        rows=RenamePairs().consume([(2,path,0x22),(1,path,0x20)])
        self.assertEqual([(k,d['_path_attributes'][path]) for k,d in rows],[('file.deleted',0x22),('file.created',0x20)])
        pairs=RenamePairs();self.assertEqual(pairs.consume([(4,path,0x22)],now=0),[])
        renamed=pairs.consume([(5,path+'-new',0x20)],now=.1)[0][1]
        self.assertEqual(renamed['_path_attributes'],{path:0x22,path+'-new':0x20})
        moves=FileIdMoves(attributes=True);moves.consume([(2,path,100,0x22)],now=0)
        moved=moves.consume([(1,path+'-moved',100,0x20)],now=.1)[0][1]
        self.assertEqual(moved['_path_attributes'],{path:0x22,path+'-moved':0x20})

    def test_windows_attribute_not_dot_name_and_hidden_ancestors(self):
        metadata=Metadata({r'c:\owned\secret':0x12,r'c:\owned\hidden.txt':0x22})
        resolver=HiddenPaths(metadata)
        self.assertTrue(resolver.hidden(r'C:\Owned\secret\report.txt'))
        self.assertTrue(resolver.hidden(r'\\?\C:\Owned\hidden.txt'))
        self.assertFalse(resolver.hidden(r'C:\Owned\.visible.txt'))
        self.assertFalse(resolver.hidden(r'C:\Owned\visible.txt'))
        self.assertFalse(any(p.endswith('report.txt') for p in metadata.calls))

    def test_disabled_does_no_attribute_work_and_policy_toggle_is_immediate(self):
        with patch('guarddesk.hidden_files.hidden',return_value=True) as query:
            self.assertFalse(excluded(r'C:\Owned\document.txt'))
            query.assert_not_called()
            self.assertTrue(excluded(r'C:\Owned\document.txt',[HIDDEN_RULE]))
            self.assertFalse(excluded(r'C:\Owned\document.txt',[]))
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[HIDDEN_RULE,r'D:\Explicit']
        self.assertEqual(decode_agent_policy(agent_policy_wire({'body':policy}))['body'],policy)
        policy['file_audit']['exclude_paths']=['@guarddesk:hidden-files:v9']
        with self.assertRaisesRegex(ValueError,'隱藏檔'):validate_policy(policy)

    def test_unc_reparse_and_unknown_never_traverse_or_guess(self):
        metadata=Metadata({r'c:\link':0x410,r'c:\denied':None})
        resolver=HiddenPaths(metadata)
        for path in (r'\\server\share\file',r'C:relative',r'C:\link\network\file',r'C:\denied\file'):
            self.assertFalse(resolver.hidden(path))
        self.assertEqual(metadata.calls,[r'c:\link',r'c:\denied'])
        self.assertEqual(metadata.fixed_calls,['c:\\'])
        metadata.fixed=lambda root:False
        self.assertFalse(resolver.hidden(r'Z:\network\file'))

    def test_cache_rate_capacity_ttl_and_authoritative_delete_hint(self):
        clock=[0.0];metadata=Metadata();resolver=HiddenPaths(metadata,clock=lambda:clock[0])
        for i in range(10000):resolver.hidden('C:\\Owned\\'+str(i))
        self.assertLessEqual(len(metadata.calls),128);self.assertLessEqual(len(resolver.cache),2048)
        resolver.remember(r'C:\Owned\gone.txt',0x22)
        self.assertTrue(resolver.hidden(r'C:\Owned\gone.txt'))
        resolver.remember(r'C:\Owned\gone.txt',0x20)
        self.assertFalse(resolver.hidden(r'C:\Owned\gone.txt'))
        clock[0]=3;metadata.values[r'c:\owned\gone.txt']=None
        self.assertFalse(resolver.hidden(r'C:\Owned\gone.txt'))
        for i in range(5000):resolver.remember('C:\\Owned\\cached'+str(i),0x20)
        self.assertEqual(len(resolver.cache),2048)

    def test_server_rule_is_pure_and_only_fixed_root_installer_churn_is_default(self):
        a=r'C:\Config.Msi\38f7f795.rbs';b=r'D:\Config.Msi\38f7f7af.rbf';doc=r'C:\Docs\38f7f7af.rbf'
        with patch('guarddesk.hidden_files.hidden',side_effect=AssertionError('Server must not query endpoint path')):
            self.assertFalse(excluded_activity('file.created',{'path':a},[HIDDEN_RULE]))
        for path in (a,b,r'\\?\C:\CONFIG.MSI\x'):
            self.assertTrue(installer_rollback_path(path));self.assertTrue(excluded(path))
        for path in (doc,r'C:\Docs\Config.Msi\x',r'C:\Config.Msi-business\x',r'\\nas\Config.Msi\x'):
            self.assertFalse(installer_rollback_path(path))
        self.assertTrue(excluded_installer_activity('file.deleted','info',{'path':a}))
        self.assertTrue(excluded_installer_activity('file.moved','info',{'source_path':a,'destination_path':b}))
        for details in ({'source_path':a,'destination_path':doc},{'path':a}):
            self.assertFalse(excluded_installer_activity('file.moved','info',details))
        for kind,severity in (('web.upload_started','info'),('application.blocked','warning'),('agent.audit_gap','critical'),('file.security_alert','warning'),('file.deleted','critical')):
            self.assertFalse(excluded_installer_activity(kind,severity,{'path':a}))

    def test_sealed_056_decoder_really_accepts_marker_without_new_schema(self):
        archive=Path(__file__).resolve().parents[1]/'dist/GuardDesk-0.4.56-source.zip'
        self.assertTrue(archive.is_file())
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[HIDDEN_RULE]
        wire=agent_policy_wire({'version':1,'body':policy})
        code="import sys,json;sys.path.insert(0,sys.argv[1]);from guarddesk import __version__;from guarddesk.policy import decode_agent_policy;p=decode_agent_policy(json.load(sys.stdin));print(json.dumps({'version':__version__,'rules':p['body']['file_audit']['exclude_paths']}))"
        result=subprocess.run([sys.executable,'-c',code,str(archive)],input=json.dumps(wire),capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout),{'version':'0.4.56','rules':[HIDDEN_RULE]})


@unittest.skipUnless(os.name=='nt','Windows attributes on owned disposable files')
class HiddenSourceTest(unittest.TestCase):
    def setUp(self):
        # AppData is itself hidden. The generic Windows temp fixture would
        # correctly exclude the entire test root, including the visible control.
        from guarddesk.agent import Agent,private_write
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'runtime')
        self.root=Path(self.temp.name);self.watch=self.root/'documents';self.watch.mkdir()
        self.config=self.root/'runtime'/'agent'/'config.json'
        private_write(self.config,{'server':'http://127.0.0.1:1','token':'test-token','device_id':'test-device','watch':str(self.watch)})
        self.agent=Agent(self.config);self.policy=copy.deepcopy(DEFAULT_POLICY)
    tearDown=fixtures.EndpointTest.tearDown
    save_policy=fixtures.EndpointTest.save_policy
    queued=fixtures.EndpointTest.queued

    def hidden(self,path,value=True):
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.SetFileAttributesW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32]
        if not api.SetFileAttributesW(str(path),0x2 if value else 0x80):raise ctypes.WinError(ctypes.get_last_error())

    def tree(self):
        folder=self.watch/'private';folder.mkdir();(folder/'inside.txt').write_text('synthetic')
        self.hidden(folder)
        hidden=self.watch/'hidden.txt';hidden.write_text('synthetic');self.hidden(hidden)
        dot=self.watch/'.visible.txt';dot.write_text('synthetic')
        doc=self.watch/'report.txt';doc.write_text('synthetic')
        self.policy['file_audit']['exclude_paths']=[HIDDEN_RULE];self.save_policy()
        return folder,hidden,dot,doc

    def test_real_snapshot_prunes_before_content_read_and_keeps_dot_file(self):
        folder,hidden,dot,doc=self.tree();opened=[];visited=[];original_open=Path.open;original_scan=os.scandir
        with self.agent.db() as db:db.execute('INSERT INTO files VALUES (?,?)',('private/old.txt','{}'))
        def read(path,*args,**kwargs):opened.append(path);return original_open(path,*args,**kwargs)
        def scan(path):visited.append(Path(path));return original_scan(path)
        with patch.object(Path,'open',read),patch('guarddesk.snapshot.os.scandir',side_effect=scan):
            for _ in range(50):
                if not self.agent.scan(max_entries=3,time_budget=1)['in_progress']:break
            else:self.fail('unbounded traversal')
        self.assertCountEqual(opened,[dot,doc]);self.assertNotIn(folder,visited)
        self.assertCountEqual([r['details']['path'] for r in self.queued()],[str(dot),str(doc)])

    def test_security_handle_delete_and_document_scope_use_same_filter(self):
        folder,hidden,dot,doc=self.tree();collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4656,path=str(hidden)),self.policy)
            hidden.unlink();collector.ingest(db,fixtures.event(2,4660),self.policy)
            collector.ingest(db,fixtures.event(3,4663,path=str(doc)),self.policy)
            collector.ingest(db,fixtures.event(4,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['file.opened','agent.audit_log_cleared'])
        from guarddesk.document_scope import permits
        self.assertFalse(permits(str(folder/'inside.txt'),self.policy['file_audit'],str(self.watch)))
        self.assertTrue(permits(str(dot),self.policy['file_audit'],str(self.watch)))

    def test_real_monitor_hidden_deletes_crossing_move_and_visible_activity(self):
        folder,hidden,dot,doc=self.tree()
        source=folder/'move.txt';source.write_text('synthetic')
        monitor=DirectoryMonitor(self.agent,{**self.policy,'file_audit':{**self.policy['file_audit'],'scope':'managed'}})
        try:
            self.assertEqual(monitor.start()['active'],1);time.sleep(.1)
            hidden.unlink();(folder/'inside.txt').unlink()
            (folder/'new.txt').write_text('synthetic')
            destination=self.watch/'moved.txt';os.replace(source,destination)
            visible=self.watch/'new-visible.txt';visible.write_text('synthetic')
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                rows=self.queued()
                if any(r['details'].get('destination_path')==str(destination) for r in rows) and any(r['details'].get('path')==str(visible) for r in rows):break
                time.sleep(.05)
            rows=self.queued()
            self.assertFalse(any(r['details'].get('path') in (str(hidden),str(folder/'inside.txt'),str(folder/'new.txt')) for r in rows))
            self.assertTrue(any(r['details'].get('source_path')==str(source) and r['details'].get('destination_path')==str(destination) for r in rows),[(r['kind'],r['details']) for r in rows])
            self.assertTrue(any(r['details'].get('path')==str(visible) for r in rows))
        finally:monitor.close()


class InstallerServerTest(unittest.TestCase):
    setUp=test_management.ManagementTest.setUp
    tearDown=test_management.ManagementTest.tearDown
    api=test_management.ManagementTest.api
    make_agent=test_management.ManagementTest.make_agent
    policy=test_management.ManagementTest.policy
    assign=test_management.ManagementTest.assign

    def test_legacy_ack_history_security_crossings_and_no_server_attribute_query(self):
        agent,did,_=self.make_agent();path=r'C:\Config.Msi\38f7f795.rbs'
        with self.store.connect() as db:Store.event(db,did,'file.deleted','info',{'path':path},'historic-installer')
        p=self.policy('Skip hidden',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[HIDDEN_RULE]}})
        self.assign(p,'device',did);self.assertIn(HIDDEN_RULE,agent.heartbeat()['body']['file_audit']['exclude_paths'])
        cases=[('skip-rollback','file.deleted','info',{'path':path}),('keep-unknown-hidden','file.opened','info',{'path':r'C:\Owned\hidden.txt'}),('keep-cross','file.moved','info',{'source_path':path,'destination_path':r'C:\Docs\proof.rbs'}),('keep-critical','file.deleted','critical',{'path':path}),('keep-upload','web.upload_started','info',{'path':path})]
        events=[{'event_id':eid,'kind':kind,'severity':severity,'details':details,'occurred':time.time()} for eid,kind,severity,details in cases]
        with patch('guarddesk.hidden_files.hidden',side_effect=AssertionError('No Server local/remote file inspection')):
            for _ in range(2):self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[r['event_id'] for r in events])
        with self.store.connect() as db:
            for eid,_,_,_ in cases:self.assertEqual(db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0],0 if eid.startswith('skip-') else 1)
            self.assertIsNotNone(db.execute("SELECT id FROM events WHERE event_id='historic-installer'").fetchone())
        self.assertTrue(self.store.verify()['valid'])


if __name__=='__main__':unittest.main()
