import copy
import json
import sqlite3
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
import test_system
from guarddesk.agent import Agent
from guarddesk.browser_host import handle_message
from guarddesk.store import Store,canonical
from guarddesk.policy import DEFAULT_POLICY


class ManagementTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def group(self,name,parent=None):return self.api('/api/groups',{'name':name,'parent_id':parent})
    def policy(self,name,overrides,enabled=True):return self.api('/api/policy-sets',{'name':name,'description':'test','overrides':overrides,'enabled':enabled})
    def assign(self,policy,kind,target='',priority=100):
        draft={'set_id':policy['id'],'target_type':kind,'target_id':target,'priority':priority,'enabled':True}
        preview=self.api('/api/assignments/preview',draft)
        return self.api('/api/assignments',{**draft,'expected_generation':preview['generation']})
    def detail(self,eid,account=None):return self.api('/api/device-detail?device_id='+eid+('&principal='+account.replace('\\','%5C') if account else ''))
    def move(self,eid,gid):
        d=next(d for d in self.api('/api/state')['devices'] if d['id']==eid)
        return self.api('/api/devices/move',{'device_id':eid,'group_id':gid,'revision':d['management_revision']})
    def assert_status(self,code,fn):
        with self.assertRaises(urllib.error.HTTPError) as error:fn()
        self.assertEqual(error.exception.code,code)
        error.exception.close()

    def test_nested_groups_cycle_duplicate_nonempty_and_revision(self):
        parent=self.group('Engineering');child=self.group('Platform',parent['id'])
        self.assert_status(400,lambda:self.api('/api/groups',{**parent,'parent_id':child['id']}))
        self.assert_status(409,lambda:self.group('engineering'))
        self.assert_status(409,lambda:self.api('/api/groups/delete',parent))
        renamed=self.api('/api/groups',{**child,'name':'Platform team'})
        self.assertEqual(renamed['revision'],2)
        self.assert_status(409,lambda:self.api('/api/groups',{**child,'name':'stale'}))
        state=self.api('/api/state')
        self.assertEqual(next(g for g in state['groups'] if g['id']==child['id'])['path'],['Engineering','Platform team'])

    def test_effective_ancestor_child_device_priority_and_source(self):
        agent,eid,_=self.make_agent();parent=self.group('Parent');child=self.group('Child',parent['id']);self.move(eid,child['id'])
        global_policy=self.policy('Global block',{'usb_mode':'block'});self.assign(global_policy,'global')
        parent_policy=self.policy('Parent readonly',{'usb_mode':'read_only'});self.assign(parent_policy,'group',parent['id'],1000)
        child_policy=self.policy('Child allow',{'usb_mode':'allow'});self.assign(child_policy,'group',child['id'],0)
        effective=self.detail(eid)['effective_policy']
        self.assertEqual(effective['body']['usb_mode'],'allow')
        self.assertEqual(effective['field_sources']['usb_mode']['name'],'Child allow')
        self.assertEqual(effective['group_path'],['Parent','Child'])
        specific=self.policy('Endpoint override',{'usb_mode':'read_only'});self.assign(specific,'device',eid,0)
        agent.heartbeat();received=agent.heartbeat()
        self.assertEqual(received['body']['usb_mode'],'read_only')
        self.assertTrue(self.api('/api/state')['devices'][0]['policy_received'])
        self.assertEqual(self.detail(eid)['effective_policy']['field_sources']['usb_mode']['kind'],'device')

    def test_same_scope_tie_is_visible_and_later_assignment_wins(self):
        _,eid,_=self.make_agent();group=self.group('Team');self.move(eid,group['id'])
        a=self.policy('A',{'usb_mode':'block'});b=self.policy('B',{'usb_mode':'read_only'})
        self.assign(a,'group',group['id']);self.assign(b,'group',group['id'])
        effective=self.detail(eid)['effective_policy']
        self.assertEqual(effective['body']['usb_mode'],'read_only')
        self.assertEqual(effective['conflicts'][0]['winner'],'B')
        self.assertEqual(effective['field_sources']['usb_mode']['name'],'B')

    def test_assignment_preview_no_write_stale_generation_and_duplicate(self):
        self.make_agent();p=self.policy('Audit',{'browser_audit':False})
        draft={'set_id':p['id'],'target_type':'global','target_id':'','priority':100,'enabled':True}
        before=self.api('/api/state');preview=self.api('/api/assignments/preview',draft)
        self.assertEqual(preview['affected_count'],1)
        self.assertEqual(self.api('/api/state')['generation'],before['generation'])
        self.assertEqual(self.api('/api/state')['assignments'],[])
        self.group('Changed after preview')
        self.assert_status(409,lambda:self.api('/api/assignments',{**draft,'expected_generation':preview['generation']}))
        self.assign(p,'global')
        self.assert_status(409,lambda:self.assign(p,'global'))

    def test_set_revisions_history_disable_and_offline_snapshot(self):
        agent,eid,_=self.make_agent();p=self.policy('USB',{'usb_mode':'read_only'});self.assign(p,'device',eid)
        agent.heartbeat();old=agent.cached_policy()
        updated=self.api('/api/policy-sets',{'id':p['id'],'revision':1,'name':'USB','description':'new','enabled':True,'overrides':{'usb_mode':'block'}})
        self.assertEqual(updated['revision'],2)
        self.assertEqual(agent.cached_policy()['body']['usb_mode'],'read_only')
        self.assertEqual(agent.heartbeat()['body']['usb_mode'],'block')
        self.assert_status(409,lambda:self.api('/api/policy-sets',{'id':p['id'],'revision':1,'name':'USB','enabled':True,'overrides':{'usb_mode':'allow'}}))
        history=self.api('/api/policy-sets/history?id='+p['id'])['items']
        self.assertEqual([r['revision'] for r in history],[2,1]);self.assertEqual(history[1]['overrides'],{'usb_mode':'read_only'})
        self.api('/api/policy-sets',{'id':p['id'],'revision':2,'name':'USB','description':'disabled','enabled':False,'overrides':{'usb_mode':'block'}})
        self.assertEqual(self.detail(eid)['effective_policy']['body']['usb_mode'],DEFAULT_POLICY['usb_mode'])
        self.assertNotEqual(old['fingerprint'],agent.heartbeat()['fingerprint'])

    def test_user_policy_uses_real_actor_and_keeps_machine_controls_separate(self):
        agent,eid,_=self.make_agent();p=self.policy('Alice personal',{'browser_audit':False,'mode':'enforce','allow_export':False})
        self.assign(p,'user','COMPANY\\Alice')
        with patch('guarddesk.agent.inventory',return_value={'user_accounts':['COMPANY\\alice','COMPANY\\bob'],'os':'fixture'}):
            machine=agent.heartbeat()
            self.assertTrue(machine['body']['browser_audit']);self.assertTrue(machine['body']['allow_export'])
            self.assertFalse(agent.policy_for_user('COMPANY\\ALICE')['body']['browser_audit'])
            with patch('guarddesk.browser_host.current_account',return_value='COMPANY\\alice'):
                self.assertFalse(handle_message(agent,{'type':'navigation','url':'https://example.com'})['recorded'])
            with patch('guarddesk.browser_host.current_account',return_value='COMPANY\\bob'):
                self.assertTrue(handle_message(agent,{'type':'navigation','url':'https://example.com'})['recorded'])
            source=self.watch/'personal.txt';source.write_text('hello')
            with patch('guarddesk.agent.current_account',return_value='COMPANY\\alice'):
                with self.assertRaises(PermissionError):agent.export(source,self.root/'blocked-personal.txt')
        self.assertFalse((self.root/'blocked-personal.txt').exists())
        unsafe=self.policy('Machine USB',{'usb_mode':'block'})
        self.assert_status(400,lambda:self.assign(unsafe,'user','COMPANY\\alice'))
        self.assert_status(400,lambda:self.api('/api/policy-sets',{'id':p['id'],'revision':1,'name':'Alice personal','enabled':True,'overrides':{'usb_mode':'block'}}))

    def test_bulk_move_is_atomic_on_stale_device_revision(self):
        _,eid,_=self.make_agent();group=self.group('Destination')
        code=self.api('/api/enrollments',{})['token']
        from guarddesk.agent import enroll
        second=enroll(self.root/'second/config.json',self.url,code,self.watch,name='second')
        rows=self.api('/api/state')['devices'];items=[{'id':d['id'],'revision':d['management_revision']} for d in rows]
        items[-1]['revision']=0
        self.assert_status(409,lambda:self.api('/api/devices/move-many',{'group_id':group['id'],'items':items}))
        self.assertTrue(all(d['group_id'] is None for d in self.api('/api/state')['devices']))
        for item in items:item['revision']=1
        self.assertEqual(self.api('/api/devices/move-many',{'group_id':group['id'],'items':items})['moved'],2)
        self.assertTrue(all(d['group_id']==group['id'] for d in self.api('/api/state')['devices']))

    def test_group_depth_limit_and_assigned_group_delete_protection(self):
        parent=None
        for n in range(8):parent=self.group('Level '+str(n),parent['id'] if parent else None)
        self.assert_status(400,lambda:self.group('Too deep',parent['id']))
        self.assertEqual(len(self.api('/api/state')['groups']),8)
        p=self.policy('Shared',{'browser_audit':True});a=self.assign(p,'group',parent['id'])
        self.assert_status(409,lambda:self.api('/api/groups/delete',parent))
        self.assert_status(409,lambda:self.api('/api/policy-sets/archive',{'id':p['id'],'revision':1}))
        item=self.api('/api/state')['assignments'][0]
        self.api('/api/assignments/delete',{'id':item['id'],'revision':item['revision']})
        self.api('/api/groups/delete',parent)
        self.api('/api/policy-sets/archive',{'id':p['id'],'revision':1})
        self.assertEqual(self.api('/api/state')['policy_sets'],[])
        self.assertEqual(len(self.api('/api/policy-sets/history?id='+p['id'])['items']),1)

    def test_readonly_role_and_device_detail_redacts_tokens(self):
        _,eid,_=self.make_agent();self.group('Visible')
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        detail=self.detail(eid)
        self.assertNotIn('token',detail['device']);self.assertIn('effective_policy',detail)
        self.assertEqual(len(self.api('/api/state')['groups']),1)
        self.assert_status(403,lambda:self.group('Forbidden'))
        self.assert_status(403,lambda:self.policy('Forbidden',{'browser_audit':False}))

    def test_device_detail_and_user_preview_never_read_audit_history(self):
        from guarddesk.server import Handler
        _,eid,_=self.make_agent()
        policy=self.policy('Personal preview',{'browser_audit':False})
        self.assign(policy,'user','COMPANY\\Alice')
        with self.store.connect() as db:
            Store.event(db,eid,'web.navigation','info',{'domain':'owned.example','url':'https://owned.example'})
            Store.event(db,eid,'application.started','info',{'process':r'C:\Owned\fixture.exe'})
            before=db.execute('SELECT count(*) FROM events').fetchone()[0]
        original=Handler.route;reads=[]
        def guarded(handler,db,method,path,body):
            if path!='/api/device-detail':return original(handler,db,method,path,body)
            def authorize(action,table,column,schema,origin):
                if action==sqlite3.SQLITE_READ:
                    reads.append(table)
                    if table=='events' or table.startswith(('events_','event_')):return sqlite3.SQLITE_DENY
                if action==sqlite3.SQLITE_FUNCTION and column in ('event_value','event_identifier'):return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorize)
            try:return original(handler,db,method,path,body)
            finally:db.set_authorizer(None)
        for daily in (False,True):
            if daily:
                from guarddesk.event_storage import enable
                with self.store.connect() as db:enable(db,self.store.path,snapshot_backup=False)
            with patch.object(Handler,'route',guarded):
                basic=self.detail(eid);preview=self.detail(eid,'COMPANY\\Alice')
        self.assertEqual(set(basic),{'device','effective_policy','preview_policy'})
        self.assertEqual(basic['device']['id'],eid)
        self.assertFalse(preview['preview_policy']['body']['browser_audit'])
        self.assertIn('devices',reads)
        self.assertFalse(any(t=='events' or t.startswith(('event_','events_')) for t in reads))
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],before)

    def test_policy_fingerprint_and_generation_match_after_heartbeat_ack(self):
        agent,eid,_=self.make_agent();agent.heartbeat();agent.heartbeat()
        self.assertTrue(self.api('/api/state')['devices'][0]['policy_received'])
        p=self.policy('Specific',{'browser_audit':False});self.assign(p,'device',eid)
        self.assertFalse(self.api('/api/state')['devices'][0]['policy_received'])
        packet=agent.heartbeat();self.assertFalse(packet['body']['browser_audit'])
        self.assertFalse(self.api('/api/state')['devices'][0]['policy_received'])
        agent.heartbeat();self.assertTrue(self.api('/api/state')['devices'][0]['policy_received'])
        self.assertTrue(self.store.verify()['valid'])


class MigrationTest(unittest.TestCase):
    def test_legacy_schema_and_policy_migrate_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'legacy.sqlite3'
            db=sqlite3.connect(path)
            db.executescript("CREATE TABLE devices(id TEXT PRIMARY KEY,token TEXT UNIQUE NOT NULL,name TEXT NOT NULL,department TEXT NOT NULL,last_seen REAL NOT NULL,policy_version INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,inventory TEXT NOT NULL DEFAULT '{}');CREATE TABLE policies(version INTEGER PRIMARY KEY,body TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL);")
            legacy={'mode':'monitor','allow_export':True,'blocked_extensions':[],'keywords':[],'max_export_mb':10}
            db.execute('INSERT INTO policies VALUES (8,?,?,?)',(canonical(legacy),time.time(),'legacy'))
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',('old','hash','Old device','Legacy',time.time()));db.commit();db.close()
            store=Store(path);Store(path)
            with store.connect() as db:
                row=db.execute('SELECT * FROM devices WHERE id="old"').fetchone()
                self.assertIsNone(row['group_id']);self.assertEqual(row['management_revision'],1)
                self.assertEqual(db.execute('SELECT body FROM policies WHERE version=8').fetchone()[0],canonical(legacy))
                self.assertEqual(Store.policy(db)['version'],9)
                self.assertEqual(db.execute("SELECT value FROM control_meta WHERE key='generation'").fetchone()[0],9)


if __name__=='__main__':unittest.main()
