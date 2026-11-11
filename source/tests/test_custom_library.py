import copy
import datetime as dt
import json
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
import test_system
from test_custom_settings import FakeAgent,Actions,schedule,packet
from guarddesk import custom_library as lib,custom_settings as custom
from guarddesk.custom_client import ScheduleEngine,check_packet
from guarddesk.store import Store,canonical
from guarddesk.management import ManagementError


def item(kind='schedules',name='Example',body=None):
    if body is None:body=[schedule()]
    return {'id':secrets.token_hex(12),'name':name,'kind':kind,'body':body,'description':'Synthetic fixture','enabled':True,'revision':0}


class LibraryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=Store(self.root/'control.sqlite3')
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('parent','Parent',NULL,1,0)")
            db.execute("INSERT INTO endpoint_groups VALUES ('child','Child','parent',1,0)")
            for did,gid in [('dev','child'),('user1',None)]:db.execute('INSERT INTO devices(id,token,name,department,last_seen,group_id) VALUES(?,?,?,?,?,?)',(did,did,did.upper(),'Synthetic',0,gid))

    def tearDown(self):self.temp.cleanup()
    def publish(self,request,ack=True):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE');p=lib.preview(db,request)
            return lib.publish(db,{**request,'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'network_ack':ack,'confirm':'publish_custom_library'},'fixture')
    def create(self,*args,**kwargs):
        data=item(*args,**kwargs);self.publish({'op':'save_item','item':data});data['revision']=1;return data
    def bind(self,data,scope='global',target='',state='apply',priority=100):
        b={'id':secrets.token_hex(12),'item_id':data['id'],'target_type':scope,'target_id':target,'state':state,'priority':priority,'mode':'merge','revision':0}
        self.publish({'op':'binding','binding':b});b['revision']=1;return b
    def resolve(self,did='dev'):
        with self.store.connect() as db:return lib.resolve(db,dict(db.execute('SELECT * FROM devices WHERE id=?',(did,)).fetchone()))

    def test_item_save_has_no_implicit_global_assignment(self):
        self.create();self.assertEqual(self.resolve()['body'],custom.DEFAULT)
        with self.store.connect() as db:self.assertEqual(len(lib.catalog(db)['items']),1)

    def test_one_item_reused_in_multiple_scopes_and_person_is_endpoint(self):
        data=self.create();self.bind(data,'group','parent');self.bind(data,'device','user1')
        self.assertEqual(len(self.resolve()['body']['schedules']),1);self.assertEqual(len(self.resolve('user1')['body']['schedules']),1)
        self.assertEqual(self.resolve()['sources'][0]['target_id'],'parent')

    def test_child_exclusion_and_device_reapply_are_per_item(self):
        a=self.create(name='A');b=self.create('software','B',[{'name':'Fixture','collection':'Exe','publisher':'CN=Fixture','product':'Fixture App','binary':'*','min_version':'0.0.0.0','max_version':'*'}])
        self.bind(a);self.bind(b);excluded=self.bind(a,'group','child','exclude')
        self.assertEqual(len(self.resolve()['body']['schedules']),0);self.assertEqual(len(self.resolve()['body']['software']),1)
        self.bind(a,'device','dev');self.assertEqual(len(self.resolve()['body']['schedules']),1)
        self.assertEqual(self.resolve()['sources'][-1]['target_type'],'device')

    def test_removing_local_exclusion_restores_inheritance(self):
        data=self.create();self.bind(data);exclude=self.bind(data,'device','dev','exclude')
        self.assertFalse(self.resolve()['body']['schedules'])
        self.publish({'op':'remove_binding','id':exclude['id'],'revision':1})
        self.assertEqual(len(self.resolve()['body']['schedules']),1)

    def test_network_equal_priority_conflict_and_explicit_priority(self):
        a=self.create('network','IPv4',{'ipv6':'prefer_ipv4'});b=self.create('network','IPv6 off',{'ipv6':'disable'})
        self.bind(a)
        with self.assertRaises(ManagementError) as error:self.bind(b)
        self.assertIn('網路設定衝突',error.exception.message)
        self.bind(b,priority=200);self.assertEqual(self.resolve()['body']['network']['ipv6'],'disable')
        self.assertEqual(len(self.resolve()['overridden']),1)

    def test_more_specific_network_beats_higher_parent_priority(self):
        a=self.create('network','Global',{'ipv6':'disable'});b=self.create('network','Child',{'ipv6':'prefer_ipv4'})
        self.bind(a,priority=999);self.bind(b,'group','child',priority=1)
        self.assertEqual(self.resolve()['body']['network']['ipv6'],'prefer_ipv4')

    def test_future_empty_group_conflict_is_rejected_without_current_devices(self):
        with self.store.connect() as db:db.execute("INSERT INTO endpoint_groups VALUES('empty','Empty',NULL,1,0)")
        a=self.create('network','A',{'ipv6':'disable'});b=self.create('network','B',{'ipv6':'prefer_ipv4'})
        self.bind(a,'group','empty')
        with self.assertRaises(ManagementError):self.bind(b,'group','empty')

    def test_schedules_merge_unique_ids_but_overlapping_times_reject(self):
        a=self.create(name='Evening');b=self.create(name='Morning',body=[schedule(times=['08:00'])])
        self.bind(a);self.bind(b);rows=self.resolve()['body']['schedules'];self.assertEqual(len(rows),2);self.assertNotEqual(rows[0]['id'],rows[1]['id'])
        c=self.create(name='Conflicting')
        with self.assertRaises(ManagementError):self.bind(c)

    def test_disable_shared_item_affects_all_bound_devices_and_retains_binding(self):
        a=self.create();self.bind(a);a['enabled']=False;self.publish({'op':'save_item','item':a})
        self.assertEqual(self.resolve()['body'],custom.DEFAULT);self.assertEqual(self.resolve('user1')['body'],custom.DEFAULT)
        with self.store.connect() as db:self.assertEqual(len(lib.catalog(db)['bindings']),1)

    def test_preview_is_readonly_and_optimistic_concurrency_checks_both_generations(self):
        a=item();request={'op':'save_item','item':a}
        with self.store.connect() as db:
            before=custom.generation(db);p=lib.preview(db,request);self.assertEqual(lib.catalog(db)['items'],[]);self.assertEqual(custom.generation(db),before)
            db.execute("UPDATE control_meta SET value=value+1 WHERE key='generation'")
            with self.assertRaises(ManagementError):lib.publish(db,{**request,'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'confirm':'publish_custom_library'},'fixture')

    def test_network_acknowledgement_and_nonempty_item_validation(self):
        with self.assertRaises(ManagementError):self.publish({'op':'save_item','item':item('network','Risk',{'ipv6':'disable'})},ack=False)
        for value in (item(body=[]),{**item(),'enabled':1},{**item(),'kind':'shell'},{**item(),'name':'bad\nname'}):
            with self.assertRaises(ManagementError):self.publish({'op':'save_item','item':value})

    def test_history_copy_draft_type_immutable_and_archive_requires_unbound(self):
        a=self.create();self.bind(a)
        with self.assertRaises(ManagementError):self.publish({'op':'archive','id':a['id'],'revision':1})
        a['name']='Revision two';self.publish({'op':'save_item','item':a})
        with self.store.connect() as db:self.assertEqual([v['revision'] for v in lib.history(db,a['id'])['versions']],[2,1])
        with self.assertRaises(ManagementError):self.publish({'op':'save_item','item':{**a,'kind':'network','body':{'ipv6':'unchanged'},'revision':2}})

    def test_legacy_migration_preserves_body_ids_barriers_empty_lists_and_hash_chain(self):
        with self.store.connect() as db:
            db.execute('INSERT INTO custom_settings VALUES(?,?,?,?,?,?)',('global','',1,canonical({'schedules':[schedule()],'network':{'ipv6':'prefer_ipv4'}}),'fixture',1))
            db.execute('INSERT INTO custom_settings VALUES(?,?,?,?,?,?)',('group','child',1,canonical({'schedules':[]}), 'fixture',1))
            Store.event(db,'dev','file.created','info',{'path':'synthetic'})
            before={d:custom.resolve(db,dict(db.execute('SELECT * FROM devices WHERE id=?',(d,)).fetchone()))['body'] for d in ('dev','user1')}
        Store(self.store.path)
        for did in ('dev','user1'):self.assertEqual(self.resolve(did)['body'],before[did])
        with self.store.connect() as db:
            self.assertEqual(len(lib.catalog(db)['items']),3);self.assertTrue(all(b['mode']=='replace' for b in lib.catalog(db)['bindings']))
        Store(self.store.path)
        with self.store.connect() as db:self.assertEqual(len(lib.catalog(db)['items']),3)
        self.assertTrue(self.store.verify()['valid'])

    def test_legacy_edit_sync_and_new_library_edit_cannot_be_overwritten_by_old_console(self):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE');p=custom.preview(db,{'scope':'global','target':'','revision':0,'body':{'schedules':[schedule()]}})
            custom.publish(db,{'scope':'global','target':'','revision':0,'body':{'schedules':[schedule()]},'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'confirm':'publish_custom'},'fixture')
            imported=lib.catalog(db)['items'][0]
        fields={k:imported[k] for k in ('id','name','kind','body','description','enabled','revision')};fields['name']='Edited in library'
        self.publish({'op':'save_item','item':fields})
        with self.assertRaises(ManagementError):
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE');p=custom.preview(db,{'scope':'global','target':'','revision':1,'body':{}})
                custom.publish(db,{'scope':'global','target':'','revision':1,'body':{},'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'confirm':'publish_custom'},'fixture')
        # Item edits keep the original schedule ID, so a rename doesn't evade
        # existing occurrence claims or create an independent power action.
        self.assertEqual(self.resolve()['body']['schedules'][0]['id'],schedule()['id'])

    def test_unknown_windows_account_scope_is_not_accepted_as_person_endpoint(self):
        data=self.create()
        with self.assertRaises(ValueError):self.bind(data,'user','DOMAIN\\Alice')

    def test_archived_ids_cannot_reappear_and_malformed_id_is_validation_error(self):
        a=self.create();self.publish({'op':'archive','id':a['id'],'revision':1})
        for candidate in ({**a,'revision':0},{**item(),'id':[]}):
            with self.assertRaises(ManagementError):self.publish({'op':'save_item','item':candidate})

    def test_old_console_cannot_publish_a_conflict_with_named_items(self):
        a=self.create();self.bind(a)
        with self.assertRaises(ManagementError):
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE');draft={'scope':'global','target':'','revision':0,'body':{'schedules':[schedule(id='legacy-other')]}};p=custom.preview(db,draft)
                custom.publish(db,{**draft,'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'confirm':'publish_custom'},'fixture')
        with self.store.connect() as db:self.assertIsNone(db.execute("SELECT 1 FROM custom_settings WHERE scope='global'").fetchone())
        self.assertEqual(len(self.resolve()['body']['schedules']),1)

    def test_rollforward_after_older_profile_edits_keeps_newer_library_and_warns(self):
        with self.store.connect() as db:db.execute('INSERT INTO custom_settings VALUES(?,?,?,?,?,?)',('global','',1,canonical({'network':{'ipv6':'prefer_ipv4'}}),'fixture',1))
        Store(self.store.path)
        with self.store.connect() as db:imported=lib.catalog(db)['items'][0]
        fields={k:imported[k] for k in ('id','name','kind','body','description','enabled','revision')};fields['name']='Newer named item';self.publish({'op':'save_item','item':fields})
        with self.store.connect() as db:db.execute("UPDATE custom_settings SET revision=2,body=? WHERE scope='global'",(canonical({'network':{'ipv6':'disable'}}),))
        Store(self.store.path);Store(self.store.path)
        with self.store.connect() as db:
            self.assertEqual(len(lib.catalog(db)['migration_notes']),1)
            self.assertEqual(json.loads(db.execute("SELECT body FROM custom_settings WHERE scope='global'").fetchone()[0])['network']['ipv6'],'disable')
        self.assertEqual(self.resolve()['body']['network']['ipv6'],'prefer_ipv4')


class LibraryApiTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    def assert_http(self,code,fn):
        with self.assertRaises(urllib.error.HTTPError) as error:fn()
        self.assertEqual(error.exception.code,code);error.exception.close()
    def write(self,request):
        p=self.api('/api/custom-library/preview',request)
        return self.api('/api/custom-library/publish',{**request,'expected_generation':p['generation'],'expected_scope_generation':p['scope_generation'],'network_ack':True,'confirm':'publish_custom_library'})
    def test_auth_roles_csrf_and_two_protocols_are_independent(self):
        agent,eid,_=self.make_agent();before=agent.heartbeat();data=item()
        self.assert_http(403,lambda:self.api('/api/custom-library/preview',{'op':'save_item','item':data},csrf=False))
        self.write({'op':'save_item','item':data})
        binding={'id':secrets.token_hex(12),'item_id':data['id'],'target_type':'device','target_id':eid,'state':'apply','priority':100,'mode':'merge','revision':0};self.write({'op':'binding','binding':binding})
        legacy=agent.call('/api/agent/custom-settings',{'protocol':1});new=agent.call('/api/agent/custom-settings',{'protocol':2})
        self.assertEqual(legacy['body'],custom.DEFAULT);self.assertEqual(len(new['body']['schedules']),1);self.assertEqual(check_packet(agent,new)['schema'],'named-items-v1')
        self.assertEqual(agent.heartbeat()['body'],before['body'])
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf'];self.assertEqual(len(self.api('/api/custom-library')['items']),1)
        self.assert_http(403,lambda:self.api('/api/custom-library/preview',{'op':'save_item','item':data}))
    def test_group_cannot_delete_until_bindings_removed(self):
        group=self.api('/api/groups',{'name':'Library target'});data=item('network','Example',{'ipv6':'unchanged'});self.write({'op':'save_item','item':data})
        binding={'id':secrets.token_hex(12),'item_id':data['id'],'target_type':'group','target_id':group['id'],'state':'apply','priority':100,'mode':'merge','revision':0};self.write({'op':'binding','binding':binding})
        self.assert_http(409,lambda:self.api('/api/groups/delete',{'id':group['id'],'revision':1}))
        self.write({'op':'remove_binding','id':binding['id'],'revision':1});self.api('/api/groups/delete',{'id':group['id'],'revision':1})
    def test_move_between_groups_keeps_more_specific_network_rule(self):
        agent,eid,_=self.make_agent();group=self.api('/api/groups',{'name':'Conflicting target'})
        for name,value,scope,target in [('Device','disable','device',eid),('Group','prefer_ipv4','group',group['id'])]:
            a=item('network',name,{'ipv6':value});self.write({'op':'save_item','item':a});self.write({'op':'binding','binding':{'id':secrets.token_hex(12),'item_id':a['id'],'target_type':scope,'target_id':target,'state':'apply','priority':100,'mode':'merge','revision':0}})
        # More specific device network wins deterministically; move is valid.
        self.api('/api/devices/move-many',{'items':[{'id':eid,'revision':1}],'group_id':group['id']})
        packet=agent.call('/api/agent/custom-settings',{'protocol':2});self.assertEqual(packet['body']['network']['ipv6'],'disable')

    def test_group_move_with_schedule_conflict_is_atomic(self):
        agent,eid,_=self.make_agent();group=self.api('/api/groups',{'name':'Power schedule'})
        for name,scope,target in [('Local','device',eid),('Group','group',group['id'])]:
            a=item(name=name);self.write({'op':'save_item','item':a});self.write({'op':'binding','binding':{'id':secrets.token_hex(12),'item_id':a['id'],'target_type':scope,'target_id':target,'state':'apply','priority':100,'mode':'merge','revision':0}})
        self.assert_http(409,lambda:self.api('/api/devices/move-many',{'items':[{'id':eid,'revision':1}],'group_id':group['id']}))
        with self.store.connect() as db:
            row=db.execute('SELECT group_id,management_revision FROM devices WHERE id=?',(eid,)).fetchone()
            self.assertIsNone(row['group_id']);self.assertEqual(row['management_revision'],1)

    def test_protocol2_repeated_action_authorization_before_cutoff_and_dedupe(self):
        from types import SimpleNamespace
        agent,eid,_=self.make_agent();rule=schedule(delay_seconds=60,defer_minutes=0,repeat={'interval_minutes':60,'until':'02:00'})
        a=item(body=[rule]);self.write({'op':'save_item','item':a});self.write({'op':'binding','binding':{'id':secrets.token_hex(12),'item_id':a['id'],'target_type':'device','target_id':eid,'state':'apply','priority':100,'mode':'merge','revision':0}})
        p=agent.call('/api/agent/custom-settings',{'protocol':2});start=dt.datetime(2026,10,21,22,0,tzinfo=dt.timezone(dt.timedelta(hours=8)))
        request={'protocol':2,'fingerprint':p['fingerprint'],'rule_id':p['body']['schedules'][0]['id'],'occurrence':start.isoformat(timespec='minutes')}
        with patch.object(custom,'time',SimpleNamespace(time=lambda:start.timestamp()+3*3600)):
            accepted=agent.call('/api/agent/custom-action/authorize',request);self.assertEqual(accepted['action'],'shutdown')
            with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-action/authorize',request)
            agent.call('/api/agent/custom-action/complete',{'token':accepted['token']})
        with patch.object(custom,'time',SimpleNamespace(time=lambda:start.timestamp()+5*3600)):
            with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-action/authorize',request)

    def test_support_cannot_read_library_and_protocol_types_are_strict(self):
        agent,eid,_=self.make_agent()
        with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-settings',{'protocol':2.0})
        self.store.add_user('support-fixture',self.password,'support')
        self.csrf=self.api('/api/login',{'username':'support-fixture','password':self.password})['csrf']
        self.assert_http(403,lambda:self.api('/api/custom-library'))
        self.assert_http(403,lambda:self.api('/api/custom-library/effective?scope=global'))


class RepeatScheduleTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.agent=FakeAgent(self.root);self.actions=Actions();self.stop=threading.Event()
        self.now=dt.datetime(2026,10,21,22,0,tzinfo=dt.timezone(dt.timedelta(hours=8))).timestamp();self.mono=1000
        self.rule=schedule(delay_seconds=60,defer_minutes=0,repeat={'interval_minutes':60,'until':'02:00'})
        self.p=packet(body={**copy.deepcopy(custom.DEFAULT),'schedules':[self.rule]})
        self.engine=ScheduleEngine(self.agent,self.actions,lambda:self.p,self.stop,clock=lambda:self.now,monotonic=lambda:self.mono)
    def tearDown(self):self.temp.cleanup()
    def advance(self,seconds):self.now+=seconds;self.mono+=seconds
    def tick(self):
        self.engine.tick(self.p)
        for _ in range(20):
            if not self.engine.pending or self.engine.pending.get('responses') or self.engine.pending.get('resume'):break
            time.sleep(.005)
    def test_22_23_midnight_01_repeat_without_one_time_limit(self):
        self.actions.answer='defer';self.tick()
        for hour in (23,0,1):
            self.tick();self.assertEqual(self.engine.report['state'],'deferred');self.advance(3600);self.tick();self.assertEqual(dt.datetime.fromtimestamp(self.now,dt.timezone(dt.timedelta(hours=8))).hour,hour)
            self.assertIsNotNone(self.engine.pending);self.assertEqual(self.engine.report['state'],'prompting')
        self.assertEqual(self.actions.executed,[])
    def test_cancel_is_another_reminder_in_repeat_mode(self):
        self.actions.answer='cancel';self.tick();self.tick();self.assertIsNotNone(self.engine.pending);self.assertEqual(self.engine.report['state'],'deferred')
        self.assertEqual(self.engine.report['next_prompt'],self.now+3600)
    def test_repeat_cutoff_only_stops_no_forced_action(self):
        self.actions.answer='defer';self.tick();self.tick();self.advance(4*3600);self.tick()
        self.assertIsNone(self.engine.pending);self.assertEqual(self.engine.report['state'],'repeat_window_ended');self.assertEqual(self.actions.executed,[])
    def test_after_several_deferrals_no_response_can_request_windows_once(self):
        self.actions.answer='defer';self.tick();self.tick();self.advance(3600);self.actions.answer='continue';self.tick();self.advance(61);self.tick()
        self.assertEqual(len(self.actions.executed),1)
        self.tick();self.assertEqual(len(self.actions.executed),1)
    def test_no_actions_after_offline_or_new_session_or_clock_jump(self):
        self.actions.answer='defer';self.tick();self.tick();self.actions.people=[{'id':1,'user':'another','active':True}];self.advance(3600);self.tick();self.assertIsNone(self.engine.pending);self.assertEqual(self.actions.executed,[])
    def test_restart_does_not_replay_repeat_campaign(self):
        self.actions.answer='defer';self.tick();self.tick()
        restarted=ScheduleEngine(self.agent,self.actions,lambda:self.p,self.stop,clock=lambda:self.now,monotonic=lambda:self.mono);restarted.tick(self.p)
        self.assertIsNone(restarted.pending);self.assertEqual(self.actions.executed,[])
    def test_schema_interval_cutoff_and_cross_midnight_conflicts(self):
        for repeat in ({'interval_minutes':0,'until':'02:00'},{'interval_minutes':241,'until':'02:00'},{'interval_minutes':60,'until':'25:00'}):
            with self.assertRaises(ValueError):custom.validate({**custom.DEFAULT,'schedules':[schedule(defer_minutes=0,repeat=repeat)]})
        conflict=schedule(id='morning',days=[4],times=['01:00'])
        with self.assertRaises(ValueError):custom.validate({**custom.DEFAULT,'schedules':[self.rule,conflict]})
    def test_server_window_allows_repeated_late_action_only_before_cutoff(self):
        self.assertEqual(custom.schedule_expiry(self.rule,self.now),self.now+4*3600)
        self.assertGreater(custom.schedule_expiry(self.rule,self.now),self.now+2*3600)
    def test_repeat_does_not_stack_abandoned_prompt_threads(self):
        class Alive:
            def is_alive(self):return True
        self.actions.answer='defer';self.tick();self.tick();self.engine.notice_threads=[Alive() for _ in range(8)];self.advance(3600);self.tick()
        self.assertIsNotNone(self.engine.pending);self.assertEqual(self.engine.report['state'],'waiting_for_previous_notice');self.assertEqual(len(self.engine.notice_threads),8)

    def test_windows_button_mapping_and_repeat_text_are_consistent(self):
        from unittest.mock import Mock
        from guarddesk.custom_windows import prompt
        for response,result in ((2,'defer'),(7,'defer'),(6,'continue'),(32000,'continue')):
            api=Mock()
            def answer(*args):args[-2]._obj.value=response;return 1
            api.WTSSendMessageW.side_effect=answer
            with patch('guarddesk.custom_windows.ctypes.WinDLL',return_value=api):self.assertEqual(prompt(1,self.rule,60),result)
            message=api.WTSSendMessageW.call_args.args[4]
            self.assertIn('可重複',message);self.assertIn('02:00',message);self.assertNotIn('限一次',message)


if __name__=='__main__':unittest.main()
