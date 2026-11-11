"""Isolated real HTTP authorization and synthetic desktop epoch regressions."""
import copy
import json
import threading
import time
import unittest
from unittest.mock import Mock,patch
import test_native_remote
import test_machine_agent
from guarddesk.remote_client import RemoteClientError,ViewerEngine
from guarddesk.remote_admin_windows import validate_ticket,Desktop,DesktopTransition,assist


class AdminServerTest(test_native_remote.NativeRemoteTest):
    def setUp(self):
        super().setUp();self._desktop_generations={}

    def prepare_admin(self):
        client,agent,did=self.prepare(protocol=6)
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,can_elevate=True,days=1))
        session=client.request(did,'control','owned admin test',admin_control=True)
        self._ack_client=client
        self._desktop_generations={}
        result=agent.call('/api/agent/remote/update',dict(session_id=session['id'],action='approve',account='TEST\\employee'))
        return client,agent,did,session,result['admin_nonce']
    def endpoint(self,agent,session,nonce,action,epoch='a'*32,desktop='default',**body):
        generation=self._desktop_generations.setdefault(epoch,len(self._desktop_generations)+1)
        result=agent.call('/api/agent/remote/update',dict(session_id=session['id'],admin_nonce=nonce,action=action,desktop_epoch=epoch,desktop_generation=generation,desktop=desktop,**body))
        if action=='frame' and result.get('status')=='active':
            with self.server.remote_lock:seq=self.server.remote_memory[session['id']]['frame']['seq']
            self.client_ack(session,epoch,seq)
        return result
    def client_ack(self,session,epoch,seq):
        return self._ack_client.call('/api/remote/presented',dict(session_id=session['id'],desktop_epoch=epoch,frame_seq=seq))
    def test_admin_mode_needs_explicit_permission_new_native_and_desktop_control(self):
        client,agent,did=self.prepare(protocol=6)
        with self.assertRaises(RemoteClientError):client.request(did,'control','',admin_control=True)
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,can_elevate=True,days=1))
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=3))
        with self.assertRaises(RemoteClientError):client.request(did,'control','',admin_control=True)
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=6))
        with self.assertRaises(RemoteClientError):client.request(did,'view','',admin_control=True)
        g=client.catalog()['grants'][0];self.assertTrue(g['can_elevate'])
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=4))
        with self.assertRaises(RemoteClientError):client.request(did,'control','',admin_control=True)
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=5))
        with self.assertRaises(RemoteClientError):client.request(did,'control','',admin_control=True)
        agent.call('/api/agent/remote/poll',dict(account='TEST\\employee',ready=True,protocol=6))
        with self.assertRaises(RemoteClientError):
            client.call('/api/remote/request',dict(device_id=did,mode='control',reason='',viewer='desktop',quality='balanced',admin_control=True))
    def test_secure_transition_drops_old_input_and_keeps_same_approved_session(self):
        client,agent,did,s,nonce=self.prepare_admin();frame=test_native_remote.frame()
        with self.assertRaises(ConnectionError):self.endpoint(agent,s,'b'*64,'frame',frame=frame)
        self.endpoint(agent,s,nonce,'frame',frame=frame)
        key=dict(type='key',key=65,down=True)
        self.assertEqual(client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='a'*32,actions=[key]))['accepted'],1)
        self.endpoint(agent,s,nonce,'frame',epoch='b'*32,desktop='winlogon',frame=frame)
        self.assertEqual(self.endpoint(agent,s,nonce,'commands',epoch='b'*32,desktop='winlogon')['commands'],[])
        stale=client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='a'*32,actions=[key]));self.assertEqual(stale['accepted'],0)
        packet=client.call('/api/remote/session?id='+s['id']);self.assertEqual(packet['desktop'],'winlogon');self.assertEqual(packet['status'],'active')
        self.assertNotIn(nonce,json.dumps(packet))
        client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='b'*32,actions=[key]))
        self.assertEqual(self.endpoint(agent,s,nonce,'commands',epoch='b'*32,desktop='winlogon')['commands'][0]['key'],65)
        self.endpoint(agent,s,nonce,'frame',epoch='c'*32,frame=frame)
        self.assertEqual(client.call('/api/remote/session?id='+s['id'])['desktop'],'default')
        with self.store.connect() as db:events=' '.join(r[0] for r in db.execute("SELECT details FROM events WHERE kind LIKE 'remote.%'"))
        self.assertNotIn(nonce,events);self.assertNotIn('jpeg',events);self.assertNotIn('"key"',events)
    def test_transient_desktop_failure_invalidates_frame_queue_without_closing(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.endpoint(agent,s,nonce,'frame',frame=test_native_remote.frame())
        first=client.call('/api/remote/session?id='+s['id'])['frame_seq']
        self.endpoint(agent,s,nonce,'admin_pause')
        packet=client.call('/api/remote/session?id='+s['id']);self.assertEqual(packet['status'],'active');self.assertNotIn('frame',packet)
        self.endpoint(agent,s,nonce,'frame',epoch='b'*32,desktop='winlogon',frame=test_native_remote.frame())
        resumed=client.call('/api/remote/session?id='+s['id']+'&after='+str(first))
        self.assertEqual(resumed['status'],'active');self.assertIn('frame',resumed);self.assertGreater(resumed['frame_seq'],first)
    def test_input_racing_secure_pause_returns_resync_and_preserves_consent(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.endpoint(agent,s,nonce,'frame',frame=test_native_remote.frame())
        self.endpoint(agent,s,nonce,'admin_pause')
        result=client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='a'*32,actions=[dict(type='key',key=65,down=True)]))
        self.assertEqual(result,dict(ok=True,accepted=0,resync=True))
        self.assertEqual(client.call('/api/remote/session?id='+s['id'])['status'],'active')
        self.endpoint(agent,s,nonce,'frame',epoch='b'*32,desktop='winlogon',frame=test_native_remote.frame())
        self.assertEqual(self.endpoint(agent,s,nonce,'commands',epoch='b'*32,desktop='winlogon')['commands'],[])
        self.assertEqual(client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='b'*32,actions=[dict(type='key',key=65,down=True)]))['accepted'],1)
    def test_desktop_changes_during_batch_validation_never_relabels_old_input(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.endpoint(agent,s,nonce,'frame',frame=test_native_remote.frame())
        class SwitchingKeys:
            def __contains__(keys,key):
                # Deterministic interleaving at the unlocked validation boundary.
                with self.server.remote_lock:
                    self.server.remote_memory[s['id']]['desktop_epoch']='b'*32
                    self.server.remote_memory[s['id']]['desktop']='winlogon'
                return True
        with patch('guarddesk.remote_codec.KEYS',SwitchingKeys()):
            result=client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='a'*32,actions=[dict(type='key',key=65,down=True)]))
        self.assertEqual(result,dict(ok=True,accepted=0,resync=True))
        self.assertEqual(self.endpoint(agent,s,nonce,'commands',epoch='b'*32,desktop='winlogon')['commands'],[])
    def test_admin_stale_frame_or_heartbeat_resyncs_without_extending_lease(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.endpoint(agent,s,nonce,'frame',frame=test_native_remote.frame())
        expiry=client.call('/api/remote/session?id='+s['id'])['expires']
        with self.store.connect() as db:db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(time.time()-4,s['id']))
        result=client.call('/api/remote/input',dict(session_id=s['id'],desktop_epoch='a'*32,actions=[dict(type='key',key=65,down=True)]))
        self.assertEqual(result,dict(ok=True,accepted=0,resync=True))
        self.assertEqual(client.call('/api/remote/session?id='+s['id'])['expires'],expiry)
    def test_admin_grant_revocation_ends_active_session_while_normal_control_remains(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,can_elevate=False,days=1))
        result=client.call('/api/remote/session?id='+s['id'])
        self.assertEqual(result['status'],'closed');self.assertEqual(result['ended_reason'],'admin_permission_revoked')
        self.assertNotIn(s['id'],self.server.remote_memory)
    def test_old_grant_post_cannot_silently_keep_admin_permission(self):
        client,agent,did,s,nonce=self.prepare_admin()
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,days=1))
        self.assertFalse(client.catalog()['grants'][0]['can_elevate'])
    def test_admin_permission_cannot_be_granted_without_control(self):
        client,agent,did=self.prepare()
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=False,can_elevate=True,days=1))
    def test_endpoint_cannot_drain_secure_keys_without_private_nonce(self):
        client,agent,did,s,nonce=self.prepare_admin()
        for action in ('frame','commands','repeat_frame','admin_pause','admin_validate'):
            with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',dict(session_id=s['id'],action=action,frame=test_native_remote.frame()))
        self.assertEqual(agent.call('/api/agent/remote/update',dict(session_id=s['id'],action='admin_watch'))['status'],'active')
        self.assertEqual(self.endpoint(agent,s,nonce,'admin_validate')['admin_protocol'],6)
        for invalid in ('','中文','a'*65,None,True):
            with self.assertRaisesRegex(ConnectionError,'HTTP 403'):self.endpoint(agent,s,invalid,'admin_validate')
    def test_empty_nonce_before_consent_cannot_claim_active_management_lease(self):
        client,agent,did=self.prepare(protocol=6)
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,can_elevate=True,days=1))
        s=client.request(did,'control','',admin_control=True)
        for action in ('admin_validate','admin_pause','commands','frame'):
            with self.assertRaisesRegex(ConnectionError,'HTTP 403'):self.endpoint(agent,s,'',action,frame=test_native_remote.frame())
        self.assertEqual(client.call('/api/remote/session?id='+s['id'])['status'],'requested')
    def test_all_grant_and_device_override_preserve_independent_admin_permission(self):
        client,agent,did=self.prepare()
        self.api('/api/remote/grant',dict(username='admin',device_id='*',enabled=True,can_control=True,can_elevate=True,days=0))
        self.assertFalse(client.catalog()['grants'][0]['can_elevate']) # device rule wins
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=False,can_control=False))
        self.assertTrue(client.catalog()['grants'][0]['can_elevate'])
    def test_update_starting_during_consent_prevents_management_child_activation(self):
        client,agent,did=self.prepare(protocol=6)
        self.api('/api/remote/grant',dict(username='admin',device_id=did,enabled=True,can_control=True,can_elevate=True,days=1))
        s=client.request(did,'control','',admin_control=True)
        with self.store.connect() as db:
            db.execute('INSERT INTO updater_refresh VALUES (?,?,?,?,?,?,?)',(did,'b'*32,'c'*32,'0.4.69',time.time(),time.time()+120,'active'))
        result=agent.call('/api/agent/remote/update',dict(session_id=s['id'],action='approve',account='TEST\\employee'))
        self.assertEqual(result['status'],'closed');self.assertNotIn('admin_nonce',result)
        self.assertEqual(client.call('/api/remote/session?id='+s['id'])['ended_reason'],'update_in_progress')
        with self.assertRaises(RemoteClientError):client.request(did,'control','',admin_control=True)


class AdminRouterTest(test_machine_agent.MachineFixture):
    def setUp(self):
        super().setUp();self.states[2]['active']=False
        self.launcher=Mock();self.router.admin_launcher=self.launcher
        self.request=dict(id='a'*32,status='requested',admin_control=True,quality='balanced',operator='MIS')
        self.original=self.router._remote_call
        def call(path,body):
            if path.endswith('/poll'):return dict(session=copy.deepcopy(self.request))
            if body.get('action')=='approve':return dict(status='active',admin_nonce='b'*64,expires=time.time()+600)
            return self.original(path,body)
        self.router._remote_call=call
    def test_broker_strips_nonce_and_binds_admin_child_to_actual_consent_owner(self):
        self.dispatch('/api/agent/remote/poll',dict(ready=True,protocol=3))
        reply=self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='approve',account='forged'))
        self.assertNotIn('admin_nonce',reply);self.launcher.launch.assert_called_once()
        args=self.launcher.launch.call_args.args;self.assertEqual(args[1],self.peer(1));self.assertEqual(args[2]['account'],'EXAMPLE\\A')
        for action in ('commands','frame','repeat_frame'):
            with self.assertRaises(PermissionError):self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action=action))
        self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='stop'));self.launcher.stop.assert_called()
    def test_launch_failure_stops_center_not_fallback_to_unprivileged_capture(self):
        self.launcher.launch.side_effect=OSError('owned launch failure')
        self.dispatch('/api/agent/remote/poll',dict(ready=True))
        with self.assertRaises(OSError):self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='approve'))
        self.assertEqual(self.calls[-1][1]['action'],'stop');self.assertFalse(self.router.remote_owner)
    def test_lock_and_changed_logon_end_exact_admin_child(self):
        self.dispatch('/api/agent/remote/poll',dict(ready=True))
        self.states[1]['locked']=True
        self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='admin_watch'))
        self.assertEqual(self.calls[-1][1]['action'],'stop')
        # Stop must also occur on this early return, not just Supervisor tick.
        self.assertFalse(self.router.remote_owner)

    def test_revoked_approval_reply_never_launches_a_child(self):
        self.dispatch('/api/agent/remote/poll',dict(ready=True))
        entered=threading.Event();release=threading.Event();errors=[]
        previous=self.router._remote_call
        def call(path,body):
            if body.get('action')=='approve':
                entered.set()
                if not release.wait(3):raise TimeoutError('owned approval fixture')
            return previous(path,body)
        self.router._remote_call=call
        def approve():
            try:self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='approve'))
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=approve);thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='stop'))
            self.launcher.revoke.assert_called_with('a'*32)
        finally:release.set();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(len(errors),1)
        self.assertIsInstance(errors[0],PermissionError);self.launcher.launch.assert_not_called()
        self.assertFalse(self.router.remote_owner)

    def test_stop_during_launch_revokes_before_launch_completes(self):
        self.dispatch('/api/agent/remote/poll',dict(ready=True))
        entered=threading.Event();release=threading.Event();errors=[]
        def launch(*args):
            entered.set()
            if not release.wait(3):raise TimeoutError('owned launcher fixture')
        self.launcher.launch.side_effect=launch
        def approve():
            try:self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='approve'))
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=approve);thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.dispatch('/api/agent/remote/update',dict(session_id='a'*32,action='stop'))
            self.launcher.revoke.assert_called_with('a'*32)
            self.assertFalse(self.router.remote_owner)
        finally:release.set();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(len(errors),1)
        self.assertIsInstance(errors[0],PermissionError);self.launcher.stop.assert_called_with('a'*32)


class AdminPureTest(unittest.TestCase):
    def run_paused_loop(self,*,expiry=120,lock=False,capture_failure=False):
        from types import SimpleNamespace
        clock=[10.0];calls=[];stop=Mock();stop.is_set.return_value=False
        stop.wait.side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)
        desktop=Mock();desktop.generation=1;desktop.name='default';desktop.epoch='a'*32;desktop.guard.return_value=True
        def select():
            if clock[0]<15:raise DesktopTransition('owned transition')
            return False
        desktop.select.side_effect=select
        if lock:desktop.check_session.side_effect=PermissionError('locked')
        def call(body):
            calls.append(dict(body))
            if body['action']=='frame':stop.is_set.return_value=True
            return dict(status='active',admin_protocol=6,commands=[])
        lease=dict(session_id='b'*32,admin_nonce='c'*64,expires=expiry,quality='balanced')
        fake_time=SimpleNamespace(time=lambda:clock[0],monotonic=lambda:clock[0])
        with patch('guarddesk.remote_admin_windows.time',fake_time),patch('guarddesk.remote_windows.Input'),patch('guarddesk.remote_windows.jpeg_frame',return_value={'jpeg':'synthetic'}) as capture:
            if capture_failure:capture.side_effect=OSError('stable capture failure')
            assist(lease,call,desktop,stop)
        return calls,desktop,clock[0]
    def test_transition_longer_than_three_seconds_resumes_same_session_new_epoch(self):
        calls,desktop,elapsed=self.run_paused_loop()
        frames=[c for c in calls if c['action']=='frame']
        self.assertEqual(len(frames),1);self.assertGreaterEqual(elapsed,15)
        self.assertNotEqual(frames[0]['desktop_epoch'],'a'*32)
        self.assertEqual({c['session_id'] for c in calls},{'b'*32})
        self.assertGreater(sum(c['action']=='admin_pause' for c in calls),12)
        desktop.check_session.assert_called();desktop.close.assert_called_once()
    def test_paused_loop_still_expires_and_does_not_capture(self):
        calls,desktop,elapsed=self.run_paused_loop(expiry=14)
        self.assertFalse(any(c['action']=='frame' for c in calls));self.assertLess(elapsed,15)
        self.assertEqual(calls[-1]['action'],'stop')
    def test_lock_during_pause_immediately_ends_control(self):
        with self.assertRaisesRegex(PermissionError,'locked'):self.run_paused_loop(lock=True)
    def test_stable_capture_failure_is_not_silently_retried(self):
        with self.assertRaisesRegex(OSError,'stable capture failure'):self.run_paused_loop(capture_failure=True)
    def test_viewer_resync_discards_input_without_ending_session(self):
        engine=ViewerEngine(Mock(),dict(id='a'*32,status='active',mode='control',admin_control=True))
        engine.fresh_until=time.monotonic()+10;engine.displayed_epoch='a'*32
        engine.inputs.add(dict(type='key',key=65,down=True))
        def call(*args):
            engine.inputs.add(dict(type='key',key=66,down=True))
            return dict(ok=True,accepted=0,resync=True)
        engine.client.call.side_effect=call
        with patch.object(engine.stop_event,'wait',side_effect=[False,True]):engine.send_inputs()
        self.assertFalse(engine.stop_event.is_set());self.assertIsNone(engine.error)
        self.assertEqual(engine.inputs.take(),[]);self.assertIsNone(engine.displayed_epoch);self.assertEqual(engine.fresh_until,0)
    def test_viewer_permission_error_still_ends_control(self):
        engine=ViewerEngine(Mock(),dict(id='a'*32,status='active',mode='control',admin_control=True))
        engine.fresh_until=time.monotonic()+10;engine.inputs.add(dict(type='key',key=65,down=True))
        engine.client.call.side_effect=RemoteClientError('permission revoked')
        with patch.object(engine.stop_event,'wait',return_value=False):engine.send_inputs()
        self.assertTrue(engine.stop_event.is_set());self.assertEqual(engine.inputs.take(),[])
    def test_ticket_identity_bounds_expiry_no_arbitrary_paths(self):
        t=dict(format=1,device_id='a'*24,session_id='b'*32,session=1,sid='S-1-5-21-1-2-3-1000',logon=10,parent=123,parent_created=15,expires=1000,admin_nonce='c'*64,quality='clarity',operator='MIS',cancel_handle=1234)
        self.assertIs(validate_ticket(t,'a'*24,'b'*32,now=500),t)
        for change in (dict(expires=400),dict(expires=1111),dict(parent=0),dict(session=0),dict(admin_nonce=''),dict(path='cmd.exe'),dict(sid='S-1-5-18')):
            with self.assertRaises((ValueError,PermissionError)):validate_ticket({**t,**change},'a'*24,'b'*32,now=500)
        with self.assertRaises(PermissionError):validate_ticket(t,'d'*24,'b'*32,now=500)
    def test_standard_account_cannot_start_management_worker(self):
        from guarddesk.remote_admin_windows import identity
        with self.assertRaises(PermissionError):identity()
    def test_wts_lock_logout_multiple_unknown_and_parent_exit_refuse_secure_capture(self):
        desktop=object.__new__(Desktop);desktop.lease=dict(session=1,logon=10,expires=time.time()+600);desktop.parent_alive=lambda:True
        valid={1:dict(active=True,locked=False,logon=10)}
        with patch('guarddesk.document_context.session_states',return_value=valid):desktop.check_session()
        for states in ({},{1:dict(active=True,locked=True,logon=10)},{1:dict(active=True,locked=False,logon=11)},
            {1:dict(active=True,locked=False,logon=10,query_failed=True)},{**valid,2:dict(active=True,locked=False,logon=20)}):
            with patch('guarddesk.document_context.session_states',return_value=states),self.assertRaises(PermissionError):desktop.check_session()
        desktop.parent_alive=lambda:False
        with patch('guarddesk.document_context.session_states',return_value=valid),self.assertRaises(PermissionError):desktop.check_session()
    def test_viewer_clears_buffer_on_new_display_epoch_and_never_uses_network_only_epoch(self):
        engine=ViewerEngine(Mock(),dict(id='a'*32,status='active',mode='control',admin_control=True))
        engine.inputs.add(dict(type='key',key=65,down=True));engine.latest=(dict(status='active',desktop_epoch='b'*32),None)
        engine.take();self.assertIsNone(engine.displayed_epoch);self.assertEqual(engine.inputs.take(),[])
    def test_secure_loop_survives_default_winlogon_default_without_replaying_old_epoch(self):
        stop=threading.Event();desktop=Mock();desktop.generation=1;desktop.name='default';desktop.epoch='a'*32;desktop.guard.return_value=True
        order=[]
        def select():
            n=len(order)
            desktop.name=('default','winlogon','default')[min(n,2)];desktop.epoch=('a','b','c')[min(n,2)]*32
            return True
        desktop.select.side_effect=select
        def call(body):
            if body['action']=='frame':order.append(body['desktop'])
            if len(order)>=3:stop.set()
            return dict(status='active',admin_protocol=6,commands=[dict(type='key',key=65,down=True,desktop_epoch='d'*32)])
        lease=dict(session_id='b'*32,admin_nonce='c'*64,expires=time.time()+10,quality='balanced')
        with patch('guarddesk.remote_windows.Input') as inputs,patch('guarddesk.remote_windows.jpeg_frame',return_value={'jpeg':'synthetic'}):
            assist(lease,call,desktop,stop)
        self.assertEqual(order,['default','winlogon','default']);inputs.return_value.send.assert_not_called();desktop.close.assert_called_once()
    def test_rolled_back_server_cannot_receive_even_one_secure_frame(self):
        desktop=Mock();desktop.generation=1;desktop.epoch=None;desktop.name=None
        calls=[]
        def old_server(body):calls.append(body['action']);return dict(status='active',commands=[])
        lease=dict(session_id='a'*32,admin_nonce='b'*64,expires=time.time()+10,quality='clarity')
        with patch('guarddesk.remote_windows.Input'),patch('guarddesk.remote_windows.clarity_frame') as capture,self.assertRaises(PermissionError):
            assist(lease,old_server,desktop,threading.Event())
        capture.assert_not_called();desktop.select.assert_not_called();self.assertEqual(calls,['admin_validate','admin_failure','stop'])
    def test_component_failure_reports_only_bounded_phase_and_code(self):
        desktop=Mock();desktop.generation=1;desktop.epoch=None;desktop.name=None
        desktop.select.side_effect=OSError('private prompt text must never leave the endpoint')
        calls=[]
        def server(body):
            calls.append(body)
            return dict(status='active',admin_protocol=6,commands=[])
        lease=dict(session_id='a'*32,admin_nonce='b'*64,expires=time.time()+10,quality='clarity')
        with patch('guarddesk.remote_windows.Input'),self.assertRaises(OSError):
            assist(lease,server,desktop,threading.Event())
        failure=next(body for body in calls if body['action']=='admin_failure')
        self.assertEqual(failure['error_type'],'OSError')
        self.assertNotIn('private prompt',str(failure));self.assertNotIn('message',failure)
        self.assertIsNone(failure['native_code']);desktop.close.assert_called_once()


class TokenSessionAccessRegression(unittest.TestCase):
    def test_real_token_session_access_denial_precedes_privilege_check(self):
        # Field v3 failed at SetTokenInformation, not at UAC or file ACL.
        # Change only transient copies of our own token, using our own session.
        # Never enable a privilege, launch a process, or touch another user.
        import ctypes,os
        from ctypes import wintypes as w
        from guarddesk.remote_admin_windows import PRIMARY_SESSION_ACCESS
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        adv=ctypes.WinDLL('advapi32',use_last_error=True)
        kernel.GetCurrentProcess.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
        kernel.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
        adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
        adv.DuplicateTokenEx.argtypes=[w.HANDLE,w.DWORD,w.LPVOID,ctypes.c_int,ctypes.c_int,ctypes.POINTER(w.HANDLE)]
        adv.SetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD]
        session=w.DWORD();self.assertTrue(kernel.ProcessIdToSessionId(os.getpid(),ctypes.byref(session)))
        source=w.HANDLE();self.assertTrue(adv.OpenProcessToken(kernel.GetCurrentProcess(),0x0a,ctypes.byref(source)))
        try:
            for access,old in ((0x12b,True),(PRIMARY_SESSION_ACCESS,False)):
                token=w.HANDLE();self.assertTrue(adv.DuplicateTokenEx(source,access,None,2,1,ctypes.byref(token)))
                try:
                    ctypes.set_last_error(0)
                    ok=adv.SetTokenInformation(token,12,ctypes.byref(session),ctypes.sizeof(session));error=ctypes.get_last_error()
                    if old:self.assertFalse(ok);self.assertEqual(error,5)
                    else:
                        # Standard users must still fail SeTcb (1314).
                        self.assertTrue(ok or error==1314,(ok,error))
                        self.assertEqual(access&0x20,0,'Child token never adjusts privileges')
                finally:kernel.CloseHandle(token)
        finally:kernel.CloseHandle(source)


if __name__=='__main__':unittest.main()
