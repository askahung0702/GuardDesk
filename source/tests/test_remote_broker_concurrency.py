"""Controlled transports, no network, pixels, credential contents or OS input."""
import threading
import time
import unittest
from guarddesk.machine_agent import Router

PATH='/api/agent/remote/update'

class BrokerConcurrency(unittest.TestCase):
    def setUp(self):
        self.states={1:dict(sid='owned-A',logon=10,active=True,locked=False,account='A')}
        self.peer=dict(session=1,sid='owned-A',logon=10)
        self.entered=threading.Event();self.release=threading.Event();self.errors=[];self.results=[]
        self.addCleanup(self.release.set)
        self.action='frame';self.reply={'status':'active','commands':[{'owned_test':True}]}
        def call(path,body):
            if (path.endswith('/poll') and self.action=='poll') or body.get('action')==self.action:
                self.entered.set()
                if not self.release.wait(2):raise TimeoutError('owned transport deadline')
                return self.reply
            return {'session':{'id':'owned'},'status':'active'}
        self.router=Router(None,lambda:self.states,call)
        self.router.remote_owner['owned']=((1,10),time.monotonic()+60)

    def invoke(self,action):
        return self.router.remote(PATH,{'session_id':'owned','action':action},self.peer,self.states[1])

    def start(self,fn):
        def work():
            try:self.results.append(fn())
            except Exception as exc:self.errors.append(exc)
        thread=threading.Thread(target=work);thread.start()
        self.addCleanup(lambda:(self.release.set(),thread.join(3)))
        return thread

    def finish_stale(self,thread):
        self.release.set();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(len(self.errors),1)
        self.assertIsInstance(self.errors[0],PermissionError);self.assertEqual(self.results,[])

    def test_frame_block_does_not_block_control_or_stop_and_discards_reply(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        start=time.monotonic();self.invoke('commands')
        self.assertEqual(self.invoke('stop')['status'],'closed')
        self.assertLess(time.monotonic()-start,.25)
        self.assertNotIn('owned',self.router.remote_owner);self.finish_stale(thread)

    def test_pending_poll_cannot_revive_after_stop_and_new_request_succeeds(self):
        self.action='poll';self.reply={'session':{'id':'stale'}}
        thread=self.start(lambda:self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1]))
        self.assertTrue(self.entered.wait(1));self.invoke('stop');self.finish_stale(thread)
        self.assertEqual(self.router.remote_owner,{})
        self.action='none'
        # Center may still report the old session while stop is in transit.
        result=self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.assertIsNone(result['session'])
        self.router._remote_call=lambda path,body:{'session':{'id':'new-request'}}
        result=self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.assertEqual(result['session']['id'],'new-request');self.assertIn('new-request',self.router.remote_owner)

    def test_end_session_invalidates_before_blocked_stop_network(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        self.router.end_session(1,10);self.finish_stale(thread)

    def test_logon_or_sid_change_during_io_is_rejected(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        self.states[1]={**self.states[1],'logon':20,'sid':'owned-B'}
        self.finish_stale(thread)

    def test_closed_control_response_invalidates_pending_media(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        original=self.router._remote_call
        self.router._remote_call=lambda path,body:{'status':'closed'}
        self.invoke('commands');self.router._remote_call=original;self.finish_stale(thread)

    def test_bounded_frame_lane_rejects_flood_and_control_still_progresses(self):
        threads=[self.start(lambda:self.invoke('frame')) for _ in range(2)]
        self.assertTrue(self.entered.wait(1))
        deadline=time.monotonic()+1
        while self.router.remote_inflight['frame']!=2 and time.monotonic()<deadline:time.sleep(.001)
        for _ in range(1000):
            with self.assertRaises(TimeoutError):self.invoke('frame')
        self.assertEqual(self.router.remote_inflight['frame'],2);self.invoke('commands')
        self.release.set()
        for thread in threads:thread.join(3)
        self.assertEqual(self.errors,[]);self.assertEqual(self.router.remote_inflight['frame'],0)
        self.assertEqual(self.router.remote_stats['busy'],1000)

    def test_transport_timeout_releases_lane(self):
        self.router._remote_call=lambda *args:(_ for _ in ()).throw(TimeoutError('owned'))
        with self.assertRaises(TimeoutError):self.invoke('frame')
        self.assertEqual(self.router.remote_inflight['frame'],0)

    def test_timeout_or_revoke_fences_other_inflight_reply(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        self.router._remote_call=lambda *args:(_ for _ in ()).throw(ConnectionError('owned authorization rejection'))
        with self.assertRaises(ConnectionError):self.invoke('commands')
        self.finish_stale(thread)

    def test_historical_wts_slots_do_not_exhaust_live_capacity(self):
        self.router.remote_owner.clear()
        for slot in range(100):
            peer=dict(session=slot,sid='owned',logon=slot)
            self.router._remote_epoch(peer)
            self.router.end_session(slot,slot)
        self.assertEqual(self.router.remote_epochs,{})

    def test_blocked_stop_cannot_regrant_old_center_id_but_new_id_works(self):
        self.action='stop'
        thread=self.start(lambda:self.invoke('stop'));self.assertTrue(self.entered.wait(1))
        result=self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.assertIsNone(result['session']);self.assertEqual(self.router.remote_owner,{})
        original=self.router._remote_call
        self.router._remote_call=lambda path,body:{'session':{'id':'fresh'}}
        self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.assertIn('fresh',self.router.remote_owner)
        self.router._remote_call=original;self.release.set();thread.join(3)
        self.assertIn('fresh',self.router.remote_owner);self.assertEqual(self.errors,[])

    def test_invalid_poll_notifies_center_stop_without_reporting_over_active_B(self):
        calls=[]
        self.router._remote_call=lambda path,body:calls.append((path,body)) or {}
        self.states[1]['active']=False
        self.states[2]=dict(sid='owned-B',logon=20,active=True,locked=False,account='B')
        self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.assertEqual(calls,[(PATH,{'session_id':'owned','action':'stop'})])
        self.assertEqual(self.router.remote_owner,{})

    def test_normal_poll_does_not_invalidate_inflight_frame(self):
        thread=self.start(lambda:self.invoke('frame'));self.assertTrue(self.entered.wait(1))
        self.router.remote('/api/agent/remote/poll',{},self.peer,self.states[1])
        self.release.set();thread.join(3);self.assertEqual(self.errors,[]);self.assertEqual(len(self.results),1)

    def test_reused_wts_slot_without_a_supervised_child_retires_old_owner(self):
        self.router._remote_epoch(self.peer)
        self.states[1]={**self.states[1],'logon':20,'sid':'owned-B','account':'B'}
        peer=dict(session=1,logon=20,sid='owned-B');calls=[]
        def call(path,body):
            calls.append((path,dict(body)))
            return {'session':{'id':'new-owner'}} if path.endswith('/poll') else {'status':'closed'}
        self.router._remote_call=call
        self.router.remote('/api/agent/remote/poll',{},peer,self.states[1])
        self.assertNotIn('owned',self.router.remote_owner)
        self.assertEqual(self.router.remote_owner['new-owner'][0],(1,20))
        self.assertEqual(calls[0],(PATH,{'session_id':'owned','action':'stop'}))

if __name__=='__main__':unittest.main()
