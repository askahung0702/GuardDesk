"""Isolated consent/frames/input simulation; never captures or controls a desktop."""
import base64
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image
from guarddesk.agent import Agent,enroll
from guarddesk.remote_client import RemoteClient,RemoteClientError,ViewerEngine,InputBuffer,viewport,pointer,console_url
from guarddesk.remote_codec import encode_jpeg,decode_frame,validate_frame
import test_system


def frame():
    with Image.new('RGB',(640,360),(25,90,110)) as image:return encode_jpeg(image)


class NativeRemoteTest(unittest.TestCase):
    api=test_system.SystemTest.api
    def setUp(self):
        self.outer=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'runtime')
        with patch('tempfile.tempdir',self.outer.name):test_system.SystemTest.setUp(self)
        self.clients=[]

    def tearDown(self):
        for client in self.clients:client.logout()
        test_system.SystemTest.tearDown(self);self.outer.cleanup()

    def prepare(self,control=True,protocol=2):
        token=self.api('/api/enrollments',{})['token'];config=self.root/('agent'+str(len(self.clients)))/'config.json'
        did=enroll(config,self.url,token,self.watch);agent=Agent(config)
        agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':protocol})
        self.api('/api/remote/grant',{'username':'admin','device_id':did,'enabled':True,'can_control':control,'days':1})
        client=RemoteClient(self.url);client.login('admin',self.password);self.clients.append(client)
        return client,agent,did

    def approved(self,mode='control'):
        client,agent,did=self.prepare();session=client.request(did,mode,'isolated native test')
        agent.call('/api/agent/remote/update',{'session_id':session['id'],'action':'approve','account':r'TEST\employee'})
        agent.call('/api/agent/remote/update',{'session_id':session['id'],'action':'frame','frame':frame()})
        return client,agent,did,session

    def test_consent_jpeg_sequence_repeat_and_independent_input_channel(self):
        # This case checks consent/order/deduplication, not elapsed-time expiry.
        # A scheduling pause must not silently turn it into the stale-frame case.
        # Replace only remote's clock object, not the shared time module used by
        # HTTP deadlines or other server threads. Expiry is tested separately.
        now=time.time()
        with patch('guarddesk.remote.time',SimpleNamespace(time=lambda:now)):
            self._consent_jpeg_sequence_repeat_and_independent_input_channel()

    def _consent_jpeg_sequence_repeat_and_independent_input_channel(self):
        client,agent,did=self.prepare();s=client.request(did,'control','native request');sid=s['id']
        packet=agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':2})
        self.assertEqual(packet['session']['viewer'],'desktop')
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame()})
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame()})
        first=client.call('/api/remote/session?id='+sid);self.assertIn('frame',first);self.assertIn('jpeg',first['frame'])
        seq=first['frame_seq'];self.assertNotIn('frame',client.call('/api/remote/session?id='+sid+'&after='+str(seq)))
        actions=[{'type':'button','button':'left','down':True,'x':.2,'y':.3},{'type':'move','x':.8,'y':.9},
                 {'type':'button','button':'left','down':False,'x':.8,'y':.9},{'type':'scroll','x':.5,'y':.5,'delta':-120},
                 {'type':'key','key':186,'down':True},{'type':'key','key':186,'down':False},{'type':'release_all'}]
        client.call('/api/remote/input',{'session_id':sid,'actions':actions})
        result=agent.call('/api/agent/remote/update',{'session_id':sid,'action':'commands'})
        self.assertEqual([{k:v for k,v in a.items() if k!='time'} for a in result['commands']],actions)
        self.assertEqual(agent.call('/api/agent/remote/update',{'session_id':sid,'action':'commands'})['commands'],[])
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'repeat_frame'})
        repeat=client.call('/api/remote/session?id='+sid+'&after='+str(seq));self.assertEqual(repeat['frame_seq'],seq);self.assertNotIn('frame',repeat)
        for after in ('--2','nan','99999999999999999999'):
            with self.assertRaises(RemoteClientError):client.call('/api/remote/session?id='+sid+'&after='+after)
        client.call('/api/remote/stop',{'session_id':sid});self.assertNotIn(sid,self.server.remote_memory)
        with self.store.connect() as db:
            logs=[r[0] for r in db.execute("SELECT details FROM events WHERE kind LIKE 'remote.%'")]
        self.assertNotIn('jpeg',json.dumps(logs));self.assertNotIn('key',json.dumps(logs))

    def test_explicit_grant_old_agent_readonly_and_login_binding(self):
        client,agent,did=self.prepare(control=False,protocol=1)
        with self.assertRaises(RemoteClientError):client.request(did,'view','requires new endpoint')
        agent.call('/api/agent/remote/poll',{'account':'TEST\\employee','ready':True,'protocol':2})
        with self.assertRaises(RemoteClientError):client.request(did,'control','view grant only')
        session=client.request(did,'view','view test')
        other=RemoteClient(self.url);other.login('admin',self.password);self.clients.append(other)
        with self.assertRaises(RemoteClientError):other.call('/api/remote/session?id='+session['id'])
        self.api('/api/remote/grant',{'username':'admin','device_id':did,'enabled':False,'can_control':False})
        self.assertEqual(client.call('/api/remote/session?id='+session['id'])['status'],'closed')

    def test_stale_video_invalid_frame_input_and_revocation(self):
        client,agent,did,s=self.approved();sid=s['id'];client.call('/api/remote/session?id='+sid)
        for action in ({'type':'scroll','x':.5,'y':.5,'delta':999999},{'type':'button','x':.5,'y':.5,'button':'left','down':1},{'type':'release_all','command':'bad'}):
            with self.assertRaises(RemoteClientError):client.call('/api/remote/input',{'session_id':sid,'actions':[action]})
        for bad in ({**frame(),'width':1921},{**frame(),'height':1081},{**frame(),'jpeg':'not-base64'}, {'jpeg':base64.b64encode(b'bad').decode(),'width':1,'height':1}):
            with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':bad})
        with self.server.remote_lock:self.server.remote_memory[sid]['frame']['time']=time.time()-4
        with self.assertRaises(RemoteClientError):client.call('/api/remote/input',{'session_id':sid,'actions':[{'type':'move','x':.5,'y':.5}]})
        self.api('/api/remote/grant',{'username':'admin','device_id':did,'enabled':False,'can_control':False})
        self.assertEqual(agent.call('/api/agent/remote/update',{'session_id':sid,'action':'commands'})['status'],'closed')

    def test_native_engine_latest_frame_and_no_input_after_stop(self):
        client,agent,did,s=self.approved();engine=ViewerEngine(client,s);engine.start()
        try:
            deadline=time.monotonic()+4;received=None
            while time.monotonic()<deadline:
                packet,error=engine.take()
                self.assertIsNone(error)
                if packet and packet[1] is not None:received=packet;break
                time.sleep(.02)
            self.assertIsNotNone(received);self.assertEqual(received[1].size,(640,360));received[1].close()
            self.assertTrue(engine.send({'type':'key','key':65,'down':True}))
            deadline=time.monotonic()+2;commands=[]
            while time.monotonic()<deadline and not commands:
                commands=agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'commands'})['commands'];time.sleep(.02)
            self.assertEqual(commands[0]['key'],65)
            engine.stop();self.assertFalse(engine.send({'type':'key','key':66,'down':True}))
            self.assertTrue(engine.closed.wait(5))
            self.assertEqual(client.call('/api/remote/session?id='+s['id'])['status'],'closed')
        finally:engine.stop();engine.closed.wait(5)

    def test_parallel_video_input_and_viewer_lease_do_not_lock_database(self):
        client,agent,did,s=self.approved();engine=ViewerEngine(client,s);stop=threading.Event();errors=[];received=[]
        def endpoint():
            try:
                while not stop.is_set():
                    if agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'frame','frame':frame()})['status']!='active':break
                    received.extend(agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'commands'})['commands'])
                    stop.wait(.05)
            except (OSError,ConnectionError) as exc:errors.append(str(exc))
        worker=threading.Thread(target=endpoint);worker.start();engine.start()
        try:
            deadline=time.monotonic()+1.5
            while time.monotonic()<deadline:
                packet,error=engine.take();self.assertIsNone(error)
                if packet and packet[1] is not None:packet[1].close()
                engine.send({'type':'move','x':.5,'y':.5});time.sleep(.04)
            self.assertGreater(engine.stats['frames'],5);self.assertTrue(received);self.assertFalse(errors)
        finally:
            stop.set();worker.join(4);engine.stop();self.assertTrue(engine.closed.wait(5))


class NativeRemotePureTest(unittest.TestCase):
    def test_loopback_only_and_bounded_input_mapping(self):
        for url in ('http://192.168.50.50:8788','https://127.0.0.1:8788','http://127.0.0.1:8788@evil.test','http://127.0.0.1:8788/path'):
            with self.assertRaises(ValueError):console_url(url)
        self.assertEqual(console_url('http://127.0.0.1:8788/'),'http://127.0.0.1:8788')
        rect=viewport((1600,900),(1200,900));self.assertEqual(rect,(0,112.5,1200,675))
        self.assertIsNone(pointer(10,10,rect));self.assertEqual(pointer(600,450,rect),{'x':.5,'y':.5})
        buffer=InputBuffer()
        for i in range(100):buffer.add({'type':'move','x':i/100,'y':.5})
        self.assertEqual(len(buffer.take()),1)
        for i in range(40):buffer.add({'type':'key','key':65,'down':bool(i%2)})
        with self.assertRaises(RemoteClientError):buffer.add({'type':'key','key':65,'down':True})
        buffer.add({'type':'release_all'});self.assertEqual(buffer.take(),[{'type':'release_all'}])

    def test_jpeg_roundtrip_size_and_bgr_orientation(self):
        from guarddesk.remote_windows import jpeg_frame
        width,height=4,2;stride=12
        raw=bytes([0,0,255]*width+[255,0,0]*width)
        with patch('guarddesk.remote_windows.capture_bgr',return_value=(width,height,stride,raw)):
            packet=jpeg_frame()
        image=decode_frame(packet)
        try:
            self.assertGreater(image.getpixel((0,0))[0],200);self.assertGreater(image.getpixel((0,1))[2],200)
        finally:image.close()
        with self.assertRaises(ValueError):validate_frame({**packet,'width':100})

    def test_agent_input_worker_runs_without_frame_roundtrip(self):
        from guarddesk.remote_windows import RemoteAgent
        commands_seen=threading.Event();release_seen=threading.Event();frame_started=threading.Event();finished=threading.Event();types=[]
        class FakeAgent:
            def call(self,path,body,**kwargs):
                if body['action']=='commands':
                    if not commands_seen.is_set():return {'status':'active','commands':[{'type':'key','key':65,'down':True}]}
                    return {'status':'active','commands':[]}
                return {'status':'closed','commands':[]}
        class FakeInput:
            def send(self,action):types.append(action['type']);commands_seen.set()
            def release(self):release_seen.set()
        def slow_frame(*args):
            frame_started.set();commands_seen.wait(2);return frame()
        worker=RemoteAgent(FakeAgent(),threading.Event());worker.show_indicator=lambda s:None;worker.close_indicator=lambda:None
        with patch('guarddesk.remote_windows.Input',FakeInput),patch('guarddesk.remote_windows.jpeg_frame',side_effect=slow_frame):
            thread=threading.Thread(target=lambda:(worker.assist({'id':'fixture','viewer':'desktop','mode':'control','quality':'balanced'}),finished.set()))
            thread.start();self.assertTrue(commands_seen.wait(2));self.assertTrue(finished.wait(4));thread.join(2)
        self.assertEqual(types,['key']);self.assertTrue(release_seen.is_set())
