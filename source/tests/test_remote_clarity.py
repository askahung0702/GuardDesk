"""Synthetic pixels and isolated API only; never capture an employee desktop."""
import base64
import threading
import unittest
from unittest.mock import patch

from PIL import Image,ImageDraw
from guarddesk.remote_codec import encode_clarity,decode_frame,validate_frame,CLARITY_BYTES
from guarddesk.remote_client import RemoteClientError,viewport,pointer,ViewerEngine
import test_native_remote as fixtures


class ClarityCodecTest(unittest.TestCase):
    def test_lossless_native_pixels_4k_portrait_and_no_fit_upscale(self):
        for size in ((1920,1080),(3840,2160),(2160,3840)):
            with Image.new('RGB',size,'#f4f5f6') as image:
                draw=ImageDraw.Draw(image);draw.text((10,10),'Readable text at 100% / 0123456789',fill='#123456')
                packet=encode_clarity(image);self.assertIn('png',packet)
                decoded=decode_frame(packet,high_resolution=True)
                try:self.assertEqual(decoded.tobytes(),image.tobytes())
                finally:decoded.close()
        self.assertEqual(viewport((1920,1080),(1920,1080)),(0,0,1920,1080))
        self.assertEqual(viewport((640,360),(1920,1080)),(640,360,640,360))
        rect=viewport((3840,2160),(1280,720),native=True)
        self.assertEqual(rect,(0,0,3840,2160))
        self.assertEqual(pointer(1920,1080,rect),{'x':.5,'y':.5})

    def test_budget_fallback_retains_dimensions_and_legacy_limits(self):
        with Image.effect_noise((640,360),90).convert('RGB') as image:
            with patch('guarddesk.remote_codec.CLARITY_BYTES',100000):packet=encode_clarity(image)
            self.assertIn('jpeg',packet);self.assertEqual((packet['width'],packet['height']),image.size)
            self.assertLessEqual(len(base64.b64decode(packet['jpeg'])),100000)
        with Image.new('RGB',(3840,2160),'white') as image:packet=encode_clarity(image)
        with self.assertRaises(ValueError):validate_frame(packet)
        for bad in ({**packet,'width':3841},{**packet,'height':3840},{**packet,'height':True},
                    {**packet,'png':'A'*(4*((CLARITY_BYTES+2)//3)+1)}):
            with self.assertRaises(ValueError):validate_frame(bad,high_resolution=True)

    def test_clarity_capture_keeps_bgr_pixels_and_agent_repeats_png(self):
        from guarddesk.remote_windows import clarity_frame,RemoteAgent
        raw=bytes([0,0,255]*4+[255,0,0]*4)
        with patch('guarddesk.remote_windows.capture_bgr',return_value=(4,2,12,raw)) as capture:
            packet=clarity_frame()
        capture.assert_called_once_with(3840,3840,max_pixels=3840*2160)
        decoded=decode_frame(packet,high_resolution=True)
        try:self.assertEqual(decoded.getpixel((0,0)),(255,0,0));self.assertEqual(decoded.getpixel((0,1)),(0,0,255))
        finally:decoded.close()
        actions=[]
        class Agent:
            def call(self,path,body,**kwargs):
                actions.append(body['action'])
                return {'status':'closed' if body['action']=='repeat_frame' else 'active'}
        agent=RemoteAgent(Agent(),threading.Event());agent.show_indicator=lambda s:None;agent.close_indicator=lambda:None
        with patch('guarddesk.remote_windows.clarity_frame',return_value=packet),patch('guarddesk.remote_windows.Input'):
            agent.assist({'id':'fixture','viewer':'desktop','mode':'view','quality':'clarity'})
        self.assertEqual(actions,['frame','repeat_frame','stop'])


class ClarityAPITest(unittest.TestCase):
    setUp=fixtures.NativeRemoteTest.setUp
    tearDown=fixtures.NativeRemoteTest.tearDown
    prepare=fixtures.NativeRemoteTest.prepare
    api=fixtures.NativeRemoteTest.api

    def test_capability_consent_large_frame_and_native_engine(self):
        client,agent,did=self.prepare(protocol=2)
        self.assertEqual(client.catalog()['clarity_protocol'],3)
        with self.assertRaises(RemoteClientError):client.request(did,'view','needs protocol 3','clarity')
        agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
        session=client.request(did,'view','native pixels','clarity');sid=session['id']
        with Image.effect_noise((1920,1080),90).convert('RGB') as image:packet=encode_clarity(image)
        self.assertGreater(len(packet.get('jpeg',packet.get('png',''))),1048576)
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':packet})
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':packet})
        engine=ViewerEngine(client,session);engine.start()
        try:
            import time
            deadline=time.monotonic()+4;received=None
            while time.monotonic()<deadline:
                update,error=engine.take();self.assertIsNone(error)
                if update and update[1] is not None:received=update[1];break
                time.sleep(.02)
            self.assertIsNotNone(received);self.assertEqual(received.size,(1920,1080));received.close()
            self.assertEqual(engine.stats['codec'],'JPEG 壓縮')
            with Image.new('RGB',(3840,2160),'#123456') as image:packet=encode_clarity(image)
            agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':packet})
            deadline=time.monotonic()+4;received=None
            while time.monotonic()<deadline:
                update,error=engine.take();self.assertIsNone(error)
                if update and update[1] is not None:
                    received=update[1]
                    if received.size==(3840,2160):break
                    received.close();received=None
                time.sleep(.02)
            self.assertIsNotNone(received);self.assertEqual(received.getpixel((100,100)),(18,52,86));received.close()
            self.assertEqual(engine.stats['codec'],'PNG 無損')
        finally:engine.stop();self.assertTrue(engine.closed.wait(5))

    def test_only_desktop_clarity_session_can_send_4k(self):
        client,agent,did=self.prepare(protocol=3)
        session=client.request(did,'view','balanced compatibility');sid=session['id']
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
        with Image.new('RGB',(3840,2160),'white') as image:packet=encode_clarity(image)
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':packet})
        client.call('/api/remote/stop',{'session_id':sid})
        with self.assertRaises(RemoteClientError):
            client.call('/api/remote/request',{'device_id':did,'mode':'view','reason':'browser budget','viewer':'browser','quality':'clarity'})
