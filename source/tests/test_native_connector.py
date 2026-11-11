import json
import threading
import time
import unittest
from unittest.mock import patch

import test_file_handoff as fixtures
import test_file_handoff_center as center_fixtures
from guarddesk import audit_sort
from guarddesk.native_connector import (BrowserPeer, ConnectorInbox, MAX_INBOX,
    _blob as blob, _integer as number, _fields, request_envelope, attachment_details)


def integer(field,value):
    return number(field*8)+number(value)


def message(*, token='own-token', path=r'C:\Owned\report.txt',
            url='https://receiver.example.test/upload?token=DO_NOT_RETAIN#secret',
            reason=2, expiry=None, extra=b'', connector=2, action='own-action', count=1):
    meta=blob(1,url.encode())+blob(5,b'private-email')+blob(9,b'private-tab-title')
    request=(blob(5,token.encode())+integer(9,connector)+blob(10,meta)+blob(14,path.encode())+
             integer(15,int(time.time()+300) if expiry is None else expiry)+integer(19,reason)+extra)
    if action is not None:request+=blob(16,action.encode())
    if count is not None:request+=integer(17,count)
    return blob(1,request)


def peer(**changes):
    return BrowserPeer(**{'pid':100,'created_filetime':133000000000000000,'session':2,
        'image':r'C:\Program Files\Google\Chrome\Application\chrome.exe',**changes})


def normalized(**changes):
    request,_=request_envelope(message(**changes))
    return attachment_details(request,peer())


class ConnectorMetadataTest(unittest.TestCase):
    def test_same_request_path_origin_identity_and_no_content_io(self):
        with patch('builtins.open',side_effect=AssertionError('No file contents')):
            details,occurred,eid=normalized()
            again=normalized()
        self.assertEqual(details['source_path'],r'C:\Owned\report.txt')
        self.assertEqual(details['site_origin'],'https://receiver.example.test')
        self.assertEqual(details['evidence'],'browser_file_attached')
        self.assertEqual(details['network_transfer'],'not_observed')
        self.assertEqual(details['application_success'],'unknown')
        self.assertEqual(details['time_evidence'],'connector_received')
        self.assertEqual(details['origin_role'],'attachment_page')
        self.assertEqual(again[2],eid)
        self.assertNotEqual(normalized(token='next')[2],eid)
        self.assertTrue(time.time()-2<occurred<=time.time())
        raw=json.dumps(details)
        for forbidden in ['DO_NOT_RETAIN','private-email','private-tab-title','own-token','own-action','upload?']:
            self.assertNotIn(forbidden,raw)
        for key in ['file_index','file_count','drop_effect','thread_id','url']:
            self.assertNotIn(key,details)

    def test_pid_reuse_changes_identity_and_action_groups_files_without_guessing_order(self):
        request,_=request_envelope(message())
        first=attachment_details(request,peer())
        reused=attachment_details(request,peer(created_filetime=133000000000000001))
        self.assertNotEqual(first[2],reused[2])
        self.assertNotEqual(first[0]['handoff_id'],reused[0]['handoff_id'])
        other=normalized(token='file-two',path=r'C:\Owned\other.txt',count=2)
        self.assertNotEqual(first[2],other[2])
        self.assertEqual(first[0]['handoff_id'],other[0]['handoff_id'])
        self.assertEqual(other[0]['action_file_count'],2)
        ungrouped,_=request_envelope(message(action=None))
        original=attachment_details(ungrouped,peer())
        reused=attachment_details(ungrouped,peer(created_filetime=133000000000000001))
        self.assertNotEqual(original[0]['handoff_id'],reused[0]['handoff_id'])

    def test_file_picker_paste_and_ipv6_origin(self):
        self.assertEqual(normalized(reason=3)[0]['action'],'file_picker')
        self.assertEqual(normalized(reason=1)[0]['action'],'file_paste')
        self.assertEqual(normalized(url='https://[::1]:444/private?a=secret')[0]['site_origin'],'https://[::1]:444')
        self.assertEqual(normalized(action=None,count=None)[0]['action'],'drag_and_drop')

    def test_reject_stale_content_ambiguous_source_and_wrong_operation(self):
        cases=[{'expiry':int(time.time()-10)},{'expiry':int(time.time()+4000)},
            {'connector':1},{'reason':0},{'reason':99},{'count':0},{'count':10001},
            {'path':r'C:\fakepath\x.txt'},{'path':r'C:\Owned\..\x.txt'},
            {'path':r'C:\Owned\report.txt:secret'},{'path':r'\\?\C:\Owned\x.txt'},
            {'path':'relative.txt'},{'path':r'\\server\share\x.txt'},
            {'url':'https://user:password@example.test/a'},
            {'url':'https://example.test\\@other.test'},
            {'url':'file:///C:/Owned'},{'url':'https://example.test:99999'},
            {'extra':blob(13,b'Never copy clipboard text')},{'extra':blob(18,b'print handle')},
            {'extra':blob(14,b'C:\\Other\\different.txt')},
            {'token':''},{'url':'https://example.test/\nsecret'}]
        for case in cases:
            with self.subTest(case=case),self.assertRaises((ValueError,UnicodeError)):
                normalized(**case)

    def test_transport_identity_is_separate_from_request_and_test_scope_is_mandatory(self):
        request,_=request_envelope(message(extra=blob(100,b'pretend trusted identity')))
        for change in [{'pid':True},{'pid':4},{'created_filetime':0},{'session':0},
                       {'image':r'C:\Owned\other.exe'},{'scope':'production'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                attachment_details(request,peer(**change))

    def test_ack_cancel_and_malformed_wire_never_create_attachment(self):
        self.assertEqual(request_envelope(blob(2,b'ack')),(None,None))
        self.assertEqual(request_envelope(blob(3,b'cancel')),(None,None))
        invalid=[b'',b'\x80',b'\x00',b'\x0b',b'\x0a\x7fX',b'\x08'+b'\xff'*10,
                 b'\x08\x01'*257,b'x'*32769,message()+blob(2,b'ack'),message()+message()]
        for raw in invalid:
            with self.subTest(raw=raw[:12]),self.assertRaises(ValueError):
                request_envelope(raw)

    def test_reply_is_allow_only_and_url_validation_does_not_wait_for_database(self):
        request,reply=request_envelope(message(url='file:///invalid'))
        inner=_fields(_fields(reply)[1][0][1].tobytes())
        self.assertEqual(inner[1][0][1].tobytes(),b'own-token')
        verdict=_fields(inner[4][0][1].tobytes())
        self.assertEqual(verdict[2],[(0,1)])
        self.assertNotIn(3,verdict)  # No block/warn rule.
        with self.assertRaises(ValueError):attachment_details(request,peer())


class ConnectorQueueTest(unittest.TestCase):
    setUp=fixtures.HandoffQueueTest.setUp
    tearDown=fixtures.HandoffQueueTest.tearDown
    policy=fixtures.HandoffQueueTest.policy
    rows=fixtures.HandoffQueueTest.rows
    def test_connector_respects_policy_and_path_exclusions_off_ipc(self):
        inbox=ConnectorInbox()
        value=normalized()
        with patch.object(self.agent,'db',side_effect=AssertionError('No DB in IPC admission')):
            self.assertTrue(inbox.offer(value))
        inbox.drain(self.queue)
        self.policy(False)
        self.queue.flush()
        self.assertFalse(self.rows())
        self.policy(True)
        inbox.offer(normalized(token='excluded',path=r'C:\Owned\excluded\x.txt'))
        inbox.offer(normalized(token='outside',path=r'C:\Other\x.txt'))
        inbox.offer(value)
        inbox.drain(self.queue)
        self.queue.flush()
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.rows()[0]['event_id'],value[2])

    def test_connector_replay_survives_worker_restart(self):
        value=normalized()
        self.queue.add_connector(value)
        self.queue.flush()
        restarted=fixtures.HandoffQueue(self.agent,experimental=True)
        restarted.add_connector(value)
        restarted.add_connector(normalized(token='new-drop'))
        restarted.flush()
        self.assertEqual(len(self.rows()),2)

    def test_full_or_contended_inbox_has_bounded_memory_and_persistent_gap(self):
        inbox=ConnectorInbox()
        for i in range(MAX_INBOX+2):
            inbox.offer(normalized(token=str(i)))
        with inbox._lock:
            self.assertFalse(inbox.offer(normalized(token='contention')))
        stats=inbox.drain(self.queue)
        self.assertEqual(stats,{'received':MAX_INBOX,'lost':3})
        self.assertEqual(inbox.drain(self.queue)['lost'],0)
        self.queue.flush()
        gaps=[r for r in self.rows() if r['kind']=='agent.audit_gap']
        self.assertEqual(gaps[0]['details']['lost_records'],3)

    def test_single_producer_concurrent_drain_accounts_for_every_offer(self):
        inbox=ConnectorInbox()
        value=normalized()
        admitted=lost=0
        class Consumer:
            def gap(self,n):
                nonlocal lost
                lost+=n
            def add_connector(self,v):
                nonlocal admitted
                admitted+=1
        done=threading.Event()
        def produce():
            for _ in range(5000):inbox.offer(value)
            done.set()
        thread=threading.Thread(target=produce)
        thread.start()
        while not done.is_set():inbox.drain(Consumer())
        thread.join()
        inbox.drain(Consumer())
        self.assertEqual(admitted+lost,5000)

    def test_eight_concurrent_session_producers_account_for_all_offers(self):
        inbox=ConnectorInbox()
        value=normalized()
        admitted=lost=0
        class Consumer:
            def gap(self,n):
                nonlocal lost
                lost+=n
            def add_connector(self,v):
                nonlocal admitted
                admitted+=1
        start=threading.Barrier(9)
        def produce():
            start.wait()
            for _ in range(10000):inbox.offer(value)
        threads=[threading.Thread(target=produce) for _ in range(8)]
        for thread in threads:thread.start()
        start.wait()
        while any(thread.is_alive() for thread in threads):inbox.drain(Consumer())
        for thread in threads:thread.join()
        inbox.drain(Consumer())
        self.assertEqual(admitted+lost,80000)


class ConnectorCenterTest(unittest.TestCase):
    setUp=center_fixtures.HandoffCenterTest.setUp
    tearDown=center_fixtures.HandoffCenterTest.tearDown
    api=center_fixtures.HandoffCenterTest.api
    make_agent=center_fixtures.HandoffCenterTest.make_agent

    def test_connector_to_center_document_evidence_replay_and_sort(self):
        from guarddesk.file_handoff import HandoffQueue
        from urllib.parse import urlencode
        agent,did,_=self.make_agent()
        try:
            agent.heartbeat()
            agent.config['audit_watch']=r'C:\Owned'
            queue=HandoffQueue(agent,experimental=True)
            value=normalized()
            queue.add_connector(value)
            queue.flush()
            agent.flush()
            queue.add_connector(value)
            queue.flush()
            agent.flush()
            rows=self.api('/api/events?'+urlencode({'device':did,'category':'documents','kind':'file.web_handoff'}))
            self.assertEqual(rows['total'],1)
            self.assertEqual(rows['items'][0]['details'],value[0])
            self.assertEqual(audit_sort.keys(json.dumps(value[0]))[2],value[0]['site_origin'])
            self.assertEqual(self.api('/api/events?'+urlencode({'device':did,'category':'uploads'}))['total'],0)
        finally:agent.close_collectors()
