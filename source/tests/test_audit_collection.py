"""Collection boundaries using synthetic events, a local DB and no listening server."""
import copy
import time
import unittest
from unittest.mock import patch

from guarddesk import audit_collection
from guarddesk.browser_host import handle_message
from guarddesk.policy import DEFAULT_POLICY, agent_policy_wire, decode_agent_policy, validate_policy_edit
from guarddesk.server import Handler
from guarddesk.store import Store, canonical, digest
import test_policy_defaults as fixtures
import test_web_upload as uploads


class CollectionPolicyTest(unittest.TestCase):
    def test_console_editor_and_domain_table(self):
        import shutil
        import subprocess
        from pathlib import Path
        node = shutil.which('node')
        self.assertIsNotNone(node)
        run = subprocess.run([node, str(Path(__file__).with_suffix('.cjs'))], capture_output=True,
                             text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_all_combinations_roundtrip_with_strict_legacy_body_and_scopes(self):
        for visits in (True, False):
            for mode in ('follow', 'enabled', 'disabled'):
                body = dict(DEFAULT_POLICY, browser_audit=visits, browser_upload_mode=mode)
                wire = agent_policy_wire({'body': body, 'user_policies': {'org\\mis': {'body': body}}})
                self.assertFalse(set(wire['body']) & audit_collection.FIELDS.keys())
                self.assertEqual(wire['body']['browser_audit'], visits and audit_collection.uploads_enabled(body))
                result = decode_agent_policy(wire)
                self.assertEqual(result['body'], body)
                self.assertEqual(result['user_policies']['org\\mis']['body'], body)
        legacy = {k:v for k,v in DEFAULT_POLICY.items() if k not in audit_collection.FIELDS}
        current = dict(DEFAULT_POLICY, browser_upload_mode='disabled', application_stop_mode='selected')
        self.assertEqual(validate_policy_edit(legacy, current), current)
        broken = copy.deepcopy(wire)
        broken['collection_options']['browser_visit_detail'] = 'unknown'
        with self.assertRaises(ValueError):
            decode_agent_policy(broken)

    def test_pending_gap_survives_policy_change_without_old_url(self):
        body = dict(DEFAULT_POLICY, browser_audit=False, browser_upload_mode='disabled')
        details = {'reason':'queue_capacity','lost_count':3,'url':'https://example.test/private'}
        self.assertEqual(audit_collection.browser_details('web.upload_gap',details,body),
                         {'reason':'queue_capacity','lost_count':3})
        self.assertIsNone(audit_collection.browser_details('web.upload_response',details,body))

    def test_stop_selection_keeps_starts_and_warnings(self):
        body = dict(DEFAULT_POLICY, application_stop_mode='selected', application_stop_programs=[r'C:\Tools\editor.exe'])
        for kind, severity, image, excluded in [
                ('application.started','info',r'C:\Other\editor.exe',False),
                ('application.stopped','info',r'C:\Tools\editor.exe',False),
                ('application.stopped','info',r'C:\Other\editor.exe',True),
                ('application.stopped','warning',r'C:\Other\editor.exe',False),
                ('application.blocked','critical',r'C:\Other\editor.exe',False)]:
            self.assertEqual(audit_collection.excluded_stop(kind, severity, {'process':image}, body), excluded)


class UploadIsolationTest(unittest.TestCase):
    setUp = uploads.WebUploadTest.setUp
    tearDown = uploads.WebUploadTest.tearDown
    message = uploads.WebUploadTest.message

    def test_existing_extension_can_upload_with_browsing_off_and_the_reverse(self):
        for visits, mode, expected in [(False, 'enabled', True), (True, 'disabled', False)]:
            body = dict(DEFAULT_POLICY, browser_audit=visits, browser_upload_mode=mode)
            with patch.object(self.agent, 'policy_for_user', return_value={'body': body}):
                status = handle_message(self.agent, {'type':'status'})
                self.assertTrue(status['browser_audit'])  # transport gate in extension 0.5.1
                self.assertEqual(status['web_upload_audit'], expected)
                self.assertEqual(handle_message(self.agent, self.message())['recorded'], expected)


class IngestionTest(unittest.TestCase):
    setUp = fixtures.PolicyDefaultsTest.setUp

    def test_legacy_replay_scoped_browser_filters_and_intact_hash_chain(self):
        handler = Handler.__new__(Handler)
        handler.headers = {'Authorization':'Bearer test-data'}
        now = time.time()
        def event(eid, kind, user):
            return {'event_id':eid,'kind':kind,'severity':'info','occurred':now,
                    'details':{'user':user,'url':'https://example.test/case?q=customer','title':'private'}}
        with self.store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                       ('owned',digest('test-data'),'Owned','test',now))
            override = canonical({'browser_audit':False,'browser_upload_mode':'enabled'})
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('quiet','Quiet','',1,1,0,?,?,'tester','[]')", (override,now))
            db.execute("INSERT INTO policy_assignments VALUES ('quiet','quiet','user',?,100,1,1,?,'tester')", ('org\\quiet',now))
            batch = [event('visit','web.navigation','ORG\\normal'),event('skip','web.navigation','ORG\\quiet'),
                     event('upload','web.upload_response','ORG\\quiet'), event('gap','agent.audit_gap','ORG\\quiet')]
            for _ in range(2):
                reply,_,_ = handler.route(db,'POST','/api/agent/events',{'events':batch})
                self.assertEqual(reply['accepted'], [e['event_id'] for e in batch])
            import json
            rows = {r[0]:json.loads(r[1]) for r in db.execute("SELECT event_id,details FROM events WHERE device_id='owned'")}
            self.assertEqual(set(rows), {'visit','upload','gap'})
            self.assertEqual(rows['visit'], {'domain':'example.test','user':'ORG\\normal'})
            self.assertEqual(rows['upload'], batch[2]['details'])
        self.assertTrue(self.store.verify()['valid'])
