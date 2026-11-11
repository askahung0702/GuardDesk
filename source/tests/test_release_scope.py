"""Server-only versions must not become endpoint jobs, including existing 68 rows."""
import json
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch
import test_updates
from guarddesk import __version__,release_scope,bundled_release
from guarddesk.store import canonical


class ReleaseScopeTest(unittest.TestCase):
    setUp=test_updates.UpdateServerTest.setUp;tearDown=test_updates.UpdateServerTest.tearDown
    api=test_updates.UpdateServerTest.api;make_agent=test_updates.UpdateServerTest.make_agent
    upload=test_updates.UpdateServerTest.upload;prepare=test_updates.UpdateServerTest.prepare
    def test_known_server_only_68_cannot_be_imported_as_Agent(self):
        with self.assertRaises(urllib.error.HTTPError) as denied:self.upload(test_updates.release(self.root/'server-only.zip','0.4.68'))
        self.assertEqual(denied.exception.code,409);denied.exception.close()
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM update_jobs').fetchone()[0],0)

    def test_existing_server_only_row_is_history_not_latest_or_deployable(self):
        info,agent,did,jid=self.prepare()
        with self.store.connect() as db:
            old=db.execute('SELECT envelope FROM update_releases WHERE id=?',(info['id'],)).fetchone()[0]
            db.execute('INSERT INTO update_releases VALUES (?,?,?,?,?)',('f'*64,'0.4.68',old,time.time(),'legacy'))
        catalog=self.api('/api/updates')
        self.assertEqual(catalog['latest_release_id'],info['id'])
        legacy=next(r for r in catalog['releases'] if r['version']=='0.4.68')
        self.assertEqual(legacy['deployment']['scope'],'server_only')
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/jobs',{'release_id':'f'*64,'device_ids':[did],'confirm':'deploy'})
        self.assertEqual(denied.exception.code,409);denied.exception.close()
        self.assertTrue(any(job['id']==jid for job in self.api('/api/updates')['jobs']))

    def test_new_endpoint_release_blocks_legacy_batch_and_requires_explicit_single_pilot(self):
        info=self.upload(test_updates.release(self.root/'new.zip',__version__))
        first,did,_=self.make_agent();second,did2,_=self.make_agent()
        first.call('/api/agent/updates/poll',{'role':'native','version':'0.4.66','broker_version':'0.4.66'})
        base={'release_id':info['id'],'device_ids':[did],'confirm':'deploy'}
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/jobs',base)
        self.assertEqual(denied.exception.code,409);denied.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/jobs',{**base,'device_ids':[did,did2],'legacy_preflight_confirmed':True})
        self.assertEqual(denied.exception.code,409);denied.exception.close()
        result=self.api('/api/updates/jobs',{**base,'legacy_preflight_confirmed':True})
        self.assertEqual(len(result['job_ids']),1)
        with self.store.connect() as db:
            detail=json.loads(db.execute("SELECT details FROM events WHERE kind='update.scheduled' ORDER BY received DESC LIMIT 1").fetchone()[0])
        self.assertTrue(detail['legacy_preflight_operator_attested'])

    def test_fresh_current_updater_does_not_need_manual_attestation(self):
        info=self.upload(test_updates.release(self.root/'new.zip',__version__));agent,did,_=self.make_agent()
        agent.call('/api/agent/updates/poll',{'role':'native','version':__version__,'broker_version':__version__})
        self.assertEqual(len(self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy'})['job_ids']),1)

    def test_server_only_publisher_does_not_compress_or_register_Agent(self):
        publisher=bundled_release.Publisher(self.store,threading.Lock());publisher.source=self.root
        with patch.object(release_scope,'CURRENT_SCOPE','server_only'),patch.object(bundled_release,'prepare',side_effect=AssertionError('must not prepare Agent')),patch('guarddesk.browser_auto_publication.ensure',return_value={}):
            publisher.work()
        self.assertEqual(publisher.snapshot()['status'],'server_only')
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM update_releases').fetchone()[0],0)

    def test_invalid_scope_cannot_hide_endpoint_components(self):
        profile=release_scope.profile(__version__)
        for bad in ({**profile,'scope':'server_only'},{**profile,'components':[{}]}, {**profile,'required_updater':'bad'}):
            with self.subTest(body=bad),self.assertRaises(ValueError):release_scope.validate(bad,__version__)

    def test_legacy_68_inflight_native_can_finish_and_main_is_not_stranded(self):
        original=release_scope.profile
        def old_profile(version,stored=None):
            value=original(version,stored)
            return {**value,'scope':'endpoint','components':list(release_scope.COMPONENTS)} if version=='0.4.68' else value
        with patch.object(release_scope,'profile',side_effect=old_profile):
            info=self.upload(test_updates.release(self.root/'legacy.zip','0.4.68'));agent,did,_=self.make_agent()
            jid=self.api('/api/updates/jobs',{'release_id':info['id'],'device_ids':[did],'confirm':'deploy'})['job_ids'][0]
        self.assertEqual(agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.66'})['waiting_for'],'server_only_release_not_required')
        with self.store.connect() as db:db.execute("UPDATE update_status SET state='downloading' WHERE job_id=? AND role='native'",(jid,))
        self.assertIsNotNone(agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.66'})['job'])
        agent.call('/api/agent/updates/status',{'job_id':jid,'role':'native','state':'healthy','version':'0.4.68'})
        self.assertIsNotNone(agent.call('/api/agent/updates/poll',{'role':'main','version':'0.4.66'})['job'])
        agent.call('/api/agent/updates/status',{'job_id':jid,'role':'main','state':'healthy','version':'0.4.68'})
        self.assertEqual(self.api('/api/updates')['jobs'][0]['status'],'completed')
