"""Owned DBs only: initial defaults, once-only upgrade, overrides and removal."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from guarddesk.store import Store, canonical
from guarddesk.policy import DEFAULT_POLICY, decode_agent_policy
from guarddesk.policy_defaults import ROAMING, APPLICATIONS, MARKER, server_policy
from guarddesk.management import ControlPlane
from guarddesk.application_exclusions import excluded_application
from guarddesk.file_exclusions import excluded_activity


class PolicyDefaultsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'control.sqlite3';self.store=Store(self.path)

    def legacy(self,body=None):
        body=copy.deepcopy(DEFAULT_POLICY if body is None else body)
        with self.store.connect() as db:
            db.execute('DELETE FROM control_meta WHERE key=?',(MARKER,))
            db.execute('UPDATE policies SET body=? WHERE version=1',(canonical(body),))
        return body

    def test_new_center_has_explicit_defaults_without_changing_legacy_decode(self):
        with self.store.connect() as db:body=Store.policy(db)['body']
        self.assertEqual(body['file_audit']['exclude_paths'],[ROAMING])
        self.assertEqual(body['application_audit_exclusions'],list(APPLICATIONS))
        self.assertEqual(decode_agent_policy({'body':{}})['body']['application_audit_exclusions'],[])
        self.assertEqual(decode_agent_policy({'body':{}})['body']['file_audit']['exclude_paths'],[])
        self.assertEqual(DEFAULT_POLICY['file_audit']['exclude_paths'],[])
        first=server_policy();first['file_audit']['exclude_paths'].clear()
        self.assertEqual(server_policy()['file_audit']['exclude_paths'],[ROAMING])

    def test_upgrade_merges_once_preserves_custom_rules_versions_and_event_hashes(self):
        before=copy.deepcopy(DEFAULT_POLICY);before['file_audit']['exclude_paths']=[r'D:\Owned']
        before['application_audit_exclusions']=['custom.exe'];self.legacy(before)
        with self.store.connect() as db:
            Store.event(db,'fixture','file.deleted','info',{'path':r'C:\Owned\keep.docx'},'owned-history')
            old=dict(db.execute("SELECT * FROM events WHERE event_id='owned-history'").fetchone())
        Store(self.path);Store(self.path)
        with self.store.connect() as db:
            current=Store.policy(db)
            self.assertEqual(current['version'],2)
            self.assertEqual(json.loads(db.execute('SELECT body FROM policies WHERE version=1').fetchone()[0]),before)
            self.assertEqual(current['body']['file_audit']['exclude_paths'],[r'D:\Owned',ROAMING])
            self.assertEqual(current['body']['application_audit_exclusions'],['custom.exe',*APPLICATIONS])
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='owned-history'").fetchone()),old)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='policy.published'").fetchone()[0],1)
        self.assertTrue(self.store.verify()['valid'])

    def test_case_variants_not_duplicated_and_explicit_clear_survives_restart(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['file_audit']['exclude_paths']=[ROAMING.upper()]
        body['application_audit_exclusions']=['CONHOST.EXE','DOCKER.EXE'];self.legacy(body)
        Store(self.path)
        with self.store.connect() as db:
            self.assertEqual(Store.policy(db)['version'],1)
            self.assertEqual(Store.policy(db)['body']['file_audit']['exclude_paths'],[ROAMING.upper()])
            db.execute('UPDATE policies SET body=? WHERE version=1',(canonical(DEFAULT_POLICY),))
        Store(self.path)
        with self.store.connect() as db:self.assertEqual(Store.policy(db)['body'],DEFAULT_POLICY)

    def test_rule_limit_keeps_custom_rules_and_records_skipped_field(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=[f'owned{i}.exe' for i in range(100)]
        self.legacy(body);Store(self.path)
        with self.store.connect() as db:
            updated=Store.policy(db)['body']
            self.assertEqual(updated['application_audit_exclusions'],body['application_audit_exclusions'])
            self.assertEqual(updated['file_audit']['exclude_paths'],[ROAMING])
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='policy.defaults_skipped'").fetchone()[0],1)

    def test_existing_scoped_override_is_preserved(self):
        self.legacy()
        with self.store.connect() as db:
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('owned','Owned','',1,1,0,?,?,?,?)",(canonical({'application_audit_exclusions':[]}),time.time(),'fixture','[]'))
            db.execute("INSERT INTO policy_assignments VALUES ('owned','owned','global','',100,1,1,?,'fixture')",(time.time(),))
        Store(self.path)
        with self.store.connect() as db:
            self.assertEqual(Store.policy(db)['body']['application_audit_exclusions'],list(APPLICATIONS))
            self.assertEqual(ControlPlane(db).resolve({'id':'fixture','group_id':None})['body']['application_audit_exclusions'],[])

    def test_overflow_in_empty_group_append_preserves_complete_old_baseline(self):
        old=self.legacy()
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('empty','Empty',NULL,1,?)",(time.time(),))
            operation=[{'path':'application_audit_exclusions','op':'append','value':[f'owned{i}.exe' for i in range(100)]}]
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('owned','Owned','',1,1,0,'{}',?,'fixture',?)",(time.time(),canonical(operation)))
            db.execute("INSERT INTO policy_assignments VALUES ('owned','owned','group','empty',100,1,1,?,'fixture')",(time.time(),))
        Store(self.path)
        with self.store.connect() as db:
            self.assertEqual(Store.policy(db)['body'],old)
            self.assertEqual(Store.policy(db)['version'],1)
            self.assertEqual(db.execute("SELECT value FROM control_meta WHERE key='generation'").fetchone()[0],1)
            self.assertEqual(db.execute('SELECT value FROM control_meta WHERE key=?',(MARKER,)).fetchone()[0],1)

    def test_exclusions_are_exact_and_keep_crossings_alerts_and_other_users_data(self):
        self.assertTrue(excluded_activity('file.created',{'path':r'C:\Users\林小姐\AppData\Roaming\Owned\a.log'},[ROAMING]))
        self.assertFalse(excluded_activity('file.created',{'path':r'C:\Users\林小姐\Documents\a.docx'},[ROAMING]))
        self.assertFalse(excluded_activity('agent.audit_gap',{'path':r'C:\Users\dev\AppData\Roaming\a'},[ROAMING]))
        self.assertFalse(excluded_activity('file.moved',{'source_path':r'C:\Users\dev\AppData\Roaming\a','destination_path':r'C:\Users\dev\Documents\a'},[ROAMING]))
        for name in APPLICATIONS:
            self.assertTrue(excluded_application('application.started','info',{'process':name},list(APPLICATIONS)))
            self.assertFalse(excluded_application('application.blocked','warning',{'process':name},list(APPLICATIONS)))


if __name__=='__main__':unittest.main()
