"""Reusable bootstrap enrolls independent agents; revoked packages cannot enroll."""
import concurrent.futures
import http.cookiejar
import io
import json
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch
import unittest
import test_system
from test_endpoint_setup import program
from guarddesk.agent import Agent, enroll, request
from guarddesk.server_setup import create
from guarddesk.server_backup import snapshot
from guarddesk.store import Store, digest


class SharedDeploymentTest(unittest.TestCase):
    api=test_system.SystemTest.api
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown

    def package(self):
        if not (self.root/'Endpoint-Connection.zip').exists():
            created=create(self.root/'setup','guarddesk.test','mis','7',exe=sys.executable)
            (self.root/'Endpoint-Connection.zip').write_bytes(Path(created['connection_bundle']).read_bytes())
        if not (self.root/'program').exists(): program(self.root/'program')
        with patch('guarddesk.endpoint_package.application_directory',return_value=self.root/'program/GuardDesk'):
            raw=self.api('/api/endpoint-package',{})
        with zipfile.ZipFile(io.BytesIO(raw)) as z: return json.loads(z.read('endpoint-connection.json'))

    def test_same_embedded_code_multiple_agents_unique_credentials_and_restart(self):
        first=self.package();second=self.package()
        code=first['deployment_code'];self.assertEqual(code,second['deployment_code'])
        agents=[]
        for i in range(2):
            config=self.root/f'agent{i}/config.json'
            enroll(config,self.url,code,self.watch,name=f'endpoint{i}')
            agents.append(Agent(config))
        self.assertNotEqual(agents[0].config['device_id'],agents[1].config['device_id'])
        self.assertNotEqual(agents[0].config['token'],agents[1].config['token'])
        state=self.api('/api/deployment');self.assertEqual(state['code']['uses'],2)
        self.assertNotIn(code,json.dumps(state))
        self.assertNotIn(code,json.dumps(self.api('/api/state')))
        self.assertNotIn(code,json.dumps(self.api('/api/events')))
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT token_hash FROM deployment_codes WHERE revoked=0').fetchone()[0],digest(code))
        self.server.store=Store(self.db)
        self.assertEqual(code,self.package()['deployment_code'])
        with self.assertRaises(ConnectionError):request(self.url,'/api/agent/heartbeat',{},token=code)

    def test_revoke_blocks_old_packages_and_rotation_keeps_registered_agents(self):
        old=self.package()['deployment_code']
        config=self.root/'agent/config.json';enroll(config,self.url,old,self.watch);agent=Agent(config)
        self.api('/api/deployment/revoke',{'confirm':'revoke'})
        self.assertFalse(self.api('/api/deployment')['active'])
        with self.assertRaises(ConnectionError):enroll(self.root/'blocked/config.json',self.url,old,self.watch)
        with self.assertRaises(urllib.error.HTTPError) as denied:self.package()
        self.assertEqual(denied.exception.code,409)
        self.assertFalse(self.api('/api/deployment')['active'])
        agent.heartbeat(refresh_inventory=False)
        self.api('/api/deployment/rotate',{'confirm':'rotate'})
        new=self.package()['deployment_code'];self.assertNotEqual(old,new)
        with self.assertRaises(ConnectionError):enroll(self.root/'old/config.json',self.url,old,self.watch)
        enroll(self.root/'new/config.json',self.url,new,self.watch)
        agent.heartbeat(refresh_inventory=False)

    def test_csrf_role_checks_and_missing_secret_fail_closed(self):
        # A download creates a reusable enrollment capability, so it requires CSRF.
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/endpoint-package',{},csrf=False)
        self.assertEqual(denied.exception.code,403)
        self.assertFalse(self.api('/api/deployment')['created'])
        old=self.package()['deployment_code']
        reader=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        session=self.api('/api/login',{'username':'reader','password':self.password},client=reader)
        for path,body in [('/api/deployment',None),('/api/deployment/revoke',{'confirm':'revoke'}),('/api/deployment/rotate',{'confirm':'rotate'})]:
            with self.assertRaises(urllib.error.HTTPError) as denied:self.api(path,body,client=reader)
            self.assertEqual(denied.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/deployment/rotate',{'confirm':'wrong'})
        (self.root/'deployment/credentials.json').unlink()
        with self.assertRaises(urllib.error.HTTPError) as denied:self.package()
        self.assertEqual(denied.exception.code,409)
        self.assertTrue(self.api('/api/deployment')['active'])
        self.api('/api/deployment/rotate',{'confirm':'rotate'})
        self.assertNotEqual(old,self.package()['deployment_code'])

    def test_parallel_enroll_and_migration_revokes_only_bootstrap(self):
        code=self.package()['deployment_code']
        def register(i):return request(self.url,'/api/agent/enroll',{'token':code,'name':str(i),'department':'fixture'})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor: results=list(executor.map(register,range(4)))
        self.assertEqual(len({r['device_id'] for r in results}),4)
        self.assertEqual(len({r['token'] for r in results}),4)
        self.assertEqual(self.api('/api/deployment')['code']['uses'],4)
        target=self.root/'migration.sqlite3';snapshot(self.db,target,migration=True)
        with Store(target).connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM deployment_codes WHERE revoked=0').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM devices WHERE revoked=0').fetchone()[0],4)
        self.assertTrue(self.api('/api/deployment')['active'])
