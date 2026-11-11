"""All-endpoint defaults with isolated DB/agents; no real desktop access."""
import time
import unittest
import urllib.error
import urllib.request
from guarddesk.agent import Agent,enroll
from guarddesk.remote_client import RemoteClient,RemoteClientError
from guarddesk.store import Store,canonical
import test_native_remote as fixtures


class RemoteAllGrantTest(unittest.TestCase):
    setUp=fixtures.NativeRemoteTest.setUp
    tearDown=fixtures.NativeRemoteTest.tearDown
    api=fixtures.NativeRemoteTest.api

    def support(self,name='helper'):
        self.api('/api/remote/account',{'username':name,'password':self.password})
        client=RemoteClient(self.url);client.login(name,self.password);self.clients.append(client)
        return client

    def endpoint(self,number):
        token=self.api('/api/enrollments',{})['token']
        did=enroll(self.root/('agent-'+str(number))/'config.json',self.url,token,self.watch,name='Fixture-'+str(number))
        agent=Agent(self.root/('agent-'+str(number))/'config.json')
        agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
        return agent,did

    def grant(self,username='helper',did='*',control=True,enabled=True,days=0):
        return self.api('/api/remote/grant',{'username':username,'device_id':did,'can_control':control,'enabled':enabled,'days':days})

    def test_existing_future_endpoints_and_legacy_viewer_catalog_without_db_fanout(self):
        client=self.support();agent,did=self.endpoint(1)
        self.assertEqual(client.catalog()['devices'],[])
        self.grant();agent2,did2=self.endpoint(2)
        catalog=client.catalog();self.assertEqual({d['id'] for d in catalog['devices']},{did,did2})
        self.assertEqual({g['device_id'] for g in catalog['grants']},{did,did2})
        self.assertTrue(all(g['username']=='helper' and g['expires']>time.time() and g['can_control'] for g in catalog['grants']))
        self.assertEqual(catalog['grant_rules'][0]['device_id'],'*');self.assertTrue(catalog['grant_rules'][0]['permanent'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM remote_all_grants').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM remote_grants').fetchone()[0],0)
        for endpoint,target in ((agent,did),(agent2,did2)):
            session=client.request(target,'control','all endpoints default')
            with self.assertRaises(RemoteClientError):client.call('/api/remote/input',{'session_id':session['id'],'actions':[{'type':'move','x':.5,'y':.5}]})
            self.assertEqual(endpoint.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})['session']['status'],'requested')
            client.call('/api/remote/stop',{'session_id':session['id']})

    def test_revoke_global_closes_active_session_and_removes_access(self):
        client=self.support();agent,did=self.endpoint(1);self.grant()
        session=client.request(did,'control','global revoke');sid=session['id']
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'TEST\employee'})
        self.grant(enabled=False)
        state=client.call('/api/remote/session?id='+sid)
        self.assertEqual((state['status'],state['ended_reason']),('closed','permission_revoked'))
        self.assertEqual(client.catalog()['devices'],[]);self.assertNotIn(sid,self.server.remote_memory)
        with self.assertRaises(RemoteClientError):client.request(did,'view','revoked')

    def test_device_rule_overrides_global_and_removal_reverts_to_default(self):
        client=self.support();agent,did=self.endpoint(1);self.grant()
        self.grant(did=did,control=False,days=1)
        grant=client.catalog()['grants'][0];self.assertFalse(grant['can_control']);self.assertEqual(grant['scope'],'device')
        with self.assertRaises(RemoteClientError):client.request(did,'control','individual readonly override')
        session=client.request(did,'view','individual view');client.call('/api/remote/stop',{'session_id':session['id']})
        self.grant(did=did,enabled=False)
        session=client.request(did,'control','falls back to all');client.call('/api/remote/stop',{'session_id':session['id']})
        self.grant(did=did,days=1);self.grant(enabled=False)
        self.assertEqual(client.catalog()['grants'][0]['scope'],'device')
        session=client.request(did,'control','specific grant retained');client.call('/api/remote/stop',{'session_id':session['id']})

    def test_global_readonly_expiry_and_account_role_change(self):
        client=self.support();agent,did=self.endpoint(1);self.grant(control=False,days=1)
        with self.assertRaises(RemoteClientError):client.request(did,'control','readonly default')
        session=client.request(did,'view','expires');sid=session['id']
        with self.store.connect() as db:db.execute('UPDATE remote_all_grants SET expires=?',(time.time()-1,))
        self.assertEqual(client.call('/api/remote/session?id='+sid)['status'],'closed')
        self.assertEqual(client.catalog()['devices'],[])
        self.grant();session=client.request(did,'view','account role removed');sid=session['id']
        with self.store.connect() as db:db.execute("UPDATE users SET role='auditor' WHERE username='helper'")
        self.api('/api/remote/catalog')
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT status FROM remote_sessions WHERE id=?',(sid,)).fetchone()[0],'closed')

    def test_only_admin_can_grant_with_csrf_and_valid_scope_account_days(self):
        client=self.support();agent,did=self.endpoint(1)
        body={'username':'helper','device_id':'*','enabled':True,'can_control':True,'days':0}
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/remote/grant',body,csrf=False)
        self.assertEqual(error.exception.code,403)
        request=urllib.request.Request(self.url+'/api/remote/grant',data=canonical(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':client.csrf})
        with self.assertRaises(urllib.error.HTTPError) as error:client.opener.open(request)
        self.assertEqual(error.exception.code,403)
        for bad in ({**body,'username':'reader'},{**body,'device_id':'missing'},
                    {**body,'days':-1},{**body,'days':31},{**body,'days':True},{**body,'days':'0'},
                    {**body,'device_id':did},{**body,'can_control':1}):
            with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/remote/grant',bad)
            self.assertEqual(error.exception.code,400)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM remote_all_grants').fetchone()[0],0)

    def test_support_scoped_catalog_revoked_endpoint_and_persisted_grants(self):
        client=self.support();other=self.support('other-helper');agent,did=self.endpoint(1);self.grant()
        self.assertEqual(other.catalog()['devices'],[]);self.assertEqual(other.catalog()['grant_rules'],[])
        # Re-open/migrate the existing database, without defaulting every user to broad rights.
        reopened=Store(self.store.path)
        with reopened.connect() as db:
            self.assertEqual(db.execute('SELECT username FROM remote_all_grants').fetchone()[0],'helper')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
        with self.store.connect() as db:db.execute('UPDATE devices SET revoked=1 WHERE id=?',(did,))
        self.assertEqual(client.catalog()['devices'],[])
        with self.assertRaises(RemoteClientError):client.request(did,'view','revoked endpoint')
        with self.store.connect() as db:
            events=[r['details'] for r in db.execute("SELECT details FROM events WHERE kind='remote.permission_changed'")]
        self.assertTrue(any('"scope":"all"' in event for event in events))
