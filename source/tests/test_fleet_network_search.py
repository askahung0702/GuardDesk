"""Authenticated paged fleet search over latest owned inventory, no event history."""
import json
import sqlite3
import time
import unittest
import urllib.error
from urllib.parse import urlencode
from unittest.mock import patch
import test_system
from guarddesk.server import Handler


class FleetNetworkSearchTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api

    def seed(self,count=1):
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('parent','Owned parent',NULL,1,?)",(time.time(),))
            db.execute("INSERT INTO endpoint_groups VALUES ('child','Owned child','parent',1,?)",(time.time(),))
            for i in range(count):
                inventory={'user_accounts':['OWNED\\tester'],'network_addresses':[f'192.0.2.{i+1}','2001:db8::7'],
                    'mac_address':'AA:BB:CC:DD:EE:FF','software':['PRIVATE-INVENTORY-NOT-SEARCHABLE'],'outbox':{'pending':i}}
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory,group_id,last_address) VALUES (?,?,?,?,?,?,?,?)',
                    (f'owned-{i}',f'owned-token-{i}',f'Owned-{i:03d}','Lab',time.time(),json.dumps(inventory),'child','198.51.100.9'))

    def search(self,q,**params):return self.api('/api/fleet?'+urlencode({'q':q,**params}))

    def test_IPv4_full_partial_multiple_and_center_source_address(self):
        self.seed()
        for query in ('192.0.2.1','192.0.2.','198.51.100.9',' 192.0.2.1 '):
            with self.subTest(q=query):self.assertEqual(self.search(query)['total'],1)

    def test_MAC_case_separators_compact_and_partial(self):
        self.seed()
        for query in ('AA:BB:CC:DD:EE:FF','aa-bb-cc-dd-ee-ff','AABBCCDDEEFF','aabb.ccdd.eeff','AA BB CC DD EE FF','bbccdd','BB-CC-DD'):
            with self.subTest(q=query):self.assertEqual(self.search(query)['total'],1)
        self.assertEqual(self.search('001122334455')['total'],0)

    def test_IPv6_case_expanded_and_partial(self):
        self.seed()
        for query in ('2001:DB8::7','2001:0db8:0:0:0:0:0:7','2001:db8:'):
            with self.subTest(q=query):self.assertEqual(self.search(query)['total'],1)
        with self.store.connect() as db:
            db.execute('UPDATE devices SET inventory=?',(json.dumps({'network_addresses':[],'mac_address':'20:01:DB:87:00:00'}),))
        self.assertEqual(self.search('2001:db8::7')['total'],0)

    def test_group_descendants_health_and_revoked_scopes_still_apply(self):
        self.seed(3)
        with self.store.connect() as db:
            db.execute("UPDATE devices SET revoked=1 WHERE id='owned-1'")
            db.execute("UPDATE devices SET last_seen=0 WHERE id='owned-2'")
        self.assertEqual(self.search('aabbccddeeff',group='parent')['total'],2)
        self.assertEqual(self.search('192.0.2.',group='parent',health='offline')['total'],1)
        self.assertEqual(self.search('aabbccddeeff',group='revoked')['total'],1)
        self.assertEqual(self.search('aabbccddeeff',group='unassigned')['total'],0)

    def test_match_applies_before_50_row_pagination(self):
        self.seed(250)
        first=self.search('aabbccddeeff',group='parent',sort='name')
        last=self.search('aabbccddeeff',group='parent',sort='name',offset=200)
        self.assertEqual((first['total'],len(first['items']),len(last['items'])),(250,50,50))
        self.assertFalse({d['id'] for d in first['items']}&{d['id'] for d in last['items']})
        self.assertEqual(self.search('192.0.2.250')['items'][0]['id'],'owned-249')

    def test_legacy_fields_literal_query_and_unrelated_inventory_not_searched(self):
        self.seed()
        for q in ('Owned-000','lab','owned\\TESTER','Owned-000 Lab'):
            with self.subTest(q=q):self.assertEqual(self.search(q)['total'],1)
        for q in ('PRIVATE-INVENTORY-NOT-SEARCHABLE','%','_',"' OR 1=1 --"):
            with self.subTest(q=q):self.assertEqual(self.search(q)['total'],0)

    def test_missing_or_wrong_network_field_types_do_not_break_name_search(self):
        self.seed()
        for assets in ({'user_accounts':[]},{'network_addresses':None,'mac_address':None},
                       {'network_addresses':'192.0.2.1','mac_address':{}},
                       {'network_addresses':[None,{},3],'mac_address':False}):
            with self.store.connect() as db:db.execute('UPDATE devices SET inventory=?',(json.dumps(assets),))
            self.assertEqual(self.search('Owned-000')['total'],1)
            self.assertEqual(self.search('192.0.2.1')['total'],0)

    def test_real_fleet_request_cannot_read_event_history_or_modify_rows(self):
        self.seed();reads=[];original=Handler.route
        def guarded(handler,db,method,path,body):
            if path!='/api/fleet':return original(handler,db,method,path,body)
            def authorize(action,table,column,*args):
                if action==sqlite3.SQLITE_READ:
                    reads.append(table)
                    if table=='events' or table.startswith(('event_','events_')):return sqlite3.SQLITE_DENY
                if action in (sqlite3.SQLITE_INSERT,sqlite3.SQLITE_UPDATE,sqlite3.SQLITE_DELETE):return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorize)
            try:return original(handler,db,method,path,body)
            finally:db.set_authorizer(None)
        with patch.object(Handler,'route',guarded):self.assertEqual(self.search('aabbccddeeff')['total'],1)
        self.assertIn('devices',reads);self.assertNotIn('events',reads)

    def test_unauthenticated_fleet_search_still_rejected(self):
        self.seed();self.api('/api/logout',{})
        with self.assertRaises(urllib.error.HTTPError) as denied:self.search('192.0.2.1')
        self.assertEqual(denied.exception.code,401);denied.exception.close()


if __name__=='__main__':unittest.main()
