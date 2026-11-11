import copy
import tempfile
import unittest
from pathlib import Path
from guarddesk.store import Store,canonical
from guarddesk import category_library as cat
from guarddesk.management import ControlPlane,save_set,generation,ManagementError
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy
from guarddesk.category_rules import domain,member,website,compile_member


def site(host='example.com',sub=True):
    return {'name':host,'type':'domain','domain':host,'include_subdomains':sub,'scheme':'any'}


class CategoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'control.sqlite3')
        self.ctx=self.store.connect();self.db=self.ctx.__enter__()
    def tearDown(self):
        self.ctx.__exit__(None,None,None);self.tmp.cleanup()
    def create(self,name='Cloud',members=None,parent=None,kind='website'):
        return cat.save(self.db,{'kind':kind,'draft':{'name':name,'description':'','parent_id':parent,'members':members if members is not None else [site()]}},'test')
    def publish(self,c,preview=False):
        return cat.publish(self.db,{**c,'expected_generation':generation(self.db)},'test',preview)
    def policy(self,c,use='website_blocked',desc=False):
        overrides={'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}} if use.startswith('website') else {'application_control':{'enabled':True,'mode':'denylist','rules':[],'block_msi':False}}
        return save_set(self.db,{'name':'Block','overrides':overrides,'category_refs':{use:[{'id':c['id'],'include_descendants':desc}]}},'test')
    def resolve(self,p):
        self.db.execute('INSERT INTO policy_assignments(id,set_id,target_type,target_id,priority,enabled,revision,created,actor) VALUES(?,?,\'global\',\'\',100,1,1,1,\'test\')',('a',p['id']))
        return ControlPlane(self.db).resolve({'id':'','group_id':None})
    def test_draft_publish_preview_and_reuse(self):
        c=self.create();before=generation(self.db);r=self.publish(c,True)
        self.assertEqual(r['affected_count'],0);self.assertEqual(generation(self.db),before)
        self.assertEqual(cat.rows(self.db,True),{})
        c=self.publish(c);p=self.policy(c);old=self.resolve(p)
        self.assertEqual(old['body']['website_control']['blocked'],['example.com'])
        draft=cat.rows(self.db)[c['id']]
        changed=cat.save(self.db,{'id':c['id'],'revision':c['revision'],'kind':'website','draft':{k:draft[k] for k in ('name','description','parent_id')}|{'members':[site('new.test')]}},'test')
        self.assertEqual(ControlPlane(self.db).resolve({'id':'','group_id':None})['fingerprint'],old['fingerprint'])
        self.publish(changed)
        new=ControlPlane(self.db).resolve({'id':'','group_id':None})
        self.assertEqual(new['body']['website_control']['blocked'],['new.test']);self.assertNotEqual(new['fingerprint'],old['fingerprint'])
        self.assertEqual(self.db.execute('SELECT count(*) FROM category_versions').fetchone()[0],2)
    def test_descendants_explicit_and_cycle_rejected(self):
        parent=self.publish(self.create(members=[]));child=self.publish(self.create('Child',[site()],parent['id']))
        expanded,_=cat.expand({'website_blocked':[{'id':parent['id'],'include_descendants':False}]},cat.rows(self.db,True));self.assertEqual(expanded['website_blocked'],[])
        expanded,_=cat.expand({'website_blocked':[{'id':parent['id'],'include_descendants':True}]},cat.rows(self.db,True));self.assertEqual(len(expanded['website_blocked']),1)
        with self.assertRaises(ManagementError):cat.save(self.db,{'id':parent['id'],'revision':parent['revision'],'kind':'website','draft':{'name':'Cloud','description':'','members':[],'parent_id':child['id']}},'test')
    def test_stale_generation_revision_duplicate_and_archive_reference(self):
        c=self.publish(self.create());p=self.policy(c)
        with self.assertRaises(ManagementError):cat.publish(self.db,{**c,'expected_generation':0},'test')
        with self.assertRaises(ManagementError):self.create('cloud')
        with self.assertRaises(ManagementError):cat.route(self.db,'POST','/api/categories/archive',c,'test',{})
        with self.assertRaises(ManagementError):self.create('Dup',[site(),site()])
    def test_wire_old_body_and_new_roundtrip(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['website_control'].update(enabled=True,blocked=['.example.com'])
        wire=agent_policy_wire({'body':body})
        self.assertNotIn('website_control',wire['body']);self.assertNotIn('application_publishers',wire['body'])
        self.assertEqual(decode_agent_policy(wire)['body'],body)
        with self.assertRaises(ValueError):decode_agent_policy({**wire,'target_controls':{'format':True}})

    def test_machine_lists_are_not_duplicated_for_32_user_policies(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['website_control'].update(enabled=True,blocked=[f's{i}.example.com' for i in range(1000)])
        packet={'body':body,'user_policies':{f'COMPANY\\u{i}':{'body':copy.deepcopy(body)} for i in range(32)}}
        wire=agent_policy_wire(packet);self.assertLess(len(canonical(wire).encode()),100000)
        decoded=decode_agent_policy(wire)
        self.assertEqual(decoded['body'],body)
        for user in decoded['user_policies'].values():self.assertEqual(user['body'],body)
    def test_website_rules_are_typed_not_substrings(self):
        self.assertEqual(domain('EXAMPLE.COM.'),'example.com')
        self.assertTrue(domain('例子.測試').startswith('xn--'))
        self.assertEqual(compile_member(member('website',site('example.com',False))),'.example.com')
        for bad in ('*dropbox*','*.example.com','https://example.com/a','user:pass@example.com','a..com','127.0.0.1','example.com/path','a.com\n'):
            with self.subTest(bad=bad),self.assertRaises(ValueError):domain(bad)
        with self.assertRaises(ValueError):website({**DEFAULT_POLICY['website_control'],'blocked':['a.com']*1001})
    def test_application_category_compiles_without_enabling_latent_rules(self):
        item={'type':'path','name':'Tool','collection':'Exe','value':r'C:\Tools\tool.exe'}
        c=self.publish(self.create(kind='application',members=[item]));p=self.policy(c,'application_deny');r=self.resolve(p)
        self.assertEqual(r['body']['application_control']['rules'],[item])
        with self.assertRaises(ValueError):member('application',{**item,'value':r'C:\Windows\explorer.exe'})
    def test_reopen_schema_preserves_categories_and_settings(self):
        c=self.publish(self.create());before=self.db.execute('SELECT published FROM categories').fetchone()[0]
        self.db.commit();Store(self.store.path)
        self.assertEqual(self.db.execute('SELECT published FROM categories').fetchone()[0],before)
        self.assertEqual(cat.catalog(self.db,{'id':[c['id']]})['selected']['total'],1)
    def test_publisher_only_and_mixed_rules(self):
        item={'type':'publisher','name':'Tool','collection':'Exe','publisher':'CN=Example','product':'Example Tool','binary':'tool.exe','min_version':'0.0.0.0','max_version':'*'}
        c=self.publish(self.create(kind='application',members=[item]));p=self.policy(c,'application_deny');r=self.resolve(p)
        from guarddesk.custom_software import publisher_xml
        xml=publisher_xml(r['body']['application_control'],r['body']['application_publishers'])
        self.assertIn('Action="Deny"',xml);self.assertIn('Example Tool',xml)
        wire=agent_policy_wire({'body':r['body']})
        self.assertFalse(wire['body']['application_control']['enabled'])
        self.assertTrue(decode_agent_policy(wire)['body']['application_control']['enabled'])
        # Exercise the actual sealed previous decoder, not a guessed legacy
        # field list. Source bytes and archive remain immutable.
        import types,zipfile
        archive=Path(__file__).resolve().parents[1]/'dist/GuardDesk-0.4.59-source.zip'
        if archive.is_file():
            with zipfile.ZipFile(archive) as z:
                key=next(n for n in z.namelist() if n.endswith('guarddesk/policy.py'))
                code=compile(z.read(key),'sealed-0.4.59-policy.py','exec')
        else:
            # The historical ZIP may be removed from the release directory.
            # Use the retained exact old EXE, never substitute current source
            # or manufacture an archive bearing the old release version.
            import hashlib,json
            from PyInstaller.archive.readers import CArchiveReader
            root=Path(__file__).resolve().parents[1]
            exe=root/'runtime/pre0460-build-70e87f8b7966471895d2a6edaf101a63/GuardDesk.exe'
            expected=json.loads((root/'evidence/packaged-smoke-0.4.59.json').read_text(encoding='utf-8'))['exe_sha256']
            self.assertEqual(hashlib.sha256(exe.read_bytes()).hexdigest(),expected)
            pyz=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz')
            metadata={};exec(pyz.extract('guarddesk'),metadata);self.assertEqual(metadata['__version__'],'0.4.59')
            code=pyz.extract('guarddesk.policy')
        legacy=types.ModuleType('guarddesk.category_legacy_policy');legacy.__package__='guarddesk'
        exec(code,legacy.__dict__)
        old=legacy.decode_agent_policy(wire)
        self.assertFalse(old['body']['application_control']['enabled'])

    def test_import_is_all_or_nothing_and_export_is_formula_safe(self):
        from guarddesk.category_rules import import_members,export_members
        imported=import_members('website','example.com\ncloud.test',False)
        self.assertFalse(imported['members'][0]['include_subdomains'])
        roundtrip=import_members('website',export_members(imported['members']))
        self.assertEqual(roundtrip['members'],imported['members'])
        failed=import_members('website','example.com\nhttps://bad.test/path')
        self.assertEqual(failed['members'],[]);self.assertEqual(failed['errors'][0]['line'],2)
        csv=export_members([{**imported['members'][0],'name':'=formula'}])
        self.assertIn("'=formula",csv)
        with self.assertRaises(ValueError):import_members('website','name,type\n"bad,domain')

    def test_specific_child_override_replaces_ancestor_category_targets(self):
        import time
        parent='a'*24;child='b'*24
        self.db.executemany('INSERT INTO endpoint_groups VALUES(?,?,?,1,?)',[(parent,'Parent',None,time.time()),(child,'Child',parent,time.time())])
        c=self.publish(self.create());p=self.policy(c)
        self.db.execute("INSERT INTO policy_assignments VALUES('one',?,'group',?,100,1,1,1,'test')",(p['id'],parent))
        direct=save_set(self.db,{'name':'Child direct','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True,'blocked':['child.test']}}},'test')
        self.db.execute("INSERT INTO policy_assignments VALUES('two',?,'group',?,100,1,1,2,'test')",(direct['id'],child))
        got=ControlPlane(self.db).resolve({'id':'','group_id':child})
        self.assertEqual(got['body']['website_control']['blocked'],['child.test'])

    def test_committed_snapshot_cache_does_not_cache_preview_or_unpublished_edits(self):
        c=self.publish(self.create());p=self.policy(c);self.resolve(p);self.db.commit()
        with self.store.connect() as other:
            before=ControlPlane(other).resolve({'id':'','group_id':None})
        draft=cat.rows(self.db)[c['id']]
        changed=cat.save(self.db,{'id':c['id'],'revision':c['revision'],'kind':'website','draft':{k:draft[k] for k in ('name','description','parent_id')}|{'members':[site('new.test')]}},'test')
        self.publish(changed,True);self.db.commit()
        with self.store.connect() as other:self.assertEqual(ControlPlane(other).resolve({'id':'','group_id':None})['body'],before['body'])
        self.publish(changed);self.db.commit()
        with self.store.connect() as other:self.assertEqual(ControlPlane(other).resolve({'id':'','group_id':None})['body']['website_control']['blocked'],['new.test'])

    def test_warm_heartbeat_does_not_reexpand_all_category_members(self):
        from unittest.mock import patch
        c=self.publish(self.create());p=self.policy(c);self.resolve(p);self.db.commit()
        with patch('guarddesk.category_library.expand',wraps=cat.expand) as expand:
            for _ in range(3):
                with self.store.connect() as other:ControlPlane(other).resolve({'id':'','group_id':None})
            self.assertEqual(expand.call_count,1)

    def test_referenced_glob_republication_rejects_unmapped_and_retains_last_policy(self):
        c=self.publish(self.create(members=[site('*.box.com')]));p=self.policy(c);old=self.resolve(p)
        self.assertEqual(old['body']['website_control']['blocked'],['box.com'])
        changed=cat.save(self.db,{'id':c['id'],'revision':c['revision'],'kind':'website','draft':{'name':'Cloud','description':'','parent_id':None,'members':[site('*.dropbox.*')]}},'test')
        for preview in (True,False):
            with self.subTest(preview=preview),self.assertRaisesRegex(ValueError,'尚未設定實際封鎖網域'):self.publish(changed,preview)
            self.assertEqual(ControlPlane(self.db).resolve({'id':'','group_id':None})['fingerprint'],old['fingerprint'])
            self.assertEqual(cat.rows(self.db,True)[c['id']]['members'][0]['pattern'],'*.box.com')
        self.assertEqual(self.db.execute('SELECT count(*) FROM category_versions').fetchone()[0],1)

    def test_mapped_glob_allowlist_and_original_direct_rules_coexist(self):
        item={'name':'Cloud','type':'host_glob','pattern':'*cloud*','scheme':'https','enforcement_domains':['cloud.example','cloud.test']}
        c=self.publish(self.create(members=[item]));p=self.policy(c,'website_allowed');got=self.resolve(p)['body']['website_control']
        self.assertEqual(got['allowed'],['https://cloud.example','https://cloud.test']);self.assertEqual(got['blocked'],[])


if __name__=='__main__':unittest.main()
