import copy
import json
import unittest
import urllib.error
import test_system
import test_management
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.policy_operations import validate_operations


class PolicyOperationsTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    assign=test_management.ManagementTest.assign
    detail=test_management.ManagementTest.detail
    group=test_management.ManagementTest.group
    move=test_management.ManagementTest.move
    policy=test_management.ManagementTest.policy

    def create(self,name,operations):
        return self.api('/api/policy-sets',{'name':name,'overrides':{},'operations':operations})

    def test_append_retains_parent_and_unrelated_settings_and_legacy_wire(self):
        agent,did,_=self.make_agent();g=self.group('team');self.move(did,g['id'])
        parent=self.policy('parent',{'file_audit':{'enabled':False,'scope':'managed','exclude_paths':[r'C:\Parent']}})
        self.assign(parent,'group',g['id'])
        child=self.create('child',[{'path':'file_audit.exclude_paths','op':'append','value':[r'C:\Child',r'c:\parent']}])
        self.assign(child,'device',did)
        effective=self.detail(did)['effective_policy']
        self.assertEqual(effective['body']['file_audit'],{'enabled':False,'scope':'managed','exclude_paths':[r'C:\Parent',r'C:\Child']})
        self.assertEqual(effective['setting_sources']['file_audit.scope']['name'],'parent')
        self.assertEqual(effective['setting_sources']['file_audit.exclude_paths']['operation'],'append')
        self.assertEqual(agent.heartbeat()['body']['file_audit'],effective['body']['file_audit'])

    def test_clear_is_different_from_inherit_and_history_keeps_operations(self):
        _,did,_=self.make_agent()
        parent=self.policy('base',{'application_audit_exclusions':['docker.exe']});self.assign(parent,'global')
        p=self.create('clear',[{'path':'application_audit_exclusions','op':'set','value':[]}]);self.assign(p,'device',did)
        self.assertEqual(self.detail(did)['effective_policy']['body']['application_audit_exclusions'],[])
        versions=self.api('/api/policy-sets/history?id='+p['id'])['items']
        self.assertEqual(versions[0]['operations'][0]['value'],[])

    def test_assignment_and_edit_preview_are_nonmutating_with_actual_diff(self):
        _,did,_=self.make_agent();p=self.create('usb',[{'path':'usb_mode','op':'set','value':'read_only'}])
        body={'set_id':p['id'],'target_type':'device','target_id':did,'priority':100,'enabled':True}
        before=self.api('/api/state');preview=self.api('/api/assignments/preview',body)
        delta=preview['items'][0]['changes'][0]
        self.assertEqual((delta['path'],delta['before'],delta['after']),('usb_mode','allow','read_only'))
        self.assertEqual(self.api('/api/state')['generation'],before['generation'])
        self.assign(p,'device',did)
        draft={'id':p['id'],'revision':1,'name':'usb','overrides':{},'operations':[{'path':'usb_mode','op':'set','value':'block'}]}
        preview=self.api('/api/policy-sets/preview',draft)
        self.assertEqual(preview['items'][0]['changes'][0]['after'],'block')
        self.assertEqual(self.detail(did)['effective_policy']['body']['usb_mode'],'read_only')
        self.group('change generation')
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/policy-sets',{**draft,'expected_generation':preview['generation']})
        self.assertEqual(e.exception.code,409);e.exception.close()

    def test_invalid_paths_types_personal_scope_and_append_bounds(self):
        for value in [[{'path':'__class__','op':'set','value':True}], [{'path':'usb_mode','op':'append','value':[]}], [{'path':'file_audit.enabled','op':'set','value':1}]]:
            with self.assertRaises(ValueError):validate_operations(value)
        p=self.create('machine',[{'path':'file_audit.enabled','op':'set','value':False}])
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/assignments/preview',{'set_id':p['id'],'target_type':'user','target_id':r'LAB\person'})
        self.assertEqual(e.exception.code,400);e.exception.close()

    def test_app_control_multiple_fields_validate_as_one_policy(self):
        p=self.create('apps',[{'path':'application_control.enabled','op':'set','value':True},{'path':'application_control.block_msi','op':'set','value':True}])
        _,did,_=self.make_agent();self.assign(p,'device',did)
        self.assertTrue(self.detail(did)['effective_policy']['body']['application_control']['block_msi'])
