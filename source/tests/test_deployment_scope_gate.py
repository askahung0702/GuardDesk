import unittest
from tools.check_deployment_scope import analyze,baseline
from guarddesk.update_preflight import candidate_size
from unittest.mock import patch
import json
from pathlib import Path
import tempfile
import zipfile
from guarddesk import __version__,update_packages as packages


class ScopeGateTest(unittest.TestCase):
    def test_sealed_67_to_68_is_server_only(self):
        result=analyze(baseline('0.4.67'),baseline('0.4.68'),'server_only')
        self.assertEqual(set(result['changed_product_files']),{'guarddesk/fleet.py','guarddesk/static/index.html','guarddesk/static/management.js'})
        self.assertFalse(result['endpoint_or_review_required'])

    def test_version_stamp_and_scope_assignment_do_not_force_endpoint_release(self):
        old={'guarddesk/__init__.py':b'__version__="1.2.3"','guarddesk/release_scope.py':b'CURRENT_SCOPE="endpoint"'}
        new={'guarddesk/__init__.py':b'__version__="1.2.4"','guarddesk/release_scope.py':b'CURRENT_SCOPE="server_only"'}
        self.assertEqual(analyze(old,new,'server_only')['changed_product_files'],[])
        for name in ('guarddesk/agent.py','guarddesk/update_client.py','guarddesk/new_unknown.py'):
            with self.subTest(name=name),self.assertRaises(ValueError):analyze(old,{**new,name:b'changed=True'},'server_only')

    def test_readonly_zip_counter_matches_real_publisher_format_and_rejects_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'_internal').mkdir()
            files={'GuardDesk.exe':b'owned fixture','GuardDeskAgent.exe':b'owned Agent','_internal/fixture':b'x'*1024}
            for n,data in files.items():(root/n).write_bytes(data)
            meta={'format':1,'version':__version__,'files':{n:packages.file_hash(root/n) for n in files}}
            (root/'_internal/agent-release.json').write_text(json.dumps(meta))
            estimate=candidate_size(root)
            with zipfile.ZipFile(root/'owned.zip','w',zipfile.ZIP_DEFLATED) as archive:
                for n in sorted([*files,'_internal/agent-release.json']):
                    with archive.open(n,'w') as output:output.write((root/n).read_bytes())
            self.assertEqual(estimate['compressed_bytes'],(root/'owned.zip').stat().st_size)
            (root/'GuardDesk.exe').write_bytes(b'changed')
            with self.assertRaises(ValueError):candidate_size(root)
