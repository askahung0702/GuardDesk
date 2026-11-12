"""Offline packaging gate: no center, native loading, installation or OS input."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import assemble_remote_preview as assembly


def completed():
    return {
        'passed': True,
        'sources_stable': True,
        'runtime_tests_requested': True,
        'sources': {},
        'artifacts': {},
        'stages': [
            {'stage': 'remote_mf_codec_probe', 'arguments': ['--dynamic-rates'], 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': ['--owned-preconnect-focus'], 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': ['--owned-window-modal'], 'exit': 0},
            {'stage': 'gn', 'exit': 0},
            {'stage': 'ninja', 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': [], 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': ['--owned-input-stress'], 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': ['--owned-grant-stall'], 'exit': 0},
            {'stage': 'remote_media_peer_probe', 'arguments': ['--owned-backlog-repro'], 'exit': 0},
        ],
    }


class RemoteBuildReceiptTest(unittest.TestCase):
    def setUp(self):
        # Test-owned receipt fixtures must not inherit the invoking build's selection.
        scope=patch.dict(os.environ);scope.start();self.addCleanup(scope.stop)
        for name in ('GUARDDESK_NATIVE_RECEIPT','GUARDDESK_MEDIA_RECEIPT','GUARDDESK_SOURCE_RECEIPT'):
            os.environ.pop(name,None)

    def test_preconnect_gate_refuses_missing_failed_or_unexecuted_runtime(self):
        assembly.require_preconnect_regression(completed())
        missing_modal=completed();missing_modal['stages'].pop(2)
        with self.assertRaisesRegex(ValueError,'modal-window'):assembly.require_preconnect_regression(missing_modal)
        for change in ('missing','failed','timeout','duplicate','compile_only'):
            body=completed();case=body['stages'][1]
            if change=='missing':body['stages'].remove(case)
            elif change=='failed':case['exit']=1
            elif change=='timeout':case['timeout']=True
            elif change=='duplicate':body['stages'].append(copy.deepcopy(case))
            else:body['runtime_tests_requested']=False
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'preconnect regression'):
                assembly.require_preconnect_regression(body)

    def test_grant_stall_receipt_requires_exact_runtime_case_and_keeps_backlog(self):
        assembly.require_grant_stall_regression(completed())
        for change in ('missing','failed','timeout','duplicate','compile_only'):
            body=completed();case=body['stages'][-2]
            if change=='missing':body['stages'].remove(case)
            elif change=='failed':case['exit']=1
            elif change=='timeout':case['timeout']=True
            elif change=='duplicate':body['stages'].append(copy.deepcopy(case))
            else:body['runtime_tests_requested']=False
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'grant stall regression'):
                assembly.require_grant_stall_regression(body)

    def test_completed_backlog_regression_is_accepted(self):
        body=completed()
        before=copy.deepcopy(body)
        assembly.require_input_backlog_regression(body)
        self.assertEqual(body,before)

    def test_dynamic_rates_gate_requires_exact_executed_passing_case(self):
        assembly.require_dynamic_rates_regression(completed())
        for change in ('missing','failed','timeout','duplicate','compile_only','incomplete','other_failure','wrong_arguments','malformed'):
            body=completed();case=body['stages'][0]
            if change=='missing':body['stages'].remove(case)
            elif change=='failed':case['exit']=1
            elif change=='timeout':case['timeout']=True
            elif change=='duplicate':body['stages'].append(copy.deepcopy(case))
            elif change=='compile_only':body['runtime_tests_requested']=False
            elif change=='incomplete':case.pop('exit')
            elif change=='other_failure':body['stages'][-1]['exit']=1
            elif change=='wrong_arguments':case['arguments']=[]
            else:body['stages']=[None]
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'dynamic rates regression'):
                assembly.require_dynamic_rates_regression(body)

    def test_media_receipt_rejects_old_success_without_dynamic_rates(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'runtime').mkdir()
            body=completed();body['stages'].pop(0)
            (root/'runtime/webrtc-owned-build-001.json').write_text(json.dumps(body),encoding='utf-8')
            with patch.object(assembly,'WORKSPACE',root),self.assertRaisesRegex(ValueError,'dynamic rates regression'):
                assembly.receipt('webrtc-owned-build-*.json',True)

    def test_pre_fix_success_receipt_without_backlog_is_rejected(self):
        body=completed()
        body['stages'].pop()
        with self.assertRaisesRegex(ValueError,'backlog regression'):
            assembly.require_input_backlog_regression(body)

    def test_compile_only_receipt_is_rejected_even_with_copied_success_case(self):
        body=completed()
        body['runtime_tests_requested']=False
        with self.assertRaises(ValueError):
            assembly.require_input_backlog_regression(body)

    def test_failed_timeout_incomplete_and_other_failed_case_are_rejected(self):
        for change in ('exit','timeout','incomplete','other'):
            body=completed()
            if change=='exit':body['stages'][-1]['exit']=1
            elif change=='timeout':body['stages'][-1]['timeout']=True
            elif change=='incomplete':body['stages'][-1].pop('exit')
            else:body['stages'][-2]['exit']=1
            with self.subTest(change=change),self.assertRaises(ValueError):
                assembly.require_input_backlog_regression(body)

    def test_wrong_arguments_duplicate_or_malformed_stages_are_rejected(self):
        for change in ('arguments','duplicate','malformed'):
            body=completed()
            if change=='arguments':body['stages'][-1]['arguments']=['--owned-input-stress']
            elif change=='duplicate':body['stages'].append(copy.deepcopy(body['stages'][-1]))
            else:body['stages']=[None]
            with self.subTest(change=change),self.assertRaises(ValueError):
                assembly.require_input_backlog_regression(body)

    def test_media_receipt_calls_gate_before_accepting_sources_and_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'runtime').mkdir()
            body=completed()
            body['stages'].pop()
            path=root/'runtime/webrtc-owned-build-001.json'
            path.write_text(json.dumps(body),encoding='utf-8')
            with patch.object(assembly,'WORKSPACE',root),self.assertRaisesRegex(ValueError,'backlog regression'):
                assembly.receipt('webrtc-owned-build-*.json',True)
            body=completed()
            path.write_text(json.dumps(body),encoding='utf-8')
            with patch.object(assembly,'WORKSPACE',root):
                actual,report=assembly.receipt('webrtc-owned-build-*.json',True)
            self.assertEqual(actual,path)
            self.assertEqual(report,body)

    def test_existing_source_and_artifact_hash_checks_still_reject_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'runtime').mkdir()
            body=completed()
            path=root/'runtime/webrtc-owned-build-001.json'
            for kind in ('source','artifact'):
                candidate=copy.deepcopy(body)
                if kind=='source':candidate['sources']={'missing.cc':'0'*64}
                else:candidate['artifacts']={'missing.exe':{'sha256':'0'*64}}
                path.write_text(json.dumps(candidate),encoding='utf-8')
                with self.subTest(kind=kind),patch.object(assembly,'WORKSPACE',root),patch.object(assembly,'SOURCE',root),patch.object(assembly,'MEDIA',root),self.assertRaises((ValueError,FileNotFoundError)):
                    assembly.receipt('webrtc-owned-build-*.json',True)

    def test_worker_receipt_keeps_existing_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'runtime').mkdir()
            body={'passed':True,'source_stable':True,'sources':{},'artifacts':{}}
            path=root/'runtime/remote-m2-native-build-001.json'
            path.write_text(json.dumps(body),encoding='utf-8')
            with patch.object(assembly,'WORKSPACE',root):
                actual,report=assembly.receipt('remote-m2-native-build-*.json')
            self.assertEqual(actual,path)
            self.assertEqual(report,body)

    def test_media_artifacts_follow_explicit_receipt_instead_of_newer_glob(self):
        from tools import remote_build_paths as paths
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ):
            root=Path(folder);runtime=root/'runtime';runtime.mkdir()
            first=runtime/'webrtc-owned-build-001.json';newer=runtime/'webrtc-owned-build-999.json'
            for receipt,label in ((first,'first'),(newer,'newer')):
                (runtime/label).mkdir()
                receipt.write_text(json.dumps({'artifact_root':'runtime/'+label}),encoding='utf-8')
            os.environ.pop('GUARDDESK_MEDIA_ARTIFACT_ROOT',None)
            os.environ['GUARDDESK_MEDIA_RECEIPT']=str(first)
            with patch.object(paths,'WORKSPACE',root):
                self.assertEqual(paths.artifact_root('WebRTC'),runtime/'first')
                os.environ.pop('GUARDDESK_MEDIA_RECEIPT')
                self.assertEqual(paths.artifact_root('WebRTC'),runtime/'newer')

    def test_external_source_does_not_allow_external_or_escaping_artifacts(self):
        from tools import remote_build_paths as paths
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ):
            root=Path(folder);runtime=root/'runtime';runtime.mkdir();(root/'outside').mkdir()
            receipt=runtime/'webrtc-owned-build-001.json'
            os.environ.pop('GUARDDESK_MEDIA_ARTIFACT_ROOT',None)
            os.environ['GUARDDESK_MEDIA_RECEIPT']=str(receipt)
            for target in ('runtime','runtime/../outside',str(root/'outside')):
                receipt.write_text(json.dumps({'artifact_root':target}),encoding='utf-8')
                with self.subTest(target=target),patch.object(paths,'WORKSPACE',root),self.assertRaises(ValueError):
                    paths.artifact_root('WebRTC')


if __name__=='__main__':
    unittest.main()
