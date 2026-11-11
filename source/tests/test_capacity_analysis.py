"""Analysis integrity: bounded payloads, retained evidence and conservative rules."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from analyze_audit_capacity import container_frames,database
from evaluate_audit_noise import analyze,candidate
from guarddesk.store import Store


class CapacityAnalysisTest(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory(dir=ROOT/'runtime');self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()

    def test_framing_reads_zlib_and_raw_without_exporting_payload(self):
        private=b'Date: fixture\r\nFrom: private-fixture@example.invalid\r\nSubject: hidden fixture\r\n\r\nprivate body'
        frames=[]
        for codec in (1,0):
            payload=zlib.compress(private) if codec else private
            body=bytearray(56);struct.pack_into('<II',body,16,20240919,20240919);struct.pack_into('<III',body,44,1,codec,len(payload))
            frames.append(b'I'*16+struct.pack('<II',2,len(body)+len(payload))+body+payload)
        path=self.root/'fixture.oms';path.write_bytes(b'H'*24+b''.join(frames));before=hashlib.sha256(path.read_bytes()).digest()
        result=container_frames(path)
        self.assertTrue(result['complete_to_eof']);self.assertEqual(result['frames'],2);self.assertEqual(result['decoded_payload_bytes'],len(private)*2)
        self.assertEqual(result['sampled_payload_classification'],{'email_header_payload':2})
        self.assertNotIn('private-fixture',json.dumps(result));self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),before)
        path.write_bytes(path.read_bytes()[:-4]);self.assertFalse(container_frames(path)['complete_to_eof'])

    def test_full_row_compression_accounts_for_hashes_and_distinct_process_ids(self):
        store=Store(self.root/'db.sqlite3')
        with store.connect() as db:
            for n in range(100):Store.event(db,'fixture','application.started','info',{'process':r'C:\Windows\helper.exe','process_id':n+1},occurred=1792380000)
        before=hashlib.sha256(store.path.read_bytes()).digest();result=database(store.path.resolve(),5000)
        self.assertEqual(result['events'],100);self.assertEqual(result['text_column_bytes']['hash'],6400)
        self.assertEqual(result['samples'][0]['same_second_semantic_repeat_candidates'],0)
        self.assertEqual(hashlib.sha256(store.path.read_bytes()).digest(),before)

    def test_cache_rules_do_not_blanket_exclude_appdata_or_business_rename(self):
        cache=r'C:\Users\fixture\AppData\Local\Microsoft\Edge\User Data\Default\Cache\cache.bin'
        doc=r'C:\Users\fixture\Documents\report.docx'
        self.assertEqual(candidate(cache),'browser_cache')
        self.assertIsNone(candidate(r'C:\Users\fixture\AppData\Local\Temp\report.docx'))
        self.assertIsNone(candidate(r'C:\Users\fixture\AppData\Local\Microsoft\Outlook\report.docx'))
        store=Store(self.root/'db.sqlite3')
        with store.connect() as db:Store.event(db,'fixture','file.moved','info',{'source_path':cache,'destination_path':doc})
        before=hashlib.sha256(store.path.read_bytes()).digest();result=analyze(store.path.resolve())
        self.assertEqual(result['mutually_exclusive_optional_candidates_after_modified_disabled'],{})
        self.assertEqual(result['document_extension_hints_not_internal_candidates'],1)
        self.assertEqual(hashlib.sha256(store.path.read_bytes()).digest(),before)
