"""Verify and summarize this private, static REA/Ghidra investigation.

Raw third-party pseudocode stays in runtime, outside product release evidence.
This verifies identity and observed call edges, not live endpoint behaviour.
"""
import datetime
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MEMBER_SHA='e3db0f2701aa93bf8745862962e7d1c26b1346c9d9dd73a6f4370a11e0db4d0f'


def load(path):
    return json.loads((ROOT/path).read_text(encoding='utf-8'))


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()


records={}
for folder in ('ipguard-rea-native-20261022','ipguard-rea-native-seeded-20261022'):
    for path in sorted((ROOT/'runtime'/folder).glob('[0-9][0-9][0-9]-*.json')):
        envelope=json.loads(path.read_text(encoding='utf-8'))
        e=envelope.get('structuredContent')
        if envelope.get('isError') or not isinstance(e,dict) or e.get('operation')!='analyze_function':continue
        assert e['provider']=={'id':'ghidra','name':'Ghidra','version':'12.1.4'}
        assert e['subject']['digest']['sha256']==MEMBER_SHA
        n=e['normalized_result'];assert n['pseudocode'] and n['procedure']['body']['available']
        assert n['facet_availability']['pseudocode']['available']
        address=n['procedure']['address']
        records[address]={'evidence_id':e['evidence_id'],'raw_path':str(path.relative_to(ROOT)),
                          'raw_sha256':digest(path),'analysis_profile_digest':e['analysis_profile']['digest'],
                          'body_bytes':n['procedure']['body']['total_bytes'],
                          'callees':[v['address'] for v in n['callees']],
                          'pseudocode_characters':len(n['pseudocode']),
                          'seeded':bool(e['analysis_profile']['parameters'].get('analysis_seeds'))}

edges=[('0x129daf60','0x12a2bb20','CopyFileW wrapper to copy processing'),
       ('0x129daf60','0x12a787c0','CopyFileW wrapper to document-record processing'),
       ('0x129d7ab0','0x12a2a430','ReadFile wrapper to read processing'),
       ('0x129e5dc0','0x12a32340','SSL_write wrapper to outgoing-buffer processing'),
       ('0x12b152d0','0x12a7a7f0','WinINet-labelled log formatter to AddUpDlLogEx'),
       ('0x12a7a7f0','0x12a7a400','AddUpDlLogEx to AddUpDlDocLog-labelled function'),
       ('0x12a7a400','0x12a7d280','Up/download document record to shared enqueue function'),
       ('0x12a787c0','0x12a7d280','General document record to same shared enqueue function')]
for caller,callee,_ in edges:assert callee in records[caller]['callees'],(caller,callee)

table=load('evidence/ipguard-native-hook-table-candidates-20261022.json')
assert table['source_sha256']==MEMBER_SHA
for api,address in [('CopyFileW','0x129daf60'),('ReadFile','0x129d7ab0'),('SSL_write','0x129e5dc0')]:
    assert any(row['api']==api and row['words'][2]==address for row in table['rows'])

source=load('evidence/ipguard-installer-assessment-20261022.json')['source']
try:
    source_after=digest(source['path'])
    source_after_status='rechecked'
except OSError as exc:
    source_after=None
    source_after_status='unavailable_at_final_check: '+type(exc).__name__
if source_after is not None:assert source_after==source['sha256']
assert digest(ROOT/'runtime/ipguard-installer-analysis-20261022/file014.tmp.bin')==MEMBER_SHA
seed_path=ROOT/'runtime/ipguard-native-hook-entry-seeds-20261022.tsv'
seed_sha=digest(seed_path)
seed_text=seed_path.read_text(encoding='utf-8')
normalized_seeds=''.join(line+'\n' for line in seed_text.splitlines() if line.strip() and not line.startswith('#'))
seed_commitment=hashlib.sha256(normalized_seeds.encode('utf-8')).hexdigest()
seeded=load('runtime/ipguard-rea-native-seeded-20261022/003-copy-handler.json')['structuredContent']
assert seeded['analysis_profile']['parameters']['analysis_seeds']['sha256']==seed_commitment
assert any('5 functions created, 0 already present, 0 failed' in s for s in seeded['limitations'])

report={'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope':'Static REA MCP + Ghidra analysis of one exact x86 DLL bundled in the user-provided IP-guard installer',
        'installer':source,'installer_final_recheck':{'status':source_after_status,'sha256':source_after,
             'limitation':'The mapped G drive was not available in the final verification process. No target source write was performed; local DLL identity is verified against the original inventory.' if source_after is None else None},
        'member':{'archive_member':'file014.tmp','original_filename':'winhadnt.dll','sha256':MEMBER_SHA},
        'toolchain':'evidence/rea-ghidra-local-toolchain-20261022.json',
        'deep_provider':'REA 6.5.0 / Ghidra 12.1.4 / local JDK 21; child-process environment only',
        'function_dossiers':records,'unique_functions_analyzed':len(records),
        'verified_static_call_edges':[{'caller':a,'callee':b,'meaning':m} for a,b,m in edges],
        'hook_table':'evidence/ipguard-native-hook-table-candidates-20261022.json',
        'seed_provenance':{'file':str(seed_path.relative_to(ROOT)),'raw_sha256':seed_sha,'normalized_commitment_sha256':seed_commitment,'functions_created':5,
                           'basis':'Entry-point candidates read from the on-disk hook table referenced by InstallDetours; analyst input, not discovered runtime execution',
                           'reason':'Default analysis did not define these indirect entry points; the initial no-procedure errors remain in the unseeded runtime evidence'},
        'findings':[
         {'status':'static-observed','claim':'InstallDetours iterates module/API/replacement records, subject to per-entry flags and conditions.'},
         {'status':'static-observed','claim':'The CopyFileW wrapper passes the two path arguments to copy processing, preserves underlying-call results/error state, and conditionally reaches document-record processing.'},
         {'status':'static-observed','claim':'A ReadFile wrapper invokes read processing before/after an underlying or chained handler; file-handle-to-path and full event semantics are not completely reconstructed.'},
         {'status':'static-observed','claim':'An SSL_write wrapper passes an outgoing buffer through processing before the underlying/chained operation. This is not proof that modern Chrome/ChatGPT uses this handler.'},
         {'status':'static-observed','claim':'The WinINet-labelled formatter references file-path, size, server/object and window-title fields and calls AddUpDlLogEx.'},
         {'status':'static-observed','claim':'AddUpDlLogEx reaches the AddUpDlDocLog-labelled routine; it and AddDocLog2-labelled general document processing call the same enqueue function at 0x12a7d280.'},
         {'status':'architecture-inference','claim':'Native interception plus a shared document log pipeline can account for presenting copy/read/upload under document operations without assuming a visible browser extension is the only collector.'}],
        'unverified':['Actual hooks/modules active on DEV/user1','Exact ChatGPT screenshot upload path and full file-to-URL correlation',
                      'Extension presence/download and selected installer components','Other browser/version/architecture coverage',
                      'Full copy/read policy, exclusion, deduplication and asynchronous I/O semantics','Network completion versus application save success',
                      'Dynamic runtime behaviour, performance, driver/Defender compatibility and any GuardDesk implementation'],
        'limitations':['Pseudocode is an inferred Ghidra representation; function/type names may be missing.',
                       'Dynamic/targetless dispatch remains unresolved; analyst-supplied seeds do not prove runtime activation.',
                       'The network driver alone and a generic file-read observation do not establish upload destination.',
                       'Only the selected DLL was deeply analyzed; the earlier 309-member inventory is broader but shallower.'],
        'checks':{'installer_final_digest_matches':source_after==source['sha256'] if source_after is not None else None,'selected_dll_unchanged':True,'all_listed_call_edges_observed':True,
                  'seed_commitment_verified':True,'raw_evidence_digests_recorded':True},
        'effects':{'target_executed':False,'running_agent_attached':False,'server_or_endpoint_changed':False,
                   'security_policy_changed':False,'company_documents_read':False,'external_company_data_upload':False,
                   'guarddesk_product_code_changed':False,'analysis_tools_added_only_to_workspace':True},
        'applicable_requirements':['GD-018','GD-020','SEC-01','SEC-06','SEC-07','SEC-11','DEF-02','DEF-04']}
out=ROOT/'evidence/ipguard-rea-native-assessment-20261022.json'
out.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'report':str(out.relative_to(ROOT)),'unique_functions':len(records),'verified_call_edges':len(edges),'dll_unchanged':True,'installer_recheck':source_after_status}))
