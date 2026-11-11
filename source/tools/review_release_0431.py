"""Self-review of the exact tested user-path template build; no deployment."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.31'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    paths={'regression':f'evidence/server-deployment-check-{VERSION}.json',
           'frozen':'evidence/packaged-smoke.json',
           'frozen_user':f'evidence/packaged-user-path-{VERSION}.json',
           'browser':f'evidence/improvements-browser-{VERSION}.json',
           'legacy':f'evidence/server-source-legacy-{VERSION}.json'}
    results={key:read(path) for key,path in paths.items()}
    assert all(r['passed'] for r in results.values())
    assert results['regression']['version']==VERSION and results['regression']['tests_run']>=296
    assert results['browser']['page_errors']==[]
    focused=(ROOT/f'evidence/user-path-unit-{VERSION}.txt').read_text(encoding='utf-8-sig')
    assert 'Ran 7 tests' in focused and focused.rstrip().endswith('OK')
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    assert results['frozen']['exe_sha256']==results['frozen_user']['exe_sha256']==signatures[0]['sha256']
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():sha(p) for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==results['frozen']['application_files']
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/index.html').read_bytes()==(ROOT/'guarddesk/static/index.html').read_bytes()
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/app.js').read_bytes()==(ROOT/'guarddesk/static/app.js').read_bytes()
    previous={'GuardDesk-0.4.30-windows-x64.zip':'e558328b6df166302870e519828bb145cc066af27b85fbce10e9ba80d370cec9',
              'GuardDesk-0.4.30-source.zip':'c8565518152cf3f70e549ac7fe98112e5121c089effb9cb603cf5a843a56f138'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    unchanged=['guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py',
               'guarddesk/event_storage.py','guarddesk/source_permissions.py',
               'requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.30-source.zip') as prior:
        for name in unchanged:assert prior.read(name)==(ROOT/name).read_bytes(),name
    documents=['README.md','doc/44-user-path-exclusions-0.4.31.md'];links=0
    for name in documents:
        source=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if link.startswith(('http:','https:','#','mailto:')):continue
            resolved=(source.parent/link.split('#')[0]).resolve()
            assert resolved==(ROOT/f'evidence/security/{VERSION}/requirements-review.json').resolve() or resolved.exists(),(name,link)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'MIS preview/publish/assignment -> unchanged string-list wire schema -> native/fallback or Server pure template match -> existing outbox/ACK/Store',
        'threats_and_controls':[
            'One whole-directory user token only; absolute drive and fixed parent, no glob/env/UNC expansion or profile discovery',
            'Validate raw template before normpath; malformed token, traversal, duplicate token and illegal symbols rejected in full policy/field operations',
            'Exact suffix and subtree boundaries; workspace2 and unrelated locations retained',
            'Rename/move requires both ends and all provided paths in range; crossings and incomplete records retained',
            'Ordinary file exclusions do not suppress web upload, program, export or agent security kinds',
            'Security handle marker and bounded fallback subtree pruning preserve existing collection behavior without new I/O',
            '256-rule parser cache plus existing 100 rules/500 characters limit; no unbounded rule compilation or enumeration',
            'Existing outbox not bulk deleted; valid old batches ACK, retained events idempotent, stored history/original hashes unchanged',
            'UI explains all profile-directory semantics and broad profile-root effect; only MIS publishes/assigns; no new default exclusions',
            'No new permissions, tasks, dependencies, destinations, schema migration or Defender/EDR setting changes',
            'Path token is not actor attribution or endpoint attestation; original privileged ACL/update checks remain'],
        'tests_run':results['regression']['tests_run'],'focused_tests':7,
        'evidence':{key:{'path':path,'sha256':sha(ROOT/path),'passed':results[key]['passed']} for key,path in paths.items()},
        'signatures':signatures,'document_links_checked':links,'prior_sealed_archives_unchanged':previous,
        'unchanged_sensitive_sources':unchanged,
        'feature_document':'doc/44-user-path-exclusions-0.4.31.md',
        'validation_note':'Initial frozen fixture used the real development workspace under C:/Users and was correctly excluded by the broad synthetic rule; isolated rule moved to D:/Users and the complete frozen suite passed with unchanged product bytes. Failed fixture output retained.',
        'limitations':[
            'Old Agent treats token as literal: Server filters, but source suppression needs Agent 0.4.31',
            'Token matches one folder under the MIS-chosen fixed parent; not verified Windows identity or current login expansion',
            'Literal existing rules retain behavior; unsupported general globs/env variables are not newly interpreted',
            'History preserved: no immediate database compaction or measured daily fleet reduction promised',
            'Owned Windows 11 fixtures/loopback only; no office Server or live Agent changes',
            'Actual SYSTEM installation/update, Windows 10 and 250 physical endpoints not accepted',
            'Company Authenticode, full SBOM/vulnerability gates, independent review and company Defender/EDR remain incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{VERSION}: exact tested build, focused/full evidence, {links} links and unchanged prior ZIPs verified; unsigned internal trial.')


if __name__=='__main__':main()
