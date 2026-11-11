"""Self-review of the exact tested internal health-filter build; no deployment."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.30'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    paths={'regression':f'evidence/server-deployment-check-{VERSION}.json',
           'frozen':'evidence/packaged-smoke.json',
           'frozen_health':f'evidence/packaged-internal-health-{VERSION}.json',
           'legacy':f'evidence/server-source-legacy-{VERSION}.json'}
    results={key:read(path) for key,path in paths.items()}
    assert all(r['passed'] for r in results.values())
    assert results['regression']['version']==VERSION and results['regression']['tests_run']>=289
    focused=(ROOT/f'evidence/internal-health-unit-{VERSION}.txt').read_text(encoding='utf-8-sig')
    assert 'Ran 8 tests' in focused and focused.rstrip().endswith('OK')
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    assert results['frozen']['exe_sha256']==results['frozen_health']['exe_sha256']==signatures[0]['sha256']
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():sha(p) for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==results['frozen']['application_files']
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/index.html').read_bytes()==(ROOT/'guarddesk/static/index.html').read_bytes()
    previous={'GuardDesk-0.4.29-windows-x64.zip':'339054de88c34c4ec4eaa7c65be355913c02c180b3e1c0972258c609b24efc5b',
              'GuardDesk-0.4.29-source.zip':'c2540af0e9930630577b1fa937363f9296d105b0baa0992554b586512b63f8ed'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    unchanged=['guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py',
               'guarddesk/event_storage.py','guarddesk/policy.py','guarddesk/source_permissions.py',
               'requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.29-source.zip') as prior:
        for name in unchanged:assert prior.read(name)==(ROOT/name).read_bytes(),name
    documents=['README.md','doc/43-internal-health-file-exclusions-0.4.30.md'];links=0
    for name in documents:
        source=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if link.startswith(('http:','https:','#','mailto:')):continue
            resolved=(source.parent/link.split('#')[0]).resolve()
            assert resolved==(ROOT/f'evidence/security/{VERSION}/requirements-review.json').resolve() or resolved.exists(),(name,link)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'Existing native/fallback collector -> exact health path exclusion -> existing authenticated outbox/API -> informational filter and ACK -> unchanged Store',
        'threats_and_controls':[
            'No basename wildcard: exact product hierarchy, 24-hex device directory and two fixed names; unrelated files retained',
            'Server/queue only ordinary file kinds at info level; warning/critical and safety alerts retained',
            'Rename/move requires both ends and all provided paths in range; crossings and incomplete records retained',
            'Source Security handle marker avoids false unresolved deletes, unknown deletes still alert',
            'Bounded fallback checks paths before hashing; excluded old baseline pruned without fake delete',
            'Existing outbox is not bulk deleted; valid old batches ACK, retained events remain idempotent',
            'Existing stored history and original hashes unchanged; local source filtering does not stop broker health writes or health validation',
            'No new permissions, tasks, dependencies, destinations, schema migration or Defender/EDR setting changes',
            'API input validation/authentication and source/privileged ACL checks remain; path classification is not endpoint attestation'],
        'tests_run':results['regression']['tests_run'],'focused_tests':8,
        'evidence':{key:{'path':path,'sha256':sha(ROOT/path),'passed':results[key]['passed']} for key,path in paths.items()},
        'signatures':signatures,'document_links_checked':links,'prior_sealed_archives_unchanged':previous,
        'unchanged_sensitive_sources':unchanged,
        'feature_document':'doc/43-internal-health-file-exclusions-0.4.30.md',
        'limitations':[
            'Custom remote ProgramData roots cannot be inferred by Server from old Agent messages; new Agent uses its local root',
            'User policy exclusions retain their existing behavior; this fixed rule does not override them',
            'History preserved: no immediate database compaction or measured daily fleet reduction promised',
            'Owned Windows 11 fixtures/loopback only; no office Server or live Agent changes',
            'Actual SYSTEM installation/update, Windows 10 and 250 physical endpoints not accepted',
            'Company Authenticode, full SBOM/vulnerability gates, independent review and company Defender/EDR remain incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{VERSION}: exact tested build, focused/full evidence, {links} links and unchanged prior ZIPs verified; unsigned internal trial.')


if __name__=='__main__':main()
