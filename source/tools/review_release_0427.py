"""Verify exact local test/build evidence before the unsigned internal release."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    checks={name:read(path) for name,path in {
        'regression':'evidence/server-deployment-check-0.4.27.json',
        'browser':'evidence/application-exclusions-browser-0.4.27.json',
        'released_legacy':'evidence/application-exclusions-legacy-0.4.27.json',
        'frozen':'evidence/packaged-smoke.json',
        'frozen_feature':'evidence/packaged-application-exclusions-0.4.27.json',
    }.items()}
    assert all(r['passed'] for r in checks.values())
    assert checks['regression']['version']=='0.4.27' and checks['regression']['tests_run']==247
    assert 'Ran 8 tests' in (ROOT/'evidence/application-exclusions-unit-0.4.27.txt').read_text(encoding='utf-8-sig')
    assert (ROOT/'evidence/application-exclusions-unit-0.4.27.txt').read_text(encoding='utf-8-sig').rstrip().endswith('OK')
    signatures=read('evidence/security/0.4.27/signatures.json')
    assert checks['frozen']['exe_sha256']==checks['frozen_feature']['exe_sha256']==signatures[0]['sha256']
    for r in signatures:assert hashlib.sha256((ROOT/r['path']).read_bytes()).hexdigest()==r['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==checks['frozen']['application_files']
    report={
        'version':'0.4.27','release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent_security_review',
        'applicable':['SEC-01','SEC-02','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':['MIS logical policy list -> existing global/group/device resolution -> ordinary process start/stop path comparison at native/main Security collector',
                     'Authenticated legacy batches -> current machine effective policy once per bounded batch -> acknowledge excluded IDs without insertion',
                     'Agent policy transport strips new body field into an audit_options envelope; new clients decode in memory, disk body remains compatible with old strict schemas',
                     'Extended worker persists old body and separate audit options, restores offline exclusions without changing audit/AppLocker on list-only changes'],
        'controls':['Default-empty list, MIS/CSRF/revision/assignment preview controls retained, no implicit per-user exemptions',
                    'Exact filename or full Windows path only, 100 entries/500 chars each, no globs/env expansion/command arguments or execution',
                    'Only application.started/stopped info excluded; warnings, criticals, blocks, unknown identities, files and uploads retained',
                    'Audit and execution-control modules separated so an audit-only policy does not override inherited blocking controls',
                    'Legacy combined policy editor restores both modules and its control values; excluding logs never changes executable policy',
                    'No new dependencies, privileges, tasks, destinations, Defender exclusions or Windows audit disabling; shared security channel still generates system events',
                    'Historical row content/hashes untouched, accepted legacy IDs drain outbox; offline arrival uses current Server policy',
                    'Released 0.4.26 archive hashes pinned for compatibility checks; only its owned one-shot Agent and pure validator exercised'],
        'evidence':{k:{'passed':v['passed'],'tests_run':v.get('tests_run')} for k,v in checks.items()},
        'focused_unit_tests':8,
        'validation_order':'247-test backend regression passed; subsequent UI-only module separation was checked with the final real-browser smoke and eight focused tests including preservation of inherited execution controls, then final binaries were built and tested',
        'signatures':signatures,
        'limitations':['Not deployed or configured on office Server/endpoints; user1 rollback/browser issue remains unconfirmed',
                       'Filename exclusions cover all matching paths and can hide ordinary start/stop evidence of same-name tools; use full paths to narrow scope',
                       'Old collectors still generate/transmit events until upgraded; only updated Server filters arrival, existing history is not reduced',
                       'Windows Security logging is retained; no guarantee of a fixed percentage reduction, whole-machine speed or 250-endpoint capacity',
                       'Actual protected SYSTEM upgrade/rollback, Windows 10, company Defender/EDR, Authenticode, complete SBOM/vulnerability gates and independent review remain unverified'],
        'feature_document':'doc/39-application-audit-exclusions-0.4.27.md',
    }
    (ROOT/'evidence/security/0.4.27/requirements-review.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('0.4.27 exact evidence verified; unsigned internal trial only.')


if __name__=='__main__':main()
