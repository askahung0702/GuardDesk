"""Check exact local evidence before creating the unsigned internal trial ZIP."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    checks={name:read(path) for name,path in {
        'regression':'evidence/server-deployment-check-0.4.26.json',
        'browser':'evidence/development-exclusions-browser-0.4.26.json',
        'native':'evidence/development-exclusions-native-0.4.26.json',
        'frozen':'evidence/packaged-smoke.json',
        'frozen_feature':'evidence/packaged-development-exclusions-0.4.26.json',
    }.items()}
    assert all(r['passed'] for r in checks.values())
    assert checks['regression']['version']=='0.4.26' and checks['regression']['tests_run']==239
    signatures=read('evidence/security/0.4.26/signatures.json')
    assert checks['frozen']['exe_sha256']==checks['frozen_feature']['exe_sha256']==signatures[0]['sha256']
    for r in signatures:assert hashlib.sha256((ROOT/r['path']).read_bytes()).hexdigest()==r['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==checks['frozen']['application_files']
    report={
        'version':'0.4.26','release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent_security_review',
        'applicable':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':['MIS opts in via existing file policy field; assignment resolves from authenticated endpoint ID/group/device, not event-supplied user',
                     'Agent native notifications/Security/snapshot use bounded path rules before event queue; snapshot prunes before file reads',
                     'Validated inbound legacy batches use current effective exclusions; acknowledge excluded IDs without immutable-row insertion',
                     'Installer bundle replacement retries known Windows errors for about 10 seconds without predeleting old file or changing ACL'],
        'controls':['Opt-in default; unchanged legacy policy schema and existing MIS/CSRF/revision/assignment controls',
                    'Exact directory segments, case/path normalization; no content scanning, blanket extension, AppData or build/dist exemption',
                    'Only ordinary file kinds excluded; cross-boundary/incomplete moves and unknown/security events remain',
                    'At most existing 100 rules and 100 events per batch, current policy resolved once; no new unbounded queue/cache',
                    'No historical rewrite/retention cleanup, broad scan, new endpoint permissions/tasks/destinations, or Defender exclusions',
                    'Each ZIP replacement retry rechecks paths; unrelated errors fail immediately, permanent denial has a deadline',
                    'No additional dependencies; existing package dependency/license inventory retained but not a complete SBOM/vulnerability assessment'],
        'evidence':{k:{'passed':v['passed'],'tests_run':v.get('tests_run')} for k,v in checks.items()},
        'signatures':signatures,
        'test_corrections':['Initial frozen fixture scanned before receiving its policy; now explicitly receives it before verifying source exclusion, and closes its SQLite inspection connection',
                            'The shared HTTP test helper allowed five seconds for rotation/download, below the new ten-second retry budget. Only those two operations now allow twenty seconds; the full suite was rerun. The earlier timeout report is retained.',
                            'Repeated setup transient WinError 5 reproduced even outside restricted execution; a later retry succeeded. Added bounded atomic ZIP retries and three negative/recovery tests. Earlier failure outputs retained.'],
        'limitations':['Not deployed to office Server or physical endpoints; user1 update rollback/browser issue still unconfirmed',
                       'Path rules are explainable metadata classification, not perfect identification of development data; legitimate files inside excluded dirs also excluded',
                       'Old Agents still collect/transmit built-in cache events until upgraded; Server filters new arrival including offline backlog using current policy',
                       'Application starts/stops (including docker/conhost), normal web history/uploads and Windows system auditing are not reduced by this option',
                       'No independent security review, Authenticode, complete SBOM/security gates, company Defender/EDR or Windows 10 acceptance',
                       '30k path classifier benchmark excludes DB/network/OS overhead and does not establish 250-endpoint capacity'],
        'feature_document':'doc/38-development-audit-exclusions-0.4.26.md',
    }
    (ROOT/'evidence/security/0.4.26/requirements-review.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('0.4.26 exact evidence verified; unsigned internal trial only.')


if __name__=='__main__':main()
