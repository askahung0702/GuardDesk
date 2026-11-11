"""Run the regression suite and record the limits of deployment evidence."""
import datetime
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guarddesk import __version__


def main():
    started = time.monotonic()
    output = io.StringIO()
    # A live all-local audit agent may run on the development workstation.
    # Keep synthetic fixtures under its already excluded product runtime so
    # test WAL churn does not flood real audit logs. Do not change policies.
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    previous_temp = tempfile.tempdir
    cleanup_error=''
    try:
        with tempfile.TemporaryDirectory(prefix='server-tests-', dir=runtime) as fixtures:
            try:
                tempfile.tempdir = fixtures
                suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
                result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
            finally:
                tempfile.tempdir = previous_temp
                # Preserve the actual test failures even when a leaked Windows
                # handle prevents fixture cleanup; never mark that run passed.
                print(output.getvalue(),flush=True)
    except OSError:
        cleanup_error='Temporary fixture cleanup failed; inspect test errors and open handles'
    report = {
        'version': __version__, 'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'passed': result.wasSuccessful() and not cleanup_error, 'tests_run': result.testsRun,'cleanup_error':cleanup_error,
        'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
        'elapsed_seconds': round(time.monotonic() - started, 2),
        'scope': 'isolated test databases and simulated clients on this Windows 11 workstation',
        'deployment_checks': [
            'separate config/program/data directories and existing-DB preflight',
            'TLS date, key matching, trust and hostname failures',
            'bounded request concurrency and silent handshake isolation',
            'consistent migration preserving accounts, endpoint identity, policies, groups and grants',
            'invalidated old login and remote sessions',
            'offline durable outbox delivered once after URL cutover',
            'policy download and acknowledgement after cutover',
            'admin/auditor/support permissions and explicit remote grants',
            'simulated consent, frame, bounded input and session close over HTTPS',
            'easy setup native Windows private DACL and controlled shared-bootstrap connection bundle',
            'loopback-only HTTP management and agent-only HTTPS share remote state',
            'port collision closes incomplete listeners; existing data never overwritten'
            ,'organization-pinned Ed25519 releases/jobs, endpoint scope, upload/download roles and CSRF'
            ,'update grouping/schedule, independent component batching, cancellation and remote-session deferral'
            ,'simulated transactional switch/health failure recovery, replay/downgrade rejection and offline stream retry'
        ],
        'not_verified': [
            'actual office Windows Server deployment and physical cross-host connectivity',
            'separate physical data drive, site ACLs, firewall and startup/reboot',
            'real two-person desktop control and native self-uninstall',
            '20 physical endpoints and long-term capacity/performance',
            'Authenticode, full SBOM and company Defender/EDR acceptance'
            ,'positive SYSTEM updater bootstrap/file switch/task restart and real logon/reboot recovery'
            ,'actual per-user update/registry switch and browser host migration; tests mock these adapters'
        ]
    }
    (ROOT / f'evidence/server-deployment-check-{__version__}.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
