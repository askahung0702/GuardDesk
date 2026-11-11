"""Reject growing endpoint candidates before release, using actual ZIP sizes.

This is a publication gate, not a field disk-space measurement or authorization
to remove caches. Old updater compatibility still needs frozen boundary proof.
"""
import argparse
import json
from pathlib import Path

from guarddesk import __version__, update_packages
from guarddesk.release_scope import CURRENT_SCOPE, profile
from guarddesk.update_preflight import candidate_size

ROOT = Path(__file__).resolve().parents[1]
HEADROOM_PERCENT = 10
# Existing protocol-1 executors enforce these limits in their installed EXE.
# Raising today's source constants does not upgrade those executors. A larger
# protocol needs a separate migration and corresponding release-gate review.
PROTOCOL1_LIMITS = {'compressed_bytes': 64 * 1024**2,
                    'incoming_bytes': 512 * 1024**2, 'files': 5000}


class ReleaseCapacityError(ValueError):
    def __init__(self, report):
        self.report = report
        super().__init__('Endpoint release exceeds updater capacity or growth headroom; '
                         'slim/split the runtime or ship a separately verified updater migration first')


def evaluate(measured, *, scope, version):
    """Separate package ceilings from retained disk working-set constraints."""
    update_packages.version(version)
    if scope not in ('endpoint', 'server_only'):
        raise ValueError('Unknown release scope')
    if scope == 'server_only':
        return {'passed': True, 'version': version, 'scope': scope,
                'agent_package_required': False, 'field_capacity_measured': False}
    if (not isinstance(measured, dict) or
            set(measured) != {'compressed_bytes', 'incoming_bytes', 'files'} or
            any(type(v) is not int or v <= 0 for v in measured.values())):
        raise ValueError('Invalid measured endpoint package size')
    source_limits = {'compressed_bytes': update_packages.MAX_ZIP,
                     'incoming_bytes': update_packages.MAX_TOTAL,
                     'files': update_packages.MAX_FILES}
    limits = {key: min(value, PROTOCOL1_LIMITS[key]) for key, value in source_limits.items()}
    checks = {}
    for key, limit in limits.items():
        ceiling = limit * (100 - HEADROOM_PERCENT) // 100
        checks[key] = {'measured': measured[key], 'hard_limit': limit,
                       'release_limit': ceiling, 'remaining': limit - measured[key],
                       'passed': measured[key] <= ceiling}
    report = {'passed': all(v['passed'] for v in checks.values()),
              'version': version, 'scope': scope, 'agent_package_required': True,
              'headroom_percent': HEADROOM_PERCENT, 'checks': checks,
              'executor_contract': 'existing-protocol-1',
              'field_capacity_measured': False,
              'field_cleanup_authorized': False,
              'required_updater': profile(version)['required_updater'],
              'limitations': ['Endpoint retained files and free disk require endpoint preflight',
                              'Installed old updater is not changed by this publication check',
                              'An oversized candidate requires slimming/splitting or a verified protocol migration']}
    if not report['passed']:
        raise ReleaseCapacityError(report)
    return report


def check(source=None):
    source = ROOT/'dist/GuardDesk' if source is None else Path(source)
    if CURRENT_SCOPE == 'server_only':
        return evaluate(None, scope=CURRENT_SCOPE, version=__version__)
    # candidate_size verifies all manifest bytes/hashes and streams the same
    # ZIP layout used by Publisher; it never creates a second large ZIP.
    measured = candidate_size(source)
    report = evaluate(measured, scope=CURRENT_SCOPE, version=__version__)
    report['candidate_exe_sha256'] = update_packages.file_hash(source/'GuardDesk.exe')
    report['candidate_manifest_sha256'] = update_packages.file_hash(source/'_internal/agent-release.json')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = check(args.source)
    except ReleaseCapacityError as exc:
        result = exc.report
    if args.output:
        # Never overwrite an existing release or diagnostic record.
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
