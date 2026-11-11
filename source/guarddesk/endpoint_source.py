"""Explicit local, pinned remote endpoint artifact for an independent trial center.

No upload API, executable probing, automatic deployment or fallback to the center
runtime. The operator must install a reviewed artifact and pin its manifest.
"""
import json
import re
from pathlib import Path

MANIFEST='_internal/agent-release.json'


def parse(value,config):
    from .remote_trial import enabled
    if not enabled():raise ValueError('Dedicated endpoint source requires a compiled remote-only test center')
    if not isinstance(value,dict) or set(value)!={'path','version','manifest_sha256','cohort_build_id'}:
        raise ValueError('Dedicated endpoint source fields invalid')
    if not isinstance(value['path'],str) or not value['path'].strip():raise ValueError('Dedicated endpoint path missing')
    if not isinstance(value['version'],str) or not re.fullmatch(r'0\.\d+\.\d+',value['version']):raise ValueError('Dedicated endpoint version invalid')
    for key in ('manifest_sha256','cohort_build_id'):
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError('Dedicated endpoint pin invalid')
    # Preserve lexical parents until plain() checks every reparse boundary.
    path=Path(value['path'])
    if not path.is_absolute():path=Path(config).absolute().parent/path
    if str(path).startswith(('\\\\','//')):raise ValueError('Dedicated endpoint source must be local')
    return {**value,'path':path.absolute()}


def inspect(value):
    from .update_packages import plain
    from .endpoint_package import sha
    from .remote_trial import enabled,PROFILE
    if not enabled():raise ValueError('Dedicated endpoint source not enabled for this center')
    source=plain(value['path'])
    manifest=plain(source/MANIFEST)
    if not manifest.is_file() or manifest.stat().st_size>2*1024*1024 or sha(manifest)!=value['manifest_sha256']:
        raise ValueError('Dedicated endpoint manifest pin mismatch; no center-runtime fallback')
    def read(name):
        path=plain(source/name)
        with path.open('rb') as stream:raw=stream.read(16385)
        if len(raw)>16384:raise ValueError('Dedicated endpoint metadata too large')
        return json.loads(raw)
    metadata=read('_internal/remote-endpoint-build.json')
    if (not isinstance(metadata,dict) or metadata.get('build_role')!='remote-endpoint' or metadata.get('install_profile')!=PROFILE
            or metadata.get('version')!=value['version'] or metadata.get('cohort_build_id')!=value['cohort_build_id']):
        raise ValueError('Dedicated endpoint build/profile/version mismatch')
    from .remote_components import read_cohort
    if read_cohort(source)['build_id']!=value['cohort_build_id']:raise ValueError('Dedicated endpoint cohort mismatch')
    from .release_scope import METADATA,validate
    scope=validate(read(METADATA),value['version'])
    if scope['scope']!='endpoint' or set(scope['components'])!={'native','main'} or scope['required_updater'] is not None:
        raise ValueError('Dedicated endpoint release scope mismatch')
    return source
