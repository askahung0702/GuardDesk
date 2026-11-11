"""Explicit deployment scope; Server versions are not endpoint upgrade targets."""
import json
from . import __version__
from .update_packages import version as parse_version

METADATA='_internal/deployment-scope.json'
CURRENT_SCOPE='endpoint'
COMPONENTS=('server','native','main','updater')


def validate(body,version):
    keys={'format','version','scope','components','min_compatible_agent','required_updater'}
    if not isinstance(body,dict) or set(body)!=keys or body['format']!=1 or body['version']!=version:raise ValueError('發布範圍與版本不符')
    parse_version(version);parse_version(body['min_compatible_agent'])
    if body['scope'] not in ('server_only','endpoint') or not isinstance(body['components'],list) or not body['components'] or len(body['components'])>4 or any(not isinstance(c,str) or c not in COMPONENTS for c in body['components']) or len(set(body['components']))!=len(body['components']):raise ValueError('發布元件範圍不正確')
    if body['required_updater'] is not None:parse_version(body['required_updater'])
    if body['scope']=='server_only' and (body['components']!=['server'] or body['required_updater'] is not None):raise ValueError('僅中心版本不可要求端點派送')
    return dict(body)


def profile(version,stored=None):
    # The sealed 68 product change was fleet.py + its search label only.
    # Its already-created jobs remain history, never fabricate completion.
    if version=='0.4.68':return {'format':1,'version':version,'scope':'server_only','components':['server'],'min_compatible_agent':'0.4.12','required_updater':None}
    if stored is not None:return validate(stored,version)
    if version==__version__:
        return validate({'format':1,'version':version,'scope':CURRENT_SCOPE,
            'components':['server'] if CURRENT_SCOPE=='server_only' else list(COMPONENTS),
            'min_compatible_agent':'0.4.12','required_updater':None if CURRENT_SCOPE=='server_only' else '0.4.69'},version)
    return {'format':1,'version':version,'scope':'endpoint','components':list(COMPONENTS),'min_compatible_agent':'0.4.12','required_updater':None}


def from_archive(archive,manifest):
    if METADATA not in manifest['files']:return profile(manifest['version'])
    info=archive.getinfo(METADATA)
    if info.file_size>4096:raise ValueError('發布範圍中繼資料過大')
    return profile(manifest['version'],json.loads(archive.read(METADATA)))


def stored(db,release_id,version):
    row=db.execute('SELECT body FROM update_release_scope WHERE release_id=?',(release_id,)).fetchone()
    return profile(version,json.loads(row[0]) if row else None)
