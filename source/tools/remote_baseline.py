"""Verify an isolated source baseline, explicitly recording unavailable releases."""
import hashlib
import json
from pathlib import Path
import zipfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def owned(workspace, name, folder):
    path = (workspace / name).resolve(strict=True)
    if not path.is_relative_to((workspace / folder).resolve()):
        raise ValueError('Baseline evidence escaped workspace')
    return path


def verify(manifest, workspace):
    workspace = Path(workspace).resolve()
    stable = owned(workspace, manifest['baseline'], 'runtime')
    archive = (workspace / manifest['archive']).resolve()
    if not archive.is_relative_to(workspace / 'dist'):
        raise ValueError('Baseline archive escaped workspace')
    before = {}
    for name, expected in manifest['files'].items():
        path = (stable / name).resolve(strict=True)
        if not path.is_relative_to(stable) or digest(path) != expected:
            raise ValueError('Stable baseline changed')
        if name.startswith('guarddesk/'):
            before[name] = path.read_bytes()
    if archive.exists():
        if digest(archive) != manifest['archive_sha256']:
            raise ValueError('Isolated sealed baseline changed')
        with zipfile.ZipFile(archive) as content:
            expanded = sum(item.file_size for item in content.infolist() if not item.is_dir())
        return before, {'archive_available': True, 'capacity_basis': 'measured_original_archive',
                        'zip_bytes': archive.stat().st_size, 'expanded_bytes': expanded}
    # This opt-in evidence is created only for the isolated internal trial.
    # It cannot assert possession, recovery or validation of missing ZIP bytes.
    declaration = manifest.get('source_revalidation')
    if not declaration:
        raise FileNotFoundError('Original baseline archive missing; explicit source revalidation required')
    receipt = owned(workspace, declaration['receipt'], 'runtime')
    if digest(receipt) != declaration['sha256']:
        raise ValueError('Baseline revalidation receipt changed')
    record = json.loads(receipt.read_text(encoding='utf-8'))
    original = {key: value for key, value in manifest.items() if key != 'source_revalidation'}
    if (record.get('format') != 1 or record.get('kind') != 'internal_trial_source_revalidation'
            or record.get('original_archive_available') is not False
            or record.get('deployable') is not False or record.get('original_manifest') != original):
        raise ValueError('Baseline revalidation declaration mismatch')
    snapshot = owned(workspace, record['snapshot'], 'runtime')
    if digest(snapshot) != record['snapshot_sha256']:
        raise ValueError('Baseline source snapshot changed')
    with zipfile.ZipFile(snapshot) as content:
        entries = content.infolist()
        if (len(entries) != len(manifest['files']) or len({i.filename for i in entries}) != len(entries)
                or {i.filename for i in entries} != set(manifest['files'])
                or sum(i.file_size for i in entries) > 128 * 1024 * 1024):
            raise ValueError('Baseline snapshot inventory mismatch')
        for item in entries:
            if hashlib.sha256(content.read(item)).hexdigest() != manifest['files'][item.filename]:
                raise ValueError('Baseline snapshot source mismatch')
    prior = owned(workspace, record['prior_product_receipt'], 'runtime')
    if digest(prior) != record['prior_product_receipt_sha256']:
        raise ValueError('Historical baseline measurement receipt changed')
    history = json.loads(prior.read_text(encoding='utf-8'))
    if history.get('passed') is not True:
        raise ValueError('Historical build did not pass')
    capacity = history['capacity']
    return before, {'archive_available': False, 'capacity_basis': 'historical_product_receipt_not_remeasured',
                    'zip_bytes': capacity['baseline_zip_bytes'],
                    'expanded_bytes': capacity['baseline_archive_expanded_bytes'],
                    'source_revalidation_receipt': declaration['receipt'],
                    'source_snapshot_sha256': record['snapshot_sha256'],
                    'original_archive_sha256': manifest['archive_sha256'], 'deployable': False}
