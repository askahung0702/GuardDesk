"""Verify pinned native license notice inputs before either product package."""
import hashlib
import json
import os
from pathlib import Path

def verify(root):
    value=os.environ.get('GUARDDESK_REMOTE_NOTICES_ROOT')
    if not value:raise ValueError('Explicit verified native notice snapshot required')
    folder=Path(value).resolve(strict=True);workspace=root.parents[1]
    if not folder.is_relative_to(workspace/'runtime'):raise ValueError('Native notices escaped workspace runtime')
    raw=(folder/'notice-manifest.json').read_bytes();manifest=json.loads(raw)
    if manifest['format']!=1 or manifest['webrtc_revision']!='3178a2873c9226a20f678ac902ed979272be0cff':raise ValueError('Native notice revision differs')
    if not {'LICENSE.md','PATENTS'}<=manifest['files'].keys():raise ValueError('Native notices missing')
    for name,expected in manifest['files'].items():
        path=folder/name
        if not path.resolve().is_relative_to(folder) or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Native notice changed: '+name)
    receipt=workspace/manifest['generator_receipt']['path']
    if not receipt.resolve().is_relative_to(workspace/'runtime') or hashlib.sha256(receipt.read_bytes()).hexdigest()!=manifest['generator_receipt']['sha256']:raise ValueError('Notice generator receipt changed')
    return folder,hashlib.sha256(raw).hexdigest()
