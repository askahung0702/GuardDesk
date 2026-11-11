"""Validate exact isolated build receipts without running product binaries."""
import hashlib
import json
from pathlib import Path
from tools.remote_build_paths import artifact_root,receipt_path

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
RUNTIME=WORKSPACE/'runtime'
ROOTS={'CMake':artifact_root('CMake'),'WebRTC':artifact_root('WebRTC')}

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def source_path(kind,name):
    path=SOURCE/name
    if kind=='WebRTC':
        path=SOURCE/'native/remote/webrtc'/name
        if not path.is_file():path=SOURCE/'native/remote'/name
    if not path.resolve().is_relative_to(SOURCE):raise ValueError('Source escaped isolated tree')
    return path

def verify_receipt(kind,path):
    body=json.loads(path.read_text(encoding='utf-8'))
    if not body.get('passed') or not body.get('sources_stable' if kind=='WebRTC' else 'source_stable'):
        raise ValueError('Latest receipt is not a stable pass: '+path.name)
    if not body.get('sources'):raise ValueError('Receipt has no source provenance')
    for name,expected in body['sources'].items():
        actual=source_path(kind,name)
        if not actual.is_file() or digest(actual)!=expected:raise ValueError('Source changed since receipt: '+name)
    if kind in ROOTS:
        if not body.get('artifacts'):raise ValueError('Receipt has no artifacts')
        for name,value in body['artifacts'].items():
            item=ROOTS[kind]/name
            if not item.resolve().is_relative_to(ROOTS[kind]) or digest(item)!=value['sha256']:raise ValueError('Artifact changed: '+name)
    if 'log_sha256' in body and digest(path.with_suffix('.log'))!=body['log_sha256']:raise ValueError('Receipt log changed')
    if kind=='CMake':
        from tools.build_remote_native import TESTS
        stages=[item for item in body['stages'] if item['stage']=='owned_ctests']
        if len(stages)!=1 or stages[0]['count']!=len(TESTS) or stages[0]['exit']!=0:raise ValueError('Native test inventory incomplete')
    if kind=='WebRTC':
        if not body.get('runtime_tests_requested'):raise ValueError('WebRTC runtime tests missing')
        if any(item.get('exit')!=0 for item in body['stages']):raise ValueError('WebRTC stage failed')
    return body

def latest():
    patterns={'Python':'remote-m2-source-next-*.json','CMake':'remote-m2-native-build-*.json','WebRTC':'webrtc-owned-build-*.json'}
    answer={}
    for kind,pattern in patterns.items():
        path=receipt_path(kind,pattern);body=verify_receipt(kind,path)
        answer[kind]={'manifest':path.name,'sha256':digest(path),'body':body}
    return answer
