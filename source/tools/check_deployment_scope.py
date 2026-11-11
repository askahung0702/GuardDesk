"""Fail closed when a declared Server-only build changes endpoint runtime code."""
import ast
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
BASELINE='0.4.69'
# Small audited Server-only boundary. Unknown modules require endpoint scope
# until their shared callers have been reviewed; docs/tools do not deploy code.
SERVER_ONLY={'guarddesk/fleet.py','guarddesk/static/index.html','guarddesk/static/management.js',
    'guarddesk/static/updates_ui.js','guarddesk/server.py','guarddesk/endpoint_purge.py',
    'guarddesk/event_storage.py','guarddesk/audit_archive.py','guarddesk/audit_reports.py',
    'guarddesk/audit_search_index.py','guarddesk/audit_sort.py','guarddesk/server_backup.py'}
# Store.canonical is also imported by the Agent. Do not grant the entire shared
# module a Server-only exception. These methods are used only by center Store
# instances (all construction sites are server/setup/offline center tools).
STORE_SERVER_METHODS={'__init__','share_ingestion','event','_verify_events','_connect','_open'}


def store_server_only(before,after):
    def remaining(raw):
        tree=ast.parse(raw)
        tree.body=[n for n in tree.body if not isinstance(n,ast.ClassDef) or n.name!='ReaderActivity']
        for node in tree.body:
            if isinstance(node,ast.ClassDef) and node.name=='Store':
                node.body=[n for n in node.body if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) or n.name not in STORE_SERVER_METHODS]
        return ast.dump(tree)
    return remaining(before)==remaining(after)


def normalized(name,raw):
    if name=='guarddesk/__init__.py':
        tree=ast.parse(raw)
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in node.targets):node.value=ast.Constant('VERSION')
        return ast.dump(tree)
    if name=='guarddesk/release_scope.py':
        tree=ast.parse(raw)
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CURRENT_SCOPE' for t in node.targets):node.value=ast.Constant('SCOPE')
        return ast.dump(tree)
    return raw


def analyze(before,after,scope):
    changed=sorted(n for n in set(before)|set(after) if normalized(n,before.get(n,b''))!=normalized(n,after.get(n,b'')))
    required=[n for n in changed if n not in SERVER_ONLY and not
              (n=='guarddesk/store.py' and store_server_only(before.get(n,b''),after.get(n,b''))) and not
              (n=='guarddesk/static/app.js' and overview_name_only(before.get(n,b''),after.get(n,b'')))]
    if scope=='server_only' and required:raise ValueError('Server-only 發布含端點／未審查變更：'+', '.join(required))
    return {'scope':scope,'changed_product_files':changed,'endpoint_or_review_required':required,'passed':True}


def overview_name_only(before,after):
    # Narrowly reviewed visual edit, not a blanket exception for app.js policy
    # editing or enrollment behavior. Every other byte must still match.
    edits=[('<th>端點名稱 / 部門</th>','<th>端點名稱</th>'),
           ('<small>${esc(d.department)}</small>','')]
    for old,new in edits:
        old=old.encode('utf-8');new=new.encode('utf-8')
        if before.count(old)!=1:return False
        before=before.replace(old,new)
    return before==after


def baseline(version):
    record=json.loads((ROOT/f'evidence/release-{version}-final.json').read_text(encoding='utf-8'))
    path=ROOT/f'dist/GuardDesk-{version}-source.zip'
    if not path.exists():path=ROOT/f'dist/archive/releases/GuardDesk-{version}-source.zip'
    item=next(i for i in record['artifacts'] if i['name']==path.name)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('封存基線雜湊不符')
    with zipfile.ZipFile(path) as archive:
        return {n:archive.read(n) for n in archive.namelist() if n.startswith('guarddesk/') and '__pycache__' not in n}


def check():
    from guarddesk.release_scope import CURRENT_SCOPE
    after={p.relative_to(ROOT).as_posix():p.read_bytes() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    isolated=ROOT/'BASELINE-MANIFEST.json'
    if isolated.is_file():
        # The migration deliberately builds from a verified 76 checkout, never
        # from root 70 or a copied absolute developer path. Preserve the normal
        # published checker outside this isolated source tree.
        manifest=json.loads(isolated.read_text(encoding='utf-8'));workspace=ROOT.parents[1]
        from tools.remote_baseline import verify
        before,evidence=verify(manifest,workspace)
        return {'baseline':'isolated_verified_0.4.76','archive_sha256':manifest['archive_sha256'],
                'baseline_evidence':evidence,**analyze(before,after,CURRENT_SCOPE)}
    return {'baseline':BASELINE,**analyze(baseline(BASELINE),after,CURRENT_SCOPE)}


if __name__=='__main__':print(json.dumps(check(),ensure_ascii=False,indent=2))
