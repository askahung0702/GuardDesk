"""Static, offline checks for the managed source payload; no product imports."""
from pathlib import Path
import argparse,ast,json,re,sys
from worktree import digest,files
ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES={'.exe','.dll','.pyd','.pdb','.obj','.lib','.zip','.whl','.sqlite','.sqlite3','.db','.wal','.pfx','.p12','.pem','.key','.pyc','.pyo','.yuv','.y4m'}
MANAGED=('source','dev','doc','config','dependencies','licenses','provenance')
def validate(root,baseline=False,import_ready=False):
    root=Path(root).resolve();problems=[];syntax=0;checked=0
    for top in MANAGED:
        tree=root/top
        if not tree.is_dir():problems.append('Missing managed folder: '+top);continue
        inventory=files(tree)  # rejects reparse points without executing files
        for rel in inventory:
            path=tree/rel;label=top+'/'+rel;checked+=1
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:problems.append('Generated/data/key file in source payload: '+label)
            if path.stat().st_size>5*1024*1024:problems.append('Unreviewed large file: '+label)
            if path.suffix=='.py':
                try:ast.parse(path.read_bytes(),filename=label);syntax+=1
                except SyntaxError:problems.append('Python syntax error: '+label)
            text=path.read_text(encoding='utf-8',errors='replace')
            for name,pattern in [('private_key',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{32,}'),
                ('AWS_access_key',r'\bAKIA[A-Z0-9]{16}\b'),('GitHub_token',r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}')]:
                if re.search(pattern,text):problems.append('Credential pattern '+name+': '+label)
    if baseline:
        record=json.loads((root/'provenance/source-provenance.json').read_text(encoding='utf-8'))
        actual=files(root/'source')
        if actual!=record['source_files']:problems.append('Initial import differs from reviewed source provenance')
    if import_ready:
        for name in ('runtime','dist','build','.venv','.build-deps','evidence'):
            if (root/name).exists():problems.append('Import generated/data directory is present: '+name)
    return {'passed':not problems,'problems':problems,'managed_files':checked,'python_syntax_checked':syntax,
        'baseline_checked':baseline,'import_ready_checked':import_ready,'product_started':False,
        'secret_scan_scope':'Private-key blocks, AWS access-key identifiers, GitHub token patterns and forbidden file extensions; not a complete secret/security audit.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',action='store_true');p.add_argument('--import-ready',action='store_true')
    a=p.parse_args();result=validate(ROOT,a.baseline,a.import_ready);print(json.dumps(result,ensure_ascii=False,indent=2))
    if not result['passed']:raise SystemExit(1)
if __name__=='__main__':main()
