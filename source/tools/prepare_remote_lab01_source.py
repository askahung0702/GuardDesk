"""Freeze a standard LAB01 candidate; never relabel the home-only trial."""
import hashlib
import json
from pathlib import Path
import shutil

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    if SOURCE.name!='remote-next-src':raise ValueError('Isolated development source required')
    if 'ENABLED = False' not in (SOURCE/'guarddesk/remote_trial.py').read_text():raise ValueError('Standard build required')
    review=WORKSPACE/'evidence/maintenance/remote-next-m2-20261030/checkpoint-007-review.json'
    if not json.loads(review.read_text()).get('passed'):raise ValueError('Checkpoint review required')
    if '__version__ = "0.4.70"' not in (WORKSPACE/'guarddesk/__init__.py').read_text():raise ValueError('Root baseline changed')
    count=1
    while (WORKSPACE/f'runtime/remote-lab01-src-{count:03}').exists():count+=1
    target=WORKSPACE/f'runtime/remote-lab01-src-{count:03}';target.mkdir();(target/'runtime').mkdir()
    hashes={}
    for folder in ('guarddesk','native','tests','tools','browser-extension','.build-deps/remote'):
        for path in sorted((SOURCE/folder).rglob('*')):
            if '__pycache__' in path.parts or not path.is_file():continue
            if path.is_symlink() or getattr(path.stat(),'st_file_attributes',0)&0x400:raise ValueError('Source link rejected')
            relative=path.relative_to(SOURCE);hashes[relative.as_posix()]=digest(path)
            output=target/relative;output.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,output)
    for name in ('AGENTS.md','app.py','mis_remote_app.py','BASELINE-MANIFEST.json','requirements.txt','requirements-build.txt','THIRD_PARTY_NOTICES.md'):
        hashes[name]=digest(SOURCE/name);shutil.copyfile(SOURCE/name,target/name)
    changed={}
    for name,old,new,expected in (('guarddesk/__init__.py','__version__ = "0.4.76"','__version__ = "0.4.79"',1),('guarddesk/static/index.html','0.4.76','0.4.79',2)):
        path=target/name;raw=path.read_text(encoding='utf-8')
        if raw.count(old)!=expected:raise ValueError('Unexpected version stamp')
        path.write_text(raw.replace(old,new),encoding='utf-8',newline='');changed[name]=digest(path)
    for name,expected in hashes.items():
        if digest(SOURCE/name)!=expected or digest(target/name)!=changed.get(name,expected):raise ValueError('Unstable snapshot '+name)
    body={'format':1,'version':'0.4.79','profile':'standard','purpose':'LAB01 controlled native-remote lab candidate',
          'source':str(SOURCE),'candidate_source':str(target),'source_files':hashes,'explicit_version_changes':changed,
          'company_changed':False,'installed':False,'deployable':False,'formal_release':False}
    (target/'LAB01-SOURCE.json').write_text(json.dumps(body,indent=2),encoding='utf-8')
    print(json.dumps({'source':str(target),'files':len(hashes),'version':'0.4.79','deployable':False}))


if __name__=='__main__':main()
