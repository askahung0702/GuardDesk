"""Create a new, versioned trial source snapshot; never edit the standard line."""
import hashlib
import json
from pathlib import Path
import shutil

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
VERSION='0.4.87'


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    if SOURCE.name!='remote-next-src':raise ValueError('Run only from the isolated development source')
    review=WORKSPACE/'evidence/maintenance/remote-next-m2-20261030/checkpoint-007-review.json'
    if not json.loads(review.read_text(encoding='utf-8')).get('passed'):raise ValueError('Checkpoint007 review required')
    if '__version__ = "0.4.70"' not in (WORKSPACE/'guarddesk/__init__.py').read_text():raise ValueError('Root baseline changed')
    count=1
    while (WORKSPACE/f'runtime/remote-trial-src-{count:03}').exists():count+=1
    target=WORKSPACE/f'runtime/remote-trial-src-{count:03}'
    target.mkdir()
    # Owned test fixtures use this path explicitly; do not depend on a previous
    # test having created it or copy any existing runtime/company data.
    (target/'runtime').mkdir()
    before={}
    for name in ('guarddesk','native','tests','tools','browser-extension'):
        root=SOURCE/name
        for path in sorted(root.rglob('*')):
            if '__pycache__' in path.parts or not path.is_file():continue
            if path.is_symlink() or getattr(path.stat(),'st_file_attributes',0)&0x400:raise ValueError('Source link refused')
            relative=path.relative_to(SOURCE)
            before[relative.as_posix()]=digest(path)
            output=target/relative;output.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,output)
            if digest(output)!=before[relative.as_posix()]:raise ValueError('Copy changed')
    for name in ('AGENTS.md','app.py','app_remote_endpoint.py','mis_remote_app.py','BASELINE-MANIFEST.json',
                 'requirements.txt','requirements-build.txt','THIRD_PARTY_NOTICES.md'):
        before[name]=digest(SOURCE/name);shutil.copyfile(SOURCE/name,target/name)
    changes={}
    for name,old,new,count in (
        ('guarddesk/remote_trial.py','ENABLED = False','ENABLED = True',1),
        ('guarddesk/__init__.py','__version__ = "0.4.76"',f'__version__ = "{VERSION}"',1),
        ('guarddesk/static/index.html','0.4.76',VERSION,2),
    ):
        path=target/name;text=path.read_text(encoding='utf-8')
        if text.count(old)!=count:raise ValueError('Unexpected candidate replacement: '+name)
        path.write_text(text.replace(old,new),encoding='utf-8',newline='')
        changes[name]={'from':before[name],'to':digest(path)}
    for name,expected in before.items():
        if digest(SOURCE/name)!=expected:raise ValueError('Source changed during snapshot')
        if name not in changes and digest(target/name)!=expected:raise ValueError('Unexpected candidate delta')
    body={'format':1,'version':VERSION,'profile':'remote-only-trial-v1','source':str(SOURCE),
          'candidate_source':str(target),'source_files':before,'explicit_build_changes':changes,
          'checkpoint007_review_sha256':digest(review),'company_changed':False,
          'installed':False,'deployable':False,'formal_release':False}
    (target/'TRIAL-SOURCE.json').write_text(json.dumps(body,indent=2),encoding='utf-8')
    print(json.dumps({'source':str(target),'version':VERSION,'files':len(before),'deployable':False}))


if __name__=='__main__':main()
