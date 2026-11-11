"""Restore only hash-locked historical release inputs into ignored runtime."""
from pathlib import Path
import argparse,json,shutil
from worktree import contained,digest
ROOT=Path(__file__).resolve().parents[1]
def restore(root,origin,lock,apply=False):
    root=Path(root).resolve(strict=True);origin=Path(origin).resolve(strict=True)
    plan=[]
    for name,wanted in lock['files'].items():
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts or rel.parts[0]!='runtime':raise ValueError('Unreviewed release input path')
        source=contained(origin,origin/rel);target=contained(root,root/rel)
        if not source.is_file() or digest(source)!=wanted:raise ValueError('Release input unavailable or hash mismatch: '+name)
        if target.exists() and (not target.is_file() or digest(target)!=wanted):raise ValueError('Existing release input differs; preserve: '+name)
        plan.append((source,target))
    if apply:
        for source,target in plan:
            target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists():shutil.copyfile(source,target)
    return {'files':len(plan),'applied':apply,'programs_executed':False,'network_used':False}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--from',dest='origin',type=Path,required=True)
    p.add_argument('--apply',action='store_true',help='Without this flag only verify and print the plan')
    a=p.parse_args();lock=json.loads((ROOT/'dependencies/release-inputs.lock.json').read_text())
    print(json.dumps(restore(ROOT,a.origin,lock,a.apply)))
if __name__=='__main__':main()
