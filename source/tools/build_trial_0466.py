"""New owned candidate directories; do not replace the installed Agent or seals."""
from pathlib import Path
import json
import os
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    candidate=ROOT/'dist/candidate-0.4.66'
    assert not candidate.exists(),'Preserve prior candidate; choose a reviewed new work directory'
    for path in [candidate,ROOT/'runtime/build-0466-mis',ROOT/'runtime/build-0466-main',ROOT/'.build-deps/mis']:
        assert path.resolve().is_relative_to(ROOT.resolve())
    for label,spec,dest in [('mis','GuardDeskMIS.spec',ROOT/'.build-deps/mis'),('main','GuardDesk.spec',candidate)]:
        log=ROOT/'runtime'/('build-0466-'+label+'.log')
        with log.open('x',encoding='utf-8') as output:
            p=subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--workpath',str(ROOT/'runtime'/('build-0466-'+label)),
                '--distpath',str(dest),str(ROOT/'tools'/spec)],cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,
                creationflags=subprocess.BELOW_NORMAL_PRIORITY_CLASS if os.name=='nt' else 0)
        if p.returncode:
            print(log.read_text(encoding='utf-8')[-4000:]);raise RuntimeError((label,p.returncode))
        print(json.dumps({'built':label,'output':str(dest),'log':str(log)}),flush=True)


if __name__=='__main__':main()
