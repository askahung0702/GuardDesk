"""Create a private hash-locked development venv; never change system Python."""
from pathlib import Path
import argparse,json,os,platform,shutil,subprocess,sys,venv
from worktree import contained,digest,stage
ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--wheelhouse',type=Path,help='Approved offline wheel folder; no network')
    group.add_argument('--download',action='store_true',help='Explicitly download locked wheels from official PyPI')
    args=parser.parse_args()
    if os.name!='nt' or sys.version_info[:2]!=(3,13) or platform.machine().lower() not in ('amd64','x86_64'):
        raise ValueError('Windows x64 CPython 3.13 is required by the checked wheel lock')
    root=ROOT.resolve();work=contained(root,root/'runtime');work.mkdir(exist_ok=True)
    work=contained(root,work/'dev-environment');work.mkdir(exist_ok=True)
    wheels=contained(work,work/'wheelhouse');wheels.mkdir(exist_ok=True)
    lock=json.loads((root/'dependencies/python/dependencies.json').read_text(encoding='utf-8'))
    requirement=root/'dependencies/python/requirements.lock'
    if args.download:
        command=[sys.executable,'-m','pip','--isolated','--disable-pip-version-check','download',
            '--index-url','https://pypi.org/simple','--require-hashes','--only-binary=:all:',
            '--no-deps','--dest',str(wheels),'-r',str(requirement)]
        subprocess.run(command,check=True,timeout=600)
    else:
        for row in lock['packages']:
            name=row['filename']
            if Path(name).name!=name:raise ValueError('Invalid locked wheel name')
            origin=args.wheelhouse.resolve(strict=True)/name
            if digest(origin)!=row['sha256']:raise ValueError('Offline wheel hash mismatch: '+name)
            dest=contained(wheels,wheels/name)
            if not dest.exists() or digest(dest)!=row['sha256']:shutil.copyfile(origin,dest)
    for row in lock['packages']:
        if digest(wheels/row['filename'])!=row['sha256']:raise ValueError('Locked wheel verification failed')
    shutil.copyfile(root/'dependencies/python/dependencies.json',work/'dependencies.json')
    interpreter=work/'venv/Scripts/python.exe'
    if not interpreter.exists():venv.EnvBuilder(with_pip=True).create(work/'venv')
    command=[str(interpreter),'-m','pip','--isolated','--disable-pip-version-check','install',
        '--no-index','--find-links',str(wheels),'--require-hashes','--no-deps','-r',str(requirement)]
    subprocess.run(command,check=True,timeout=300)
    target,_=stage(root)
    env=os.environ.copy();env.update(PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH=str(target),GUARDDESK_BUILD_LOCK=str(work/'dependencies.json'))
    result=subprocess.run([str(interpreter),'-c',
        'from pathlib import Path;from tools.build_dependencies import verify;import json;print(json.dumps(verify(Path.cwd())))'],
        cwd=target,env=env,check=True,capture_output=True,text=True,timeout=90)
    (work/'environment-check.json').write_text(result.stdout,encoding='utf-8')
    print('Environment ready. Next: python dev/develop.py test')
if __name__=='__main__':main()
