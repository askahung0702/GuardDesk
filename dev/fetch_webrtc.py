"""Explicit acquisition of official, pinned third-party tools into ignored runtime."""
from pathlib import Path
import argparse,json,os,shutil,subprocess
from worktree import contained
ROOT=Path(__file__).resolve().parents[1]
def run(cmd,cwd,env):return subprocess.run(cmd,cwd=cwd,env=env,check=True)
def clone_or_check(path,url,revision,env):
    if path.exists():
        result=subprocess.run(['git','rev-parse','HEAD'],cwd=path,capture_output=True,text=True,check=True)
        if result.stdout.strip()!=revision:raise ValueError('Existing checkout differs; preserve and review: '+str(path))
        return
    run(['git','clone','--no-checkout',url,str(path)],ROOT,env)
    run(['git','checkout','--detach',revision],path,env)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download',action='store_true',help='Explicitly fetch multi-GB official dependencies and run their normal hooks')
    args=parser.parse_args();lock=json.loads((ROOT/'dependencies/toolchains.lock.json').read_text())
    if not args.download:
        print(json.dumps({'plan':lock,'download_started':False},indent=2));return
    if os.name!='nt' or not shutil.which('git'):raise ValueError('Windows x64 with Git and required Visual Studio tools needed')
    runtime=contained(ROOT,ROOT/'runtime');runtime.mkdir(exist_ok=True)
    tools=contained(ROOT,runtime/'toolchains');tools.mkdir(exist_ok=True)
    depot=contained(ROOT,tools/'depot_tools')
    env=os.environ.copy();env.update(DEPOT_TOOLS_UPDATE='0',DEPOT_TOOLS_WIN_TOOLCHAIN='0',
        DEPOT_TOOLS_METRICS='0',DEPOT_TOOLS_COLLECT_METRICS='0',GYP_MSVS_VERSION='2026',
        vs2026_install=r'C:\Program Files (x86)\Microsoft Visual Studio\2026\BuildTools')
    clone_or_check(depot,lock['depot_tools']['url'],lock['depot_tools']['revision'],env)
    env['PATH']=str(depot)+os.pathsep+env.get('PATH','')
    work=contained(ROOT,runtime/'w');work.mkdir(exist_ok=True)
    config=ROOT/'dependencies/webrtc.gclient'
    existing=work/'.gclient'
    if existing.exists() and existing.read_bytes()!=config.read_bytes():raise ValueError('Existing gclient configuration differs; preserve')
    existing.write_bytes(config.read_bytes())
    source=work/'src'
    clone_or_check(source,lock['webrtc']['url'],lock['webrtc']['revision'],env)
    # The official .bat shim is invoked through the Windows shell; argv contains
    # only fixed upstream commands and reviewed pinned hashes, never user paths.
    run([str(depot/'gclient.bat'),'sync','--revision','src@'+lock['webrtc']['revision']],work,env)
    print('Pinned WebRTC synchronized. Next: python dev/develop.py webrtc')
if __name__=='__main__':main()
