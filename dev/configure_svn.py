"""Set ignore properties on this working copy only. Never commits."""
from pathlib import Path
import argparse,shutil,subprocess
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apply',action='store_true');p.add_argument('--svn',type=Path)
    args=p.parse_args()
    binary=str(args.svn) if args.svn else shutil.which('svn')
    if not binary:
        candidate=Path(r'C:\Program Files\TortoiseSVN\bin\svn.exe')
        if candidate.is_file():binary=str(candidate)
    if not args.apply:
        print('Plan: svn propset svn:global-ignores --file config/svn-global-ignores.txt .');return
    if not binary:raise ValueError('Use a checked-out SVN working copy with svn.exe available')
    # .svn may live at the parent project root (project/trunk layout).
    subprocess.run([binary,'info','--show-item','wc-root',str(ROOT)],check=True,capture_output=True)
    subprocess.run([binary,'propset','svn:global-ignores','--file',str(ROOT/'config/svn-global-ignores.txt'),str(ROOT)],check=True)
    print('Working-copy property changed; review and commit this property with company procedures.')
if __name__=='__main__':main()
