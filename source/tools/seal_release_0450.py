"""Seal verified unsigned archives without altering previous releases."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.50'
def sha(data):return hashlib.sha256(data).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))

def main():
    review=read(ROOT/f'evidence/security/{VERSION}/requirements-review.json');full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert review['internal_checks_passed'] and full['passed'] and full['source_unchanged_during_run']
    from run_regression_0450 import snapshot
    assert full['source_sha256']==snapshot()
    output=ROOT/f'evidence/release-{VERSION}-final.json'
    if output.exists():raise FileExistsError('Release already sealed')
    artifacts=[]
    for kind in ('windows-x64','source'):
        path=ROOT/f'dist/GuardDesk-{VERSION}-{kind}.zip'
        with zipfile.ZipFile(path) as archive:
            names=archive.namelist();assert len(names)==len(set(names))
            assert not any(PurePosixPath(n).is_absolute() or '..' in PurePosixPath(n).parts or '\\' in n for n in names)
            manifest=json.loads(archive.read('MANIFEST-SHA256.json'));assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            for name,digest in manifest.items():assert sha(archive.read(name))==digest,name
            if kind=='source':
                for name,digest in full['source_sha256'].items():assert manifest[name.replace('\\','/')]==digest,name
            else:assert manifest['GuardDesk/GuardDesk.exe']==review['exe_sha256']
            assert json.loads(archive.read(f'evidence/security/{VERSION}/requirements-review.json'))==review
            assert sha(archive.read(f'evidence/security/{VERSION}/full-regression.log'))==full['log_sha256']
        digest=sha(path.read_bytes());assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        artifacts.append({'name':path.name,'bytes':path.stat().st_size,'sha256':digest,'manifest_files_verified':len(manifest)})
    result={'version':VERSION,'status':'unsigned_internal_trial','formal_release_ready':False,'office_changed':False,'required_upgrade':'server_only_existing_agents_compatible','artifacts':artifacts,'exe_sha256':review['exe_sha256'],'full_regression_tests':full['tests'],'frozen_update_progress_browser_passed':True,'review':f'evidence/security/{VERSION}/requirements-review.json','remaining':review['remaining']}
    output.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))

if __name__=='__main__':main()
