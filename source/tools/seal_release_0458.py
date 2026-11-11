"""Seal the verified unsigned candidate; old releases remain immutable."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
from run_regression_0458 import snapshot
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.58'
def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    review=read(ROOT/f'evidence/security/{VERSION}/requirements-review.json')
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json');scoped=read(ROOT/f'evidence/scoped-regression-{VERSION}.json')
    assert review['internal_checks_passed'] and not review['formal_release_ready']
    assert full['passed'] and scoped['passed'] and scoped['source_sha256']==snapshot()==review['final_source_sha256']
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
                for name,digest in scoped['source_sha256'].items():assert manifest[name.replace('\\','/')]==digest,name
            else:assert manifest['GuardDesk/GuardDesk.exe']==review['exe_sha256']
            assert json.loads(archive.read(f'evidence/security/{VERSION}/requirements-review.json'))==review
            assert sha(archive.read(f'evidence/security/{VERSION}/full-regression.log'))==full['log_sha256']
        digest=sha(path.read_bytes());assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        artifacts.append({'name':path.name,'bytes':path.stat().st_size,'sha256':digest,'manifest_files_verified':len(manifest)})
    result={'version':VERSION,'status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':True,
            'company_change_scope':review['company_change_scope'],'candidate_deployed_to_office':False,
            'required_upgrade':'Preserve existing identity/outbox/config; update complete Server and both endpoint components to 0.4.58. MIS configures browser-accepted HTTPS publication once; signed policy and per-user host projection then arrive centrally. Verify actual extension handshake and non-confidential request before acceptance.',
            'artifacts':artifacts,'exe_sha256':review['exe_sha256'],'regression_run':full['tests'],'regression_passed':full['tests']-full['skipped'],'regression_skipped':full['skipped'],
            'scoped_regression_run':scoped['tests'],'scoped_regression_passed':scoped['tests']-scoped['skipped'],'validation_method':review['validation_method'],
            'final_delta_files':review['final_delta_files'],'review':f'evidence/security/{VERSION}/requirements-review.json','remaining':review['remaining']}
    output.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
