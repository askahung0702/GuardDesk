"""Seal verified new internal archives; no archive overwrite or deployment."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.60'
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def sha(blob):return hashlib.sha256(blob).hexdigest()
def main():
    result_path=ROOT/'evidence/release-0.4.60-final.json'
    if result_path.exists():raise FileExistsError('Release already sealed')
    review_path=ROOT/'evidence/security/0.4.60/requirements-review.json';review=read(review_path)
    assert review['internal_checks_passed'] and not review['formal_release_ready']
    artifacts=[]
    for kind in ('windows-x64','source'):
        path=ROOT/'dist'/f'GuardDesk-{VERSION}-{kind}.zip'
        with zipfile.ZipFile(path) as z:
            names=z.namelist();assert len(names)==len(set(names))
            assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
            manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            assert all(sha(z.read(name))==value for name,value in manifest.items())
            assert read(review_path)==json.loads(z.read('evidence/security/0.4.60/requirements-review.json'))
            assert z.read('doc/81-server-deployment-0.4.60.md')==(ROOT/'doc/81-server-deployment-0.4.60.md').read_bytes()
            if kind=='windows-x64':
                assert all(manifest['GuardDesk/'+name]==value for name,value in review['application_files'].items())
            else:
                assert all(manifest[name.replace('\\','/')]==value for name,value in review['final_source_sha256'].items())
            assert not any(n.endswith(('.key','.sqlite3')) or 'runtime' in PurePosixPath(n).parts for n in names)
        digest=sha(path.read_bytes());assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        artifacts.append({'name':path.name,'bytes':path.stat().st_size,'sha256':digest,'manifest_files_verified':len(manifest)})
    result={'version':VERSION,'status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':False,
        'candidate_deployed_to_office':False,'artifacts':artifacts,'review':str(review_path.relative_to(ROOT)),
        'source_regression_tests':{'category_and_adjacent':204,'deployment':76,'skipped':0},
        'exe_sha256':review['exe_sha256'],'proofs':review['proofs'],'remaining':review['remaining'],
        'deployment_guide':review['deployment_guide'],'required_upgrade':'Replace complete Server program directory with backup while stopped, retain original data/server.json/TLS/signing material and launch existing config. Pilot general and native Agent 0.4.60 separately for website enforcement. No Edge native-drop completion claim.'}
    result_path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
