"""Seal new archives only, retaining previous immutable release records."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
    target=ROOT/'evidence/release-0.4.62-final.json';assert not target.exists()
    review=read(ROOT/'evidence/security/0.4.62/requirements-review.json');assert review['internal_checks_passed'] and not review['formal_release_ready']
    zip_proof_path=ROOT/'evidence/packaged-zip-0.4.62.json';zip_proof=read(zip_proof_path);assert zip_proof['passed']
    artifacts=[]
    for kind in ('windows-x64','source'):
        p=ROOT/'dist'/('GuardDesk-0.4.62-'+kind+'.zip')
        with zipfile.ZipFile(p) as z:
            names=z.namelist();assert len(names)==len(set(names)) and all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
            manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            assert all(sha(z.read(n))==v for n,v in manifest.items())
            assert not any(n.endswith(('.key','.sqlite3')) or 'runtime' in PurePosixPath(n).parts for n in names)
            assert json.loads(z.read('evidence/security/0.4.62/requirements-review.json'))==review
            expected=review['application_files'] if kind=='windows-x64' else review['final_source_sha256']
            assert all(manifest[('GuardDesk/' if kind=='windows-x64' else '')+n]==v for n,v in expected.items())
        digest=sha(p.read_bytes());assert p.with_name(p.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        if kind=='windows-x64':assert zip_proof['archive_sha256']==digest and zip_proof['exe_sha256']==review['application_files']['GuardDesk.exe']
        artifacts.append({'name':p.name,'bytes':p.stat().st_size,'sha256':digest,'manifest_files_verified':len(manifest)})
    result={'version':'0.4.62','status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':False,'candidate_deployed_to_office':False,
      'artifacts':artifacts,'proofs':{**review['proofs'],'actual_zip':{'path':str(zip_proof_path.relative_to(ROOT)),'sha256':sha(zip_proof_path.read_bytes())}},'category_source_tests':214,'deployment_tests':76,'separate_owned_registry_tests':1,
      'exe_sha256':review['application_files']['GuardDesk.exe'],'review':'evidence/security/0.4.62/requirements-review.json',
      'deployment_guide':'doc/84-server-deployment-0.4.62.md','remaining':review['remaining'],
      'deployment':'Stop original Server; back up original application/data; replace complete application directory; reuse original server.json and startup entry. Do not run Setup-Management or reenroll endpoints.'}
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
