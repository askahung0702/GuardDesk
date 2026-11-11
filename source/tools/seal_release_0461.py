"""Immutable 0.4.61 Server/source/MIS archives and exact manifests."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    target=ROOT/'evidence/release-0.4.61-final.json'
    if target.exists():raise FileExistsError('Already sealed')
    review=read(ROOT/'evidence/security/0.4.61/requirements-review.json');assert review['internal_checks_passed'] and not review['formal_release_ready']
    artifacts=[]
    for kind in ('windows-x64','source','mis-remote'):
        path=ROOT/'dist'/('GuardDesk-0.4.61-'+kind+'.zip')
        with zipfile.ZipFile(path) as z:
            names=z.namelist();assert len(names)==len(set(names)) and all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
            manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            assert all(sha(z.read(n))==v for n,v in manifest.items())
            assert not any(n.endswith(('.key','.sqlite3')) or 'runtime' in PurePosixPath(n).parts for n in names)
            if kind=='windows-x64':assert all(manifest['GuardDesk/'+n]==v for n,v in review['application_files'].items())
            if kind=='source':assert all(manifest[n.replace('\\','/')]==v for n,v in review['final_source_sha256'].items())
            if kind!='mis-remote':assert json.loads(z.read('evidence/security/0.4.61/requirements-review.json'))==review
            else:assert manifest['Runtime/GuardDeskRemote.exe']==review['viewer_sha256']
        digest=sha(path.read_bytes());assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        artifacts.append({'name':path.name,'sha256':digest,'bytes':path.stat().st_size,'manifest_files_verified':len(manifest)})
    report={'version':'0.4.61','status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':False,'candidate_deployed_to_office':False,
      'artifacts':artifacts,'proofs':review['proofs'],'exe_sha256':review['exe_sha256'],'viewer_sha256':review['viewer_sha256'],
      'regression_tests':132,'regression_skipped':0,'separate_launcher_tests':1,'review':'evidence/security/0.4.61/requirements-review.json',
      'deployment_guide':'doc/82-mis-workstation-remote-0.4.61.md','remaining':review['remaining'],
      'deployment':'Update complete Server to 0.4.61 with original data/config/TLS/signing keys. Grant each MIS/support account; download configured MIS tool from remote assistance page or use generic package with existing local Agent connection. Each user must consent.'}
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__':main()
