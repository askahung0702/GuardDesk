"""Immutable Server/source/standalone MIS internal artifacts."""
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    target=ROOT/'evidence/release-0.4.63-final.json';assert not target.exists()
    r=read(ROOT/'evidence/security/0.4.63/requirements-review.json');assert r['internal_checks_passed'] and not r['formal_release_ready']
    zip_proof=read(ROOT/'evidence/packaged-zip-0.4.63.json');assert zip_proof['passed']
    artifacts=[]
    for kind in ('windows-x64','source'):
        p=ROOT/'dist'/('GuardDesk-0.4.63-'+kind+'.zip')
        with zipfile.ZipFile(p) as z:
            names=z.namelist();assert len(names)==len(set(names)) and all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
            m=json.loads(z.read('MANIFEST-SHA256.json'));assert set(names)==set(m)|{'MANIFEST-SHA256.json'} and all(sha(z.read(n))==h for n,h in m.items())
            assert not any(n.endswith(('.key','.sqlite3')) or 'runtime' in PurePosixPath(n).parts for n in names)
            expected=r['application_files'] if kind=='windows-x64' else r['final_source_sha256']
            assert all(m[('GuardDesk/' if kind=='windows-x64' else '')+n]==h for n,h in expected.items())
            assert json.loads(z.read('evidence/security/0.4.63/requirements-review.json'))==r
        digest=sha(p.read_bytes());assert p.with_name(p.name+'.sha256').read_text().split()[0]==digest
        if kind=='windows-x64':assert zip_proof['archive_sha256']==digest and zip_proof['exe_sha256']==r['application_files']['GuardDesk.exe']
        artifacts.append({'name':p.name,'sha256':digest,'bytes':p.stat().st_size,'manifest_files_verified':len(m)})
    generic=r['generic_executable'];p=ROOT/'dist'/generic['artifact'];assert sha(p.read_bytes())==generic['sha256'];assert p.with_name(p.name+'.sha256').read_text().split()[0]==generic['sha256'];artifacts.append(generic)
    result={'version':'0.4.63','status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':False,'artifacts':artifacts,'proofs':r['proofs'],
      'source_tests':142,'separate_executable_api_test':1,'review':'evidence/security/0.4.63/requirements-review.json','deployment_guide':'doc/85-mis-single-exe-and-tray-0.4.63.md','remaining':r['remaining'],
      'deployment':'Update Server complete program with original config/data. Admin downloads configured single EXE from remote page. Generic EXE uses existing local Agent public connection or manual HTTPS. Reasons optional; consent required. X stops current assistance and hides; tray restores/exits. No autostart.'}
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
