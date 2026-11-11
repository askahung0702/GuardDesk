"""Verify actual archives/extracted CLI, preserve immutable trial hashes."""
import hashlib,json,subprocess,uuid,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def main():
    target=ROOT/'evidence/release-0.4.67-final.json';assert not target.exists()
    review=read(ROOT/'evidence/security/0.4.67/requirements-review.json');assert review['internal_checks_passed'] and not review['formal_release_ready']
    artifacts=[];extracted=None
    for kind in ('windows-x64','source'):
        path=ROOT/'dist'/f'GuardDesk-0.4.67-{kind}.zip'
        with zipfile.ZipFile(path) as z:
            names=z.namelist();assert len(names)==len(set(names))
            assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
            manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in manifest.items())
            assert json.loads(z.read('evidence/security/0.4.67/requirements-review.json'))==review
            expected=review['application_files'] if kind=='windows-x64' else review['source_sha256']
            assert all(manifest[('GuardDesk/' if kind=='windows-x64' else '')+n.replace('\\','/')]==h for n,h in expected.items())
            if kind=='windows-x64':
                from guarddesk.server_setup import secure_directory
                extracted=ROOT/'runtime'/('packaged-0467-'+uuid.uuid4().hex)
                assert extracted.resolve().parent==(ROOT/'runtime').resolve()
                secure_directory(extracted)
                for n in names:
                    if n.startswith('GuardDesk/'):
                        dest=extracted/n
                        assert dest.resolve().is_relative_to(extracted.resolve())
                        dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(n))
                exe=extracted/'GuardDesk/GuardDesk.exe'
                result=subprocess.run([str(exe),'component-info'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
                assert result.returncode==0 and json.loads(result.stdout)['version']=='0.4.67'
                assert sha(exe)==review['application_files']['GuardDesk.exe']
        digest=sha(path);assert path.with_name(path.name+'.sha256').read_text().split()[0]==digest
        artifacts.append({'name':path.name,'sha256':digest,'bytes':path.stat().st_size,'manifest_files_verified':len(manifest)})
    result={'version':'0.4.67','status':'unsigned_internal_trial','formal_release_ready':False,'company_changed':False,
        'source_tests':272,'artifacts':artifacts,'exact_extracted_exe_started':True,'extracted':str(extracted.relative_to(ROOT)),
        'review':'evidence/security/0.4.67/requirements-review.json','deployment_guide':'doc/92-machine-remote-all-users-0.4.67.md',
        'deployment':'Update Server first with original data/config; pilot native and main together. Existing native SYSTEM task starts each user helper with same device ID. Do not reinstall/register B.',
        'remaining':review['remaining']}
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
