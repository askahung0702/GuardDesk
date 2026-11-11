"""Verify immutable candidate archives, not a formal deployment approval."""
import hashlib,io,json,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.49'

def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))

def main():
    review=read(ROOT/f'evidence/security/{VERSION}/requirements-review.json')
    regression=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert review['internal_checks_passed'] and review['native_admin_fixture_accepted']
    assert regression['passed'] and regression['source_unchanged_during_run']
    output=ROOT/f'evidence/release-{VERSION}-final.json'
    if output.exists():raise FileExistsError('Candidate already sealed; preserve the seal')
    artifacts=[]
    for kind in ('windows-x64','source'):
        path=ROOT/f'dist/GuardDesk-{VERSION}-{kind}.zip'
        with zipfile.ZipFile(path) as archive:
            names=archive.namelist();assert len(names)==len(set(names))
            assert not any(PurePosixPath(n).is_absolute() or '..' in PurePosixPath(n).parts or '\\' in n for n in names)
            manifest=json.loads(archive.read('MANIFEST-SHA256.json'))
            assert set(names)==set(manifest)|{'MANIFEST-SHA256.json'}
            for name,digest in manifest.items():assert sha(archive.read(name))==digest,name
            if kind=='source':
                for name,digest in regression['source_sha256'].items():assert manifest[name.replace('\\','/')]==digest,name
            else:
                assert manifest['GuardDesk/GuardDesk.exe']==review['exe_sha256']
                assert manifest['GuardDesk/_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']==review['native_dll_sha256']
            assert read(ROOT/f'evidence/security/{VERSION}/requirements-review.json')==json.loads(archive.read(f'evidence/security/{VERSION}/requirements-review.json'))
        digest=sha(path.read_bytes())
        assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==digest
        artifacts.append({'name':path.name,'bytes':path.stat().st_size,'sha256':digest,'manifest_files_verified':len(manifest)})
    browser=ROOT/f'dist/GuardDesk-Browser-Enterprise-{VERSION}.zip'
    assert sha(browser.read_bytes())=='1b10f1508df73f0322736614f7c86b450179199155cd08353d033257d52231c4'
    with zipfile.ZipFile(browser) as archive:
        assert archive.testzip() is None
        assert json.loads(archive.read('deployment-status.json'))['status']=='publication_required'
        with zipfile.ZipFile(io.BytesIO(archive.read('extension-source.zip'))) as source:
            for name in source.namelist():assert source.read(name)==(ROOT/'browser-extension'/name).read_bytes(),name
    artifacts.append({'name':browser.name,'bytes':browser.stat().st_size,'sha256':sha(browser.read_bytes()),'extension_source_files_verified':True})
    result={'version':VERSION,'status':'unsigned_internal_trial_candidate','formal_release_ready':False,'office_deployment_performed':False,'artifacts':artifacts,'exe_sha256':review['exe_sha256'],'native_dll_sha256':review['native_dll_sha256'],'full_regression_tests':regression['tests'],'full_regression_passed':True,'native_admin_fixture_passed':True,'review':'evidence/security/'+VERSION+'/requirements-review.json','remaining':review['remaining']}
    output.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))

if __name__=='__main__':main()
