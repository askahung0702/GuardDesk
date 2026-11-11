"""Generic portable MIS viewer; uses existing local Agent connection or input."""
import hashlib,json,shutil,tempfile,zipfile,io
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.mis_support import package
from guarddesk.server_setup import secure_directory
def main():
    output=ROOT/'dist'/('GuardDesk-'+__version__+'-mis-remote.zip')
    if output.exists() or output.with_name(output.name+'.sha256').exists():raise FileExistsError('Archive already sealed')
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='mis-package-') as tmp:
        private=secure_directory(Path(tmp),allow_empty=True);app=private/'GuardDesk';shutil.copytree(ROOT/'dist/GuardDesk',app)
        blob=package(None,app)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        manifest=json.loads(z.read('MANIFEST-SHA256.json'));assert all(hashlib.sha256(z.read(n)).hexdigest()==v for n,v in manifest.items())
        assert 'Runtime/GuardDeskRemote.exe' in manifest and 'mis-connection.json' not in manifest
        assert not any(n.endswith(('.key','.sqlite3')) for n in manifest)
    output.write_bytes(blob);digest=hashlib.sha256(blob).hexdigest();output.with_name(output.name+'.sha256').write_text(digest+'  '+output.name+'\n',encoding='ascii')
    report={'version':__version__,'scope':'portable_generic_MIS_no_company_connection','artifact':output.name,'bytes':len(blob),'sha256':digest,
            'viewer_sha256':manifest['Runtime/GuardDeskRemote.exe'],'files':len(manifest),'contains_enrollment_code':False,'contains_company_private_key':False,
            'company_changed':False,'status':'unsigned_internal_trial'}
    (ROOT/'evidence'/('mis-package-'+__version__+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
if __name__=='__main__':main()
