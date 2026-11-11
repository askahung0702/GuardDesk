"""Build a fixed-payload ACL preparation helper; no installed tree is changed."""
from pathlib import Path
import hashlib,json,subprocess
S=Path(__file__).resolve().parents[1];R=S.parents[1]
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    original=R/'dist/GuardDesk-Management-0.4.94-internal.zip'
    if sha(original)!='61371e4ebb04d472eb106f4dea868a4fae33a84276ec3c65bec102c525da1f70':raise ValueError('Original sealed management ZIP changed')
    sealed=json.loads((R/'runtime/center-integration-094-001/sealed-package.json').read_text())
    n=1
    while (R/f'runtime/center-source-permissions-094-{n:03}').exists():n+=1
    E=R/f'runtime/center-source-permissions-094-{n:03}';E.mkdir()
    source=S/'tools/center_source_prepare.cs';before=sha(source)
    expected={k.removeprefix('GuardDesk/'):v for k,v in sealed['file_hashes'].items() if k.startswith('GuardDesk/')}
    manifest=E/'center-files.txt';manifest.write_text(''.join(h+' '+k+'\n' for k,h in sorted(expected.items())),encoding='utf-8')
    exe=E/'GuardDeskCenterPrepare.exe';csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    command=[str(csc),'/nologo','/optimize+','/platform:x64','/target:exe','/out:'+str(exe),'/resource:'+str(manifest)+',center-files',str(source)]
    result=subprocess.run(command,capture_output=True,timeout=60)
    (E/'build.log').write_bytes(result.stdout+result.stderr)
    report={'passed':result.returncode==0 and sha(source)==before,'source_sha256':before,'compiler_sha256':sha(csc),'pinned_original_zip_sha256':sha(original),'embedded_manifest_sha256':sha(manifest),'expected_program_files':len(expected),'installed_center_or_endpoint_changed':False,'Defender_settings_changed':False,'signed':False,'deployable':False}
    if exe.exists():report['helper_sha256']=sha(exe)
    (E/'build-receipt.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'folder':str(E),'passed':report['passed']}));raise SystemExit(not report['passed'])
if __name__=='__main__':main()
