"""Create secret-free binary/source ZIPs from the already tested Windows build."""
import hashlib
import json
import platform
import shutil
import sys
import zipfile
from importlib.metadata import distribution
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.build-deps/remote'))
DIST=ROOT/'dist'
VERSION='0.4.69'


def main():
    from tools.build_dependencies import verify
    verify(ROOT)
    from tools.check_deployment_scope import check
    check()
    for suffix in ('windows-x64.zip','source.zip'):
        target=DIST/f'GuardDesk-{VERSION}-{suffix}'
        if target.exists() or target.with_name(target.name+'.sha256').exists():
            raise FileExistsError('Release archive already sealed; use a new version: '+str(target))
    exe=DIST/'GuardDesk/GuardDesk.exe'
    from guarddesk.release_scope import CURRENT_SCOPE
    if CURRENT_SCOPE=='endpoint':
        boundary=json.loads((ROOT/f'evidence/update-boundary-frozen-{VERSION}.json').read_text(encoding='utf-8'))
        assert boundary['passed'] and boundary['version']==VERSION and boundary['exe_sha256']==hashlib.sha256(exe.read_bytes()).hexdigest(),'Endpoint release requires exact old-updater/candidate boundary evidence'
    report=json.loads((ROOT/'evidence/packaged-smoke.json').read_text(encoding='utf-8'))
    assert report['passed'] and report['exe_sha256']==hashlib.sha256(exe.read_bytes()).hexdigest(),'Build must pass packaged smoke first'
    assert report['gui_sha256']==hashlib.sha256((exe.parent/'GuardDeskAgent.exe').read_bytes()).hexdigest(),'Windowless Agent must pass packaged smoke first'
    actual={p.relative_to(exe.parent).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in exe.parent.rglob('*') if p.is_file()}
    assert report['application_files']==actual,'Runtime and bundled scripts must match the exact tested application tree'
    review=json.loads((ROOT/f'evidence/security/{VERSION}/requirements-review.json').read_text(encoding='utf-8'))
    assert review['internal_checks_passed'] and review['version']==VERSION and review['application_files']==actual,'Exact release review is required before sealing'
    licenses=DIST/'licenses'
    licenses.mkdir(exist_ok=True)
    dependencies={}
    for name in ['cryptography','cffi','pyinstaller','pyreadline3','Pillow']:
        package=distribution(name)
        dependencies[name]=package.version
        folder=licenses/name
        folder.mkdir(exist_ok=True)
        for item in package.files or []:
            if 'license' in str(item).lower() or 'copying' in str(item).lower():
                path=Path(package.locate_file(item))
                if path.is_file():
                    shutil.copyfile(path,folder/path.name)
    python_license=Path(sys.base_prefix)/'LICENSE.txt'
    shutil.copyfile(python_license,licenses/'PYTHON-LICENSE.txt')
    shutil.copyfile(ROOT/'tools/licenses/Tcl-8.6.15.license.terms',licenses/'Tcl-8.6.15.license.terms')
    shutil.copyfile(DIST/'GuardDesk/_internal/_tk_data/license.terms',licenses/'Tk-license.terms')
    import tkinter
    dependencies.update({'Tcl':tkinter.Tcl().eval('info patchlevel'),'Tk':tkinter.TkVersion})
    dependencies.update({'Python':platform.python_version(),'platform':platform.platform(),'GuardDesk':VERSION})
    (DIST/'build-info.json').write_text(json.dumps(dependencies,indent=2),encoding='utf-8')
    common=[ROOT/'README.md',ROOT/'AGENTS.md',ROOT/'Start-GuardDesk.ps1',ROOT/'Install-Endpoint.ps1',ROOT/'Install-Endpoint.cmd',ROOT/'Uninstall-Endpoint.cmd',ROOT/'THIRD_PARTY_NOTICES.md',ROOT/'Server-Config.example.json',ROOT/'Setup-Management.cmd']
    common.append(ROOT/'Start-Remote.cmd')
    common.append(ROOT/'Start-MIS-Remote.cmd')
    common.append(ROOT/'Diagnose-Remote.cmd')
    for path in common:
        if path.suffix.lower()=='.cmd':
            assert b'\n' not in path.read_bytes().replace(b'\r\n',b''),'Windows CMD entry point requires CRLF: '+path.name
    common += [p for folder in ['doc','evidence','browser-extension'] for p in (ROOT/folder).rglob('*') if p.is_file()]
    binaries=[p for p in (DIST/'GuardDesk').rglob('*') if p.is_file()]
    binary_files={p.relative_to(DIST).as_posix():p for p in binaries}
    binary_files.update({p.relative_to(ROOT).as_posix():p for p in common})
    binary_files.update({p.relative_to(DIST).as_posix():p for p in licenses.rglob('*') if p.is_file()})
    binary_files['build-info.json']=DIST/'build-info.json'
    source_files={p.relative_to(ROOT).as_posix():p for p in common}
    for folder in ['guarddesk','tests','tools','native']:
        for p in (ROOT/folder).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':
                source_files[p.relative_to(ROOT).as_posix()]=p
    for name in ['app.py','mis_remote_app.py','requirements.txt','requirements-build.txt','.gitignore']:
        source_files[name]=ROOT/name
    archives=[]
    for name,files in [(f'GuardDesk-{VERSION}-windows-x64.zip',binary_files),(f'GuardDesk-{VERSION}-source.zip',source_files)]:
        manifest={path:hashlib.sha256(p.read_bytes()).hexdigest() for path,p in sorted(files.items())}
        with zipfile.ZipFile(DIST/name,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for path,p in sorted(files.items()):
                assert not any(part in ['runtime','.git','.venv','__pycache__'] for part in Path(path).parts)
                archive.write(p,path)
            archive.writestr('MANIFEST-SHA256.json',json.dumps(manifest,indent=2))
        with zipfile.ZipFile(DIST/name) as archive:
            assert archive.testzip() is None
            actual=json.loads(archive.read('MANIFEST-SHA256.json'))
            assert all(hashlib.sha256(archive.read(path)).hexdigest()==sha for path,sha in actual.items())
        sha=hashlib.sha256((DIST/name).read_bytes()).hexdigest()
        (DIST/(name+'.sha256')).write_text(sha+'  '+name+'\n',encoding='ascii')
        archives.append({'name':name,'bytes':(DIST/name).stat().st_size,'sha256':sha,'files':len(files)})
    print(json.dumps({'archives':archives,'no_runtime_credentials':True},indent=2))


if __name__=='__main__':
    main()
