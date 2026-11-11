"""Build a separate endpoint for offline review, never enroll/install/publish.

Keeps the standard spec and all prior snapshots intact. This creates no setup
bundle or credentials, and does not mark the candidate Defender-accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def normalized(code):
    return code.replace(co_filename='owned',co_consts=tuple(normalized(v) if isinstance(v,types.CodeType) else v for v in code.co_consts))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--owned-cohort',type=Path,required=True)
    parser.add_argument('--owned-notices',type=Path,required=True)
    parser.add_argument('--owned-service',type=Path,required=True)
    parser.add_argument('--candidate-version',default=None)
    args=parser.parse_args()
    if SOURCE.name!='remote-next-src':raise ValueError('Isolated development source required')
    cohort=args.owned_cohort.resolve(strict=True);notices=args.owned_notices.resolve(strict=True)
    service=args.owned_service.resolve(strict=True)
    service_receipt=json.loads((service/'receipt.json').read_text())
    if not service.is_relative_to(WORKSPACE/'runtime') or not service_receipt.get('passed'):
        raise ValueError('Owned service receipt required')
    if digest(service/'Release/GuardDeskService.exe')!=service_receipt['sha256']:raise ValueError('Service image changed')
    if not all(digest(SOURCE/name)==value for name,value in service_receipt['sources'].items()):raise ValueError('Service source changed')
    if not all(p.is_relative_to(WORKSPACE/'runtime') for p in (cohort,notices)):raise ValueError('Inputs escaped runtime')
    from tools.remote_notices import verify as verify_notices
    previous=os.environ.get('GUARDDESK_REMOTE_NOTICES_ROOT')
    try:
        os.environ['GUARDDESK_REMOTE_NOTICES_ROOT']=str(notices)
        verify_notices(SOURCE)
    finally:
        if previous is None:os.environ.pop('GUARDDESK_REMOTE_NOTICES_ROOT',None)
        else:os.environ['GUARDDESK_REMOTE_NOTICES_ROOT']=previous
    from tools.build_dependencies import verify
    dependencies=verify(SOURCE)
    from guarddesk.remote_components import read_cohort,REMOTE_FILES
    pins=read_cohort(cohort)
    # Require a verified native receipt pair, including the current media fix.
    from tools.assemble_remote_preview import receipt,NATIVE,MEDIA
    native,native_body=receipt('remote-m2-native-build-*.json')
    media,media_body=receipt('webrtc-owned-build-*.json',True)
    for name in REMOTE_FILES:
        root=NATIVE if name in ('GuardDeskRemoteWorker.exe','GuardDeskRemoteBridge.dll') else MEDIA
        if pins['files'][name]!=digest(root/name):raise ValueError('Cohort is not current tested native output')
    number=1
    while (WORKSPACE/f'runtime/remote-endpoint-build-{number:03}').exists() or (WORKSPACE/f'runtime/remote-endpoint-src-{number:03}').exists():number+=1
    output=WORKSPACE/f'runtime/remote-endpoint-build-{number:03}';output.mkdir()
    frozen=WORKSPACE/f'runtime/remote-endpoint-src-{number:03}';frozen.mkdir()
    files=[]
    for name in ('guarddesk','tools'):
        files.extend(p for p in (SOURCE/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.extend(SOURCE/name for name in ('app_remote_endpoint.py','app_remote_installer.py','requirements.txt','requirements-build.txt','AGENTS.md'))
    before={}
    for path in files:
        if path.is_symlink() or getattr(path.stat(),'st_file_attributes',0)&0x400:raise ValueError('Source link refused')
        name=path.relative_to(SOURCE);before[name.as_posix()]=digest(path)
        destination=frozen/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,destination)
        if digest(destination)!=before[name.as_posix()]:raise ValueError('Copy changed')
    trial=frozen/'guarddesk/remote_trial.py';text=trial.read_text(encoding='utf-8')
    if text.count('ENABLED = False')!=1:raise ValueError('Unexpected trial build flag')
    trial.write_text(text.replace('ENABLED = False','ENABLED = True'),encoding='utf-8')
    changes={'guarddesk/remote_trial.py':digest(trial)}
    if args.candidate_version:
        from guarddesk.update_packages import version
        version(args.candidate_version)
        init=frozen/'guarddesk/__init__.py'
        from guarddesk import __version__
        original=init.read_text()
        if original.count(__version__)!=1:raise ValueError('Version source unexpected')
        init.write_text(original.replace(__version__,args.candidate_version),encoding='utf-8')
        changes['guarddesk/__init__.py']=digest(init)
    source_receipt={'format':1,'build_role':'remote-endpoint','source':str(SOURCE),'files':before,
                    'explicit_build_changes':changes,
                    'version_changed':bool(args.candidate_version),'review_only':True,'deployable':False}
    (frozen/'ENDPOINT-SOURCE.json').write_text(json.dumps(source_receipt,indent=2)+'\n')
    report={'format':1,'passed':False,'source':str(frozen),'dependencies':dependencies,
            'cohort_build_id':pins['build_id'],'native_receipts':{native.name:digest(native),media.name:digest(media)},
            'installed':False,'published':False,'Defender_accepted':False,'deployable':False}
    log=output/'build.log'
    try:
        env=os.environ.copy();env['PYTHONPATH']=str(frozen);env['PYTHONNOUSERSITE']='1'
        env['PYINSTALLER_CONFIG_DIR']=str(output/'pyinstaller-cache')
        env['GUARDDESK_REMOTE_COHORT_ROOT']=str(cohort);env['GUARDDESK_REMOTE_NOTICES_ROOT']=str(notices)
        env['GUARDDESK_REMOTE_SERVICE_ROOT']=str(service)
        with log.open('x',encoding='utf-8') as stream:
            result=subprocess.run([sys.executable,'-m','PyInstaller','--clean','--noconfirm',
                '--distpath',str(output/'product'),'--workpath',str(output/'work'),
                str(frozen/'tools/GuardDeskRemoteEndpoint.spec')],cwd=frozen,env=env,
                stdout=stream,stderr=subprocess.STDOUT,timeout=600)
        report['build_exit']=result.returncode
        if result.returncode:raise ValueError('Endpoint build failed; no prior output reused')
        from PyInstaller.archive.readers import CArchiveReader
        from tools.remote_endpoint_artifact import check_inventory,deployment_scope
        product=output/'product/GuardDesk'
        from guarddesk import __version__
        if json.loads((product/'_internal/deployment-scope.json').read_text())!=deployment_scope(args.candidate_version or __version__):
            raise ValueError('Endpoint deployment scope does not match artifact roles')
        inventory={p.relative_to(product).as_posix():{'sha256':digest(p),'bytes':p.stat().st_size}
                   for p in product.rglob('*') if p.is_file()}
        verified={}
        for name in ('GuardDesk.exe','GuardDeskAgent.exe','GuardDeskInstaller.exe'):
            archive=CArchiveReader(str(product/name));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
            modules={}
            for module in (n for n in pyz.toc if n=='guarddesk' or n.startswith('guarddesk.')):
                path=frozen/(module.replace('.','/')+'.py')
                if not path.is_file():path=frozen/module.replace('.','/')/'__init__.py'
                if normalized(pyz.extract(module))!=normalized(compile(path.read_bytes(),str(path),'exec',dont_inherit=True,optimize=0)):
                    raise ValueError('Frozen module differs from source: '+module)
                modules[module]=digest(path)
            is_installer=name=='GuardDeskInstaller.exe'
            check_inventory(modules,inventory,installer=is_installer)
            entry='app_remote_installer' if is_installer else 'app_remote_endpoint'
            if entry not in archive.toc or 'app' in archive.toc:raise ValueError('Wrong packaged entry')
            verified[name]=modules
        report['files']=inventory;report['verified_PYZ_modules']=verified
        tests=[]
        for command,expected in [(['component-info'],0),*(([name],1) for name in ('serve','server-setup','add-user','remote-viewer','agent','browser-host','update-service','document-session-context'))]:
            result=subprocess.run([str(product/'GuardDesk.exe'),*command],capture_output=True,timeout=30)
            if result.returncode!=expected:raise ValueError('Unexpected frozen CLI exit: '+str(command))
            if expected==0:
                body=json.loads(result.stdout)
                if body['build_role']!='remote-endpoint' or body['install_profile']!='remote-only-trial-v1':raise ValueError('Wrong frozen profile')
            elif b'Command is not part of the dedicated remote endpoint' not in result.stderr:
                raise ValueError('Frozen role did not fail at entry')
            tests.append({'command':command[0],'exit':result.returncode})
        for command in ('endpoint-setup','endpoint-uninstall','usb-install','usb-worker','remote-service-worker','endpoint-native-install','machine-session','remote-admin-session'):
            installer=command in ('endpoint-setup','endpoint-uninstall','usb-install','endpoint-native-install')
            result=subprocess.run([str(product/('GuardDeskInstaller.exe' if installer else 'GuardDesk.exe')),command,'--help'],capture_output=True,timeout=30)
            if result.returncode:raise ValueError('Frozen parser unavailable: '+command)
            tests.append({'command':command,'help_exit':0})
        report['frozen_CLI_checks']=tests
        # Do not mark a build passed after only import/help/version checks.
        # This executes nested startup dependencies from the runtime PYZ in a
        # fresh interpreter, with no guarddesk source-tree fallback.
        startup_report=output/'runtime-startup-gate.json'
        with (output/'runtime-startup-gate.log').open('x',encoding='utf-8') as stream:
            gate=subprocess.run([sys.executable,str(SOURCE/'tools/probe_remote_runtime_startup.py'),
                '--product',str(product),'--report',str(startup_report)],
                cwd=output,stdout=stream,stderr=subprocess.STDOUT,timeout=30)
        if gate.returncode or not json.loads(startup_report.read_text())['passed']:
            raise ValueError('Frozen runtime startup gate failed; candidate must not be packaged')
        report['runtime_startup_gate_sha256']=digest(startup_report)
        resume_report=output/'install-resume-gate.json'
        with (output/'install-resume-gate.log').open('x',encoding='utf-8') as stream:
            gate=subprocess.run([sys.executable,str(SOURCE/'tools/probe_remote_install_resume.py'),
                '--product',str(product),'--report',str(resume_report)],
                cwd=output,stdout=stream,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(resume_report.read_text())['passed']:
            raise ValueError('Frozen offline installation resume gate failed; candidate must not be packaged')
        report['install_resume_gate_sha256']=digest(resume_report)
        report['source_stable']=all(digest(SOURCE/name)==value for name,value in before.items())
        report['artifact_stable']=all(digest(product/name)==value['sha256'] for name,value in inventory.items())
        if not report['source_stable'] or not report['artifact_stable']:raise ValueError('Source or artifact changed during review')
        report['expanded_bytes']=sum(v['bytes'] for v in inventory.values())
        report['passed']=True
    except Exception as exc:
        report['failure']={'type':type(exc).__name__,'message':str(exc)}
    report['log_sha256']=digest(log) if log.exists() else None
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'receipt':str(output/'receipt.json'),'passed':report['passed'],'deployable':False}),flush=True)
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
