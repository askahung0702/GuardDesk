"""Verify compiled trial guards in owned frozen bytes; no install or desktop."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--owned-source',type=Path,required=True)
    parser.add_argument('--owned-product',type=Path,required=True)
    args=parser.parse_args()
    workspace=Path(__file__).resolve().parents[3];runtime=workspace/'runtime'
    source=args.owned_source.resolve(strict=True);product=args.owned_product.resolve(strict=True)
    if not source.is_relative_to(runtime) or not source.name.startswith('remote-trial-src-'):
        raise ValueError('Owned compiled trial source required')
    if not product.is_relative_to(runtime) or product.name!='GuardDesk':raise ValueError('Owned product required')
    sys.path.insert(0,str(source))
    from tools.build_remote_product_preview import inspect_pyz
    build_path=product.parents[1]/'receipt.json';build=json.loads(build_path.read_text())
    if not build.get('passed'):raise ValueError('Product receipt not passed')
    for name,item in build['files'].items():
        if digest(product/name)!=item['sha256']:raise ValueError('Product changed: '+name)
    from guarddesk import remote_trial
    from guarddesk import __version__
    if not remote_trial.enabled():raise ValueError('Source is not compiled trial')
    number=1
    while (runtime/f'remote-trial-frozen-{number:03}.json').exists():number+=1
    report={'format':1,'passed':False,'source':str(source),'build_receipt_sha256':digest(build_path),
            'company_changed':False,'installed':False,'desktop_capture':False,'OS_input':False,
            'network_requests':False,'deployable':False,'checks':[]}
    try:
        for relative in ('GuardDesk.exe','GuardDeskAgent.exe','_internal/GuardDeskRemote.exe'):
            archive,modules=inspect_pyz(product/relative,('guarddesk.remote_trial','guarddesk.remote_trial_install'))
            pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
            module=types.ModuleType('guarddesk.owned_frozen_trial');module.__package__='guarddesk'
            exec(pyz.extract('guarddesk.remote_trial'),module.__dict__)
            if module.ENABLED is not True:raise ValueError('Frozen trial flag is not true')
            for command in ('endpoint-setup','endpoint-native-install','usb-worker','machine-session','endpoint-uninstall'):
                module.command_allowed(command)
            for command in ('agent','desktop-agent','update-service','apply-user-update','browser-install','windows-install','enroll'):
                try:module.command_allowed(command)
                except PermissionError:pass
                else:raise ValueError('Frozen forbidden command accepted: '+command)
            report['checks'].append({'image':relative,'exact_modules':len(modules),'compiled_trial_guards':True})
        executable=product/'GuardDesk.exe'
        result=subprocess.run([str(executable),'component-info'],capture_output=True,timeout=30)
        if result.returncode or json.loads(result.stdout)['version']!=__version__:raise ValueError('Frozen component info failed')
        report['checks'].append({'command':'component-info','exit':0,'version':__version__})
        absent=runtime/'owned-trial-intentionally-absent'/'config.json'
        if absent.exists():raise ValueError('Negative fixture unexpectedly exists')
        for command in ('agent','desktop-agent','update-service'):
            result=subprocess.run([str(executable),command,'--config',str(absent)],capture_output=True,timeout=30)
            message=result.stderr.decode('utf-8',errors='replace')
            if result.returncode==0 or 'This remote-only trial disables collection' not in message:
                raise ValueError('Frozen CLI did not reject before config access: '+command)
            report['checks'].append({'command':command,'rejected_before_config':True,'exit':result.returncode})
        report['passed']=True
    except Exception as error:report['failure']={'type':type(error).__name__,'message':str(error)}
    output=runtime/f'remote-trial-frozen-{number:03}.json'
    output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'receipt':str(output),'passed':report['passed'],'deployable':False}))
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
