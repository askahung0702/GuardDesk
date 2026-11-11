"""Run a real frozen center on localhost and inspect its own actual downloads.

Only new private workspace fixtures. Never enrolls an endpoint, installs tasks,
captures a screen, sends input, imports a CA or touches company data/settings.
Old protocol verification runs extracted bytecode, not the installed updater.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
import types
import urllib.request
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.remote_checkpoint_receipts import SOURCE,WORKSPACE,RUNTIME,digest
from tools.build_remote_product_preview import inspect_pyz,normalize

def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def main():
    p=argparse.ArgumentParser();p.add_argument('--owned-product',type=Path,required=True);p.add_argument('--private-local-appdata',action='store_true');args=p.parse_args()
    from tools.development_host_policy import require_center_test_host
    require_center_test_host(WORKSPACE)
    origin=args.owned_product.resolve(strict=True)
    if not origin.is_relative_to(RUNTIME) or origin.name!='GuardDesk':raise ValueError('Owned product path required')
    receipt=origin.parents[1]/'receipt.json';built=json.loads(receipt.read_text(encoding='utf-8'))
    if not built['passed']:raise ValueError('Product build review did not pass')
    for name,item in built['files'].items():
        if digest(origin/name)!=item['sha256']:raise ValueError('Reviewed product bytes changed')
    base=RUNTIME
    prefix='remote-next-frozen-center-'
    if args.private_local_appdata:
        if os.name!='nt':raise ValueError('Windows private fixture required')
        base=Path(os.environ['LOCALAPPDATA']).resolve(strict=True);prefix='GuardDeskOwnedCenterCheck-'
    number=1
    while (base/f'{prefix}{number:03}').exists():number+=1
    from guarddesk.server_setup import secure_directory,create
    root=secure_directory(base/f'{prefix}{number:03}')
    report={'format':1,'passed':False,'product_receipt_sha256':digest(receipt),'company_product_changed':False,
        'installed_endpoint':False,'actual_SYSTEM_updater_executed':False,'full_MIS_UAC_acceptance':False,'deployable':False,'phases':[]}
    proc=None;log=root/'center.log'
    try:
        private=secure_directory(root/'program');application=private/'GuardDesk';shutil.copytree(origin,application)
        password='Owned!'+secrets.token_hex(20)+'A1';agent_port=port();console_port=port()
        if agent_port==console_port:console_port=port()
        created=create(root/'data','owned-remote.invalid','owned-mis',password,exe=application/'GuardDesk.exe',port=agent_port,console_port=console_port,native_console_ipv4=['10.20.30.40'])
        config=Path(created['config']);value=json.loads(config.read_text(encoding='utf-8'));value['host']='127.0.0.1';config.write_text(json.dumps(value),encoding='utf-8')
        from guarddesk.machine_service import enabled as full_service
        if full_service():
            if value.get('remote_native')!={'enabled':True,'console_ipv4':['10.20.30.40']}:raise ValueError('Fresh full center did not opt into native remote')
            from guarddesk.server_config import load
            from guarddesk.remote_preview_config import prepare
            prepared=prepare(load(config)['remote_native'])
            if not prepared['enabled']:raise ValueError('Protected native configuration did not activate')
            report['native_preview_configuration_and_real_ACL_verified']=True
        report['phases'].append('owned_private_setup')
        with log.open('x',encoding='utf-8') as stream:
            proc=subprocess.Popen([str(application/'GuardDesk.exe'),'serve','--config',str(config)],cwd=root,stdout=stream,stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));url=created['console'];csrf=None
            def request(path,body=None,timeout=5):
                data=None if body is None else json.dumps(body).encode()
                headers={'Content-Type':'application/json'}
                if csrf:headers['X-CSRF-Token']=csrf
                return opener.open(urllib.request.Request(url+path,data=data,headers=headers),timeout=timeout)
            limit=time.monotonic()+90
            while True:
                if proc.poll() is not None:raise RuntimeError('Owned frozen center exited during startup')
                try:
                    with request('/api/health',timeout=1) as response:health=json.load(response)
                    break
                except (OSError,ValueError):
                    if time.monotonic()>=limit:raise TimeoutError('Owned frozen center startup')
                    time.sleep(.1)
            with request('/api/login',{'username':'owned-mis','password':password}) as response:csrf=json.load(response)['csrf']
            report['phases'].append('real_frozen_login')
            limit=time.monotonic()+90
            while True:
                with request('/api/updates') as response:catalog=json.load(response)
                state=catalog['bundled_release']
                if state['status']=='ready':break
                if state['status'] in ('failed','server_only','not_packaged'):raise RuntimeError('Owned publisher did not prepare an endpoint release: '+state['status'])
                if time.monotonic()>=limit:raise TimeoutError('Owned frozen publisher')
                time.sleep(.2)
            report['phases'].append('real_frozen_publisher_ready')
            downloads={}
            for name,path in (('endpoint.zip','/api/endpoint-package'),('mis.exe','/api/mis-support-executable')):
                target=root/('downloaded-'+name)
                with request(path,{},timeout=90) as response,target.open('xb') as output:
                    total=0
                    while chunk:=response.read(65536):
                        total+=len(chunk)
                        if total>64*1024*1024:raise ValueError('Owned download exceeded existing package limit')
                        output.write(chunk)
                downloads[name]={'sha256':digest(target),'bytes':total}
            with zipfile.ZipFile(root/'downloaded-endpoint.zip') as z:
                endpoint=json.loads(z.read('endpoint-files.json'))['files']
                if endpoint!=built['endpoint_files']:raise ValueError('Actual downloaded endpoint differs from reviewed projection')
                if 'GuardDesk/_internal/GuardDeskMIS.exe' in z.namelist():raise ValueError('MIS duplicated in downloaded endpoint')
                for name,expected in endpoint.items():
                    if hashlib.sha256(z.read('GuardDesk/'+name)).hexdigest()!=expected:raise ValueError('Downloaded endpoint file changed: '+name)
                inner=json.loads(z.read('GuardDesk/_internal/agent-release.json'))
                if inner['files']!={n:h for n,h in endpoint.items() if n!='_internal/agent-release.json'}:raise ValueError('Downloaded inner manifest differs')
            archive,mis_modules=inspect_pyz(root/'downloaded-mis.exe',('guarddesk.mis_native_media','guarddesk.remote_relay','guarddesk.remote_components'))
            names={n.replace('\\','/'):n for n in archive.toc}
            embedded=archive.extract(names['_internal/remote/remote-cohort.json'])
            if hashlib.sha256(embedded).hexdigest()!=digest(application/'_internal/remote/remote-cohort.json'):raise ValueError('Downloaded MIS has different cohort')
            report['phases'].append('actual_authenticated_endpoint_and_MIS_downloads')
            from guarddesk.store import Store,canonical
            from guarddesk import updates,update_packages as packages
            store=Store(root/'data/control.sqlite3')
            with store.connect() as db:
                row=db.execute('SELECT envelope FROM update_releases').fetchone();envelope=json.loads(row[0])
                counts={'devices':db.execute('SELECT count(*) FROM devices').fetchone()[0],'update_jobs':db.execute('SELECT count(*) FROM update_jobs').fetchone()[0]}
            if counts!={'devices':0,'update_jobs':0}:raise ValueError('Owned review unexpectedly created an endpoint/job')
            public=packages.public_key(packages.signer(root/'data'));signed=packages.verify(envelope,public)
            package=updates.repository(store)/(signed['sha256']+'.zip')
            if signed['files']!=built['endpoint_files']:raise ValueError('Actual frozen Publisher signature differs from endpoint download')
            with zipfile.ZipFile(package) as z:packages.inspect_zip(z,signed['files'])
            # Exact old sealed bytecode, only protocol verification/extraction.
            from PyInstaller.archive.readers import CArchiveReader
            old_path=WORKSPACE/'dist/archive/releases/GuardDesk-0.4.66-windows-x64.zip'
            expected_old='1141339ab3445e16c1124c3065e8976ffbca98ec1b91e2e0a6dabc0c1e9015f2'
            if digest(old_path)!=expected_old:raise ValueError('Sealed old executor archive changed')
            old_exe=root/'old-066-not-executed.exe'
            with zipfile.ZipFile(old_path) as z:old_exe.write_bytes(z.read('GuardDesk/GuardDesk.exe'))
            old=CArchiveReader(str(old_exe)).open_embedded_archive('PYZ.pyz')
            canonical_code=next(v for v in old.extract('guarddesk.store').co_consts if isinstance(v,types.CodeType) and v.co_name=='canonical')
            old_canonical=types.FunctionType(canonical_code,{'json':json})
            # Execute the exact old serializer too. Current serialization rejects
            # NaN; protocol manifests have finite, validated values. Compare this
            # actual signed payload, not unrelated code line numbers/options.
            if old_canonical(envelope['payload'])!=canonical(envelope['payload']):raise ValueError('Actual signed payload differs under old serializer')
            module=types.ModuleType('guarddesk.owned_old_packages');module.__package__='guarddesk'
            exec(old.extract('guarddesk.update_packages'),module.__dict__)
            module.canonical=old_canonical
            old_manifest=module.validate_manifest(module.verify(envelope,public));destination=root/'old-066-owned-extraction'
            module.extract(package,old_manifest,destination)
            if any(digest(destination/n)!=h for n,h in old_manifest['files'].items()):raise ValueError('Old frozen protocol extraction differs')
            report.update(downloads=downloads,MIS_frozen_sources=mis_modules,counts=counts,
                signed_payload={'sha256':digest(package),'bytes':package.stat().st_size,'files':len(signed['files'])},
                old_frozen_protocol={'version':'0.4.66','sealed_archive_sha256':expected_old,'signature_and_extraction_passed':True,'scope':'Actual extracted old bytecode; no old process/SYSTEM tasks/installed files were operated'})
            report['phases'].append('old_frozen_protocol_signature_and_extraction');report['passed']=True
    except Exception as error:report['failure']={'type':type(error).__name__,'message':str(error)}
    finally:
        if proc is not None:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        report['owned_server_stopped']=proc is None or proc.poll() is not None
        report['log_sha256']=digest(log) if log.exists() else None
        with (root/'receipt.json').open('x',encoding='utf-8') as output:json.dump(report,output,indent=2);output.write('\n')
    print(json.dumps({'receipt':str(root/'receipt.json'),'passed':report['passed'],'deployable':False}))
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
