"""Create the requested private single-home-PC trial center and exact download.

Fixed reviewed 0.4.77 candidate only. No installed Agent, firewall, CA store,
Defender, desktop, UAC, company data or startup tasks are operated here.
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
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

WORKSPACE=Path(__file__).resolve().parents[3]
RUNTIME=WORKSPACE/'runtime'
SOURCE=RUNTIME/'remote-trial-src-002'
PRODUCT=RUNTIME/'remote-next-product-003/product/GuardDesk'
ADDRESS='192.168.50.30'
PORT=17887
CONSOLE=17888


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--create-authorized-home-trial',action='store_true',required=True)
    args=parser.parse_args()
    if os.name!='nt':raise ValueError('Owned Windows development host required')
    sys.path[:0]=[str(SOURCE),str(SOURCE/'.build-deps/remote')]
    from guarddesk import __version__,remote_trial
    from guarddesk.server_setup import secure_directory,create
    from guarddesk.remote_preview_config import prepare
    from guarddesk.server_config import load,check
    from guarddesk.source_permissions import WindowsSecurity,validate_descriptor,SYSTEM,ADMINISTRATORS,TRUSTED_INSTALLER
    from tools.build_remote_product_preview import inspect_pyz
    if __version__!='0.4.77' or not remote_trial.enabled():raise ValueError('Exact compiled trial source required')
    built_path=PRODUCT.parents[1]/'receipt.json'
    built=json.loads(built_path.read_text(encoding='utf-8'))
    if not built.get('passed') or not built.get('source_stable'):raise ValueError('Reviewed frozen build required')
    for name,item in built['files'].items():
        if digest(PRODUCT/name)!=item['sha256']:raise ValueError('Product changed: '+name)
    for receipt in ('remote-trial-frozen-001.json','remote-next-frozen-center-002/receipt.json'):
        if not json.loads((RUNTIME/receipt).read_text()).get('passed'):raise ValueError('Missing frozen validation')
    # Binding the exact local NIC also rejects a stale address or occupied port.
    for host,port in ((ADDRESS,PORT),('127.0.0.1',CONSOLE)):
        with socket.socket() as probe:probe.bind((host,port))
    parent=Path(os.environ['LOCALAPPDATA']).resolve(strict=True)
    if parent!=Path('C:/Users/dev/AppData/Local'):raise ValueError('Unexpected development account')
    api=WindowsSecurity();allowed={SYSTEM,ADMINISTRATORS,TRUSTED_INSTALLER,api.current_user()}
    for item in (parent,*parent.parents):
        if item.is_symlink() or getattr(item.stat(),'st_file_attributes',0)&0x400:raise ValueError('Reparse ancestor')
        owner,entries=api.descriptor(item)
        entries=[(k,f,m,owner if sid=='S-1-3-4' else sid) for k,f,m,sid in entries]
        validate_descriptor(item,owner,entries,allowed,ancestor=True)
    number=1
    while (parent/f'GuardDeskRemoteTrial-20261101-{number:03}').exists():number+=1
    root=secure_directory(parent/f'GuardDeskRemoteTrial-20261101-{number:03}')
    receipt=RUNTIME/f'remote-home-trial-{number:03}.json'
    if receipt.exists():raise ValueError('Receipt collision; preserve both')
    report={'format':1,'version':__version__,'profile':remote_trial.PROFILE,'passed':False,
            'private_root':str(root),'endpoint_url':f'https://{ADDRESS}:{PORT}',
            'console_url':f'http://127.0.0.1:{CONSOLE}',
            'built_receipt_sha256':digest(built_path),'company_product_changed':False,
            'installed_endpoint':False,'firewall_changed':False,'defender_changed':False,
            'CA_store_changed':False,'startup_task_created':False,'desktop_capture':False,
            'OS_input':False,'full_MIS_UAC_acceptance':False,'home_HTTPS_verified':False,
            'home_media_UDP_verified':False,'formal_release':False,'deployable':False,'phases':[]}
    proc=None;log=None
    try:
        program=root/'program';shutil.copytree(PRODUCT,program)
        for name,item in built['files'].items():
            if digest(program/name)!=item['sha256']:raise ValueError('Private program copy differs')
        password='Trial!'+secrets.token_hex(24)+'A1';username='remote-test-admin'
        created=create(root/'data',ADDRESS,username,password,exe=program/'GuardDesk.exe',port=PORT,console_port=CONSOLE)
        config=Path(created['config']);settings=json.loads(config.read_text())
        settings['host']=ADDRESS
        settings['remote_native']={'enabled':True,'console_ipv4':[ADDRESS]}
        config.write_text(json.dumps(settings,indent=2),encoding='utf-8')
        prepared=load(config);check(prepared);native=prepare(prepared['remote_native'])
        if not native['enabled'] or native['console_ipv4']!=[ADDRESS]:raise ValueError('Native opt-in not applied')
        # The administrator secret remains inside this private directory only.
        (root/'operator-credentials.json').write_text(json.dumps({'username':username,'password':password,'console':created['console']}),encoding='utf-8')
        report['phases'].append('private_path_real_ACL_config_and_TLS_verified')
        log=(root/'center.log').open('x',encoding='utf-8')
        proc=subprocess.Popen([str(program/'GuardDesk.exe'),'serve','--config',str(config)],
            cwd=root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        log.close();log=None
        import psutil
        process_created=psutil.Process(proc.pid).create_time()
        report.update(server_pid=proc.pid,server_process_created=process_created,server_executable=str(program/'GuardDesk.exe'))
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        csrf=None
        def request(path,body=None,timeout=5):
            data=None if body is None else json.dumps(body).encode()
            headers={'Content-Type':'application/json'}
            if csrf:headers['X-CSRF-Token']=csrf
            return opener.open(urllib.request.Request(created['console']+path,data=data,headers=headers),timeout=timeout)
        deadline=time.monotonic()+90
        while True:
            if proc.poll() is not None:raise RuntimeError('Owned center exited; preserve private log')
            try:
                with request('/api/health',timeout=1) as response:json.load(response)
                break
            except (OSError,ValueError):
                if time.monotonic()>deadline:raise TimeoutError('Owned console startup')
                time.sleep(.2)
        context=ssl.create_default_context(cafile=str(root/'data/tls/ca.pem'))
        tls=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        with tls.open(created['endpoint']+'/api/health',timeout=5) as response:json.load(response)
        # Network agent port must never expose the management surface.
        try:tls.open(created['endpoint']+'/api/fleet',timeout=5)
        except urllib.error.HTTPError as error:
            if error.code!=403:raise
        else:raise ValueError('Management API exposed on agent port')
        with request('/api/login',{'username':username,'password':password}) as response:csrf=json.load(response)['csrf']
        report['phases'].append('actual_frozen_TLS_localhost_login_and_agent_surface_verified')
        # Publisher owns the same package lock as the download endpoint. Wait
        # for its observable ready state rather than racing startup or removing
        # the production concurrency limit (initial attempt correctly got429).
        deadline=time.monotonic()+120
        while True:
            with request('/api/updates') as response:catalog=json.load(response)
            publication=catalog['bundled_release']
            if publication['status']=='ready':break
            if publication['status'] in ('failed','server_only','not_packaged'):
                raise RuntimeError('Owned publication not ready: '+publication['status'])
            if time.monotonic()>deadline:raise TimeoutError('Owned Publisher readiness')
            time.sleep(.5)
        report['phases'].append('actual_frozen_publisher_ready')
        downloads={}
        for name,path in (('GuardDesk-RemoteTrial-0.4.77-Endpoint.zip','/api/endpoint-package'),('GuardDesk-RemoteTrial-0.4.77-MIS.exe','/api/mis-support-executable')):
            target=root/name
            with request(path,{},timeout=120) as response,target.open('xb') as out:
                total=0
                while chunk:=response.read(65536):
                    total+=len(chunk)
                    if total>64*1024*1024:raise ValueError('Download limit exceeded')
                    out.write(chunk)
            downloads[name]={'sha256':digest(target),'bytes':total}
        target=root/'GuardDesk-RemoteTrial-0.4.77-Endpoint.zip'
        with zipfile.ZipFile(target) as z:
            endpoint=json.loads(z.read('endpoint-files.json'))['files']
            if endpoint!=built['endpoint_files']:raise ValueError('Downloaded projection mismatch')
            for name,expected in endpoint.items():
                if hashlib.sha256(z.read('GuardDesk/'+name)).hexdigest()!=expected:raise ValueError('Downloaded content mismatch')
            connection=json.loads(z.read('endpoint-connection.json'))
            if connection['server']!=created['endpoint'] or connection['ca_sha256']!=hashlib.sha256(z.read('GuardDesk-CA.pem')).hexdigest():raise ValueError('Wrong trial TLS connection')
            if 'browser_deployment' in connection or 'browser-trust.json' in z.namelist():raise ValueError('Browser configuration in trial package')
            for name in ('Setup-Endpoint.cmd','Uninstall-Remote-Test.cmd','README-Remote-Test.txt'):
                if name not in z.namelist():raise ValueError('Missing trial entry: '+name)
            if any(n.endswith(('.key','.sqlite3')) or 'credentials' in n for n in z.namelist()):raise ValueError('Private center material in installer')
        _,modules=inspect_pyz(root/'GuardDesk-RemoteTrial-0.4.77-MIS.exe',('guarddesk.mis_native_media','guarddesk.remote_components'))
        report.update(downloads=downloads,MIS_exact_modules=len(modules))
        report['phases'].append('authenticated_actual_download_and_all_package_files_verified')
        # This linkable delivery directory contains only endpoint bootstrap and
        # public trust; never database, operator password or private keys.
        delivery=secure_directory(WORKSPACE/'dist'/f'RemoteTrial-0.4.77-home-{number:03}')
        shutil.copyfile(target,delivery/target.name)
        if digest(delivery/target.name)!=downloads[target.name]['sha256']:raise ValueError('Delivery copy changed')
        (delivery/'SHA256.txt').write_text(downloads[target.name]['sha256']+'  '+target.name+'\n',encoding='ascii')
        (delivery/'README.txt').write_text(
            'GuardDesk 0.4.77 僅遠端內部試用（未簽章，非正式發布）\n'
            '只用於本次未裝過 GuardDesk 的家用 Windows 11 x64；不要群派公司端點。\n'
            f'連上VPN；先確認 Test-NetConnection {ADDRESS} -Port {PORT} -InformationLevel Quiet 回 True。\n'
            '將ZIP複製到家裡電腦後完整解壓，正常雙擊 Setup-Endpoint.cmd，核對後允許UAC。\n'
            '不關閉Defender／SmartScreen；若被偵測或阻擋，保留訊息並停止測試。\n'
            '只測遠端：不收集文件／瀏覽／程式稽核、不盤點軟體、不套控制、不自動更新、不安裝系統CA。\n'
            '仍回報必要裝置及登入工作階段識別與就緒狀態；協助期間傳送畫面、游標及操作。\n'
            '每次協助需你同意。真正UAC操作另約測試，不要把帳密貼入對話或報告。\n'
            '結束先按停止協助，再以原帳號執行 Uninstall-Remote-Test.cmd。檔案／標記保留，\n'
            '子程序完整排空與卸載後直接重裝仍待驗證，切勿將移除回覆當成已清乾淨。\n'
            '目前單一未旋轉螢幕、最多1080p；VPN UDP、UAC、效能與完整生命週期尚未驗收。\n'
            '此包含僅測試中心使用的註冊碼，請勿轉交他人。公司Server不用更新。\n',encoding='utf-8-sig')
        report.update(passed=True,delivery=str(delivery),server_running=proc.poll() is None)
        if not report['server_running']:raise RuntimeError('Owned server stopped before delivery')
    except Exception as error:
        report['passed']=False;report['failure']={'type':type(error).__name__,'message':str(error)}
        if proc is not None:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        report['server_running']=False
    finally:
        if log:log.close()
        with receipt.open('x',encoding='utf-8') as out:json.dump(report,out,indent=2)
    print(json.dumps({'receipt':str(receipt),'passed':report['passed'],'server_running':report['server_running'],
                      'delivery':report.get('delivery'),'deployable':False}))
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
