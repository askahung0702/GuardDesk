"""Build a numbered full center/standard Agent/MIS candidate; never install.

Uses exact tested native receipts and a separate source snapshot. The only
snapshot overrides are version/UI stamps and the full machine-service build
flag; remote-only collection restrictions are NOT enabled or silently removed.
"""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,types,zipfile

S=Path(__file__).resolve().parents[1];R=S.parents[1]
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def norm(c):return c.replace(co_filename='reviewed',co_consts=tuple(norm(v) if isinstance(v,types.CodeType) else v for v in c.co_consts))
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf-8')
def pins(root):return {p.relative_to(root).as_posix():sha(p) for name in ('guarddesk','tools','native','browser-extension','tests') for p in (root/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts}

def main():
    p=argparse.ArgumentParser();p.add_argument('--version',required=True);p.add_argument('--cohort',type=Path,required=True);p.add_argument('--service',type=Path,required=True);p.add_argument('--notices',type=Path,required=True);p.add_argument('--tests',type=Path,required=True);a=p.parse_args()
    if S.name!='remote-next-src':raise ValueError('Use the isolated development source')
    from guarddesk.update_packages import version,MAX_ZIP,MAX_TOTAL,MAX_FILES,safe_name
    from guarddesk import __version__
    if version(a.version)<=version(__version__):raise ValueError('New candidate version required')
    test_path=a.tests.resolve(strict=True)
    if not test_path.is_relative_to(R/'runtime') or not json.loads(test_path.read_text())['passed']:raise ValueError('Passing source review required')
    from tools.assemble_remote_preview import receipt,NATIVE,MEDIA
    nr,nb=receipt('remote-m2-native-build-*.json');wr,wb=receipt('webrtc-owned-build-*.json',True)
    from guarddesk.remote_components import read_cohort,REMOTE_FILES,validate_layout
    C=a.cohort.resolve(strict=True);V=a.service.resolve(strict=True);N=a.notices.resolve(strict=True)
    if not all(x.is_relative_to(R/'runtime') for x in (C,V,N)):raise ValueError('Input escaped runtime')
    cohort=read_cohort(C);service=json.loads((V/'receipt.json').read_text());assert service['passed']
    assert sha(V/'Release/GuardDeskService.exe')==service['sha256']
    assert all(sha(S/n)==h for n,h in service['sources'].items())
    for name in REMOTE_FILES:
        if sha((NATIVE if name in ('GuardDeskRemoteWorker.exe','GuardDeskRemoteBridge.dll') else MEDIA)/name)!=cohort['files'][name]:
            raise ValueError('Cohort differs from latest tested native artifact; assemble after final build: '+name)
    from tools.build_dependencies import verify
    dependencies=verify(S)
    number=1
    while (R/f'runtime/remote-center-build-{number:03}').exists() or (R/f'runtime/remote-center-src-{number:03}').exists():number+=1
    B=R/f'runtime/remote-center-build-{number:03}';F=R/f'runtime/remote-center-src-{number:03}';B.mkdir();F.mkdir()
    before=pins(S)
    for name in ('guarddesk','tools','native','browser-extension','tests'):shutil.copytree(S/name,F/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name in ('app.py','mis_remote_app.py','requirements.txt','requirements-build.txt','AGENTS.md','BASELINE-MANIFEST.json','THIRD_PARTY_NOTICES.md'):shutil.copyfile(S/name,F/name)
    for name in ('guarddesk/__init__.py','guarddesk/static/index.html'):
        file=F/name;text=file.read_text(encoding='utf-8');assert __version__ in text;file.write_text(text.replace(__version__,a.version),encoding='utf-8')
    flag=F/'guarddesk/machine_service.py';text=flag.read_text();assert text.count('ENABLED = False')==1;flag.write_text(text.replace('ENABLED = False','ENABLED = True'),encoding='utf-8')
    frozen=pins(F);write(F/'SOURCE-RECEIPT.json',{'source':str(S),'files':before,'frozen':frozen,'build_overrides':['version stamps','full machine-service build flag'],'remote_only_trial':False})
    report={'passed':False,'version':a.version,'source':str(F),'cohort':cohort['build_id'],'dependencies':dependencies,'source_review_sha256':sha(test_path),'native_receipts':{nr.name:sha(nr),wr.name:sha(wr)},'service_receipt':str(V/'receipt.json'),'installed':False,'published':False,'deployable':False,'stages':[]}
    log=B/'build.log'
    try:
        env=os.environ.copy();env.update(PYTHONNOUSERSITE='1',PYTHONPATH=str(F),GUARDDESK_REMOTE_COHORT_ROOT=str(C),GUARDDESK_REMOTE_NOTICES_ROOT=str(N),GUARDDESK_REMOTE_SERVICE_ROOT=str(V),PYINSTALLER_CONFIG_DIR=str(B/'cache'))
        with log.open('x',encoding='utf-8') as out:
            for role,spec in (('MIS','GuardDeskMIS.spec'),('product','GuardDesk.spec')):
                if role=='product':env['GUARDDESK_MIS_BUILD_PATH']=str(B/'MIS/GuardDeskMIS.exe')
                result=subprocess.run([sys.executable,'-X','utf8','-m','PyInstaller','--clean','--noconfirm','--distpath',str(B/role),'--workpath',str(B/(role+'-work')),str(F/'tools'/spec)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=900)
                report['stages'].append({'role':role,'exit':result.returncode})
                if result.returncode:raise ValueError('Build failed; keep log, do not use an old executable')
        from PyInstaller.archive.readers import CArchiveReader
        A=B/'product/GuardDesk';mis=B/'MIS/GuardDeskMIS.exe';verified={}
        for name,exe in [('MIS',mis),('console',A/'GuardDesk.exe'),('agent',A/'GuardDeskAgent.exe'),('viewer',A/'_internal/GuardDeskRemote.exe')]:
            archive=CArchiveReader(str(exe));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')));modules=[]
            for module in pyz.toc:
                if module!='guarddesk' and not module.startswith('guarddesk.'):continue
                file=F/(module.replace('.','/')+'.py')
                if not file.is_file():file=F/module.replace('.','/')/'__init__.py'
                if norm(pyz.extract(module))!=norm(compile(file.read_bytes(),str(file),'exec',dont_inherit=True,optimize=0)):raise ValueError('Frozen source differs: '+module)
                modules.append(module)
            verified[name]=modules
            if name=='MIS':
                embedded={n.replace('\\','/'):n for n in archive.toc}
                for n in ('GuardDeskMisNative.dll','remote-cohort.json'):assert hashlib.sha256(archive.extract(embedded['_internal/remote/'+n])).hexdigest()==sha(C/'_internal/remote'/n)
                assert not any(n.endswith(('GuardDeskRemoteWorker.exe','GuardDeskRemoteMedia.exe','GuardDeskRemoteBridge.dll')) for n in embedded)
        assert {'guarddesk.machine_service','guarddesk.remote_service_worker','guarddesk.native_installer','guarddesk.remote_native_broker'}<=set(verified['console'])
        assert sha(A/'_internal/GuardDeskService.exe')==service['sha256'] and sha(A/'_internal/GuardDeskMIS.exe')==sha(mis)
        validate_layout(A);assert read_cohort(A)['build_id']==cohort['build_id']
        files={q.relative_to(A).as_posix():{'sha256':sha(q),'bytes':q.stat().st_size} for q in A.rglob('*') if q.is_file()}
        for name in files:safe_name(name)
        from guarddesk.endpoint_payload import project,entry
        projection,overrides=project(A,{n:v['sha256'] for n,v in files.items()});preview=B/'unsigned-endpoint-review-only.zip'
        with zipfile.ZipFile(preview,'x',zipfile.ZIP_DEFLATED) as z:
            for name,wanted in sorted(projection.items()):
                digest=hashlib.sha256()
                with entry(A,name,overrides) as stream,z.open(name,'w') as writer:
                    while chunk:=stream.read(65536):digest.update(chunk);writer.write(chunk)
                assert digest.hexdigest()==wanted
        size={'compressed_bytes':preview.stat().st_size,'incoming_bytes':sum(len(overrides[n]) if n in overrides else files[n]['bytes'] for n in projection),'files':len(projection)}
        assert size['compressed_bytes']<=MAX_ZIP and size['incoming_bytes']<=MAX_TOTAL and size['files']<=MAX_FILES
        assert '_internal/GuardDeskService.exe' in projection and '_internal/GuardDeskMIS.exe' not in projection
        from tools.remote_baseline import verify as baseline
        _,history=baseline(json.loads((S/'BASELINE-MANIFEST.json').read_text()),R)
        report.update(files=files,endpoint_files=projection,MIS={'sha256':sha(mis),'bytes':mis.stat().st_size},frozen_PYZ_sources=verified,publication_capacity=size,baseline_evidence=history)
        for args in (['component-info'],['server-setup','--help'],['remote-service-worker','--help'],['endpoint-setup','--help']):
            result=subprocess.run([str(A/'GuardDesk.exe'),*args],capture_output=True,timeout=30);assert result.returncode==0
            if args==['component-info']:assert json.loads(result.stdout)=={'version':a.version,'update_protocol':1,'architecture':'windows-x64'}
        probe=B/'frozen-removal.json'
        with log.open('a',encoding='utf-8') as out:
            gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_remote_removal.py'),'--product',str(A),'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen removal contract did not pass')
        report['frozen_removal_gate']=str(probe)
        probe=B/'frozen-software.json'
        with log.open('a',encoding='utf-8') as out:
            gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_software_deployment.py'),'--product',str(A),'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen MSI deployment contract did not pass')
        report['frozen_software_gate']=str(probe)
        probe=B/'frozen-reinstall.json'
        with log.open('a',encoding='utf-8') as out:
            gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_endpoint_reinstall.py'),'--product',str(A),'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen reinstall boundary did not pass')
        report['frozen_reinstall_gate']=str(probe)
        probe=B/'frozen-display-diagnostics.json'
        with log.open('a',encoding='utf-8') as out:
            gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_remote_display_diagnostics.py'),'--product',str(A),'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen remote display diagnostics did not pass')
        report['frozen_display_diagnostic_gate']=str(probe)
        probe=B/'frozen-update-capacity.json'
        with log.open('a',encoding='utf-8') as out:
            gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_update_capacity.py'),'--product',str(A),'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
        if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen capacity/explicit upgrade boundary did not pass')
        report['frozen_update_capacity_gate']=str(probe)
        report['frozen_lifecycle_gates']={}
        for role,exe in (('product',A/'GuardDesk.exe'),('mis',mis)):
            probe=B/('frozen-lifecycle-'+role+'.json')
            with log.open('a',encoding='utf-8') as out:
                gate=subprocess.run([sys.executable,'-X','utf8',str(F/'tools/probe_remote_lifecycle.py'),
                    '--exe',str(exe),'--role',role,'--report',str(probe)],cwd=F,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
            if gate.returncode or not json.loads(probe.read_text())['passed']:raise ValueError('Frozen lifecycle boundary did not pass: '+role)
            report['frozen_lifecycle_gates'][role]=str(probe)
        report['source_stable']=pins(S)==before and pins(F)==frozen
        assert report['source_stable'];report['passed']=True
    except Exception as error:report['failure']={'type':type(error).__name__,'message':str(error)}
    report['log_sha256']=sha(log) if log.exists() else None;write(B/'receipt.json',report)
    print(json.dumps({'receipt':str(B/'receipt.json'),'passed':report['passed'],'deployable':False}));raise SystemExit(not report['passed'])

if __name__=='__main__':main()
