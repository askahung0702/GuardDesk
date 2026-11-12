"""Complete internal management package. Fail closed; never install or deploy."""
from pathlib import Path
import argparse,contextlib,json,msvcrt,os,re,shutil,subprocess,sys,time,uuid
from worktree import contained,digest,environment,files,python,stage,webrtc_source
from management_package import package,publish,scan,verify_zip,write
from native_inputs import prepare
from restore_release_inputs import restore
ROOT=Path(__file__).resolve().parents[1]

def version(value):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):raise ValueError('Numeric x.y.z version required')
    return tuple(map(int,value.split('.')))

def output_path(root,value,revision):
    baseline=json.loads((root/'CURRENT-BASELINE.json').read_text(encoding='utf-8'))
    contract=json.loads((root/'DEVELOPMENT-BASELINE.json').read_text(encoding='utf-8'))
    if contract['accepted_version']!=baseline['version'] or contract['accepted_revision']!=baseline['revision']:
        raise ValueError('Development baseline contract differs; reconcile before building')
    if version(value)<=version(baseline['version']):raise ValueError('Use a version newer than the sealed accepted baseline')
    if not re.fullmatch('[0-9]{3}',revision) or revision=='000':raise ValueError('Revision must be 001..999')
    target=contained(root,root/f'dist/GuardDesk-Management-{value}-internal-{revision}.zip')
    if target.exists() or target.with_suffix('.zip.sha256').exists():raise ValueError('Output already exists; never overwrite')
    return target,baseline

@contextlib.contextmanager
def build_lock(root):
    folder=contained(root,root/'runtime');folder.mkdir(exist_ok=True)
    with (folder/'management-build.lock').open('a+b') as stream:
        stream.seek(0);stream.write(b'0');stream.flush();stream.seek(0)
        try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
        except OSError as exc:raise ValueError('Another management build holds this checkout') from exc
        try:yield
        finally:stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)

def one_new(root,pattern,before):
    found=set(root.glob(pattern))-before
    if len(found)!=1:raise ValueError('Expected exactly one new receipt: '+pattern)
    return found.pop()

def passing(path):
    body=json.loads(path.read_text(encoding='utf-8'))
    if body.get('passed') is not True:raise ValueError('Gate did not pass: '+str(path))
    return body

def prerequisites(root,args):
    target,baseline=output_path(root,args.version,args.revision);python(root)
    lock=json.loads((root/'dependencies/management-package.lock.json').read_text())
    if digest(Path(lock['compiler']))!=lock['compiler_sha256']:raise ValueError('Reviewed C# compiler differs')
    restore(root,args.artifact_root or root,json.loads((root/'dependencies/release-inputs.lock.json').read_text()),False)
    artifact=Path(args.artifact_root or root)/baseline['artifact']['path']
    if digest(artifact)!=baseline['artifact']['sha256']:raise ValueError('Accepted baseline package differs')
    if args.reuse_native_from:
        if getattr(args,'webrtc_source',None) is not None:raise ValueError('Choose native cache or WebRTC source rebuild, not both')
        prepare(root,root/'source',args.reuse_native_from,json.loads((root/'dependencies/native-cache.lock.json').read_text()),False)
    else:
        webrtc_source(root,getattr(args,'webrtc_source',None))
        for name in ('2019','2026'):
            if not Path(f'C:/Program Files (x86)/Microsoft Visual Studio/{name}/BuildTools').exists():raise ValueError('Approved VS'+name+' Build Tools required')
    defender=Path(os.environ.get('ProgramData','C:/ProgramData'))/'Microsoft/Windows Defender/Platform/CurrentVersion/MpCmdRun.exe'
    if not defender.is_file():raise ValueError('Normal Defender scanner required')
    return target

class Pipeline:
    def __init__(self,root,run,exe,source,env,report):
        self.root=root;self.run=run;self.exe=exe;self.source=source;self.env=env;self.report=report
    def command(self,name,args,timeout=1200,cwd=None):
        print('Stage: '+name,flush=True);entry={'stage':name,'passed':False,'log':name+'.log'}
        self.report['stages'].append(entry);write_progress(self.run,self.report)
        with (self.run/entry['log']).open('xb') as log:
            result=subprocess.run([str(x) for x in args],cwd=cwd or self.source,env=self.env,
                stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        entry['exit_code']=result.returncode;entry['passed']=result.returncode==0
        entry['log_sha256']=digest(self.run/entry['log']);write_progress(self.run,self.report)
        if result.returncode:raise ValueError('Stage failed: '+name+'; read '+entry['log'])
    def module(self,name,module,*args,**kwargs):self.command(name,[self.exe,'-X','utf8','-m',module,*args],**kwargs)
    def new(self,name,pattern,args,timeout=1200):
        before=set((self.root/'runtime').glob(pattern));self.command(name,args,timeout)
        return one_new(self.root/'runtime',pattern,before)

def write_progress(run,report):
    temp=run/'progress.tmp';temp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temp.replace(run/'progress.json')

def execute(root,args):
    target,baseline=output_path(root,args.version,args.revision)
    exe=python(root);source,staged=stage(root);env=environment(root)
    # Ambient receipt/cohort variables must never silently select another build.
    for key in list(env):
        if key.startswith(('GUARDDESK_NATIVE_','GUARDDESK_MEDIA_','GUARDDESK_SOURCE_','GUARDDESK_TEST_COHORT','GUARDDESK_REMOTE_')):env.pop(key)
    env.pop('GUARDDESK_WEBRTC_SOURCE',None)
    if not args.reuse_native_from:env['GUARDDESK_WEBRTC_SOURCE']=str(webrtc_source(root,getattr(args,'webrtc_source',None)))
    # Keep the actual ZIP/ACL fixture below legacy Win32 MAX_PATH even in a deep checkout.
    run=contained(root,root/('runtime/management-build-'+uuid.uuid4().hex[:8]))
    run.mkdir();before=files(root/'source');baseline_before=digest(root/'CURRENT-BASELINE.json')
    report={'format':1,'workflow':'management-build-v1','version':args.version,'revision':args.revision,
        'accepted_baseline':baseline['version']+'/'+baseline['revision'],'passed':False,'stages':[],
        'local_center_started':False,'Agent_installed':False,'field_changed':False,'signed':False,
        'deployable':False,'native_mode':'verified_cache' if args.reuse_native_from else 'rebuild',
        'baseline_promoted':False,'started':time.time(),'canonical_source_hashes':before}
    pipeline=Pipeline(root,run,exe,source,env,report)
    try:
        pipeline.command('source-check',[exe,root/'dev/validate_source.py'])
        pipeline.command('dependencies',[exe,'-c','from pathlib import Path;from tools.build_dependencies import verify;print(verify(Path.cwd()))'])
        lock=json.loads((root/'dependencies/release-inputs.lock.json').read_text())
        report['release_inputs']=restore(root,args.artifact_root or root,lock,True)
        original=contained(args.artifact_root or root,Path(args.artifact_root or root)/baseline['artifact']['path'])
        if digest(original)!=baseline['artifact']['sha256']:raise ValueError('Accepted 105 package hash differs or unavailable')
        copied=run/'accepted-baseline.zip';shutil.copyfile(original,copied)
        if digest(copied)!=baseline['artifact']['sha256']:raise ValueError('Baseline copy differs')
        pipeline.command('notices',[exe,root/'dev/prepare_notices.py'])
        if args.reuse_native_from:
            selection,proof=prepare(root,source,args.reuse_native_from,json.loads((root/'dependencies/native-cache.lock.json').read_text()))
            service=Path(selection.pop('service'));env.update(selection);report['native_inputs']=proof
        else:
            # Tools are explicit prerequisites; never download or install them here.
            report['webrtc_source']=env['GUARDDESK_WEBRTC_SOURCE']
            native=pipeline.new('native','remote-m2-native-build-*.json',[exe,'-m','tools.build_remote_native','--owned-tests'])
            media=pipeline.new('webrtc','webrtc-owned-build-*.json',[exe,'-m','tools.build_remote_webrtc','--run-owned-ui-tests'],7200)
            service_receipt=pipeline.new('service','remote-service-build-*/receipt.json',[exe,'-m','tools.build_remote_service'])
            service=service_receipt.parent
            env.update(GUARDDESK_NATIVE_RECEIPT=str(native),GUARDDESK_MEDIA_RECEIPT=str(media))
            passing(native);passing(media);passing(service_receipt)
        pipeline.module('native-input-validation','tools.assemble_remote_preview','--assemble-owned')
        # Match the exact cohort named by this invocation's JSON, not latest glob.
        cohort_json=json.loads((run/'native-input-validation.log').read_text(encoding='utf-8').splitlines()[-1])
        cohort=contained(root,Path(cohort_json['snapshot']));env['GUARDDESK_TEST_COHORT']=str(cohort)
        pipeline.module('document','tools.build_document_trace')
        unit_before=set((root/'runtime/test-results').glob('unit-*.json'))
        pipeline.command('source-regression',[exe,root/'dev/run_unit.py'])
        unit=one_new(root/'runtime/test-results','unit-*.json',unit_before);unit_body=passing(unit)
        if unit_body['skipped'] or unit_body['tests']<195:raise ValueError('Full cumulative source inventory requires at least 195 cases and zero skips')
        report['source_regression']={'receipt':str(unit),'sha256':digest(unit),'tests':unit_body['tests']}
        receipt=pipeline.new('integrated','remote-center-build-*/receipt.json',[exe,'-X','utf8','-m','tools.build_integrated_center',
            '--version',args.version,'--cohort',cohort,'--service',service,
            '--notices',root/'runtime/remote-native-notices-001','--tests',unit],3600)
        build=passing(receipt);product=receipt.parent/'product/GuardDesk'
        pipeline.command('runtime-startup',[exe,'-X','utf8',Path(build['source'])/'tools/probe_remote_runtime_startup.py',
            '--product',product,'--report',run/'runtime-startup.json'])
        passing(run/'runtime-startup.json')
        print('Stage: complete ZIP',flush=True)
        candidate,proof=package(root,source,run,receipt,args.version,args.revision,env)
        pipeline.command('actual-zip-acl-cmd',[exe,'-X','utf8',Path(build['source'])/'tools/probe_management_source_setup.py',
            '--pipeline-run','--helper-root',run,'--final-package',candidate,'--expected-version',args.version,
            '--baseline-package',copied,'--baseline-sha256',baseline['artifact']['sha256']],1200)
        acl=passing(run/'final-package-tests.json')
        if len(acl['cases'])!=21:raise ValueError('Actual ZIP boundary test inventory differs')
        report['Defender']=scan(run,[candidate,product,run/'GuardDeskCenterPrepare.exe'],env)
        verify_zip(candidate,proof['file_hashes'])
        if any(digest(product/name)!=row['sha256'] for name,row in build['files'].items()):raise ValueError('Product changed after scan')
        if digest(run/'GuardDeskCenterPrepare.exe')!=proof['file_hashes']['GuardDeskCenterPrepare.exe']:raise ValueError('Helper changed after scan')
        if files(root/'source')!=before or digest(root/'CURRENT-BASELINE.json')!=baseline_before:
            raise ValueError('Source or accepted baseline changed during build')
        if digest(receipt)!=proof['build_receipt_sha256']:raise ValueError('Build receipt changed')
        report.update(build_receipt=str(receipt),build_receipt_sha256=digest(receipt),cohort=build['cohort'],
            package_sha256=proof['sha256'],package=str(target),actual_zip_cases=len(acl['cases']),
            source_stable=True,accepted_baseline_unchanged=True)
        publish(candidate,target,proof['sha256']);report['passed']=True
    except Exception as exc:
        report['failure']={'type':type(exc).__name__,'message':str(exc)}
        print('STOPPED: '+str(exc),flush=True)
    finally:
        report['finished']=time.time();write(run/'receipt.json',report);write_progress(run,report)
        print('Result='+('INTERNAL_PACKAGE_BUILT' if report['passed'] else 'STOPPED_NO_PACKAGE'))
        print('Report='+str(run/'receipt.json'),flush=True)
    return 0 if report['passed'] else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True,help='New numeric version, newer than accepted baseline')
    parser.add_argument('--revision',default='001')
    parser.add_argument('--artifact-root',type=Path,help='Approved historical artifacts root; copied by exact hash')
    parser.add_argument('--reuse-native-from',type=Path,help='Explicit approved 105 cache root; unchanged source only')
    parser.add_argument('--webrtc-source',type=Path,help='Explicit existing pinned WebRTC source for a real rebuild')
    parser.add_argument('--check',action='store_true',help='Read-only prerequisite check, no build/staging/download')
    args=parser.parse_args()
    root=ROOT.resolve(strict=True)
    try:
        target=prerequisites(root,args)
        if args.check:
            print('Output='+str(target));print('Mode='+('verified native cache' if args.reuse_native_from else 'native rebuild'))
            print('No build, installation, network or baseline promotion performed.');return 0
        with build_lock(root):return execute(root,args)
    except Exception as exc:print('STOPPED: '+str(exc),flush=True);return 1
if __name__=='__main__':raise SystemExit(main())
