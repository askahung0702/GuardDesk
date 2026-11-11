"""Build and inspect real frozen product bytes for owned offline review only.

Does not launch the product, enroll, contact a center, install, sign or publish.
Outputs are numbered development snapshots; no existing release is overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.remote_checkpoint_receipts import SOURCE,WORKSPACE,RUNTIME,digest,latest

def normalize(code):
    return code.replace(co_filename='owned-source',co_consts=tuple(normalize(v) if isinstance(v,types.CodeType) else v for v in code.co_consts))

def inspect_pyz(path,required):
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(path));name=next(n for n in archive.toc if n.startswith('PYZ'))
    pyz=archive.open_embedded_archive(name);verified={}
    for module in sorted(n for n in pyz.toc if n=='guarddesk' or n.startswith('guarddesk.')):
        source=SOURCE/(module.replace('.','/')+'.py')
        if not source.is_file():source=SOURCE/module.replace('.','/')/'__init__.py'
        if not source.is_file():raise ValueError('Frozen GuardDesk module lacks source: '+module)
        actual=pyz.extract(module)
        if normalize(actual)!=normalize(compile(source.read_bytes(),str(source),'exec',dont_inherit=True,optimize=0)):
            raise ValueError('Frozen source differs: '+module)
        verified[module]=digest(source)
    if not set(required)<=verified.keys():raise ValueError('Required frozen modules missing: '+str(set(required)-verified.keys()))
    return archive,verified

def main():
    p=argparse.ArgumentParser();p.add_argument('--owned-cohort',type=Path,required=True);p.add_argument('--owned-notices',type=Path,required=True);args=p.parse_args()
    cohort=args.owned_cohort.resolve(strict=True)
    if not cohort.is_relative_to(RUNTIME):raise ValueError('Cohort escaped runtime')
    from guarddesk.remote_components import read_cohort,COHORT_MANIFEST,validate_layout
    from guarddesk.update_packages import MAX_ZIP,MAX_TOTAL,MAX_FILES,safe_name
    pins=read_cohort(cohort);builds=latest()
    number=1
    while (RUNTIME/f'remote-next-product-{number:03}').exists():number+=1
    output=RUNTIME/f'remote-next-product-{number:03}';output.mkdir()
    report={'format':1,'status':'development_offline_product_snapshot_not_deployable','passed':False,'deployable':False,
        'installed':False,'company_product_changed':False,'old_frozen_updater_executed':False,'full_MIS_UAC_acceptance':False,
        'cohort_build_id':pins['build_id'],'receipts':{kind:{k:v for k,v in item.items() if k!='body'} for kind,item in builds.items()},'stages':[]}
    from tools.build_dependencies import verify as verify_dependencies
    report['build_dependencies']=verify_dependencies(SOURCE)
    env=os.environ.copy();env['PYTHONPATH']=str(SOURCE);env['PYTHONNOUSERSITE']='1'
    env['GUARDDESK_REMOTE_COHORT_ROOT']=str(cohort)
    env['GUARDDESK_REMOTE_NOTICES_ROOT']=str(args.owned_notices.resolve(strict=True))
    before={p.relative_to(SOURCE).as_posix():digest(p) for folder in ('guarddesk','tools') for p in (SOURCE/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    log=output/'build.log'
    try:
        with log.open('x',encoding='utf-8') as stream:
            for label,spec in (('MIS','GuardDeskMIS.spec'),('product','GuardDesk.spec')):
                if label=='product':env['GUARDDESK_MIS_BUILD_PATH']=str(output/'MIS/GuardDeskMIS.exe')
                command=[sys.executable,'-m','PyInstaller','--clean','--noconfirm','--distpath',str(output/label),'--workpath',str(output/(label+'-work')),str(SOURCE/'tools'/spec)]
                result=subprocess.run(command,cwd=SOURCE,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=600)
                report['stages'].append({'stage':label,'exit':result.returncode})
                if result.returncode:raise RuntimeError(label+' build failed; old executable not reused')
        mis=output/'MIS/GuardDeskMIS.exe'
        archive,mis_modules=inspect_pyz(mis,('guarddesk.mis_native_media','guarddesk.mis_native_loader','guarddesk.remote_components','guarddesk.remote_relay'))
        embedded={n.replace('\\','/'):n for n in archive.toc}
        for name in ('GuardDeskMisNative.dll',COHORT_MANIFEST):
            data=archive.extract(embedded['_internal/remote/'+name])
            if hashlib.sha256(data).hexdigest()!=digest(cohort/'_internal/remote'/name):raise ValueError('MIS embedded cohort differs: '+name)
        notice_root=args.owned_notices.resolve();notice_manifest=json.loads((notice_root/'notice-manifest.json').read_text(encoding='utf-8'))
        for name in (*notice_manifest['files'],'notice-manifest.json'):
            if hashlib.sha256(archive.extract(embedded['_internal/remote-notices/'+name])).hexdigest()!=digest(notice_root/name):raise ValueError('MIS embedded notice differs: '+name)
        if any(n.endswith(('GuardDeskRemoteWorker.exe','GuardDeskRemoteMedia.exe','GuardDeskRemoteBridge.dll')) for n in embedded):raise ValueError('Endpoint components duplicated in MIS')
        application=output/'product/GuardDesk';validate_layout(application)
        for name in (*notice_manifest['files'],'notice-manifest.json'):
            if digest(application/'_internal/remote-notices'/name)!=digest(notice_root/name):raise ValueError('Endpoint embedded notice differs: '+name)
        report['native_notice_manifest_sha256']=digest(notice_root/'notice-manifest.json')
        if read_cohort(application)['build_id']!=pins['build_id']:raise ValueError('Endpoint cohort differs')
        if digest(application/'_internal/GuardDeskMIS.exe')!=digest(mis):raise ValueError('Embedded MIS differs from reviewed build')
        report['frozen_PYZ_sources']={'MIS':mis_modules}
        for relative in ('GuardDesk.exe','GuardDeskAgent.exe','_internal/GuardDeskRemote.exe'):
            _,modules=inspect_pyz(application/relative,('guarddesk.remote_native_broker','guarddesk.machine_agent','guarddesk.remote_native','guarddesk.remote_components',
                'guarddesk.context_permissions','guarddesk.worker_startup','guarddesk.native_installer'))
            report['frozen_PYZ_sources'][relative]=modules
        files={path.relative_to(application).as_posix():{'sha256':digest(path),'bytes':path.stat().st_size} for path in application.rglob('*') if path.is_file()}
        for name in files:safe_name(name)
        from guarddesk.endpoint_payload import project,entry
        from guarddesk.update_preflight import candidate_size
        from tools.check_update_capacity import evaluate
        endpoint_files,overrides=project(application,{name:value['sha256'] for name,value in files.items()})
        preview=output/'unsigned-product-review-only.zip'
        expanded=0
        with zipfile.ZipFile(preview,'x',zipfile.ZIP_DEFLATED) as z:
            for name,wanted in sorted(endpoint_files.items()):
                sha=hashlib.sha256()
                with entry(application,name,overrides) as reader,z.open(name,'w') as writer:
                    while chunk:=reader.read(65536):sha.update(chunk);writer.write(chunk);expanded+=len(chunk)
                if sha.hexdigest()!=wanted:raise ValueError('Endpoint projection changed during review')
        compressed=preview.stat().st_size
        measured=candidate_size(application)
        if measured!={'compressed_bytes':compressed,'incoming_bytes':expanded,'files':len(endpoint_files)}:raise ValueError('Actual publisher ZIP and preflight projection disagree')
        report['publication_capacity']=evaluate(measured,scope='endpoint',version=__import__('guarddesk').__version__)
        baseline=json.loads((SOURCE/'BASELINE-MANIFEST.json').read_text(encoding='utf-8'))
        from tools.remote_baseline import verify as verify_baseline
        _,baseline_evidence=verify_baseline(baseline,WORKSPACE)
        report['baseline_evidence']=baseline_evidence
        old_expanded=baseline_evidence['expanded_bytes'];old_zip=baseline_evidence['zip_bytes']
        capacity={'compressed_bytes':compressed,'expanded_bytes':expanded,'files':len(endpoint_files),'zip_limit':MAX_ZIP,'expanded_limit':MAX_TOTAL,'files_limit':MAX_FILES,
            'protocol1_package_fits':compressed<=MAX_ZIP and expanded<=MAX_TOTAL and len(endpoint_files)<=MAX_FILES,
            'center_full_runtime_expanded_bytes':sum(v['bytes'] for v in files.values()),'MIS_excluded_from_endpoint_payload':True,
            'baseline_zip_bytes':old_zip,'baseline_archive_expanded_bytes':old_expanded,
            'baseline_measurement_basis':baseline_evidence['capacity_basis'],
            'zip_growth_bytes':compressed-old_zip,'expanded_growth_bytes':expanded-old_expanded,
            'conservative_clean_download_extract_stage_baseline_rollback_bytes':compressed+2*expanded+old_expanded,
            'existing_endpoint_cache_bytes':'unknown_requires_preflight','old_512MiB_working_set_acceptance':False,
            'note':'Full archive sizes measured. Existing cache/installed copies and actual old updater must be checked separately; no limit raised or cache removed.'}
        report.update(files=files,endpoint_files=endpoint_files,capacity=capacity,archive={'sha256':digest(preview),'bytes':compressed},MIS={'sha256':digest(mis),'bytes':mis.stat().st_size})
        if not capacity['protocol1_package_fits']:raise ValueError('Actual full product exceeds unchanged protocol-1 package limits')
        after={p.relative_to(SOURCE).as_posix():digest(p) for folder in ('guarddesk','tools') for p in (SOURCE/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        report['source_stable']=before==after
        if not report['source_stable']:raise ValueError('Source changed during product build')
        report['passed']=True
    except Exception as error:report['failure']={'type':type(error).__name__,'message':str(error)}
    report['log_sha256']=digest(log) if log.exists() else None
    with (output/'receipt.json').open('x',encoding='utf-8') as out:json.dump(report,out,indent=2);out.write('\n')
    print(json.dumps({'receipt':str(output/'receipt.json'),'passed':report['passed'],'deployable':False}))
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
