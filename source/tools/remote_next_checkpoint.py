"""Freeze stable, passing isolated development evidence; never install/deploy."""
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.remote_checkpoint_receipts import SOURCE,WORKSPACE,RUNTIME,digest,latest,ROOTS

def main():
    if sys.argv[1:]!=['--freeze']:raise SystemExit('Use --freeze')
    builds=latest() # refuse latest failures or stale bytes before creating a checkpoint
    baseline=json.loads((SOURCE/'BASELINE-MANIFEST.json').read_text(encoding='utf-8'))
    if digest(WORKSPACE/baseline['archive'])!=baseline['archive_sha256']:raise ValueError('Sealed archive changed')
    modified={};added={}
    for name,expected in baseline['files'].items():
        if digest(WORKSPACE/baseline['baseline']/name)!=expected:raise ValueError('Stable source changed: '+name)
        path=SOURCE/name;actual=digest(path) if path.is_file() else None
        if actual!=expected:modified[name]={'baseline':expected,'current':actual}
    for folder in ('guarddesk','native/remote','tools','tests'):
        for path in (SOURCE/folder).rglob('*'):
            name=path.relative_to(SOURCE).as_posix()
            if path.is_file() and '__pycache__' not in path.parts and name not in baseline['files']:added[name]=digest(path)
    evidence=WORKSPACE/'evidence/maintenance/remote-next-m2-20261030';number=1
    while (evidence/f'checkpoint-{number:03}').exists():number+=1
    target=evidence/f'checkpoint-{number:03}';target.mkdir(parents=True)
    def copy(path,name):
        to=target/name;to.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,to);return digest(to)
    for name in set(modified)|set(added):
        path=SOURCE/name
        if path.is_file():copy(path,'source/'+name)
    logs={}
    patterns=('remote-m2-*','remote-m3-*','remote-m4-*','remote-next-uac*','webrtc-*.json','webrtc-*.log','mis-native-*.json','owned-mis-native-*.json','media-token-*.json',
        'remote-legacy-fixture-trace-*.json','remote-legacy-fixture-trace-*.log','remote-preview-config-*.json','remote-next-projected-capacity-*.json','remote-frozen-download-review-*.json','remote-doc-links-*.json','remote-acceptance-plan-review-*.json')
    for pattern in patterns:
        for path in RUNTIME.glob(pattern):
            if path.is_file() and path.suffix in ('.json','.log'):logs[path.name]=copy(path,path.name)
    field={}
    for pattern in ('uac-v*-field-*.json','uac-v1-task-cleanup-by-v2.json','uac-probe-prepared*.json','webrtc-build-input-inventory-*.json'):
        for path in evidence.glob(pattern):
            name='field-evidence/'+path.name;field[name]=copy(path,name)
    artifacts={}
    for kind in ('CMake','WebRTC'):
        for name in builds[kind]['body']['artifacts']:
            label='artifacts/'+kind+'/'+name;artifacts[label]=copy(ROOTS[kind]/name,label)
    packaging={}
    # Whitelist scalar receipts only; owned center data, keys, connection
    # bundles and enrollment-bearing downloads are deliberately not copied.
    for folder,allowed in (('remote-next-frozen-center-*',('receipt.json','center.log')),
                           ('remote-next-cohort-*',('cohort-preview.json',)),
                           ('remote-native-notices-*',('notice-manifest.json',)),
                           ('webrtc-product-notices-*',('receipt.json',))):
        for root in RUNTIME.glob(folder):
            for sibling in allowed:
                item=root/sibling
                if item.is_file():
                    name='packaging/'+root.name+'/'+sibling;packaging[name]=copy(item,name)
    for path in RUNTIME.glob('remote-next-product-*/receipt.json'):
        body=json.loads(path.read_text(encoding='utf-8'))
        name='packaging/'+path.parent.name+'/receipt.json';packaging[name]=copy(path,name)
        for sibling in ('build.log','publication-capacity.json'):
            item=path.parent/sibling
            if item.is_file():
                label='packaging/'+path.parent.name+'/'+sibling;packaging[label]=copy(item,label)
        if body.get('passed'):
            for sibling in ('unsigned-product-review-only.zip','MIS/GuardDeskMIS.exe'):
                item=path.parent/sibling;label='packaging/'+path.parent.name+'/'+sibling;packaging[label]=copy(item,label)
    for path in RUNTIME.glob('owned-mis-native-frozen-*.json'):
        logs[path.name]=copy(path,path.name)
    for version in ('','-v2'):
        path=RUNTIME/f'remote-next-uac-probe{version}/GuardDeskUacProbe/GuardDeskUacProbe.exe'
        if path.is_file():
            name=f'artifacts/uac-probe{version or "-v1"}.exe';artifacts[name]=copy(path,name)
    report=dict(format=2,status='development_offline_verified_not_deployable',requirements=['REMOTE-PERF-01','REMOTE-UAC-01'],
        stable_files_verified=len(baseline['files']),sealed_sha256=digest(WORKSPACE/baseline['archive']),modified=modified,added=added,
        logs=logs,field_evidence=field,artifacts=artifacts,packaging=packaging,builds={kind:{k:v for k,v in item.items() if k!='body'} for kind,item in builds.items()},
        Python_tests=builds['Python']['body']['tests'],native_tests=next(x['count'] for x in builds['CMake']['body']['stages'] if x['stage']=='owned_ctests'),
        WebRTC_runtime_stages=[x['stage'] for x in builds['WebRTC']['body']['stages'] if x['stage'].startswith('remote_')],
        M2_complete=False,M3_complete=False,M4_complete=False,company_product_changed=False,full_MIS_UAC_test=False,
        signing_and_Defender_acceptance=False,deployable=False,
        remaining=['Actual SYSTEM worker/media boundary and same-SID isolation acceptance','Real MIS UAC, cancellation, elevated application, lock/logoff/user switching',
          'LAN/relay/impairment/long-run/text quality and input-to-present/resource acceptance','Final Authenticode-signed download, installed old SYSTEM updater next upgrade and rollback','Final distribution licensing/SBOM/vulnerability review and company Defender Windows10/11'])
    (target/'checkpoint.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'checkpoint':str(target),'stable_verified':len(baseline['files']),'Python_tests':report['Python_tests'],'native_tests':report['native_tests'],'deployable':False}))

if __name__=='__main__':main()
