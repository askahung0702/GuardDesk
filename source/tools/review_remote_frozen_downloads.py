"""Re-read exact authenticated owned downloads without running any executable."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.remote_checkpoint_receipts import RUNTIME,digest
from tools.build_remote_product_preview import inspect_pyz

def emit(report):
    number=1
    while (RUNTIME/f'remote-frozen-download-review-{number:03}.json').exists():number+=1
    target=RUNTIME/f'remote-frozen-download-review-{number:03}.json'
    with target.open('x',encoding='utf-8') as output:json.dump(report,output,indent=2);output.write('\n')
    print(json.dumps({'receipt':str(target),'passed':report['passed'],'deployable':False}))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--owned-result',type=Path,required=True)
    parser.add_argument('--owned-product',type=Path,required=True)
    args=parser.parse_args();receipt=args.owned_result.resolve(strict=True);product=args.owned_product.resolve(strict=True)
    if not receipt.is_relative_to(RUNTIME) or not receipt.parent.name.startswith('remote-next-frozen-center-') or receipt.name!='receipt.json':raise ValueError('Owned center receipt required')
    if not product.is_relative_to(RUNTIME) or product.name!='GuardDesk':raise ValueError('Owned product required')
    original=json.loads(receipt.read_text(encoding='utf-8'));built_path=product.parents[1]/'receipt.json';built=json.loads(built_path.read_text(encoding='utf-8'))
    if not original['passed'] or not built['passed'] or original['product_receipt_sha256']!=digest(built_path):raise ValueError('Reviewed provenance differs')
    for label in ('endpoint.zip','mis.exe'):
        path=receipt.parent/('downloaded-'+label);expected=original['downloads'][label]
        if path.stat().st_size!=expected['bytes'] or digest(path)!=expected['sha256']:raise ValueError('Authenticated download changed')
    from guarddesk.remote_components import read_cohort,COHORT_MANIFEST
    cohort=read_cohort(product);mis=receipt.parent/'downloaded-mis.exe'
    archive,modules=inspect_pyz(mis,('guarddesk.mis_native_loader','guarddesk.mis_native_media','guarddesk.remote_relay'))
    entries={n.replace('\\','/'):n for n in archive.toc};checked={}
    notices=json.loads((product/'_internal/remote-notices/notice-manifest.json').read_text(encoding='utf-8'))
    expected=['_internal/remote/GuardDeskMisNative.dll','_internal/remote/'+COHORT_MANIFEST]
    expected+=['_internal/remote-notices/'+n for n in (*notices['files'],'notice-manifest.json')]
    for name in expected:
        actual=hashlib.sha256(archive.extract(entries[name])).hexdigest()
        wanted=cohort['files']['GuardDeskMisNative.dll'] if name=='_internal/remote/GuardDeskMisNative.dll' else digest(product/name)
        if actual!=wanted:raise ValueError('Downloaded MIS embedded bytes differ: '+name)
        checked[name]=actual
    if any(n.endswith(('GuardDeskRemoteWorker.exe','GuardDeskRemoteMedia.exe','GuardDeskRemoteBridge.dll')) for n in entries):raise ValueError('Endpoint components duplicated in downloaded MIS')
    with zipfile.ZipFile(receipt.parent/'downloaded-endpoint.zip') as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError('Duplicate downloaded endpoint names')
        files=json.loads(z.read('endpoint-files.json'))['files']
        if files!=built['endpoint_files']:raise ValueError('Downloaded projection differs')
        if 'GuardDesk/_internal/GuardDeskMIS.exe' in names:raise ValueError('MIS duplicated in downloaded endpoint')
        for name,expected_hash in files.items():
            if hashlib.sha256(z.read('GuardDesk/'+name)).hexdigest()!=expected_hash:raise ValueError('Downloaded endpoint file differs: '+name)
    report={'format':1,'passed':True,'owned_center_receipt_sha256':digest(receipt),'product_receipt_sha256':digest(built_path),
        'cohort_build_id':cohort['build_id'],'authenticated_downloads':original['downloads'],'MIS_PYZ_sources':modules,
        'MIS_embedded_hashes':checked,'endpoint_files_verified':len(files),'company_product_changed':False,
        'executables_run':False,'deployable':False}
    emit(report)

if __name__=='__main__':
    try:main()
    except Exception as error:
        emit({'format':1,'passed':False,'failure':{'type':type(error).__name__,'message':str(error)},'company_product_changed':False,'deployable':False})
        raise
