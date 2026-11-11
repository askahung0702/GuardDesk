"""Optional, hash-locked native cache. Never execute or alter the origin."""
from pathlib import Path
import json,shutil,stat
from worktree import digest,contained

def plain(root,path):
    root=Path(root).resolve(strict=True);path=Path(path).absolute()
    if not path.is_relative_to(root) or '..' in path.parts:raise ValueError('Cache path escaped root')
    for part in [path,*path.parents]:
        if part==root:break
        if part.exists() and part.lstat().st_file_attributes&stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('Reparse cache path')
    return contained(root,path)

def prepare(root,stage,origin,lock,apply=True):
    root=Path(root).resolve(strict=True);stage=Path(stage).resolve(strict=True);origin=Path(origin).resolve(strict=True)
    destination=contained(root,root/'runtime/native-input-cache')
    plan=[];selection={};proof={}
    for kind,row in lock.items():
        if kind not in ('CMake','WebRTC','service'):continue
        receipt=plain(origin,origin/row['receipt'])
        if digest(receipt)!=row['sha256']:raise ValueError('Native cache receipt mismatch: '+kind)
        body=json.loads(receipt.read_text(encoding='utf-8'))
        if not body.get('passed') or not body.get('sources'):raise ValueError('Incomplete cache: '+kind)
        if kind!='service' and not body.get('sources_stable' if kind=='WebRTC' else 'source_stable'):
            raise ValueError('Unstable cache source')
        for name,wanted in body['sources'].items():
            source=stage/name
            if kind=='WebRTC':
                source=stage/'native/remote/webrtc'/name
                if not source.is_file():source=stage/'native/remote'/name
            if not source.resolve().is_relative_to(stage) or digest(source)!=wanted:
                raise ValueError('Native cache source changed; rebuild: '+name)
        if any((item.get('exit') if isinstance(item,dict) else item)!=0 for item in body.get('stages',[])):raise ValueError('Cache stage failed')
        if kind=='WebRTC' and body.get('revision')!=row['revision']:raise ValueError('WebRTC revision differs')
        target=destination/kind
        target_receipt=target/receipt.name
        plan.append((receipt,target_receipt,row['sha256']))
        if 'log_sha256' in body:
            log=receipt.with_suffix('.log');plan.append((log,target_receipt.with_suffix('.log'),body['log_sha256']))
        artifact_root=plain(origin,origin/row['artifacts'])
        artifacts=body.get('artifacts') if kind!='service' else {'GuardDeskService.exe':{'sha256':body['sha256']}}
        if not artifacts:raise ValueError('No cached artifacts')
        for name,value in artifacts.items():
            if Path(name).name!=name:raise ValueError('Invalid cached artifact name')
            plan.append((plain(origin,artifact_root/name),target/'Release'/name,value['sha256']))
        if kind=='service':selection['service']=str(target)
        else:
            prefix='NATIVE' if kind=='CMake' else 'MEDIA'
            selection['GUARDDESK_'+prefix+'_RECEIPT']=str(target_receipt)
            selection['GUARDDESK_'+prefix+'_ARTIFACT_ROOT']=str(target/'Release')
        proof[kind]={'receipt':row['receipt'],'sha256':row['sha256'],'source_matches':True,'mode':'verified_reuse_not_rebuilt'}
    if set(proof)!={'CMake','WebRTC','service'}:raise ValueError('Cache inventory incomplete')
    # Validate every byte before copying any input. Existing differences are not overwritten.
    for source,target,wanted in plan:
        if digest(source)!=wanted:raise ValueError('Cached artifact/log hash mismatch: '+str(source))
        plain(root,target)
        if target.exists() and digest(target)!=wanted:raise ValueError('Existing cache differs; preserve it')
    if apply:
        for source,target,wanted in plan:
            target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists():shutil.copyfile(source,target)
            if digest(target)!=wanted:raise ValueError('Cache copy changed')
    return selection,proof
