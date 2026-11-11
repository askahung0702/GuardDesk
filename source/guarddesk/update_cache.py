"""Prune only trusted, receipted terminal ZIP caches; retain unknown legacy data."""
import json
import re
import math
from itertools import islice
from . import update_packages as packages

RECEIPT='cache-receipt.json'


def record(root,state,write):
    job=state.get('job')
    # Incomplete legacy recovery metadata cannot authorize cache management.
    if not isinstance(job,dict) or not {'id','created','release_id'}<=job.keys():return
    jid=job['id']
    if not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise ValueError('快取工作識別碼不正確')
    directory=packages.plain(root/jid)
    if not directory.is_dir() or not (directory/'package.zip').is_file():return
    if packages.plain(directory/RECEIPT).is_file():return  # Idempotent recovery; tampered receipts are never overwritten.
    body={'format':1,'job_id':jid,'state':state['phase'],'created':state['job']['created'],'sha256':state['job']['release_id']}
    write(directory/RECEIPT,body)


def prune(root,current,privileged=False):
    root=packages.plain(root);items=[];entries=list(islice(root.iterdir(),257))
    if len(entries)>256:raise OSError('更新快取項目超過保留檢查上限')
    for directory in entries:
        if directory.name==current or not re.fullmatch('[0-9a-f]{32}',directory.name):continue
        directory=packages.plain(directory)
        if not directory.is_dir():continue
        receipt=packages.plain(directory/RECEIPT)
        if not receipt.is_file():continue  # No inference about legacy/unknown jobs.
        if receipt.stat().st_size>2048:raise ValueError('更新快取收據過大')
        value=json.loads(receipt.read_text(encoding='utf-8'))
        if (not isinstance(value,dict) or set(value)!={'format','job_id','state','created','sha256'}
            or value['format']!=1 or value['job_id']!=directory.name or value['state'] not in ('healthy','rolled_back','failed')
            or type(value['created']) not in (int,float) or not math.isfinite(value['created']) or value['created']<0 or not re.fullmatch('[0-9a-f]{64}',str(value['sha256']))):raise ValueError('更新快取收據不正確')
        # Never touch directories with unknown files or incomplete downloads.
        if {p.name for p in directory.iterdir()}!={'package.zip',RECEIPT}:continue
        items.append((value['created'],directory,value))
    items.sort(key=lambda item:(item[0],item[1].name),reverse=True)
    keep={items[0][1]} if items else set()  # Most recent terminal cache for diagnosis.
    removed=0
    for _,directory,value in items:
        if directory in keep:continue
        if privileged:
            from .update_native import protected_tree
            protected_tree(directory)
        if packages.file_hash(directory/'package.zip')!=value['sha256']:raise ValueError('保留套件與快取收據不符')
        from .update_client import remove_managed
        remove_managed(root,directory,'[0-9a-f]{32}',privileged);removed+=1
    return removed
