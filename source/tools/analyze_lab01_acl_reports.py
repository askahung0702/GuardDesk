"""Offline correlation of the two explicitly supplied LAB01 DACL reports."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[1]
DID='ee1e1e17c6c8730a37603b1e'
SID='S-1-5-21-111111111-222222222-333333333-11016'


def analyze(audit_raw,dacl_raw):
    audit=audit_raw.decode('utf-8-sig').replace('\r\n','\n')
    records=dacl_raw.decode('utf-16-le').lstrip('\ufeff').splitlines()
    saved=[(int(n),int(s),p) for n,s,p in re.findall(r'^SavedNode=(\d+) Scope=(\d+) Path="(.*)"$',audit,re.M)]
    nodes=[(int(n),int(s),p) for n,s,p in re.findall(r'^Node=(\d+) Scope=(\d+) Path="(.*)"$',audit,re.M)]
    assert saved==nodes and len(records)==2*len(saved)
    assert [n for n,_,_ in saved]==list(range(1,len(saved)+1))
    assert len({p.casefold() for _,_,p in saved})==len(saved)
    totals=re.search(r'^Nodes=(\d+) Directories=(\d+)$',audit,re.M)
    assert totals and int(totals[1])==len(saved)
    assert audit.endswith('ExitCode=0\n') or audit.endswith('ExitCode=0\r\n')
    assert 'Result=READ_ONLY_COLLECTION_COMPLETE_NOT_A_TRUST_VALIDATION' in audit
    assert not any(t in audit for t in ['SnapshotError=','ListingError=','SkippedUnavailableOrReparse=','LimitOrQueueOrOutputFailure='])
    roots={1:rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}',2:r'C:\Program Files\GuardDeskPilot\Updater',3:r'C:\Program Files\GuardDeskPilot\USBControl'}
    unique={};counts=Counter();bad=[]
    for i,(n,scope,path) in enumerate(saved):
        name,sddl=records[2*i:2*i+2]
        assert name==path.rsplit('\\',1)[-1]
        assert path==roots[scope] or path.startswith(roots[scope]+'\\')
        counts[scope]+=1
        if sddl not in unique:
            aces=re.findall(r'\(([^()]*)\)',sddl)
            assert sddl.startswith('D:') and aces
            assert re.sub(r'\([^()]*\)','',sddl) in ('D:AI','D:PAI')
            parsed=[]
            for ace in aces:
                kind,flags,rights,obj,inh,trustee=ace.split(';')
                assert kind=='A' and not obj and not inh
                mask={'FA':0x1f01ff,'RC':0x20000}.get(rights)
                if mask is None:mask=int(rights,16)
                parsed.append(dict(flags=flags,mask=mask,trustee=trustee))
            unique[sddl]=parsed
        for ace in unique[sddl]:
            if ace['mask']&0x500D0156 and ace['trustee'] not in ('SY','BA'):
                bad.append(dict(node=n,scope=scope,path=path,sddl=sddl,**ace))
    target=roots[1]+'\\updates'
    expected=[target]+[target+'\\'+j for j in ['264626046385d80b133c831738b747ae','62f0fa075ac160ce37231d9a79350d05','660a1644e7c0412616c3341062ce96f6','82fcee146799c0834eff6bbb876a8ba9']]+[target+'\\'+f for f in ['transaction-native.json','updater-refresh.json']]+[target+'\\'+j+'\\package.zip' for j in ['264626046385d80b133c831738b747ae','62f0fa075ac160ce37231d9a79350d05','660a1644e7c0412616c3341062ce96f6','82fcee146799c0834eff6bbb876a8ba9']]
    assert len(bad)==11 and {x['path'] for x in bad}==set(expected)
    assert all(x['trustee']==SID and x['mask']==0x1f01ff for x in bad)
    assert len([x for x in bad if 'ID' not in x['flags']])==1
    assert bad[0]['path']==target and bad[0]['flags']=='OICI'
    return dict(passed=True,inputs=[dict(name=n,bytes=len(b),sha256=hashlib.sha256(b).hexdigest()) for n,b in [('Audit.txt',audit_raw),('DACLs.txt',dacl_raw)]],
        nodes=len(saved),directories=int(totals[2]),per_scope=dict(counts),unique_dacls=len(unique),
        result='Complete collection; only observed disallowed write ACE is user1 full-control explicit at updates, inherited by ten descendants',
        offending_aces=bad,root_dacl=records[1],
        collection_errors=[],field_owner_and_sacl='not collected; not attested by these snapshots',
        limitations=['DACL snapshots describe collection time, not live concurrent state','No owner/SACL or installer/upgrade acceptance','Original capacity blocker remains independently unresolved'],
        field_actions='User executed read-only audit; agent read only the two specified files and did not modify LAB01 or share',
        requirements=['MACHINE-01','GD-002','GD-006','GD-007','GD-008','GD-020','GD-021','GD-022','SEC-02','SEC-03','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04'])


def main():
    share=Path(r'D:\Artifacts\LabArtifacts\maintenance')
    bodies=[]
    for name in ['Audit.txt','DACLs.txt']:
        path=share/name
        assert path.stat().st_size<=20*1024*1024
        bodies.append(path.read_bytes())
    result=analyze(*bodies)
    (ROOT/'evidence/maintenance/lab01-acl-audit-field-analysis-20261029.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['passed','nodes','directories','per_scope','unique_dacls','result']},ensure_ascii=False))


if __name__=='__main__':main()
