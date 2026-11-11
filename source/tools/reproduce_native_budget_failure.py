"""Exercise real transaction/budget code using owned sparse-file retention fixtures.

No installed Agent, company directory, task, credentials or executable is used.
This reproduces a possible mechanism; it does not measure LAB01's directories.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_updates import UpdateTransactionTest,Adapter
from guarddesk.update_client import Transaction
from guarddesk.update_native import NativeAdapter

MiB=1024*1024


def sparse(path,length):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w+b') as stream:
        if os.name=='nt':
            import msvcrt
            from ctypes import wintypes as w
            api=ctypes.WinDLL('kernel32',use_last_error=True)
            api.DeviceIoControl.argtypes=[w.HANDLE,w.DWORD,w.LPVOID,w.DWORD,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID]
            api.DeviceIoControl.restype=w.BOOL
            returned=w.DWORD()
            if not api.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()),0x900c4,None,0,None,0,ctypes.byref(returned),None):
                raise ctypes.WinError(ctypes.get_last_error())
        stream.truncate(length)


def scenario(retained):
    fixture=UpdateTransactionTest();fixture.setUp()
    try:
        program=fixture.root/'owned-program';program.mkdir()
        names=['USBControl','Updater']
        if retained:
            names+=['USBControl.install-failed-'+'1'*16,'Updater.install-failed-'+'1'*16,
                    'USBControl.rollback-'+'2'*32,'Updater.rollback-'+'2'*32,'USBControl.stage-'+'3'*32]
        for name in names:sparse(program/name/'owned-runtime.bin',80*MiB)
        cache=fixture.agent.config_path.parent/'updates'
        sparse(cache/('4'*32)/'package.zip',177*MiB)
        class BoundedAdapter(Adapter):
            def __init__(self):
                super().__init__(program)
                self.program=program;self.agent=fixture.agent;self.cleanups=0
            def budget(self,incoming):NativeAdapter.budget(self,incoming)
            def stage(self,job):return program/('USBControl.stage-'+job['id'])
            def cleanup(self,state):self.cleanups+=1
        adapter=BoundedAdapter();tx=Transaction(fixture.agent,'native',adapter)
        before={p.relative_to(program).as_posix():p.stat().st_size for p in program.rglob('*') if p.is_file()}
        caught=None
        try:tx.apply(fixture.envelope)
        except OSError as exc:caught={'type':type(exc).__name__,'message':str(exc)}
        state=json.loads(tx.journal.read_text(encoding='utf-8'))
        result={'retained_copies':retained,'program_logical_mib':len(names)*80,'cache_fixture_mib':177,
                'exception':caught,'transaction_phase':state['phase'],'failure_detail_recorded':'failure' in state,
                'stops':adapter.stops,'switches':adapter.switches,'cleanups':adapter.cleanups,
                'download_exists':(tx.root/fixture.payload['id']/'package.zip').is_file(),
                'new_stage_exists':adapter.stage(fixture.payload).exists(),
                'identity_preserved':fixture.agent.config_path.read_bytes()==fixture.original,
                'queue_pending':fixture.agent.queue_status()['pending']}
        if retained:
            assert caught and '512 MiB' in caught['message']
            assert state['phase']=='downloading' and 'failure' not in state
            assert adapter.stops==adapter.switches==adapter.cleanups==0
            assert result['download_exists'] and not result['new_stage_exists']
            after={p.relative_to(program).as_posix():p.stat().st_size for p in program.rglob('*') if p.is_file()}
            assert after==before
        else:
            assert caught is None and state['phase']=='healthy' and adapter.cleanups==1
        assert result['identity_preserved'] and result['queue_pending']==1
        return result
    finally:fixture.doCleanups()


def main():
    review=json.loads((ROOT/'evidence/security/0.4.59/requirements-review.json').read_text(encoding='utf-8'))
    hashes={}
    for n in ('guarddesk/update_client.py','guarddesk/update_native.py'):
        h=hashlib.sha256((ROOT/n).read_bytes()).hexdigest()
        assert review['final_source_sha256'][n.replace('/','\\')]==h
        hashes[n]=h
    report={'passed':True,'scope':'Owned sparse-file capacity model and fake nonexecutable package through real Transaction/NativeAdapter.budget; not LAB01/SYSTEM acceptance',
            'source_matches_0459_review':hashes,'scenarios':[scenario(False),scenario(True)],
            'lab01_root_cause_confirmed':False,'company_changed':False,'product_changed':False,
            'remaining':'Obtain elevated full logical bytes/file count of LAB01 protected program tree. The seven 80 MiB copies and 177 MiB cache are model inputs, not measurements.'}
    p=ROOT/'evidence/maintenance/native-retained-budget-reproduction-20261029.json'
    p.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
