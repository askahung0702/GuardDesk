"""Execute actual old/new frozen functions on owned metadata, never installed tasks."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import tracemalloc
import types
import zipfile
from unittest.mock import patch
from PyInstaller.archive.readers import CArchiveReader
import guarddesk
from guarddesk import update_packages as packages
from guarddesk.store import canonical

ROOT=Path(__file__).resolve().parents[1]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(path,module):return CArchiveReader(str(path)).open_embedded_archive('PYZ.pyz').extract('guarddesk.'+module)


def methods(code):return {c.co_name:c for c in code.co_consts if isinstance(c,types.CodeType)}


def checks(path):
    code=methods(extract(path,'native_installer'));scope={'packages':packages,'json':json,'__package__':'guarddesk'}
    scope['read_json']=types.FunctionType(code['read_json'],scope,argdefs=(65536,))
    return types.FunctionType(code['assert_quiescent'],scope,argdefs=(True,))


def writer(path,new):
    code=methods(extract(path,'update_client'))
    scope={'packages':packages,'canonical':canonical,'os':os,'time':time,'__package__':'guarddesk'}
    if new:scope['_save_plain']=types.FunctionType(code['_save_plain'],scope)
    return types.FunctionType(code['save'],scope)


def main():
    candidate=ROOT/'dist/GuardDesk/GuardDesk.exe';target=ROOT/'evidence/frozen-machine-handoff-0.4.66.json'
    assert not target.exists()
    oldhashes={'0.4.64':'3c458a229988dc3d05bb6fd9dbc2125f42fe24a69a27622050a335f0d121be31',
               '0.4.65':'c1fa2c63faa631f0bd938f297a8bab15729a6a6e552f862ded2a6016417af135'}
    raw=(ROOT/'dist/transaction-native.json').read_bytes();measurements={}
    with tempfile.TemporaryDirectory(prefix='frozen-state-0466-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);old={}
        for version,digest in oldhashes.items():
            archive=ROOT/'dist'/f'GuardDesk-{version}-windows-x64.zip';assert sha(archive)==digest
            with zipfile.ZipFile(archive) as z:
                old[version]=root/(version+'.exe');old[version].write_bytes(z.read('GuardDesk/GuardDesk.exe'))
        state=types.ModuleType('guarddesk.transaction_status');state.__package__='guarddesk'
        exec(extract(candidate,'transaction_status'),state.__dict__)
        with patch.dict('sys.modules',{'guarddesk.transaction_status':state}),patch.object(guarddesk,'transaction_status',state,create=True):
            new_check=checks(candidate);old64=checks(old['0.4.64']);old65=checks(old['0.4.65'])
            new_save=writer(candidate,True);old_save=writer(old['0.4.65'],False)
            owned=root/'owned';(owned/'updates').mkdir(parents=True);p=owned/'updates/transaction-native.json'
            body=json.loads(raw);body.update(phase='healthy',reported=True,version='0.4.64')
            p.write_text(json.dumps(body,ensure_ascii=False),encoding='utf-8');before=p.read_bytes()
            try:old64(owned)
            except ValueError:pass
            else:raise AssertionError('64 must reproduce original defect')
            old65(owned);new_check(owned);assert before==p.read_bytes()
            new_save(p,body);old65(owned);assert json.loads(p.read_text(encoding='utf-8'))==body
            body['padding']='x'*2_000_000;new_save(p,body)
            control=state.control_path(p);measurements['control_bytes']=control.stat().st_size
            assert measurements['control_bytes']<4096
            opened=Path.open
            def safe_open(path,*args,**kwargs):
                if path==p:raise AssertionError('New normal gate read the full journal')
                return opened(path,*args,**kwargs)
            tracemalloc.start();start=time.perf_counter()
            with patch.object(Path,'open',safe_open):
                for _ in range(100):new_check(owned)
            measurements.update(ready_100_checks_seconds=time.perf_counter()-start,ready_peak_python_bytes=tracemalloc.get_traced_memory()[1])
            tracemalloc.stop()
            assert measurements['ready_peak_python_bytes']<1024*1024
            # Real old frozen writer does not know the control file. New reader
            # must detect the atomic replacement even with a stale healthy summary.
            old_save(p,{'phase':'switching','padding':'x'*700000})
            try:new_check(owned)
            except OSError:pass
            else:raise AssertionError('Stale terminal summary authorized old writer switch')
            old_save(p,{'phase':'healthy','padding':'x'*4_000_000})
            start=time.perf_counter();new_check(owned)
            measurements['legacy_4MB_first_scan_seconds']=time.perf_counter()-start
            tracemalloc.start();state._cache.clear();start=time.perf_counter();new_check(owned)
            measurements.update(legacy_4MB_traced_scan_seconds=time.perf_counter()-start,legacy_peak_python_bytes=tracemalloc.get_traced_memory()[1])
            tracemalloc.stop();assert measurements['legacy_peak_python_bytes']<1024*1024
            start=time.perf_counter()
            for _ in range(100):new_check(owned)
            measurements['legacy_cached_100_checks_seconds']=time.perf_counter()-start
            # Control and legacy code must both refuse malformed or active state.
            for phase in ('prepared','switching','restarting','unexpected'):
                new_save(p,{'phase':phase,'padding':'x'*700000})
                try:new_check(owned)
                except OSError:pass
                else:raise AssertionError(phase)
            control.write_bytes(b'{}')
            try:new_check(owned)
            except OSError:pass
            else:raise AssertionError('Corrupt summary accepted')
    proof=dict(passed=True,version='0.4.66',candidate_exe_sha256=sha(candidate),prior_archives=oldhashes,
        real_supplied_journal_bytes=len(raw),measurements=measurements,
        checks=['actual archived 64 frozen function reproduces 64KiB defect',
                'old 65 and new 66 frozen gates read unchanged real-size owned terminal copy',
                'actual new frozen writer retains full old-readable recovery JSON plus small summary',
                'new frozen ready gate never opens 2MB recovery payload, measured bounded memory',
                'actual old 65 frozen writer supersedes summary; new gate refuses switching',
                'new frozen legacy streaming accepts 4MB without 600KiB limit, bounded memory and cache',
                'active, unknown and corrupt states remain blocked'],
        scope='Actual frozen function/module code in Python; owned files only, not installed SYSTEM/WTS/field updater',
        company_changed=False,formal_release_ready=False)
    target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(proof,ensure_ascii=False))


if __name__=='__main__':main()
