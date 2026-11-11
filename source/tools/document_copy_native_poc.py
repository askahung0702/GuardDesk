"""Controlled CopyFileExW proof only; NOT a global employee copy collector.

Uses exclusively self-created fixtures. No hooks, injection, driver installation,
Security policy changes or employee document reads. Does not enqueue production
events. A generic read/write correlation is deliberately not called 'copied'.
"""
import ctypes
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    if os.name!='nt':raise OSError('Windows required')
    from ctypes import wintypes as w
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CopyFileExW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(w.BOOL),w.DWORD]
    kernel.CopyFileExW.restype=w.BOOL
    results=[]
    with tempfile.TemporaryDirectory(prefix='owned-copy-poc-',dir=ROOT/'runtime') as temp:
        root=Path(temp);source=root/'測試來源.txt';dest=root/'測試目的.txt'
        data=b'GuardDesk owned copy fixture\n'*1024
        source.write_bytes(data)
        for attempt in range(2):
            cancel=w.BOOL(False);started=time.monotonic();ctypes.set_last_error(0)
            success=bool(kernel.CopyFileExW(str(source),str(dest),None,None,ctypes.byref(cancel),1)) # FAIL_IF_EXISTS
            code=0 if success else ctypes.get_last_error()
            results.append({'api':'CopyFileExW','source':'owned_fixture_source','destination':'owned_fixture_destination',
                            'success':success,'windows_error':code,'milliseconds':round((time.monotonic()-started)*1000,3),
                            'evidence':'explicit_owned_api_call_result','production_event_enqueued':False})
        assert results[0]['success'] and not results[1]['success'] and results[1]['windows_error'] in (80,183)
        assert dest.read_bytes()==data
        assert source.stat().st_ino!=dest.stat().st_ino
    report={'passed':True,'checked_at':time.time(),'scope':'controlled_native_copy_api_only','general_copy_collector_implemented':False,
            'fixture_sha256':hashlib.sha256(data).hexdigest(),'results':results,
            'gaps':['Does not observe copies performed by Explorer or other applications','No kernel minifilter implementation/build/signing/acceptance; SDK present, WDK km headers/build tools not found on PATH','A separate signed driver design and real cross-application tests are required before general coverage'],
            'office_accessed':False,'security_controls_changed':False}
    target=ROOT/'evidence/document-copy-native-poc-0.4.48.json'
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True))


if __name__=='__main__':main()
