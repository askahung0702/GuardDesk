"""Local metadata cost only; no installed Agent or Defender claim."""
import ctypes,json,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.file_exclusions import excluded
from guarddesk.hidden_files import HIDDEN_RULE,resolver

def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as temporary:
        folder=Path(temporary);paths=[]
        api=ctypes.WinDLL('kernel32',use_last_error=True);api.SetFileAttributesW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32]
        for i in range(30):
            path=folder/(str(i)+'.txt');path.write_text('owned synthetic fixture');paths.append(str(path))
            if i%2==0 and not api.SetFileAttributesW(str(path),2):raise ctypes.WinError(ctypes.get_last_error())
        timings={};counts={};cpu={}
        for name,rules in (('disabled',[]),('enabled',[HIDDEN_RULE])):
            start=time.perf_counter();started_cpu=time.process_time();filtered=0
            for _ in range(100):
                for path in paths:filtered+=bool(excluded(path,rules))
            timings[name]=round((time.perf_counter()-start)*1000,3);cpu[name]=round((time.process_time()-started_cpu)*1000,3);counts[name]=filtered
        assert counts=={'disabled':0,'enabled':1500},counts
        r=resolver();report={'scope':'3000 repeated observations over 30 owned local files, 15 hidden; warm bounded metadata cache; not whole endpoint resource acceptance','observations_per_case':3000,'wall_ms':timings,'cpu_ms':cpu,'filtered':counts,'metadata_cache_entries':len(r.cache),'queries_in_latest_1s_window':r.queries,'company_changed':False,'field_8h_24h_verified':False}
        (ROOT/'evidence/hidden-filter-cost-0.4.57.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))

if __name__=='__main__':main()
