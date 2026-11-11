"""Serial isolated integration checks on the exact compiled candidate."""
import os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    steps=[('packaged',['tests/packaged_smoke.py']),('progress',['tests/update_progress_browser_smoke.py','--frozen']),('documents',['tests/document_audit_browser_smoke.py','--frozen']),('custom',['tests/custom_library_browser_smoke.py','--frozen']),('sort',['tests/audit_sort_browser_smoke.py','--frozen']),('search',['tests/audit_search_browser_smoke.py','--frozen']),('mail',['tests/mail_reports_browser_smoke.py','--frozen']),('metadata-perf',['tools/update_progress_performance.py'])]
    for name,args in steps:
        print('START '+name,flush=True);log=ROOT/f'runtime/verify-0453-{name}.txt'
        with log.open('w',encoding='utf-8') as stream:result=subprocess.run([sys.executable,*args],cwd=ROOT,env={**os.environ,'PYTHONIOENCODING':'utf-8'},stdout=stream,stderr=subprocess.STDOUT,timeout=900)
        if result.returncode:print(log.read_text(encoding='utf-8',errors='replace')[-7000:],flush=True);return result.returncode
        print('PASS '+name,flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
