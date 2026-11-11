"""Serialize owned frozen UI/integration checks; never access office data."""
import os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    env={**os.environ,'PYTHONIOENCODING':'utf-8'}
    steps=[('packaged',['tests/packaged_smoke.py']),('documents',['tests/document_audit_browser_smoke.py','--frozen']),('custom',['tests/custom_library_browser_smoke.py','--frozen']),('sort',['tests/audit_sort_browser_smoke.py','--frozen']),('search',['tests/audit_search_browser_smoke.py','--frozen']),('mail',['tests/mail_reports_browser_smoke.py','--frozen']),('upload',['tests/web_upload_browser_smoke.py']),('query-perf',['tools/document_audit_performance.py']),('native-perf',['tools/document_native_performance.py'])]
    for name,args in steps:
        print('START '+name,flush=True);path=ROOT/f'runtime/verify-0449-{name}.txt'
        with path.open('w',encoding='utf-8') as stream:r=subprocess.run([sys.executable,*args],env=env,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=900)
        if r.returncode:print(path.read_text(encoding='utf-8',errors='replace')[-6000:],flush=True);return r.returncode
        print('PASS '+name,flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
