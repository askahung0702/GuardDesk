"""Serialize owned UI/native/performance checks to avoid shared test contention."""
import os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    env={**os.environ,'PYTHONIOENCODING':'utf-8'}
    steps=[
        ('document-browser',['tests/document_audit_browser_smoke.py','--frozen']),
        ('sort-browser',['tests/audit_sort_browser_smoke.py','--frozen']),
        ('search-browser',['tests/audit_search_browser_smoke.py','--frozen']),
        ('mail-browser',['tests/mail_reports_browser_smoke.py','--frozen']),
        ('custom-browser',['tests/custom_library_browser_smoke.py','--frozen']),
        ('upload-browser',['tests/web_upload_browser_smoke.py']),
        # Real HKCU test is invoked separately with its preflight. On this
        # workstation an existing installation must not be overwritten.
        ('query-performance',['tools/document_audit_performance.py']),
        ('final-review',['tools/review_release_0448.py']),
    ]
    if '--extension-only' in sys.argv:
        steps=[('packaged-final',['tests/packaged_smoke.py']),('upload-browser',['tests/web_upload_browser_smoke.py']),('final-review',['tools/review_release_0448.py'])]
    for name,args in steps:
        target=ROOT/'runtime'/f'document-audit-{name}-0448.txt'
        print('START '+name,flush=True)
        with target.open('w',encoding='utf-8') as stream:
            result=subprocess.run([sys.executable,*args],cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=900,env=env)
        if result.returncode:
            print(target.read_text(encoding='utf-8',errors='replace')[-5000:],flush=True)
            raise SystemExit(result.returncode)
        print('PASS '+name,flush=True)


if __name__=='__main__':main()
