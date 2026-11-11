"""Serial isolated integration checks on the exact compiled candidate."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    steps=[('packaged',['tests/packaged_smoke.py']),('progress',['tests/update_progress_browser_smoke.py','--frozen']),('documents',['tests/document_audit_browser_smoke.py','--frozen']),('uploads',['tests/upload_memory_browser_smoke.py','--frozen-host']),('upload-framing',['tests/packaged_web_upload_smoke.py'])]
    if '--after-packaged' in sys.argv:
        proof=json.loads((ROOT/'evidence/packaged-smoke.json').read_text(encoding='utf-8'));app=ROOT/'dist/GuardDesk'
        assert proof['passed'] and proof['application_files']=={p.relative_to(app).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in app.rglob('*') if p.is_file()}
        steps=steps[1:]
    for name,args in steps:
        print('START '+name,flush=True);log=ROOT/f'runtime/verify-0456-{name}.txt'
        with log.open('w',encoding='utf-8') as stream:result=subprocess.run([sys.executable,*args],cwd=ROOT,env={**os.environ,'PYTHONIOENCODING':'utf-8'},stdout=stream,stderr=subprocess.STDOUT,timeout=900)
        if result.returncode:print(log.read_text(encoding='utf-8',errors='replace')[-7000:],flush=True);return result.returncode
        print('PASS '+name,flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
