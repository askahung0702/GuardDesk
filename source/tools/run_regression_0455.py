import hashlib,json,os,re,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def snapshot():
    result={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for area in ('guarddesk','native','browser-extension','tests') for p in (ROOT/area).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.html','.css','.json','.cpp','.dll') and '__pycache__' not in p.parts}
    result['app.py']=hashlib.sha256((ROOT/'app.py').read_bytes()).hexdigest()
    return result


def main():
    before=snapshot();start=time.monotonic();log=ROOT/('runtime/full-tests-0455-'+uuid.uuid4().hex[:12]+'.txt')
    env={**os.environ,'PYTHONIOENCODING':'utf-8'}
    with log.open('xb') as stream:result=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_*.py','-v','-f'],cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT)
    body=log.read_text(encoding='utf-8',errors='replace');match=re.search(r'Ran (\d+) tests in ([\d.]+)s',body)
    evidence={'passed':result.returncode==0 and snapshot()==before,'exit_code':result.returncode,'tests':int(match[1]) if match else None,'elapsed_seconds':round(time.monotonic()-start,3),'source_unchanged_during_run':snapshot()==before,'source_sha256':before,'log':log.relative_to(ROOT).as_posix(),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
    (ROOT/'evidence/full-tests-0.4.55.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in evidence.items() if k!='source_sha256'}));return 0 if evidence['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
