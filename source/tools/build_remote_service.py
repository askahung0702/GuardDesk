"""Build fixed SCM host and run owned child/job tests. Never install a service."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT.parent
CMAKE=Path('C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe')
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    number=1
    while (RUNTIME/f'remote-service-build-{number:03}').exists():number+=1
    output=RUNTIME/f'remote-service-build-{number:03}';output.mkdir()
    paths=[*(ROOT/'native/service').iterdir(),*(ROOT/'native/remote').glob('*.hpp'),
           ROOT/'native/remote/cohort.cpp',ROOT/'native/remote/ipc_peer.cpp']
    sources={p.relative_to(ROOT).as_posix():digest(p) for p in paths if p.is_file()}
    report={'passed':False,'sources':sources,'installed':False,'SCM_tested':False,'SYSTEM_tested':False,'stages':[]}
    try:
        with (output/'build.log').open('x',encoding='utf-8') as log:
            for command in ([str(CMAKE),'-S',str(ROOT/'native/service'),'-B',str(output),'-G','Visual Studio 16 2019','-A','x64'],
                            [str(CMAKE),'--build',str(output),'--config','Release','--parallel','2']):
                result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180)
                report['stages'].append(result.returncode)
                if result.returncode:raise ValueError('Native service build failed')
            result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe')],stdout=log,stderr=subprocess.STDOUT,timeout=30)
            if result.returncode:raise ValueError('Owned service lifetime failed')
        image=output/'Release/GuardDeskService.exe'
        tests=[]
        for args,expected in [(['--component-info'],0),([],87),(['--owned-child','1'],87),(['--device-id','../bad'],87)]:
            result=subprocess.run([str(image),*args],capture_output=True,timeout=10)
            if result.returncode!=expected:raise ValueError('Native service entry mismatch')
            tests.append({'arguments':args,'exit':result.returncode})
        if not all(digest(ROOT/name)==value for name,value in sources.items()):raise ValueError('Source changed during build')
        report.update(passed=True,sha256=digest(image),entry_tests=tests,owned_lifetime_cases=['cooperative_stop','worker_failure_exit','coordinator_job_not_inherited_by_helper','timeout_owned_job_termination'])
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    (output/'receipt.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'receipt':str(output/'receipt.json'),'passed':report['passed']}))
    if not report['passed']:raise SystemExit(1)
if __name__=='__main__':main()
