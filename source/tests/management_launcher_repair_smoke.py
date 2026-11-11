"""Actual cmd.exe plus a tiny owned .NET fixture; never runs the office Server."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.build_management_start_repair import launcher


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='launcher-v2-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);program=root/'program & !';program.mkdir();exe=program/'GuardDesk.exe'
        source=root/'Fixture.cs'
        source.write_text('''using System; using System.IO; using System.Text;
class Fixture { static int Main(string[] args) {
 if (args.Length == 1 && args[0] == "component-info") {
   if (Environment.GetEnvironmentVariable("OWNED_RUNTIME_FAIL") == "1") { Console.Error.WriteLine("OWNED RUNTIME ERROR"); return 7; }
   Console.WriteLine("{\\"version\\":\\"owned-fixture\\"}"); return 0;
 }
 File.WriteAllText(Environment.GetEnvironmentVariable("OWNED_MARKER"),String.Join("\\n",args),Encoding.UTF8);
 Console.Error.WriteLine("OWNED SERVER EXIT: "+Environment.GetEnvironmentVariable("OWNED_SERVE_RESULT"));
 return Int32.Parse(Environment.GetEnvironmentVariable("OWNED_SERVE_RESULT"));
} }''',encoding='ascii')
        compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        built=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(exe),str(source)],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert built.returncode==0,built.stdout+built.stderr
        def run_case(name,config=True,missing_exe=False,runtime_fail=False,serve_result=23,blocked_log=False):
            data=root/(name+' 資料 & ! (owned)');data.mkdir()
            script=data/'Start-Management.cmd';body=launcher([exe if not missing_exe else program/'absent.exe']);script.write_bytes(body)
            assert b'server-setup' not in body and b'\n' not in body.replace(b'\r\n',b'')
            if config:(data/'server.json').write_text('{}',encoding='ascii')
            if blocked_log:(data/'Management-Startup.txt').mkdir()
            marker=data/'marker.txt';env=os.environ.copy();env.update(OWNED_MARKER=str(marker),OWNED_RUNTIME_FAIL='1' if runtime_fail else '0',OWNED_SERVE_RESULT=str(serve_result))
            cmd=Path(os.environ['SystemRoot'])/'System32/cmd.exe'
            proc=subprocess.Popen(f'"{cmd}" /d /s /v:off /c ""{script}""',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
            expected_serve=config and not missing_exe and not runtime_fail and not blocked_log
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if proc.poll() is not None:
                        early_out,early_err=proc.communicate(timeout=5)
                        raise AssertionError((name+' closed before user EXIT',early_out,early_err))
                    if marker.exists() if expected_serve else ((data/'Management-Startup.txt').is_file() and ('ERROR:' in (data/'Management-Startup.txt').read_text(errors='replace'))) or blocked_log:break
                    time.sleep(.05)
                else:
                    last_out,last_err=proc.communicate(b'exit\r\n',timeout=5)
                    log=(data/'Management-Startup.txt').read_bytes() if (data/'Management-Startup.txt').is_file() else b''
                    raise AssertionError((name+' did not reach expected branch',log,last_out,last_err))
                time.sleep(.3)
                assert proc.poll() is None,name+' lost its persistent console'
                out,err=proc.communicate(b'exit\r\n',timeout=10)
            finally:
                if proc.poll() is None:proc.kill();proc.communicate(timeout=5)
            if expected_serve:
                assert marker.read_text(encoding='utf-8-sig').splitlines()==['serve','--config',str(data/'server.json'),'--open-console']
                assert ('OWNED SERVER EXIT: '+str(serve_result)).encode() in err+out
            else:assert not marker.exists(),name+' unexpectedly invoked serve'
            if config:assert (data/'server.json').read_bytes()==b'{}'
            return out+err, data
        output,_=run_case('missing-config',config=False);assert b'server.json is missing' in output;checks.append('Missing config remains visible; no runtime/server invoked')
        output,_=run_case('missing-exe',missing_exe=True);assert b'GuardDesk.exe was not found' in output;checks.append('Missing executable remains visible; no fallback to setup')
        output,_=run_case('runtime-failure',runtime_fail=True);assert b'OWNED RUNTIME ERROR' in output;checks.append('Runtime failure exit 7 is logged and remains visible; serve not invoked')
        run_case('serve-failure',serve_result=23);checks.append('Native server exits 23 immediately; actual cmd /k remains alive until explicit EXIT')
        run_case('serve-success',serve_result=0);checks.append('Native command returns 0; console remains until explicit EXIT; exact serve/config arguments')
        run_case('blocked-log',blocked_log=True);checks.append('Unwritable log destination stops before any native server invocation and keeps the console')
        checks.append('Space, Chinese, ampersand, exclamation and parentheses in data path preserve the exact config argument; fixture config unchanged')
        data=root/'actual-frozen-validation';data.mkdir();script=data/'Start-Management.cmd'
        script.write_bytes(launcher([ROOT/'dist/GuardDesk/GuardDesk.exe']))
        (data/'server.json').write_bytes(b'{}')
        cmd=Path(os.environ['SystemRoot'])/'System32/cmd.exe'
        proc=subprocess.Popen(f'"{cmd}" /d /s /v:off /c ""{script}""',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            time.sleep(1)
            assert proc.poll() is None,'Actual frozen launcher did not retain its command window'
            out,err=proc.communicate(b'exit\r\n',timeout=20)
        finally:
            if proc.poll() is None:proc.kill();proc.communicate(timeout=5)
        assert '設定需含'.encode('utf-8') in out+err,(out,err)
        assert (data/'server.json').read_bytes()==b'{}'
        assert not any(p.suffix in ('.sqlite3','.db') for p in data.iterdir())
        checks.append('Actual 0.4.33 frozen EXE validates an owned invalid config and its UTF-8 error remains visible; no DB created or config changed')
    archive=ROOT/'dist/GuardDesk-Management-Start-Repair-v2.zip'
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        manifest=json.loads(z.read('MANIFEST-SHA256.json'))
        assert all(hashlib.sha256(z.read(n)).hexdigest()==v for n,v in manifest.items())
        assert z.read('Start-Management.cmd')==launcher()
        assert set(z.namelist())=={'Start-Management.cmd','README.txt','MANIFEST-SHA256.json'}
    report={'passed':True,'artifact':'dist/GuardDesk-Management-Start-Repair-v2.zip','sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'checks':checks,'status':'internal_trial_launcher_only','office_server_modified':False,'limits':['Native fixture validates command-window behavior; actual Server startup failure still needs its visible error','Startup text records paths/version check/console exit only; live Server errors remain on screen to avoid an unbounded live log','No company Defender/EDR/Windows Server acceptance performed']}
    (ROOT/'evidence/management-launcher-repair-v2.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
