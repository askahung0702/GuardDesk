"""CMD acceptance with an owned fake installed CLI; no local Agent is queried."""
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
from tools.build_existing_update_check import collector


def main():
    checks=[];artifact=ROOT/'dist/GuardDesk-Installed-Updater-Check.zip'
    with tempfile.TemporaryDirectory(prefix='installed-check-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);program=root/'program & !';program.mkdir();exe=program/'GuardDesk.exe';source=root/'Fixture.cs'
        source.write_text('''using System; using System.IO; class Fixture { static int Main(string[] args) {
 if(args.Length!=3 || args[0]!="updater-check" || args[1]!="--device-id") return 99;
 File.AppendAllText(Environment.GetEnvironmentVariable("OWNED_INVOCATIONS"),args[2]+"\\n");
 Console.WriteLine("{\\"passed\\":true,\\"native_version\\":\\"0.4.19\\",\\"check_only\\":true}");
 return Environment.GetEnvironmentVariable("OWNED_FAIL")=="1"?2:0;
} }''',encoding='ascii')
        compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(exe),str(source)],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        cmd=Path(os.environ['SystemRoot'])/'System32/cmd.exe'
        def run(name,ids=(),missing_exe=False,missing_data=False,fail=False,persistent=False,blocked=False):
            folder=root/(name+' 私人 & ! (owned)');folder.mkdir();data=folder/'data';data.mkdir()
            for did in ids:(data/did).mkdir()
            binary=exe if not missing_exe else program/'missing.exe'
            script=folder/'Collect-Installed-Update-Check.cmd';script.write_bytes(collector(binary,data if not missing_data else folder/'missing-data'))
            output=folder/'GuardDesk-Installed-Update-Check.txt'
            if blocked:output.mkdir()
            invocations=folder/'invocations.txt';env=os.environ.copy();env.update(OWNED_INVOCATIONS=str(invocations),OWNED_FAIL='1' if fail else '0')
            if persistent:
                entry=folder/'Diagnose-Installed-Updater.cmd';entry.write_bytes((ROOT/'dist/installed-update-check/Diagnose-Installed-Updater.cmd').read_bytes());script=entry
            proc=subprocess.Popen(f'"{cmd}" /d /s /v:off /c ""{script}""',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                if persistent:
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        if invocations.exists() and output.is_file() and output.read_text(encoding='utf-8').count('CheckExitCode=')==min(8,len(ids)):break
                        if proc.poll() is not None:raise AssertionError('Persistent wrapper closed early')
                        time.sleep(.05)
                    else:raise AssertionError('Collector did not finish')
                    time.sleep(.15);assert proc.poll() is None
                out,err=proc.communicate(b'exit\r\n' if persistent else b'',timeout=15)
            finally:
                if proc.poll() is None:proc.kill();proc.communicate(timeout=5)
            invoked=invocations.read_text().splitlines() if invocations.exists() else []
            text=output.read_text(encoding='utf-8') if output.is_file() else ''
            return invoked,text,out+err,proc.returncode
        invoked,text,console,code=run('filtered',ids=['a'*24,'not-a-device','b'*23,'z'*24,'b'*24])
        assert invoked==['a'*24,'b'*24] and text.count('CheckExitCode=0')==2,(invoked,text,console,code)
        checks.append('Only exact lowercase 24-hex IDs invoke the existing updater-check CLI with fixed arguments')
        invoked,text,_,_=run('bounded',ids=[format(i,'024x') for i in range(10)])
        assert len(invoked)==8;checks.append('At most eight endpoint IDs are checked; only one fixed native-data directory is enumerated')
        for option in ('missing_exe','missing_data'):
            invoked,text,_,_=run(option,ids=['a'*24],**{option:True});assert not invoked and 'ERROR:' in text
        invoked,text,_,_=run('no-id',ids=['not-valid']);assert not invoked and 'ERROR:' in text
        checks.append('Missing installed executable/data/ID stops without another binary, installer or fallback script')
        invoked,text,_,_=run('failed-check',ids=['a'*24],fail=True);assert invoked==['a'*24] and 'CheckExitCode=2' in text
        checks.append('Existing CLI failure result is retained in the report without attempting repair or update')
        invoked,_,_,_=run('persistent',ids=['a'*24],persistent=True);assert invoked==['a'*24]
        checks.append('Actual CMD entry remains open after collection until explicit EXIT; space/Chinese/&/!/parentheses paths preserve arguments')
        invoked,_,_,code=run('blocked-output',ids=['a'*24],blocked=True);assert not invoked and code==1
        checks.append('Unwritable output stops before native CLI execution')
    with zipfile.ZipFile(artifact) as z:
        assert z.testzip() is None;manifest=json.loads(z.read('MANIFEST-SHA256.json'))
        assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in manifest.items())
        assert not any(n.endswith(('.exe','.dll','.ps1','.db','.sqlite3','.pem','.key')) for n in z.namelist())
        for name in ('Collect-Installed-Update-Check.cmd','Diagnose-Installed-Updater.cmd'):
            body=z.read(name);assert b'\n' not in body.replace(b'\r\n',b'')
            for forbidden in (b'powershell.exe',b'ExecutionPolicy',b'EncodedCommand',b'Unblock-File',b'usb-install',b'update-service',b'server-setup'):
                assert forbidden.lower() not in body.lower(),forbidden
    report={'passed':True,'artifact':str(artifact.relative_to(ROOT)).replace('\\','/'),'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'checks':checks+['ZIP CRC/SHA256 verified; no executable, DLL, PowerShell, credential or DB bundled'],'office_user1_inspected':False,'local_installed_agent_queried':False,'status':'internal_trial_existing_CLI_wrapper','applicable':['SEC-01','SEC-03','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04'],'limits':['Owned .NET fixture tests wrapper arguments and behavior, not user1 or Defender acceptance','Only invokes the pre-existing updater-check; it may not explain an earlier transient failure','user1 application/signature policy remains unchanged; blocked CMD/executable requires MIS review']}
    (ROOT/'evidence/installed-update-check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
