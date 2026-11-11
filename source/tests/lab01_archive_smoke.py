"""Real CMD and NTFS moves on owned fixtures only; no installed Agent/task access."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_lab01_archive import DID, JOBS, STAGE, REVISION, render

# Independent transcription from the supplied dir screenshot, deliberately NOT
# populated from the generator's allowlist (v1's fixture copied its bad ID).
OBSERVED_JOB_DIRS = [
    '264626046385d80b133c831738b747ae', '62f0fa075ac160ce37231d9a79350d05',
    '660a1644e7c0412616c3341062ce96f6', '82fcee146799c0834eff6bbb876a8ba9',
]
LEGACY_ID = '82fcee146799c0834eff6bb876a8ba9'

SOURCE = r'''
using System; using System.IO; using System.Diagnostics;
class Fixture {
 static string E(string n) { return Environment.GetEnvironmentVariable(n) ?? ""; }
 static int Main(string[] a) {
  string role=Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName).ToLowerInvariant();
  File.AppendAllText(E("OWNED_LOG"),role+" "+String.Join("|",a)+"\n");
  if(role=="fltmc") return E("OWNED_ADMIN_FAIL")=="1"?1:0;
  if(role=="choice") {
   string f=E("OWNED_CHOICE_INDEX"); int n=File.Exists(f)?Int32.Parse(File.ReadAllText(f)):0;
   File.WriteAllText(f,(n+1).ToString()); string s=E("OWNED_CHOICES");
   return n<s.Length ? Int32.Parse(s.Substring(n,1)) : 255;
  }
  if(role=="schtasks") {
   if(a[0]=="/query") { Console.WriteLine("<Task><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Task>"); return 0; }
   if(a[0]=="/end") {
    if(E("OWNED_END_FAIL")=="1") return 1;
    File.WriteAllText(E("OWNED_TASK_STATE"),"stopped");
    if(E("OWNED_CHANGE_STATE")=="1") File.AppendAllText(E("OWNED_NATIVE_JSON")," ");
    return 0;
   }
   if(a[0]=="/run") {
    if(E("OWNED_RUN_FAIL")=="1") return 1;
    File.WriteAllText(E("OWNED_TASK_STATE"),"running"); return 0;
   }
   return 98;
  }
  if(role=="guarddesk") {
   if(a.Length!=3 || a[0]!="updater-check" || a[1]!="--device-id" || a[2]!="ee1e1e17c6c8730a37603b1e") return 99;
   Console.WriteLine("Owned CLI fixture: passed / native_version=0.4.59 / check_only");
   return E("OWNED_CLI_FAIL")=="1"?1:0;
  }
  if(role=="icacls") {
   if(Array.IndexOf(a,"/inheritance:r")>=0 || Array.IndexOf(a,"/setowner")>=0)
    return E("OWNED_ACL_FAIL")=="1"?1:0; // Never change real ACL in the fault fixture.
   int at=Array.IndexOf(a,"/save");
   if(at>=0 && E("OWNED_DACL_DENIED")=="1") return 1;
   if(at>=0 && E("OWNED_DACL_MISSING")=="1") return 0;
   if(at>=0 && E("OWNED_COLLISION")=="1" && a[at+1].EndsWith("DACL-1-before.txt")) {
    Directory.CreateDirectory(Path.Combine(Path.GetDirectoryName(a[at+1]),"Programs",a[0]));
   }
   int result=Forward(role,a);
   if(at>=0 && E("OWNED_DACL_CHANGE")=="1" && a[at+1].EndsWith("after.txt")) File.AppendAllText(a[at+1],"changed");
   if(at>=0 && E("OWNED_DACL_SAME_SIZE")=="1" && a[at+1].EndsWith("after.txt")) {
    byte[] b=File.ReadAllBytes(a[at+1]); b[b.Length-1]^=1; File.WriteAllBytes(a[at+1],b);
   }
   return result;
  }
  return Forward(role,a);
 }
 static int Forward(string role,string[] a) {
  string args=""; foreach(string s in a) args+=(args.Length==0?"":" ")+"\""+s.Replace("\"","\\\"")+"\"";
  var p=Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32",role+".exe"),args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true});
  var o=System.Threading.Tasks.Task.Factory.StartNew(()=>p.StandardOutput.BaseStream.CopyTo(Console.OpenStandardOutput()));
  var e=System.Threading.Tasks.Task.Factory.StartNew(()=>p.StandardError.BaseStream.CopyTo(Console.OpenStandardError()));
  if(!p.WaitForExit(20000)) {p.Kill();return 97;} System.Threading.Tasks.Task.WaitAll(o,e);
  File.AppendAllText(E("OWNED_LOG"),"RETURN "+role+"="+p.ExitCode+"\n"); return p.ExitCode;
 }
}
'''


def main():
    cases = []
    failures_path = ROOT / f'evidence/maintenance/lab01-archive-test-attempts-20261029-{REVISION}.jsonl'
    try:
        assert JOBS == OBSERVED_JOB_DIRS and all(len(j)==32 for j in OBSERVED_JOB_DIRS)
        saved=JOBS[3]
        try:
            JOBS[3]=LEGACY_ID
            try: render()
            except ValueError: pass
            else: raise AssertionError('31-character job ID accepted at build time')
        finally: JOBS[3]=saved
        cases.append('Allowlist independently matches supplied directory screenshot; build rejects 31-hex job ID')
        legacy_zip=ROOT/'dist/GuardDesk-LAB01-Controlled-Archive-20261029.zip'
        assert hashlib.sha256(legacy_zip.read_bytes()).hexdigest()=='680afe29756d71244e0ab8cb31a75d64ca4d39064b05915624db487987878cb0'
        with zipfile.ZipFile(legacy_zip) as z: legacy_bat=z.read('Archive-LAB01.bat').decode('ascii')
        with tempfile.TemporaryDirectory(prefix='lab01-archive-', dir=ROOT / 'runtime') as temp:
            base = Path(temp)
            cs = base / 'Fixture.cs'; cs.write_text(SOURCE, encoding='ascii')
            exe = base / 'fixture.exe'
            compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            proc = subprocess.run([str(compiler), '/nologo', '/out:'+str(exe), str(cs)], capture_output=True, timeout=30)
            assert proc.returncode == 0, proc.stdout + proc.stderr
            tools = base / 'tools'; tools.mkdir()
            for n in ['fltmc', 'choice', 'schtasks', 'icacls', 'certutil', 'findstr']:
                shutil.copyfile(exe, tools / (n+'.exe'))
            cmd = Path(os.environ['SystemRoot']) / 'System32/cmd.exe'

            def run(name, choices='2111', *, modify=None, host=None, legacy=False, **faults):
                root = base / (name+' 中文 & ! (owned)'); root.mkdir()
                program = root / 'program'; data = root / 'data' / DID; updates = data / 'updates'
                updates.mkdir(parents=True); program.mkdir()
                for leaf in ['Updater','USBControl',STAGE,'Updater.rollback-'+JOBS[2],
                             'USBControl.rollback-'+JOBS[2], 'Updater.install-failed-1f3093d7c419ae6b',
                             'USBControl.install-failed-1f3093d7c419ae6b']:
                    (program / leaf).mkdir(); (program / leaf / 'preserve.txt').write_bytes(leaf.encode())
                shutil.copyfile(exe, program / 'Updater/GuardDesk.exe')
                for j in OBSERVED_JOB_DIRS:
                    (updates / j).mkdir(); (updates / j / 'package.zip').write_bytes(b'owned fixture zip')
                pins = {}
                for relative in ['install-transaction.json','updates\\transaction-native.json','updates\\updater-refresh.json']:
                    p = data.joinpath(*relative.split('\\')); p.write_bytes(b'{"owned":"'+relative.encode()+b'"}')
                    pins[relative] = hashlib.sha256(p.read_bytes()).hexdigest()
                (data / 'config.json').write_bytes(b'PRIVATE fixture config must survive')
                (data / 'outbox').mkdir(); (data / 'outbox/event.bin').write_bytes(b'PRIVATE queued evidence')
                archive = root / 'archive-parent' / DID
                script = root / 'Archive-LAB01.bat'
                fixture=dict(host=host or os.environ['COMPUTERNAME'], program=program,
                    data=data, archive=archive, tools=tools, pins=pins,
                    zip_hash=hashlib.sha256(b'owned fixture zip').hexdigest())
                if legacy:
                    body=legacy_bat.replace('set "GD_HOST=LAB01"','set "GD_HOST='+fixture['host']+'"')
                    redirects={
                        rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}':data,
                        rf'C:\ProgramData\GuardDeskPilot\RepairArchive\{DID}':archive,
                        r'C:\ProgramData\GuardDeskPilot\RepairArchive':archive.parent,
                        r'C:\ProgramData\GuardDeskPilot\USBControl':data.parent,
                        r'C:\Program Files\GuardDeskPilot':program,
                        r'C:\Windows\System32':tools,
                        r'C:\ProgramData\GuardDeskPilot':root,
                        r'C:\Program Files':root, r'C:\ProgramData':root,
                    }
                    for old,target in sorted(redirects.items(),key=lambda item:-len(item[0])):
                        body=body.replace(old,str(target).replace('%','%%'))
                    script.write_bytes(body.encode('utf-8'))
                else: script.write_bytes(render(fixture))
                if modify: modify(root,program,data,archive)
                keep = {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file() and p != script}
                env = os.environ.copy()
                env.update(OWNED_LOG=str(root/'invocations.txt'), OWNED_CHOICE_INDEX=str(root/'choice-index'),
                    OWNED_CHOICES=choices, OWNED_TASK_STATE=str(root/'task-state'),
                    OWNED_NATIVE_JSON=str(updates/'transaction-native.json'))
                env.update({'OWNED_'+k.upper():'1' for k,v in faults.items() if v})
                (root/'task-state').write_text('running')
                p = subprocess.run(f'"{cmd}" /d /s /v:off /c ""{script}""', env=env, input=b'',
                    capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                reports = list(root.glob('LAB01-Maintenance-*.txt'))
                report = reports[0].read_text(encoding='utf-8', errors='replace') if reports else ''
                log = (root/'invocations.txt').read_text(encoding='utf-8') if (root/'invocations.txt').exists() else ''
                archived = list(archive.glob('20261029-*')) if archive.exists() else []
                output = (p.stdout+p.stderr).decode('utf-8', errors='replace')
                assert 'was unexpected' not in output and '不是內部或外部' not in output and 'is not recognized as' not in output, output
                # All preserved live files remain byte-identical, including private config/outbox.
                for rel, body in keep.items():
                    if '/'+STAGE+'/' in '/'+rel or any('/updates/'+j+'/' in '/'+rel for j in JOBS):
                        continue
                    if change_state and rel.endswith('updates/transaction-native.json'):
                        continue
                    assert (root / rel).read_bytes()==body, (name,rel)
                return dict(code=p.returncode, report=report, log=log, archived=archived,
                    root=root, program=program, data=data, output=output,
                    hash_output=[f.read_bytes().hex() for f in root.glob('LAB01-Hash-*.txt')],
                    dacl_outputs={str(f.relative_to(root)):f.read_bytes().hex() for a in archived for f in a.glob('DACL-*.txt')},
                    state=(root/'task-state').read_text())

            change_state = False
            x=run('delivered-v1-directory-mismatch',choices='1',legacy=True)
            assert x['code']==1 and 'Result=PREFLIGHT_FAILED' in x['report'] and not x['archived'],x
            assert 'guarddesk ' not in x['log'] and 'schtasks ' not in x['log'],x
            cases.append('Sealed delivered v1 BAT, only redirected to owned paths/tools: reproduces same PREFLIGHT_FAILED before hashes/tasks when actual fourth directory has 32 chars')
            if os.environ.get('OWNED_ONE_CASE')=='1':
                x=run('DACL-after-change',dacl_change=True)
                assert x['code']==1 and 'ARCHIVE_MOVE_OR_DACL_CHECK_FAILED' in x['report'],x
                print('Owned one-case DACL fault passed'); return
            x=run('check', choices='1')
            assert x['code']==0 and 'READ_ONLY_CHECK_COMPLETE' in x['report'] and not x['archived'], x
            assert '/end' not in x['log'] and '/run' not in x['log']
            assert 'guarddesk ' not in x['log']
            cases.append('C check: real certutil; no installed CLI execution, task mutation or archive')
            def missing(r,p,d,a): (p/STAGE).rename(r/'owned-stage-elsewhere')
            def wrong_type(r,p,d,a):
                missing(r,p,d,a); (p/STAGE).write_bytes(b'owned non-directory fixture')
            for name,modify,reason in [('required-directory-missing',missing,'PATH_NOT_VISIBLE'),
                                        ('required-directory-is-file',wrong_type,'PATH_NOT_DIRECTORY')]:
                x=run(name,choices='1',modify=modify)
                assert x['code']==1 and 'Result='+reason in x['report'] and 'FailedPath="'+str(x['program']/STAGE)+'"' in x['report'],x
                assert 'guarddesk ' not in x['log'] and 'schtasks ' not in x['log'] and not x['archived']
                cases.append(name+': exact FailedPath/attributes recorded, no installed CLI/task/archive')
            x=run('success')
            assert x['code']==0 and 'ARCHIVED_WAIT_FOR_FRESH_HEALTH' in x['report'], x
            assert x['state']=='running' and len(x['archived'])==1
            a=x['archived'][0]
            assert (a/'Programs'/STAGE/'preserve.txt').read_bytes()==STAGE.encode()
            assert not (x['program']/STAGE).exists()
            for j in JOBS:
                assert (a/'Packages'/j/'package.zip').read_bytes()==b'owned fixture zip'
                assert not (x['data']/'updates'/j).exists()
            assert x['report'].count('=identical_owner_still_requires_MIS_review')==5
            cases.append('A happy path: real same-volume CMD moves, real icacls DACL save and certutil SHA256 comparisons; only five allowlisted dirs moved')
            for name, kwargs in [
                ('wrong-host',dict(host='NOT-THIS-HOST')), ('not-admin',dict(admin_fail=True)),
                ('cli-denied',dict(cli_fail=True)), ('gate1-declined',dict(choices='22')),
                ('choice-error',dict(choices='')), ('end-denied',dict(end_fail=True)),
                ('gate2-declined',dict(choices='212')), ('new-ACL-failure',dict(acl_fail=True)),
                ('DACL-read-denied',dict(dacl_denied=True)), ('DACL-save-missing',dict(dacl_missing=True)),
                ('dest-collision',dict(collision=True)),
            ]:
                x=run(name,**kwargs)
                assert x['code']!=0 and (x['program']/STAGE).exists(), x
                assert not any((a/'Packages'/JOBS[0]).exists() for a in x['archived'])
                assert x['state']=='running', x
                cases.append(name+': stops; no allowlisted dir moved; original running-task state retained/restored')
            x=run('wrong-journal',modify=lambda r,p,d,a:(d/'install-transaction.json').write_bytes(b'changed'))
            assert x['code']==1 and '/end' not in x['log'] and not x['archived'], x
            assert 'CheckDetail=HASH_MISMATCH' in x['report'] and str(x['data']/'install-transaction.json') in x['report'],x
            x=run('wrong-zip',modify=lambda r,p,d,a:(d/'updates'/JOBS[1]/'package.zip').write_bytes(b'changed'))
            assert x['code']==1 and '/end' not in x['log'] and not x['archived'], x
            cases.append('Changed JSON or ZIP hash refuses before task END or archive creation')
            change_state=True
            x=run('journal-after-stop',change_state=True)
            assert x['code']==1 and x['state']=='running' and not x['archived'], x
            change_state=False
            cases.append('JSON changes after task END: recheck rejects and restores updater without moves')
            for name,kwargs,reason in [
                ('DACL-after-change',dict(dacl_change=True),'ARCHIVE_MOVE_OR_DACL_CHECK_FAILED'),
                ('DACL-after-same-size-change',dict(dacl_same_size=True),'ARCHIVE_MOVE_OR_DACL_CHECK_FAILED'),
                ('capacity-unverified',dict(choices='2112'),'POST_ARCHIVE_MANUAL_REVIEW_REQUIRED'),
                ('restart-failure',dict(run_fail=True),'UPDATER_RESTART_FAILED_MANUAL_ACTION_REQUIRED'),
            ]:
                x=run(name,**kwargs)
                assert x['code']==1 and reason in x['report'], x
                assert len(x['archived'])==1 and (x['archived'][0]/'Programs'/STAGE).exists()
                if name!='restart-failure': assert x['state']=='running'
                cases.append(name+': preserves partial/full archive and originals, non-success exit, no automatic rollback/redeploy')
            # Actual owned NTFS junction: top-level path must be rejected, never traverse/move it.
            def junction(r,p,d,a):
                old=p/STAGE; old.rename(p/'owned-real-stage')
                q=subprocess.run([str(cmd),'/d','/c','mklink','/J',str(old),str(p/'owned-real-stage')],capture_output=True)
                assert q.returncode==0,q.stdout+q.stderr
            x=run('stage-junction',modify=junction)
            assert x['code']==1 and '/end' not in x['log'] and not x['archived'],x
            assert 'Result=PATH_REPARSE_POINT_REFUSED' in x['report'] and 'FailedPath=' in x['report'],x
            cases.append('Actual owned NTFS junction at allowlisted stage rejected before installed CLI/task calls')
            cases.append('Chinese, spaces, &, ! and parentheses in owned BAT/roots preserve literal paths')
        artifact=ROOT/f'dist/GuardDesk-LAB01-Controlled-Archive-20261029-{REVISION}.zip'
        with zipfile.ZipFile(artifact) as z:
            assert z.testzip() is None
            manifest=json.loads(z.read('MANIFEST-SHA256.json'))
            assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in manifest.items())
            bat_name=f'Archive-LAB01-{REVISION}.bat'
            assert set(z.namelist())=={bat_name,'README.txt','runbook.txt','MANIFEST-SHA256.json'}
            bat=z.read(bat_name)
            assert bat==render() and b'\n' not in bat.replace(b'\r\n',b'')
            for word in (b'powershell',b'cscript',b'mshta',b'taskkill',b'/delete',b'/disable',b'rmdir',b'ExecutionPolicy',b'EncodedCommand'):
                assert word.lower() not in bat.lower(),word
            assert b'call :move_one' in bat and bat.count(b'call :move_one')==5
            if os.environ['COMPUTERNAME'].upper()!='LAB01':
                with tempfile.TemporaryDirectory(prefix='lab01-delivery-',dir=ROOT/'runtime') as d:
                    delivered=Path(d)/'Archive-LAB01.bat'; delivered.write_bytes(bat)
                    p=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{delivered}""',input=b'',capture_output=True,timeout=15)
                    assert p.returncode==1 and b'restricted to LAB01' in p.stdout,p.stdout+p.stderr
                    assert sorted(x.name for x in Path(d).iterdir())==['Archive-LAB01.bat']
                cases.append('Actual unmodified BAT extracted from final ZIP refuses on current non-LAB01 host before CLI/tool/task/output operations')
        report=dict(passed=True, checks=cases, artifact=str(artifact.relative_to(ROOT)),
            sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            field_operations_performed=False, installed_agent_queried=False,
            status='unsigned_internal_operator_assisted_maintenance',
            limitations=['Fixture does not validate actual SYSTEM task stop/start, real admin ACL creation/owner or LAB01 acceptance',
                'Center job state, exact task identity/action/running state, process exit, parent/subtree owner/ACL/reparse and post capacity are explicit operator gates',
                'Abrupt CMD closure cannot guarantee updater restart; report/runbook requires MIS manual recovery',
                'No permanent retention fix, product upgrade or full Defender/Win10/11/performance acceptance'],
            requirements=['GD-006','GD-007','GD-008','GD-009','GD-020','GD-021','GD-022',
                'SEC-01','SEC-02','SEC-03','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'])
        (ROOT/f'evidence/maintenance/lab01-controlled-archive-smoke-20261029-{REVISION}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False))
    except Exception as e:
        with failures_path.open('a',encoding='utf-8') as f:
            f.write(json.dumps(dict(passed=False, completed_checks=cases, error=repr(e)),ensure_ascii=False)+'\n')
        raise


if __name__=='__main__':
    main()
