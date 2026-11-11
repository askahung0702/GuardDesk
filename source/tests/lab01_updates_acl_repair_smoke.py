"""Actual NTFS protected updates-root model; no office installation access."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.build_lab01_updates_acl_repair import render,DID,SID
from tools.analyze_lab01_acl_reports import analyze
from lab01_archive_smoke import SOURCE
from guarddesk.source_permissions import WindowsSecurity
from guarddesk.update_native import protected_tree


def main():
    checks=[]
    try:
        system=Path(os.environ['SystemRoot'])/'System32';cmd=system/'cmd.exe'
        api=WindowsSecurity();user=api.current_user();world='S-1-1-0'
        def icacls(*args):
            p=subprocess.run([str(system/'icacls.exe'),*map(str,args)],capture_output=True,timeout=25)
            assert p.returncode==0,(args,p.returncode,p.stdout,p.stderr)
        with tempfile.TemporaryDirectory(prefix='lab01-updates-acl-',dir=ROOT/'runtime') as tmp:
            base=Path(tmp).resolve();assert base.is_relative_to((ROOT/'runtime').resolve())
            source=SOURCE.replace('int at=Array.IndexOf(a,"/save");',r'''
   if(Array.IndexOf(a,"/remove:g")>=0 && E("OWNED_REMOVE_FAIL")=="1") return 5;
   int at=Array.IndexOf(a,"/save");
''').replace('if(role=="icacls") {',r'''
  if(role=="certutil" && E("OWNED_HASH_FAIL")=="1") return 5;
  if(role=="whoami") { Console.WriteLine("SeRestorePrivilege"); return 0; }
  if(role=="icacls") {
''')
            cs=base/'Fixture.cs';cs.write_text(source,encoding='ascii');exe=base/'fixture.exe'
            compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            p=subprocess.run([str(compiler),'/nologo','/out:'+str(exe),str(cs)],capture_output=True,timeout=30)
            assert p.returncode==0,p.stdout+p.stderr
            tools=base/'tools';tools.mkdir()
            for name in ['fltmc','choice','icacls','certutil','whoami','findstr']:shutil.copyfile(exe,tools/(name+'.exe'))
            cli=base/'GuardDesk.exe';shutil.copyfile(exe,cli)
            jobs=['264626046385d80b133c831738b747ae','62f0fa075ac160ce37231d9a79350d05','660a1644e7c0412616c3341062ce96f6','82fcee146799c0834eff6bbb876a8ba9']
            def run(name,choices='21',explicit=False,wrong_host=False,**faults):
                case=base/(name+' 中文 & ! (owned)');case.mkdir()
                data=case/DID;data.mkdir()
                icacls(data,'/inheritance:r','/grant:r',f'*{user}:(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-3-4:(OI)(CI)(RC)')
                target=data/'updates';target.mkdir()
                # Same failure boundary as field: clean parent, separately protected
                # updates with one explicit nontrusted grant and ten inherited nodes.
                icacls(target,'/inheritance:r','/grant:r',f'*{user}:(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-3-4:(OI)(CI)(RC)',f'*{world}:(OI)(CI)F')
                for job in jobs:
                    (target/job).mkdir();(target/job/'package.zip').write_bytes(b'OWNED PACKAGE '+job.encode())
                for name in ['transaction-native.json','updater-refresh.json']:(target/name).write_bytes(b'{"owned":"preserve original transaction"}')
                (data/'config.json').write_bytes(b'OWNED IDENTITY PRESERVE');(data/'private-queue.bin').write_bytes(b'OWNED PENDING EVENTS PRESERVE')
                entries=[data,*data.rglob('*')]
                before={p:(api.descriptor(p),p.read_bytes() if p.is_file() else None,p.stat().st_file_attributes) for p in entries}
                assert len([p for p in entries if any(e[3]==world for e in before[p][0][1])])==11
                try:protected_tree(data,allow_current_user=True)
                except OSError as e:assert '非信任' in str(e)
                else:raise AssertionError('Protected updates must fail even with trusted parent')
                if explicit:icacls(target/jobs[0]/'package.zip','/grant:r',f'*{world}:F')
                script=case/'Repair-LAB01-Updates-ACL.bat'
                script.write_bytes(render(dict(host='NOT-THIS-HOST' if wrong_host else os.environ['COMPUTERNAME'],parent=data,tools=tools,exe=cli,trustee='*'+world)))
                env=os.environ.copy();env.update(OWNED_LOG=str(case/'calls.txt'),OWNED_CHOICE_INDEX=str(case/'choice-index'),OWNED_CHOICES=choices)
                env.update({'OWNED_'+k.upper():'1' for k,v in faults.items() if v})
                p=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{script}""',env=env,input=b'',capture_output=True,timeout=45)
                console=(p.stdout+p.stderr).decode('utf-8',errors='replace')
                assert 'was unexpected' not in console and 'is not recognized as' not in console,console
                reports=list(case.glob('LAB01-Updates-ACL-Repair-*.txt'))
                report=reports[0].read_text(encoding='utf-8',errors='replace') if reports else ''
                log=(case/'calls.txt').read_text(encoding='utf-8') if (case/'calls.txt').exists() else ''
                for path,(desc,body,attrs) in before.items():
                    assert api.descriptor(path)[0]==desc[0] and path.stat().st_file_attributes==attrs
                    if body is not None:assert path.read_bytes()==body
                    if not path.is_relative_to(target):assert api.descriptor(path)==desc
                for line in log.splitlines():
                    if '/remove:g' in line:assert str(target)+'|' in line and '|/t' not in line.lower() and '|/l' in line
                return dict(code=p.returncode,case=case,data=data,target=target,before=before,report=report,log=log)
            x=run('exact-field-layout')
            assert x['code']==0 and 'INSTALLED_CHECK_PASSED_CAPACITY_ARCHIVE_STILL_PENDING' in x['report'],x
            protected_tree(x['data'],allow_current_user=True)
            for path,(before,_,_) in x['before'].items():
                after=api.descriptor(path)
                assert sorted(after[1])==sorted(e for e in before[1] if e[3]!=world),(path,before,after)
            backup=list(x['case'].glob('LAB01-Updates-ACL-Before-*.txt'))
            assert len(backup)==1
            records=backup[0].read_bytes().decode('utf-16-le').lstrip('\ufeff').splitlines()
            assert len(records)==2 and records[0]=='updates' and ';FA;;;WD)' in records[1]
            assert 'GuardDesk.exe updater-check|--device-id|'+DID in x['log'].replace('guarddesk ','GuardDesk.exe ')
            checks.append('Real protected updates under already-clean data parent: actual production ACL predicate rejects before, single-target remove:g propagates to all ten inherited objects and predicate passes after (fixture owner/current SID only)')
            checks.append('Exact parent/sibling DACLs, all source owners/attributes/transaction/identity/private queue/package bytes and all nonremoved ACEs unchanged; backup contains updates only and supports the documented parent restore target')
            for name,options,marker in [
                ('readonly',dict(choices='1'),'READ_ONLY_ACL_REPORT_COMPLETE'),
                ('decline',dict(choices='22'),'CANCELLED_NO_REMOVE_ATTEMPT'),
                ('wrong-host',dict(wrong_host=True),''),
                ('nonadmin',dict(admin_fail=True),''),
                ('backup-denied',dict(dacl_denied=True),'BACKUP_FAILED_NO_REMOVE_ATTEMPT'),
                ('backup-hash-failed',dict(hash_fail=True),'BACKUP_FAILED_NO_REMOVE_ATTEMPT'),
                ('remove-denied',dict(remove_fail=True),'GRANT_REMOVE_FAILED_OR_PARTIAL'),
            ]:
                x=run(name,**options)
                if marker:assert marker in x['report'],x
                for path,(desc,_,_) in x['before'].items():assert api.descriptor(path)==desc
                assert 'guarddesk ' not in x['log']
                checks.append(name+': no source ACL/content/owner change or installed CLI')
            x=run('explicit-child',explicit=True,cli_fail=True)
            assert x['code']!=0 and 'INSTALLED_CHECK_FAILED_KEEP_BACKUP' in x['report'],x
            assert not any(e[3]==world for e in api.descriptor(x['target'])[1])
            assert any(e[3]==world for e in api.descriptor(x['target']/jobs[0]/'package.zip')[1])
            try:protected_tree(x['data'],allow_current_user=True)
            except OSError:pass
            else:raise AssertionError('Independent child ACE must not be silently stripped')
            checks.append('Unexpected independent child grant remains; reports CLI failure, no recursive reset/removal')
        artifact=ROOT/'dist/GuardDesk-LAB01-Updates-ACL-Repair-20261029.zip'
        with zipfile.ZipFile(artifact) as z:
            assert z.testzip() is None
            for n,h in json.loads(z.read('MANIFEST-SHA256.json')).items():assert hashlib.sha256(z.read(n)).hexdigest()==h
            bat=z.read('Repair-LAB01-Updates-ACL.bat');assert bat==render() and bat.isascii()
            assert ('*'+SID).encode() in bat and b'"updates" /save' in bat
            if os.environ['COMPUTERNAME'].upper()!='LAB01':
                with tempfile.TemporaryDirectory(prefix='lab01-updates-delivered-',dir=ROOT/'runtime') as tmp:
                    p=Path(tmp)/'Repair-LAB01-Updates-ACL.bat';p.write_bytes(bat)
                    r=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{p}""',input=b'',capture_output=True,timeout=15)
                    assert r.returncode==1 and b'restricted to LAB01' in r.stdout
                    assert list(Path(tmp).iterdir())==[p]
            checks.append('Actual unmodified ZIP BAT rejects non-LAB01 before any output/tools; ZIP CRC/manifest/render match')
        # Keep parser negative cases independent of the field share and exact counts.
        for a,d in [(b'SavedNode=1 Scope=1 Path="x"\r\n',b''),(b'ExitCode=0\r\n',b'')]:
            try:analyze(a,d)
            except (AssertionError,UnicodeError):pass
            else:raise AssertionError('Incomplete report accepted')
        checks.append('Offline parser rejects incomplete/unpaired reports; field CRLF normalization and raw-byte hash are separate')
        result=dict(passed=True,checks=checks,artifact=str(artifact.relative_to(ROOT)),sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            status='unsigned_internal_scoped_updates_DACL_maintenance',field_changes_by_agent=False,
            limits=['No actual LAB01 execution or true SYSTEM owner/CLI/task acceptance','Real NTFS fixture uses Everyone F and current test owner as allowed solely for fixture','Previously observed privileged icacls restore 1300 remains unaccepted on company endpoint; no policy or privilege change','Capacity archive, full upgrade, company Windows/Defender/performance and ACL provenance remain pending'],
            requirements=['MACHINE-01','GD-002','GD-006','GD-007','GD-008','GD-020','GD-021','GD-022','SEC-02','SEC-03','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04'])
        (ROOT/'evidence/maintenance/lab01-updates-acl-repair-smoke-20261029.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,ensure_ascii=False))
    except Exception as e:
        with (ROOT/'evidence/maintenance/lab01-updates-acl-repair-attempts-20261029.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(dict(passed=False,checks=checks,error=repr(e)),ensure_ascii=False)+'\n')
        raise


if __name__=='__main__':main()
