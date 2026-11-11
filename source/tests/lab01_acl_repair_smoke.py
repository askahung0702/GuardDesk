"""Real Windows DACL propagation/restore and CMD on owned data; no office ACLs."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
import ctypes
from ctypes import wintypes as w

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.build_lab01_acl_repair import DID,render
from lab01_archive_smoke import SOURCE
from guarddesk.source_permissions import WindowsSecurity
from guarddesk.update_native import protected_tree

WORLD='S-1-1-0'


def main():
    checks=[]
    try:
        api=WindowsSecurity();user_sid=api.current_user()
        system=Path(os.environ['SystemRoot'])/'System32'
        cmd=system/'cmd.exe'
        def icacls(*args,cwd=None):
            p=subprocess.run([str(system/'icacls.exe'),*map(str,args)],cwd=cwd,capture_output=True,timeout=25)
            assert p.returncode==0,(args,p.returncode,p.stdout,p.stderr)
            return p
        with tempfile.TemporaryDirectory(prefix='lab01-acl-repair-',dir=ROOT/'runtime') as tmp:
            base=Path(tmp).resolve()
            assert base.is_relative_to((ROOT/'runtime').resolve())
            source=SOURCE.replace('int at=Array.IndexOf(a,"/save");',r'''
   if(Array.IndexOf(a,"/remove:g")>=0 && E("OWNED_REMOVE_FAIL")=="1") return 5;
   if(a.Length==1 && E("OWNED_QUERY_FAIL")=="1") return 5;
   int at=Array.IndexOf(a,"/save");
''').replace('if(role=="icacls") {',r'''
  if(role=="certutil" && E("OWNED_HASH_FAIL")=="1") return 5;
  if(role=="whoami") {
   if(E("OWNED_RESTORE_PRIV_QUERY_FAIL")=="1") return 5;
   Console.WriteLine(E("OWNED_RESTORE_PRIV_MISSING")=="1" ? "SeChangeNotifyPrivilege" : "SeRestorePrivilege");
   return 0;
  }
  if(role=="icacls") {
''')
            cs=base/'Fixture.cs';cs.write_text(source,encoding='ascii')
            exe=base/'fixture.exe'
            compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            p=subprocess.run([str(compiler),'/nologo','/out:'+str(exe),str(cs)],capture_output=True,timeout=30)
            assert p.returncode==0,p.stdout+p.stderr
            tools=base/'tools';tools.mkdir()
            for n in ['fltmc','choice','icacls','certutil','whoami','findstr']:shutil.copyfile(exe,tools/(n+'.exe'))
            binary=base/'Updater.exe';shutil.copyfile(exe,binary)
            # Executable filename must be GuardDesk for the owned CLI dispatcher.
            binary.rename(base/'GuardDesk.exe');binary=base/'GuardDesk.exe'

            def run(name,choices='21',*,explicit_child=False,wrong_host=False,junction=False,**faults):
                root=base/(name+' 中文 & ! (owned)');root.mkdir()
                parent=root/'parent';parent.mkdir();data=parent/DID;data.mkdir()
                # Fixture-only trusted current SID keeps standard-user cleanup possible.
                # Production protected_tree is not altered or relaxed.
                icacls(data,'/inheritance:r','/grant:r',f'*{user_sid}:(OI)(CI)F',
                    '*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-3-4:(OI)(CI)(RC)',f'*{WORLD}:(OI)(CI)F')
                child=data/'child';child.mkdir()
                config=data/'config.json';config.write_bytes(b'OWNED PRIVATE CONFIG PRESERVE')
                queue=child/'queue.bin';queue.write_bytes(b'OWNED OFFLINE EVENT PRESERVE')
                if explicit_child:icacls(queue,'/grant:r',f'*{WORLD}:F')
                original={config:config.read_bytes(),queue:queue.read_bytes()}
                owners={p:api.descriptor(p)[0] for p in [data,child,config,queue]}
                before=api.descriptor(data)
                try:protected_tree(data,allow_current_user=True)
                except OSError as e:assert '非信任' in str(e),str(e)
                else:raise AssertionError('Actual owned extra full-control grant was not rejected')
                real_data=data
                if junction:
                    data.rename(root/'owned-data-target');real_data=root/'owned-data-target'
                    p=subprocess.run([str(cmd),'/d','/c','mklink','/J',str(data),str(real_data)],capture_output=True)
                    assert p.returncode==0,p.stdout+p.stderr
                script=root/'Repair-LAB01-Data-ACL.bat'
                script.write_bytes(render(dict(host='NOT-THIS-HOST' if wrong_host else os.environ['COMPUTERNAME'],
                    parent=parent,exe=binary,tools=tools,trustee='*'+WORLD)))
                env=os.environ.copy();env.update(OWNED_LOG=str(root/'invocations.txt'),
                    OWNED_CHOICE_INDEX=str(root/'choice-index'),OWNED_CHOICES=choices)
                env.update({'OWNED_'+k.upper():'1' for k,v in faults.items() if v})
                p=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{script}""',env=env,input=b'',
                    capture_output=True,timeout=45,creationflags=subprocess.CREATE_NO_WINDOW)
                text=(p.stdout+p.stderr).decode('utf-8',errors='replace')
                assert 'was unexpected' not in text and 'is not recognized as' not in text,text
                report_files=list(root.glob('LAB01-ACL-Repair-*.txt'))
                report=report_files[0].read_text(encoding='utf-8',errors='replace') if report_files else ''
                log=(root/'invocations.txt').read_text(encoding='utf-8') if (root/'invocations.txt').exists() else ''
                if not junction:
                    for path,body in original.items():assert path.read_bytes()==body,(name,path)
                    for path,owner in owners.items():assert api.descriptor(path)[0]==owner,(name,path)
                assert 'schTasks'.lower() not in log.lower() and '/reset' not in log.lower() and '/setowner' not in log.lower()
                for line in log.splitlines():
                    if '/remove:g' in line:assert '|/t' not in line.lower() and '|/l' in line.lower(),line
                return dict(code=p.returncode,root=root,data=real_data,parent=parent,before=before,
                    report=report,log=log,output=text,backups=list(root.glob('LAB01-ACL-Before-*.txt')))

            x=run('read-only',choices='1')
            assert x['code']==0 and 'READ_ONLY_ACL_REPORT_COMPLETE' in x['report'],x
            assert api.descriptor(x['data'])==x['before'] and not x['backups'] and 'guarddesk ' not in x['log']
            checks.append('C only queries exact owned root ACL; no backup/change/CLI/task operations')
            x=run('repair-success')
            assert x['code']==0 and 'INSTALLED_CHECK_PASSED_CAPACITY_ARCHIVE_STILL_PENDING' in x['report'],x
            protected_tree(x['data'],allow_current_user=True)
            after=api.descriptor(x['data'])
            assert after[0]==x['before'][0]
            assert sorted(after[1])==sorted(e for e in x['before'][1] if e[3]!=WORLD),(x['before'],after)
            assert not any(e[3]==WORLD for e in api.descriptor(x['data']/'child/queue.bin')[1])
            assert len(x['backups'])==1
            backup=x['backups'][0]
            body=backup.read_bytes().decode('utf-16-le').lstrip('\ufeff')
            assert DID in body and 'queue.bin' not in body and '\\child' not in body
            checks.append('Real NTFS extra inherited full-control grant causes actual protected_tree rejection; root-only remove:g removes it and inherited child grants; all other ACEs, owners, config/queue bytes retained')
            restore=subprocess.run([str(system/'icacls.exe'),str(x['parent']),'/restore',str(backup),'/l'],capture_output=True,timeout=25)
            assert restore.returncode in (0,1300),(restore.returncode,restore.stdout,restore.stderr)
            admin_restore_verified=restore.returncode==0
            if not admin_restore_verified:
                checks.append('Actual icacls /restore refused with 1300 under non-admin token; privileged command acceptance remains pending, not counted as passed restore')
                # Fixture-only WRITE_DAC restoration verifies saved root DACL
                # semantics without pretending the failed admin command passed.
                records=body.splitlines();assert len(records)==2 and records[0]==DID and records[1].startswith('D:')
                adv=api.adv;descriptor=w.LPVOID();acl=w.LPVOID();present=w.BOOL();defaulted=w.BOOL()
                adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
                adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
                adv.GetSecurityDescriptorDacl.argtypes=[w.LPVOID,ctypes.POINTER(w.BOOL),ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)]
                adv.GetSecurityDescriptorDacl.restype=w.BOOL
                adv.SetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID]
                adv.SetNamedSecurityInfoW.restype=w.DWORD
                assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(records[1],1,ctypes.byref(descriptor),None)
                try:
                    assert adv.GetSecurityDescriptorDacl(descriptor,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(defaulted)) and present
                    protection=0x80000000 if 'P' in records[1].split('(')[0] else 0x20000000
                    code=adv.SetNamedSecurityInfoW(str(x['data']),1,4|protection,None,None,acl,None)
                    assert code==0,code
                finally:api.kernel.LocalFree(descriptor)
            assert api.descriptor(x['data'])==x['before']
            try:protected_tree(x['data'],allow_current_user=True)
            except OSError:pass
            else:raise AssertionError('Rollback must restore original untrusted grant as documented')
            checks.append('Saved root DACL restores exact descriptor and inherited grant via '+('actual icacls /restore' if admin_restore_verified else 'fixture-only Win32 WRITE_DAC API; this is NOT privileged icacls acceptance')+'; manual rollback decision remains required')
            x=run('explicit-child-not-expanded',explicit_child=True,cli_fail=True)
            assert x['code']==1 and 'ACL_COMMAND_COMPLETED_INSTALLED_CHECK_FAILED_KEEP_BACKUP' in x['report'],x
            assert not any(e[3]==WORLD for e in api.descriptor(x['data'])[1])
            assert any(e[3]==WORLD for e in api.descriptor(x['data']/'child/queue.bin')[1])
            try:protected_tree(x['data'],allow_current_user=True)
            except OSError:pass
            else:raise AssertionError('Explicit child grant must remain and prevent broad success')
            checks.append('Independent explicit child grant remains rejected; no recursive removal/reset and no false full-repair result')
            for name,kwargs,marker in [
                ('wrong-host',dict(wrong_host=True),''), ('not-admin',dict(admin_fail=True),''),
                ('gate-declined',dict(choices='22'),'CANCELLED_NO_REMOVE_ATTEMPT'),
                ('query-failed',dict(query_fail=True),'ACL_QUERY_FAILED_NO_REMOVE_ATTEMPT'),
                ('restore-privilege-missing',dict(restore_priv_missing=True),'RESTORE_PRIVILEGE_UNAVAILABLE_NO_REMOVE_ATTEMPT'),
                ('restore-privilege-query-failed',dict(restore_priv_query_fail=True),'RESTORE_PRIVILEGE_UNAVAILABLE_NO_REMOVE_ATTEMPT'),
                ('backup-denied',dict(dacl_denied=True),'BACKUP_FAILED_NO_REMOVE_ATTEMPT'),
                ('backup-missing',dict(dacl_missing=True),'BACKUP_FAILED_NO_REMOVE_ATTEMPT'),
                ('backup-hash-failed',dict(hash_fail=True),'BACKUP_FAILED_NO_REMOVE_ATTEMPT'),
                ('remove-failed',dict(remove_fail=True),'GRANT_REMOVE_FAILED_OR_PARTIAL_INSPECT_BEFORE_RETRY'),
            ]:
                x=run(name,**kwargs)
                assert x['code']!=0 and (not marker or marker in x['report']),x
                assert api.descriptor(x['data'])==x['before'] and 'guarddesk ' not in x['log'],x
                if name!='remove-failed':assert '/remove:g' not in x['log'],x
                checks.append(name+': no owner/content/ACL change, no installed CLI/task; specific failure retained')
            x=run('root-junction',junction=True)
            assert x['code']==1 and 'PATH_UNAVAILABLE_OR_REPARSE_REFUSED' in x['report'],x
            assert 'icacls ' not in x['log'] and api.descriptor(x['data'])==x['before']
            checks.append('Actual owned root junction refused before DACL tools or installed CLI')
            checks.append('Actual CMD Chinese/space/&/!/parentheses paths preserve literal reports and backup paths')

        artifact=ROOT/'dist/GuardDesk-LAB01-Data-ACL-Repair-20261029.zip'
        with zipfile.ZipFile(artifact) as z:
            assert z.testzip() is None;m=json.loads(z.read('MANIFEST-SHA256.json'))
            assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in m.items())
            assert set(z.namelist())=={'Repair-LAB01-Data-ACL.bat','README.txt','MANIFEST-SHA256.json'}
            bat=z.read('Repair-LAB01-Data-ACL.bat');assert bat==render()
            assert b'\n' not in bat.replace(b'\r\n',b'') and bat.isascii()
            for word in [b'powershell',b'cscript',b'mshta',b'taskkill',b'schtasks.exe',b'/reset',b'/setowner',b'/grant']:
                # Preview describes forbidden operations; only inspect executable lines.
                executable_lines=b'\n'.join(l for l in bat.splitlines() if l.startswith(b'"%GD_'))
                assert word.lower() not in executable_lines.lower(),word
            assert b'/remove:g "%GD_TRUSTEE%" /l' in bat and b'EXAMPLE\\user1' in bat
            if os.environ['COMPUTERNAME'].upper()!='LAB01':
                with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='lab01-acl-delivered-') as t:
                    p=Path(t)/'Repair-LAB01-Data-ACL.bat';p.write_bytes(bat)
                    r=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{p}""',input=b'',capture_output=True,timeout=15)
                    assert r.returncode==1 and b'restricted to LAB01' in r.stdout
                    assert len(list(Path(t).iterdir()))==1
                checks.append('Actual unmodified delivered BAT rejects current non-LAB01 host before any tool/output/change')
        report=dict(passed=True,artifact=str(artifact.relative_to(ROOT)),sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            checks=checks,field_operations_performed=False,installed_agent_queried=False,
            requirements=['MACHINE-01','GD-006','GD-007','GD-008','GD-020','GD-021','GD-022','SEC-02','SEC-03','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],
            status='unsigned_internal_operator_assisted_scoped_DACL_maintenance',
            privileged_icacls_restore_verified=admin_restore_verified,
            limits=['Owned real Windows DACL uses Everyone as nontrusted trustee and fixture current SID as trusted owner; no actual EXAMPLE user1 SID/domain/owner/SYSTEM acceptance',
                'Manual gates remain required for exact root owner, privileged grants, private backup path, installed executable trust, no concurrent update and no descendant reparse links',
                'Root DACL backup excludes owner/SACL and independently explicit child ACLs; no full-tree reset/owner repair',
                'Capacity archive, actual update/identity/queue, Windows10/11 company Defender/performance and persistent retention fix still pending'])
        (ROOT/'evidence/maintenance/lab01-data-acl-repair-smoke-20261029.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False))
    except Exception as e:
        with (ROOT/'evidence/maintenance/lab01-data-acl-repair-attempts-20261029.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps({'passed':False,'completed_checks':checks,'error':repr(e)},ensure_ascii=False)+'\n')
        raise


if __name__=='__main__':main()
