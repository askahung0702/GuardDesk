"""Actual CMD, icacls and junction boundaries on owned fixture roots only."""
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
from tools.build_lab01_acl_audit import render
from lab01_archive_smoke import SOURCE
from guarddesk.source_permissions import WindowsSecurity


def main():
    checks=[]
    try:
        api=WindowsSecurity();system=Path(os.environ['SystemRoot'])/'System32';cmd=system/'cmd.exe'
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='lab01-audit-') as t:
            base=Path(t).resolve();assert base.is_relative_to((ROOT/'runtime').resolve())
            cs=base/'Fixture.cs';cs.write_text(SOURCE,encoding='ascii');exe=base/'fixture.exe'
            compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            p=subprocess.run([str(compiler),'/nologo','/out:'+str(exe),str(cs)],capture_output=True,timeout=30)
            assert p.returncode==0,p.stdout+p.stderr
            tools=base/'tools';tools.mkdir()
            for n in ['fltmc','choice','icacls']:shutil.copyfile(exe,tools/(n+'.exe'))
            def run(name,*,junction=False,limit=False,wronghost=False,choice='1',**faults):
                root=base/(name+' 中文 & ! (owned)');root.mkdir()
                data=root/'data';updater=root/'Updater';native=root/'USBControl'
                for p in (data,updater,native):p.mkdir()
                child=data/'child & ! ^ ; %PATH% (owned)';child.mkdir()
                empty=child/'empty';empty.mkdir()
                file=child/'config %COMSPEC% & ! ^ ; (owned).json';file.write_bytes(b'OWNED SECRET CONTENT MUST NOT BE READ')
                hidden=data/';hidden-system-owned.bin';hidden.write_bytes(b'OWNED HIDDEN CONTENT')
                a=subprocess.run([str(system/'attrib.exe'),'+h','+s',str(hidden)],capture_output=True);assert a.returncode==0
                grant=subprocess.run([str(system/'icacls.exe'),str(file),'/grant','*S-1-1-0:F'],capture_output=True);assert grant.returncode==0
                outside=root/'outside-owned';outside.mkdir();(outside/'outside-owned-marker').write_bytes(b'OUTSIDE MUST NOT BE COLLECTED')
                if junction:
                    p=subprocess.run([str(cmd),'/d','/c','mklink','/J',str(data/'owned-junction'),str(outside)],capture_output=True)
                    assert p.returncode==0,p.stdout+p.stderr
                before={p:(p.read_bytes(),api.descriptor(p),p.stat().st_file_attributes) for q in [data,updater,native,outside] for p in q.rglob('*') if p.is_file()}
                script=root/'Audit-LAB01-ACL.bat'
                script.write_bytes(render(dict(HOST='NOT-THIS-HOST' if wronghost else os.environ['COMPUTERNAME'],
                    TOOLS=tools,DATA=data,UPDATER=updater,NATIVE=native,MAX_NODES='3' if limit else '4096')))
                env=os.environ.copy();env.update(OWNED_LOG=str(root/'invocations.txt'),OWNED_CHOICE_INDEX=str(root/'choice-index'),OWNED_CHOICES=choice)
                env.update({'OWNED_'+k.upper():'1' for k,v in faults.items() if v})
                p=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{script}""',env=env,input=b'',capture_output=True,timeout=40)
                console=(p.stdout+p.stderr).decode('utf-8',errors='replace')
                assert 'was unexpected' not in console and 'is not recognized as' not in console,console
                dirs=list(root.glob('LAB01-ACL-Audit-*'))
                report=(dirs[0]/'Audit.txt').read_text(encoding='utf-8',errors='replace') if dirs else ''
                raw=(dirs[0]/'DACLs.txt').read_bytes() if dirs else b''
                sddl=raw.decode('utf-16-le') if raw else ''
                log=(root/'invocations.txt').read_text(encoding='utf-8') if (root/'invocations.txt').exists() else ''
                for path,body in before.items():
                    assert path.read_bytes()==body[0] and api.descriptor(path)==body[1] and path.stat().st_file_attributes==body[2],path
                assert 'OWNED SECRET CONTENT' not in report+sddl and 'OWNED HIDDEN CONTENT' not in report+sddl
                assert 'outside-owned-marker' not in report+sddl+log,(report,sddl,log)
                assert '|/t' not in log.lower() and '/remove' not in log.lower() and '/grant' not in log.lower()
                return dict(code=p.returncode,report=report,sddl=sddl,log=log,dirs=dirs,console=console)
            x=run('normal')
            assert x['code']==0 and 'READ_ONLY_COLLECTION_COMPLETE_NOT_A_TRUST_VALIDATION' in x['report'],x
            assert '%PATH%' in x['sddl'] and '%COMSPEC%' in x['sddl'] and ';hidden-system-owned.bin' in x['sddl'],x
            assert ';FA;;;WD)' in x['sddl'],x
            records=x['sddl'].lstrip('\ufeff').splitlines()
            assert len(records)==2*x['report'].count('SavedNode='),(records,x['report'])
            assert all(records[i+1].startswith('D:') for i in range(0,len(records),2))
            checks.append('Real CMD/icacls snapshots include hidden/system files, explicit Everyone F and empty directories; UTF16 aggregate is byte-valid with one record per successful node')
            checks.append('Chinese, &, !, ^, semicolon and literal %PATH%/%COMSPEC% in names never become shell code; contents, owner/DACL and attributes unchanged')
            x=run('junction',junction=True)
            assert x['code']==2 and 'SkippedUnavailableOrReparse=' in x['report'] and 'READ_ONLY_COLLECTION_PARTIAL' in x['report'],x
            checks.append('Actual NTFS directory junction and outside marker skipped before DACL query, unlike observed icacls /T /L traversal; no /T anywhere')
            x=run('node-limit',limit=True)
            assert x['code']==2 and x['report'].count('SavedNode=')==3 and 'LimitOrQueueOrOutputFailure=' in x['report'],x
            checks.append('Node bound stops additional traversal and reports partial rather than trusted/success')
            for name,options in [('wrong-host',dict(wronghost=True)),('not-admin',dict(admin_fail=True)),('declined',dict(choice='2'))]:
                x=run(name,**options);assert x['code']!=0 and not x['dirs'] and 'icacls ' not in x['log'],x
                checks.append(name+': no output/source mutation or DACL traversal')
            x=run('snapshot-failure',dacl_denied=True)
            assert x['code']==2 and 'SnapshotError=' in x['report'],x
            checks.append('Read DACL failure recorded with path/exit code and partial result; not ignored as safe')
        artifact=ROOT/'dist/GuardDesk-LAB01-ACL-Audit-20261029.zip'
        with zipfile.ZipFile(artifact) as z:
            assert z.testzip() is None;m=json.loads(z.read('MANIFEST-SHA256.json'))
            assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in m.items())
            assert set(z.namelist())=={'Audit-LAB01-ACL.bat','README.txt','MANIFEST-SHA256.json'}
            bat=z.read('Audit-LAB01-ACL.bat');assert bat==render() and bat.isascii()
            for bad in [b'/remove',b'/grant',b'/reset',b'/setowner',b'/restore',b'powershell',b'schtasks.exe',b'GuardDesk.exe',b'/t /l']:
                assert bad.lower() not in bat.lower(),bad
        result=dict(passed=True,artifact=str(artifact.relative_to(ROOT)),sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),checks=checks,
            field_operations_performed=False,company_share_changed=False,status='unsigned_internal_read_only_metadata_collection',
            limits=['No owner/SACL collection or trust verdict; DACL collection only','Parallel replacement race cannot be eliminated by CMD attribute checks; maintenance without concurrent directory changes required','DIR enumerates one directory before its 256 KiB names limit is checked; no per-process hard timeout','Actual LAB01 findings, remediation, company Windows/Defender/performance still pending'],
            requirements=['GD-006','GD-007','GD-008','GD-020','GD-021','GD-022','SEC-02','SEC-03','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-04'])
        (ROOT/'evidence/maintenance/lab01-acl-audit-smoke-20261029.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,ensure_ascii=False))
    except Exception as e:
        with (ROOT/'evidence/maintenance/lab01-acl-audit-attempts-20261029.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps({'passed':False,'completed_checks':checks,'error':repr(e)},ensure_ascii=False)+'\n')
        raise


if __name__=='__main__':main()
