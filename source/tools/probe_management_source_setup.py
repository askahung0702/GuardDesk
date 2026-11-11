"""Real delivered ZIP / inherited NTFS ACL regression; never starts a center.

Only self-created fixtures below the selected owned helper-build folder change.
Use --final-package to additionally run the real CMD's program-check boundary.
"""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, subprocess, sys, zipfile
from ctypes import wintypes as w

S=Path(__file__).resolve().parents[1]; R=S.parents[1]
sys.path.insert(0,str(S))
from guarddesk.endpoint_files import secure_directory
from guarddesk.source_permissions import WindowsSecurity, check_source
import threading

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--helper-root',type=Path,required=True)
    parser.add_argument('--final-package',type=Path)
    parser.add_argument('--pipeline-run',action='store_true')
    parser.add_argument('--expected-version',default='0.4.94')
    parser.add_argument('--baseline-package',type=Path)
    parser.add_argument('--baseline-sha256')
    a=parser.parse_args(); E=a.helper_root.resolve(strict=True)
    valid_name=E.name.startswith('management-build-') if a.pipeline_run else E.name.startswith('center-source-permissions-094-')
    if E.parent!=R/'runtime' or not valid_name:raise ValueError('Owned build folder required')
    if a.pipeline_run and (not a.final_package or not a.baseline_package or not a.baseline_sha256):raise ValueError('Complete pipeline inputs required')
    api=WindowsSecurity(); sid=api.current_user(); adv=api.adv
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
    adv.GetSecurityDescriptorDacl.argtypes=[w.LPVOID,ctypes.POINTER(w.BOOL),ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)]
    adv.SetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID]
    adv.SetNamedSecurityInfoW.restype=w.DWORD
    def dacl(path,sddl):
        sd=w.LPVOID(); acl=w.LPVOID(); present=w.BOOL(); default=w.BOOL()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(sd),None):raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not adv.GetSecurityDescriptorDacl(sd,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(default)):raise ctypes.WinError(ctypes.get_last_error())
            code=adv.SetNamedSecurityInfoW(str(path),1,0x80000004,None,None,acl,None)
            if code:raise ctypes.WinError(code)
        finally:api.kernel.LocalFree(sd)
    base=f'(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
    import secrets
    parent=secure_directory(E/(('p-' if a.pipeline_run else ('owned-final-parent-' if a.final_package else 'owned-inherited-parent-'))+secrets.token_hex(4)))
    # Exact reported grants: Users RX, inherited CI AD, inherited CI WD.
    # Unrelated deny and CREATOR OWNER are retained, not replaced by a template.
    dacl(parent,'D:P(D;OICI;0x10000;;;NU)'+base+'(A;CI;4;;;BU)(A;CI;2;;;BU)(A;OICIIO;FA;;;CO)')
    parent_before=api.descriptor(parent)
    root=parent/('新 Server (測試)' if a.pipeline_run else '全新 Server 安裝 (測試)');root.mkdir()
    old=a.baseline_package.resolve(strict=True) if a.pipeline_run else R/'dist/GuardDesk-Management-0.4.94-internal-004.zip'
    if a.pipeline_run and not old.is_relative_to(R/'runtime'):raise ValueError('Baseline package escaped runtime')
    assert sha(old)==(a.baseline_sha256 if a.pipeline_run else 'ba37273ffd8f2facf5f14d02aa3ad1f785efa4b60964296f6f7328622cf6e004')
    package=a.final_package or old
    with zipfile.ZipFile(package) as z:z.extractall(root)
    helper=E/'GuardDeskCenterPrepare.exe'
    originals={p.relative_to(root).as_posix():sha(p) for p in root.rglob('*') if p.is_file()}
    paths=[root,root/'GuardDesk',*(root/'GuardDesk').rglob('*')]
    owners={str(p):api.descriptor(p)[0] for p in paths}
    def non_users(p):return sorted((k,flags&~16,mask,trustee) for k,flags,mask,trustee in api.descriptor(p)[1] if trustee!='S-1-5-32-545')
    other_before={str(p):non_users(p) for p in paths}
    report={'passed':False,'no_center_started':True,'installed_changed':False,'Defender_changed':False,'cases':[]}
    def run(args,name,expected):
        result=subprocess.run(args if isinstance(args,str) else [str(x) for x in args],capture_output=True,timeout=120)
        raw=result.stdout+result.stderr;(E/(name+'.log')).write_bytes(raw)
        report['cases'].append({'name':name,'exit':result.returncode,'expected':expected})
        assert result.returncode==expected,(name,result.returncode,raw[-500:])
        return raw.decode('utf-8',errors='replace')
    output=E/('final-package-tests.json' if a.final_package else 'owned-tests.json')
    try:
        if not a.final_package:
            before=api.descriptor(root)
            text=run([root/'GuardDeskCenterPrepare.exe','--prepare',root],'delivered004-inherited-ACL-failure',1)
            assert 'ACL_READBACK_FAILED' in text and 'OriginalDACLRestoreSucceeded=True' in text
            assert api.descriptor(root)==before
            report['inherited_CI_WD_AD_reproduced_on_delivered_004']=True
        run([helper,'--check-only',root],'inherited-before-check',2)
        run([helper,'--prepare',root],'inherited-fixed-prepare',0)
        run([helper,'--prepare',root],'inherited-idempotent-prepare',0)
        run([helper,'--check-only',root],'inherited-fixed-check',0)
        check_source(root/'GuardDesk',threading.Event())
        assert api.descriptor(parent)==parent_before
        assert all(api.descriptor(p)[0]==owners[str(p)] for p in paths)
        # Propagation/conversion can coalesce equivalent ACEs; compare per-SID
        # unions by type/inheritance flags, ignoring only inherited provenance.
        def effective(entries):
            out={}
            for kind,flags,mask,trustee in entries:
                # Windows may split an OICI grant into this-object + OICIIO
                # when resolving CREATOR OWNER on propagated descendants.
                # Compare each scope rather than requiring ACE-list identity.
                scopes=[]
                if not flags&8:scopes.append('this')
                if flags&1:scopes.append('files')
                if flags&2:scopes.append('directories')
                for scope in scopes:
                    key=(kind,flags&4,scope,trustee);out[key]=out.get(key,0)|mask
            return out
        differences=[{'path':str(p.relative_to(root)), 'before':other_before[str(p)],'after':non_users(p)} for p in paths if effective(non_users(p))!=effective(other_before[str(p)])]
        if differences:(E/'non-users-ACE-differences.json').write_text(json.dumps(differences[:12],indent=2),encoding='utf-8')
        assert not differences
        assert all(sha(root/n)==h for n,h in originals.items())
        report.update(inherited_CI_WD_AD_fixed_on_real_NTFS=True,
            original_payload_bytes_unchanged=True,other_owner_grants_and_denies_preserved=True,parent_unchanged=True)
        if a.final_package:
            assert (root/'Setup-Management.cmd').read_bytes().isascii()
            for cp in (437,950,65001):
                command=f'chcp {cp}>nul & call "{root / "Setup-Management.cmd"}" --check-program-only'
                text=run('cmd.exe /d /s /c "'+command+'"',f'final-CMD-check-cp{cp}',0)
                assert 'not recognized' not in text and 'PROGRAM_SOURCE_READY' in text
            # Real missing-program CMD error branch; no wizard/listener can run.
            exe=root/'GuardDeskCenterPrepare.exe'; hold=root/'GuardDeskCenterPrepare.exe.held';exe.rename(hold)
            try:
                for cp in (437,950,65001):
                    command=f'chcp {cp}>nul & call "{root / "Setup-Management.cmd"}" --check-program-only'
                    text=run('cmd.exe /d /s /c "'+command+'"',f'final-CMD-missing-cp{cp}',2)
                    assert 'not recognized' not in text and 'No center data' in text
            finally:hold.rename(exe)
            # Exercise the actual frozen product's source permission and package
            # builder without initializing or starting any management center.
            # These are fabricated PUBLIC connection values, never installed.
            import base64
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives.serialization import Encoding
            from datetime import datetime,timedelta,timezone
            key=ed25519.Ed25519PrivateKey.generate()
            name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'Self-owned offline package test')])
            now=datetime.now(timezone.utc)
            ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
                .sign(key,None).public_bytes(Encoding.PEM))
            connection=E/'owned-public-connection.zip'
            body={'version':1,'server':'https://offline-fixture.invalid:8787','ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}
            with zipfile.ZipFile(connection,'w') as z:
                z.writestr('endpoint-connection.json',json.dumps(body))
                z.writestr('GuardDesk-CA.pem',ca)
                z.writestr('update-trust.json',json.dumps({'format':1,'public_key':base64.b64encode(os.urandom(32)).decode('ascii')}))
            endpoint=E/('owned-final-endpoint-'+parent.name+'.zip')
            run([root/'GuardDesk/GuardDesk.exe','endpoint-package','--connection-zip',connection,'--output',endpoint],'frozen-final-offline-endpoint-package',0)
            with zipfile.ZipFile(endpoint) as z:
                m=json.loads(z.read('endpoint-files.json'));assert m['version']==a.expected_version
                for n,h in m['files'].items():assert hashlib.sha256(z.read('GuardDesk/'+n)).hexdigest()==h
                assert 'GuardDesk/_internal/GuardDeskService.exe' in z.namelist()
            report['actual_frozen_offline_endpoint_package']={'passed':True,'version':m['version'],'files':len(m['files']),'sha256':sha(endpoint)}
        # Root CI explicit grants (the old fixture shape) still work.
        dacl(root,'D:P'+base+'(A;CI;6;;;BU)')
        run([helper,'--prepare',root],'explicit-CI-grants-fixed',0)
        # Different dangerous rights are not silently repaired, nor are unrelated
        # files/reparse targets or corrupt payload accepted.
        for name,extra,reason in [
            ('users-modify','(A;OICI;0x1301bf;;;BU)','USERS_REPLACEMENT_OR_OTHER_WRITE'),
            ('other-write','(A;;2;;;AU)','OTHER_UNTRUSTED_WRITE')]:
            dacl(root,'D:P'+base+extra);before=api.descriptor(root)
            text=run([helper,'--prepare',root],name+'-refused',1)
            assert reason in text and api.descriptor(root)==before
            dacl(root,'D:P'+base)
        extra=root/'unrelated-company-file.txt';extra.write_text('SELF-OWNED NEGATIVE FIXTURE')
        try:
            before=api.descriptor(root);run([helper,'--prepare',root],'unrelated-file-refused',1)
            assert api.descriptor(root)==before
        finally:extra.unlink()
        victim=root/'GuardDesk/_internal/agent-release.json';raw=victim.read_bytes();victim.write_bytes(raw+b' ')
        try:
            before=api.descriptor(root);run([helper,'--prepare',root],'bad-hash-refused',1)
            assert api.descriptor(root)==before
        finally:victim.write_bytes(raw)
        # Size is rejected before reading the oversized file or changing ACL.
        original=victim.read_bytes()
        try:
            with victim.open('r+b') as f:f.truncate(513*1024*1024)
            before=api.descriptor(root)
            text=run([helper,'--prepare',root],'oversize-file-refused',1)
            assert 'PROGRAM_BYTES_LIMIT_EXCEEDED' in text and api.descriptor(root)==before
        finally:victim.write_bytes(original)
        link=root/'GuardDesk/_internal/owned-junction';target=secure_directory(E/('owned-junction-target-'+secrets.token_hex(4)))
        mark=target/'marker.txt';mark.write_text('SELF-OWNED REPARSE TARGET')
        run('cmd.exe /d /s /c "mklink /J "'+str(link)+'" "'+str(target)+'""','create-owned-junction',0)
        try:
            before=api.descriptor(root)
            text=run([helper,'--prepare',root],'junction-refused',1)
            assert 'REPARSE_PATH_REFUSED' in text and api.descriptor(root)==before and mark.read_text()=='SELF-OWNED REPARSE TARGET'
        finally:os.rmdir(link) # remove only the verified junction itself
        run([helper,'--prepare',Path(root.anchor)],'drive-root-refused',1)
        run([helper,'--prepare',parent],'non-package-folder-refused',1)
        # No center/data/config, credentials, or endpoint were created.
        assert not list(parent.rglob('control.sqlite3')) and not list(parent.rglob('server.json'))
        assert all(sha(root/n)==h for n,h in originals.items())
        report.update(passed=True,archive_sha256=sha(package),fixture=str(root),program_files=len(originals),
            actual_helper_permission_predicate_passed=True,source_permission_predicate_passed=True,
            original_payload_bytes_unchanged=True)
    finally:output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},ensure_ascii=False))

if __name__=='__main__':main()
