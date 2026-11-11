"""Real Windows PowerShell against owned metadata; never query installed Agent."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/collect_update_failure.ps1'
PS = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
DID = 'a' * 24
JID = 'b' * 32


def main():
    checks = []
    with tempfile.TemporaryDirectory(dir=ROOT / 'runtime', prefix='update-failure-') as tmp:
        root = Path(tmp)
        program = root / '程式 & ! (test)'
        data = root / 'data'
        private = data / 'USBControl' / DID
        updates = private / 'updates'
        updates.mkdir(parents=True)
        for name in ('Updater', 'USBControl'):
            (program / name / '_internal').mkdir(parents=True)
        def write(path, value):
            path.write_text(json.dumps(value), encoding='utf-8')
        write(private / 'broker-health.json', {'version':'0.4.59','native_version':'0.4.59','time':1793232000,'pid':123,'token':'DO-NOT-EXPORT'})
        write(private / 'native-health.json', {'version':'0.4.59','time':1793232001,'pid':456})
        write(private / 'update-broker-status.json', {'code':'execution_failed','error_type':'OSError','error':'SECRET-EXCEPTION'})
        transaction = updates / 'transaction-native.json'
        write(transaction, {'phase':'switching','old_version':'0.4.59','target':'0.4.64','reported':False,
            'job':{'id':JID,'token':'SECRET-JOB','release':{'payload':'SECRET-PAYLOAD'}},
            'failure':{'stage':'switching','type':'PermissionError','winerror':32,'errno':13,'detail':'SECRET-DETAIL'},
            'rollback_failure':{'stage':'unknown','type':'OSError','winerror':5},'config':'SECRET-CONFIG'})
        write(program / 'Updater/_internal/agent-release.json', {'version':'0.4.59','files':{'sensitive':'SECRET-MANIFEST'}})
        write(program / 'USBControl/_internal/agent-release.json', {'version':'0.4.59'})
        write(updates / 'updater-refresh.json', {'phase':'failed','old_version':'0.4.59','target':'0.4.64','job_id':JID})
        (updates / JID).mkdir()
        (updates / JID / 'package.zip').write_bytes(b'owned-package-not-executed')
        (program / ('USBControl.rollback-' + JID)).mkdir()
        (program / 'secret-directory').mkdir()
        write(private / 'config.json', {'token':'SECRET-CREDENTIAL'})
        def snapshot():
            return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for base in (program,data) for p in base.rglob('*') if p.is_file()}
        before = snapshot()
        def run(name):
            out = root / (name+'.json')
            result = subprocess.run([str(PS),'-NoProfile','-NonInteractive','-File',str(SCRIPT),
                '-DeviceId',DID,'-ProgramRoot',str(program),'-DataRoot',str(data),'-OutputPath',str(out)],
                capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise AssertionError((result.returncode,result.stdout.decode(errors='replace'),result.stderr.decode(errors='replace')))
            return out,json.loads(out.read_text(encoding='utf-8'))
        out, body = run('normal')
        text = out.read_text(encoding='utf-8')
        assert 'SECRET' not in text and 'DO-NOT-EXPORT' not in text, text
        t = body['metadata']['native_transaction']
        assert t['failure']['winerror']==32 and t['rollback_failure']['winerror']==5
        assert t['job_id']==JID and t['phase']=='switching'
        assert body['metadata']['updater_manifest']['version']=='0.4.59'
        assert body['cache']['packages'][0]['package.zip']==len(b'owned-package-not-executed')
        assert 'secret-directory' not in text
        assert snapshot()==before
        checks.append('Real PS5 metadata snapshot preserves original/rollback codes and updater version; credentials/envelope/free-text are excluded; inputs unchanged')
        # A forged field must not escape just because its JSON key is allowed.
        write(transaction, {'phase':'SECRET-PHASE','target':'SECRET-VERSION',
            'failure':{'stage':'SECRET-STAGE','type':'SECRET-TYPE','winerror':'SECRET-CODE'},'job':{'id':'SECRET-ID'}})
        _, body = run('hostile')
        assert 'SECRET' not in json.dumps(body)
        checks.append('Forged values under allowed keys are rejected rather than exported')
        transaction.write_bytes(b'x' * (2097152+1))
        _, body = run('large')
        assert body['metadata']['native_transaction']['status']=='too_large'
        transaction.write_text('{bad json',encoding='utf-8')
        _, body = run('broken')
        assert body['metadata']['native_transaction']['status']=='read_error'
        transaction.unlink()
        _, body = run('missing')
        assert body['metadata']['native_transaction']['status']=='read_error'
        checks.append('Oversized, malformed and missing transaction metadata produce bounded per-file failures')
        # The report never overwrites prior evidence or writes under protected roots.
        for target in (out,data/'report.json',program/'report.json'):
            result = subprocess.run([str(PS),'-NoProfile','-NonInteractive','-File',str(SCRIPT),'-DeviceId',DID,
                '-ProgramRoot',str(program),'-DataRoot',str(data),'-OutputPath',str(target)],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode!=0
        checks.append('Existing report and installation/data output targets rejected')
        for i in range(70):
            (updates / format(i,'032x')).mkdir()
        _, body = run('bounded')
        assert body['cache']['truncated'] is True and len(body['cache']['packages'])<=64
        checks.append('Cache inventory stops after 64 entries; never recurses into packages or program trees')
    report = {'passed':True,'script_sha256':hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        'checks':checks,'lab01_inspected':False,'installed_agent_queried':False,'company_changed':False,
        'limits':['Owned metadata fixtures; not LAB01 or company policy acceptance','No lock-owner determination or full recursive cache size','No Authenticode signing; company script policy remains in force']}
    (ROOT/'evidence/maintenance/update-failure-metadata-smoke-20261029.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':
    main()
