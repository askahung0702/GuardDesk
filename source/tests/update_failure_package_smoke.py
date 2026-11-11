"""Run actual maintenance ZIP CMD with child-only roots pointing to owned fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    proof=json.loads((ROOT/'evidence/maintenance/lab01-diagnostic-package-20261029-v2.json').read_text())
    artifact=ROOT/proof['artifact']
    assert hashlib.sha256(artifact.read_bytes()).hexdigest()==proof['sha256']
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='diag-zip-') as tmp:
        base=Path(tmp);bundle=base/'診斷 & ! (test)';bundle.mkdir()
        program=base/'program';data=base/'data';program.mkdir();data.mkdir()
        with zipfile.ZipFile(artifact) as z:
            assert z.testzip() is None
            manifest=json.loads(z.read('MANIFEST-SHA256.json'))
            assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in manifest.items())
            assert set(z.namelist())==set(manifest)|{'MANIFEST-SHA256.json'}
            z.extractall(bundle)
        (program/'GuardDeskPilot/Updater/_internal').mkdir(parents=True)
        (program/'GuardDeskPilot/Updater/_internal/agent-release.json').write_text('{"version":"9.8.7"}')
        cmd=Path(os.environ['SystemRoot'])/'System32/cmd.exe'
        entry=bundle/'Diagnose-LAB01-Update.cmd'
        shipped=entry.read_bytes()
        assert b'\\WindowsPowerShell\\v1.0\\powershell.exe' in shipped
        assert all(c>=32 or c in (10,13) for c in shipped)
        # PowerShell normalizes ProgramFiles itself. Explicit test-only roots are
        # safer than overriding the environment. Shipped ZIP remains unchanged.
        fixture=shipped.replace(b' -DeviceId ',(' -ProgramRoot "'+str(program/'GuardDeskPilot')+'" -DataRoot "'+str(data/'GuardDeskPilot')+'" -DeviceId ').encode('ascii'))
        assert fixture!=shipped
        entry.write_bytes(fixture)
        p=subprocess.run(f'"{cmd}" /d /s /v:off /c ""{entry}""',input=b'\r\n',
                         capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert p.returncode==0,(p.returncode,p.stdout.decode(errors='replace'),p.stderr.decode(errors='replace'))
        report=json.loads((bundle/'GuardDesk-Update-Failure.json').read_text(encoding='utf-8'))
        assert report['device_id']=='ee1e1e17c6c8730a37603b1e'
        assert report['metadata']['updater_manifest']['version']=='9.8.7'
        assert report['metadata']['native_transaction']['status']=='read_error'
    result={'passed':True,'artifact':proof['artifact'],'sha256':proof['sha256'],
        'scope':'Actual ZIP CRC/hash and collector bytes; CMD static executable/control-byte check; CMD run with explicit test-only roots; space/Chinese/&/!/parentheses path',
        'installed_agent_queried':False,'lab01_inspected':False,'company_changed':False,
        'policy_modified':False,'bypass_used':False,'unsigned':True}
    (ROOT/'evidence/maintenance/update-failure-package-smoke-20261029.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':main()
