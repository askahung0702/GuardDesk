"""Verify the actual frozen offline publication command without publishing."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    with tempfile.TemporaryDirectory(prefix='publication-',dir=ROOT/'runtime') as d:
        output=Path(d)/'new-output'
        run=subprocess.run([str(exe),'browser-release','--output',str(output)],capture_output=True,timeout=30)
        if run.returncode:raise RuntimeError(run.stderr.decode('utf-8',errors='replace'))
        result=json.loads(run.stdout.decode('utf-8'))
        assert result['status']=='store_publication_required'
        publication=json.loads((output/'publication.json').read_text(encoding='utf-8'))
        assert not publication['private_key_included'] and publication['network_requests']==0
        assert not publication['force_policy_applied'] and not publication['browser_installation_verified']
        for name,digest in json.loads((output/'SHA256.json').read_text(encoding='utf-8')).items():assert sha(output/name)==digest
        existing=ROOT/'dist/browser-publication-0.4.49'
        assert {p.name:sha(p) for p in output.iterdir()}=={p.name:sha(p) for p in existing.iterdir()}
        result.update(output='temporary_fixture_compared_to_dist/browser-publication-0.4.49',passed=True,publication_files={p.name:sha(p) for p in output.iterdir()},enterprise_zip_sha256=sha(ROOT/'dist/GuardDesk-Browser-Enterprise-0.4.49.zip'),frozen_exe_sha256=sha(exe))
    (ROOT/'evidence/browser-publication-0.4.49.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))

if __name__=='__main__':main()
