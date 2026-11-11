"""Reproduce the byte-cap failure using supplied LAB01 byte totals, in owned paths."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.reproduce_native_budget_failure import sparse
from guarddesk.update_native import NativeAdapter


def main():
    proof=json.loads((ROOT/'evidence/maintenance/lab01-budget-minimum-proof-20261029.json').read_text())
    review=json.loads((ROOT/'evidence/security/0.4.59/requirements-review.json').read_text())
    source={}
    for name in ('guarddesk/update_client.py','guarddesk/update_native.py'):
        source[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
        assert source[name]==review['final_source_sha256'][name.replace('/','\\')]
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='lab01-observed-budget-') as tmp:
        base=Path(tmp);program=base/'program';updates=base/'data/updates'
        program.mkdir();updates.mkdir(parents=True)
        # Sparse logical bytes: no company files copied, no 434 MB physical write.
        sample=program/'owned-logical-size.bin'
        sparse(sample,proof['program_bytes_user_reported'])
        adapter=SimpleNamespace(program=program,agent=SimpleNamespace(config_path=base/'data/config.json'))
        NativeAdapter.budget(adapter,0)  # Existing program bytes alone fit.
        failure=None
        try:NativeAdapter.budget(adapter,proof['candidate_uncompressed_payload_bytes'])
        except OSError as exc:
            assert '512 MiB' in str(exc)
            failure={'type':type(exc).__name__,'classified_reason':'aggregate_byte_limit_512_mib'}
        assert failure and sample.stat().st_size==proof['program_bytes_user_reported']
        assert not list(updates.iterdir())
    result={'passed':True,'source_matches_0459_review':source,
        'program_bytes':proof['program_bytes_user_reported'],'candidate_bytes':proof['candidate_uncompressed_payload_bytes'],
        'updates_bytes_modeled':0,'sum_bytes':proof['minimum_budget_bytes_excluding_updates'],
        'cap_bytes':proof['limit_bytes'],'failure':failure,'scope':'Exact supplied byte total represented by one owned sparse file; real NativeAdapter.budget and storage_budget, no Windows protected installation or actual LAB01 execution',
        'confirmed':'Current reported program bytes plus verified candidate payload exceed byte cap even with zero updates bytes',
        'unconfirmed':'Original historical OSError text was not saved; field remediation/retry not performed',
        'company_changed':False,'product_changed':False}
    (ROOT/'evidence/maintenance/lab01-observed-budget-reproduction-20261029.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':main()
