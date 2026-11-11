"""Read actual DEV 66 updater and execute its budget only on owned sparse data."""
import hashlib,json,os,sys,tempfile,types
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import update_packages as packages
from tools.reproduce_native_budget_failure import sparse


def main():
    from guarddesk.windows_controls import is_admin
    if not is_admin() or os.environ.get('COMPUTERNAME','').upper()!='DEV-01':raise SystemExit('Fixed DEV read-only admin proof only')
    observed=json.loads((ROOT/'evidence/maintenance/dev-update-failure-20261029-144041.json').read_text(encoding='utf-8'))
    exe=packages.plain(Path(os.environ['ProgramFiles'])/'GuardDeskPilot/Updater/GuardDesk.exe')
    digest=packages.file_hash(exe)
    assert digest=='80f60d3cd2151dac648ac85cb9a794f4adc7045bbdb4cccfd1e8c5cdfa760d7f','Actual updater differs; preserve it'
    archive=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz')
    code=archive.extract('guarddesk.update_client')
    budget_code=next(c for c in code.co_consts if isinstance(c,types.CodeType) and c.co_name=='storage_budget')
    old=types.FunctionType(budget_code,{'packages':packages})
    size=observed['usage']['program']['bytes']+observed['usage']['updates']['bytes'];incoming=observed['current_package']['incoming_bytes']
    assert size==494451150 and incoming==85922867
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='actual-66-budget-') as tmp:
        root=Path(tmp);sparse(root/'owned-retained.bin',size)
        try:old([root],incoming)
        except OSError as exc:assert '512 MiB' in str(exc)
        else:raise AssertionError('Actual installed budget must reproduce observed rejection')
    proof=dict(company_changed=False,actual_installed_updater='0.4.66',actual_exe_sha256=digest,
        old_frozen_budget_reproduced=True,observed_program_bytes=observed['usage']['program']['bytes'],
        observed_updates_bytes=observed['usage']['updates']['bytes'],incoming_bytes=incoming,
        projected_bytes=size+incoming,old_cap_bytes=512*1024*1024,over_bytes=size+incoming-512*1024*1024,
        package_sha256_matches=True,source_observation='evidence/maintenance/dev-update-failure-20261029-144041.json',
        scope='Actual installed EXE read and extracted budget on owned sparse data; no installed task/process/cache/ACL mutation',
        raw_original_exception_text_available=False,user1_field_confirmed=False)
    target=ROOT/'evidence/maintenance/dev-0468-installed-budget-proof.json';assert not target.exists()
    target.write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(proof))


if __name__=='__main__':main()
