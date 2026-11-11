"""Read actual old DEV updater; reproduce its budget on sparse owned fixtures."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
from PyInstaller.archive.readers import CArchiveReader

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import update_packages as packages
from tools.reproduce_native_budget_failure import sparse


def main():
    from guarddesk.windows_controls import is_admin
    if not is_admin() or os.environ.get('COMPUTERNAME','').upper()!='DEV-01':raise SystemExit('Fixed read-only DEV-01 admin diagnostic')
    observed=json.loads((ROOT/'evidence/maintenance/dev-update-failure-20261029-125841.json').read_text(encoding='utf-8'))
    exe=packages.plain(Path(os.environ['ProgramFiles'])/'GuardDeskPilot/Updater/GuardDesk.exe')
    expected=json.loads((ROOT/'evidence/security/0.4.60/requirements-review.json').read_text(encoding='utf-8'))['exe_sha256']
    actual=packages.file_hash(exe);assert actual==expected,'Installed updater differs from sealed 0.4.60'
    code=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz').extract('guarddesk.update_client')
    function=next(c for c in code.co_consts if isinstance(c,types.CodeType) and c.co_name=='storage_budget')
    check=types.FunctionType(function,{'packages':packages})
    program=observed['usage']['program']['bytes'];updates=observed['usage']['updates']['bytes']
    incoming=observed['current_package']['incoming_bytes'];compressed=observed['current_package']['bytes']
    cap=512*1024*1024
    result=dict(company_changed=False,installed_updater='0.4.60',actual_exe_sha256=actual,
                matches_sealed_0460=True,program_bytes=program,updates_bytes=updates,incoming_bytes=incoming,
                projected_bytes=program+updates+incoming,cap_bytes=cap,over_bytes=program+updates+incoming-cap,
                source_observation='evidence/maintenance/dev-update-failure-20261029-125841.json')
    with tempfile.TemporaryDirectory(prefix='dev-budget-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);snapshot=root/'owned-logical-bytes.bin';sparse(snapshot,program+updates)
        try:check([root],incoming)
        except OSError as exc:
            assert '512 MiB' in str(exc);result['actual_frozen_budget_reproduced']=True
        else:raise AssertionError('Must reproduce actual old updater rejection')
        # One archive followed by a NEW job still adds another compressed ZIP.
        sparse(snapshot,program+updates-compressed+compressed)
        try:check([root],incoming)
        except OSError:result['archiving_only_one_zip_then_new_job_still_blocked']=True
        else:raise AssertionError('Must account for next fresh job download')
    private=Path(os.environ['ProgramData'])/'GuardDeskPilot/USBControl'/observed['device_id']/'updates'
    result['job_download_directories']=[]
    for path in private.iterdir():
        import re
        if not re.fullmatch('[0-9a-f]{32}',path.name):continue
        packages.plain(path);p=packages.plain(path/'package.zip')
        result['job_download_directories'].append(dict(id=path.name,package_bytes=p.stat().st_size if p.exists() else None))
    result['remaining']=['Historical exception text was not persisted by old updater; actual observed values and actual installed frozen budget reproduce the rejection',
                         'No program/cache/journal/task/ACL changed; fresh successful retry not yet performed',
                         'Both ended download directories require center-state and broker-stop checks before any controlled archive; keep program rollback and all JSON originals']
    (ROOT/'evidence/maintenance/dev-installed-budget-proof-20261029.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
