"""Verify the frozen, owned UAC component probe without elevation or UI input."""
from pathlib import Path
import hashlib
import json
import marshal
import subprocess
import sys
import types
import unittest
from PyInstaller.archive.readers import CArchiveReader

ROOT=Path(__file__).resolve().parents[1]
WORKSPACE=ROOT.parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]


def main():
    if sys.argv[1:] not in ([],['--v2']):raise SystemExit('Only fixed --v2 variant is supported')
    variant='-v2' if sys.argv[1:] else ''
    exe=WORKSPACE/('runtime/remote-next-uac-probe'+variant)/'GuardDeskUacProbe/GuardDeskUacProbe.exe'
    archive=CArchiveReader(str(exe));embedded=archive.open_embedded_archive('PYZ.pyz');hashes={}
    import tools
    for name,relative,entry in (
        ('tools.uac_prompt_identity','tools/uac_prompt_identity.py',False),
        ('tools.remote_next_uac_probe','tools/remote_next_uac_probe.py',True),
        ('guarddesk.remote_admin_windows','guarddesk/remote_admin_windows.py',False),
        ('guarddesk.remote_windows','guarddesk/remote_windows.py',False),
        ('guarddesk.machine_agent','guarddesk/machine_agent.py',False),
        ('guarddesk.machine_agent_windows','guarddesk/machine_agent_windows.py',False),
        ('guarddesk.document_context','guarddesk/document_context.py',False),
        ('guarddesk.native_browser_identity','guarddesk/native_browser_identity.py',False),
        ('guarddesk.native_installer','guarddesk/native_installer.py',False),
        ('guarddesk.context_permissions','guarddesk/context_permissions.py',False),
        ('guarddesk.update_native','guarddesk/update_native.py',False)):
        source=ROOT/relative
        code=marshal.loads(archive.extract('remote_next_uac_probe')) if entry else embedded.extract(name)
        if code!=compile(source.read_bytes(),str(source),'exec'):raise RuntimeError('Frozen/source mismatch: '+name)
        hashes[relative]=hashlib.sha256(source.read_bytes()).hexdigest()
        module=types.ModuleType(name);module.__package__=name.rsplit('.',1)[0];module.__file__=str(source)
        sys.modules[name]=module
        parent=__import__(module.__package__);setattr(parent,name.rsplit('.',1)[1],module)
        exec(code,module.__dict__)
    log=WORKSPACE/('runtime/remote-next-uac-frozen-tests'+variant+'.log')
    with log.open('x',encoding='utf-8') as stream:
        names=['test_remote_next_uac_probe','test_remote_admin.AdminPureTest','test_remote_admin.AdminRouterTest',
            'test_remote_m2_lifecycle.LocalLeaseTest','test_remote_broker_concurrency']
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))
    check=subprocess.run([str(exe),'--check'],capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    report=dict(format=1,scope='Frozen owned UAC component probe; no actual UAC or MIS end-to-end acceptance',
        frozen_tests=result.testsRun,passed=result.wasSuccessful() and not result.skipped and check.returncode==0,
        exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),source_hashes=hashes,
        readonly_check_exit=check.returncode,readonly_check=check.stdout.decode('utf-8','replace').strip(),
        company_product_changed=False,system_executed=False,secure_capture=False,os_input=False,
        real_UAC_verified=False,signed=False,deployable=False)
    target=WORKSPACE/('evidence/maintenance/remote-next-m2-20261030/uac-probe-prepared'+variant+'.json')
    with target.open('x',encoding='utf-8') as stream:json.dump(report,stream,ensure_ascii=False,indent=2)
    print(json.dumps(report,ensure_ascii=False))
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
