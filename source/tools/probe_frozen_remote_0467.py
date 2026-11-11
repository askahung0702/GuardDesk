"""Actual frozen remote code on owned fixtures; no installed tasks or screens."""
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import time
import types
import unittest
import zipfile
from unittest.mock import patch
from PyInstaller.archive.readers import CArchiveReader

ROOT=Path(__file__).resolve().parents[1]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
    import guarddesk
    target=ROOT/'evidence/frozen-machine-remote-0.4.67-v2.json';assert not target.exists()
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    archive=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz')
    modules={};code_hashes={}
    for name in ('remote_readiness','store','remote','agent','remote_windows','desktop_agent','machine_agent','machine_agent_windows','machine_agent_session'):
        full='guarddesk.'+name;code=archive.extract(full)
        source=ROOT/'guarddesk'/(name+'.py')
        assert code==compile(source.read_bytes(),str(source),'exec'),name
        module=types.ModuleType(full);module.__package__='guarddesk';module.__file__=str(source)
        sys.modules[full]=module;setattr(guarddesk,name,module);exec(code,module.__dict__)
        modules[name]=module;code_hashes[name]=sha(source)
    names=['test_machine_remote_global','test_machine_agent','test_machine_agent_windows']
    log=io.StringIO();start=time.monotonic()
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))
    assert result.wasSuccessful() and not result.skipped,log.getvalue()
    # Actual old archived Server code against a new initialized owned DB.
    previous=ROOT/'dist/GuardDesk-0.4.66-windows-x64.zip'
    assert sha(previous)=='1141339ab3445e16c1124c3065e8976ffbca98ec1b91e2e0a6dabc0c1e9015f2'
    import tempfile
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='old-remote-0467-') as tmp:
        old_exe=Path(tmp)/'GuardDesk.exe'
        with zipfile.ZipFile(previous) as z:old_exe.write_bytes(z.read('GuardDesk/GuardDesk.exe'))
        old_archive=CArchiveReader(str(old_exe)).open_embedded_archive('PYZ.pyz')
        old=types.ModuleType('guarddesk.remote');old.__package__='guarddesk'
        exec(old_archive.extract('guarddesk.remote'),old.__dict__)
        fixture=importlib.import_module('test_machine_remote_global').ReadinessServerTest()
        fixture.setUp()
        try:
            agent,did,_=fixture.make_agent()
            agent.call('/api/agent/remote/poll',{'account':'OWNED\\B','ready':False,'protocol':3,'readiness':'not_ready'})
            with patch.dict(sys.modules,{'guarddesk.remote':old}),patch.object(guarddesk,'remote',old):
                agent.call('/api/agent/remote/poll',{'account':'OWNED\\B','ready':True,'protocol':3,'readiness':'ready'})
                device=next(d for d in fixture.api('/api/remote/catalog')['devices'] if d['id']==did)
                assert device['ready']
            with fixture.store.connect() as db:
                assert len(db.execute('SELECT * FROM remote_presence').fetchone())==4
            device=next(d for d in fixture.api('/api/remote/catalog')['devices'] if d['id']==did)
            assert device['ready'] and device['readiness']=='ready'
        finally:fixture.tearDown()
    proof=dict(passed=True,version='0.4.67',candidate_exe_sha256=sha(exe),tests=result.testsRun,
        modules=code_hashes,seconds=time.monotonic()-start,old_server_archive_sha256=sha(previous),
        old_frozen_server_four_column_poll_and_catalog_on_new_DB=True,
        scope='Actual frozen module code in Python, owned Windows pipe and isolated HTTP center; not installed SYSTEM/WTS or company endpoint',
        employee_desktop_captured=False,company_changed=False,formal_release_ready=False)
    target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (ROOT/'runtime/frozen-remote-0467-v2.log').write_text(log.getvalue(),encoding='utf-8')
    print(json.dumps(proof,ensure_ascii=False))


if __name__=='__main__':main()
