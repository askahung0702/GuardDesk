"""Compiled one-shot scan, own visible-root files and loopback Server only."""
import ctypes,hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
import test_system
from guarddesk import __version__
from guarddesk.hidden_files import HIDDEN_RULE
from guarddesk.store import Store,canonical

def main():
    original_temp=tempfile.TemporaryDirectory
    def visible_temp(*args,**kwargs):return original_temp(*args,**{**kwargs,'dir':ROOT/'runtime'})
    case=test_system.SystemTest('runTest')
    with patch.object(test_system.tempfile,'TemporaryDirectory',side_effect=visible_temp):case.setUp()
    try:
        api=ctypes.WinDLL('kernel32',use_last_error=True);api.SetFileAttributesW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32]
        hidden=case.watch/'hidden.txt';hidden.write_text('owned synthetic')
        folder=case.watch/'private';folder.mkdir();inside=folder/'inside.txt';inside.write_text('owned synthetic')
        dot=case.watch/'.visible.txt';dot.write_text('owned synthetic');visible=case.watch/'visible.txt';visible.write_text('owned synthetic')
        for path in (hidden,folder):
            if not api.SetFileAttributesW(str(path),2):raise ctypes.WinError(ctypes.get_last_error())
        def policy(enabled):
            with case.store.connect() as db:
                p=Store.policy(db);p['body']['file_audit']['exclude_paths']=[HIDDEN_RULE] if enabled else []
                db.execute('INSERT INTO policies VALUES (?,?,?,?)',(p['version']+1,canonical(p['body']),__import__('time').time(),'owned-fixture'))
        policy(True);agent,did,_=case.make_agent();config=agent.config_path;agent.heartbeat()
        exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
        def scan():
            result=subprocess.run([str(exe),'agent','--config',str(config),'--once'],cwd=ROOT,capture_output=True,timeout=40,creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode==0,result.stderr.decode('utf-8',errors='replace')
        scan()
        with agent.db() as db:baseline={r[0] for r in db.execute('SELECT path FROM files')}
        assert baseline=={'.visible.txt','visible.txt'},baseline
        with case.store.connect() as db:first={json.loads(r[0])['path'] for r in db.execute("SELECT details FROM events WHERE device_id=? AND kind='file.created'",(did,))}
        assert first=={str(dot),str(visible)},first
        policy(False);agent.heartbeat();scan()
        with case.store.connect() as db:after={json.loads(r[0])['path'] for r in db.execute("SELECT details FROM events WHERE device_id=? AND kind='file.created'",(did,))}
        assert after=={str(dot),str(visible),str(hidden),str(inside)},after
        assert case.store.verify()['valid']
        report={'passed':True,'version':__version__,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'checks':['Real frozen --once scanner excludes hidden file and hidden ancestor from baseline/events','Visible and dot-name controls reach loopback center','Uncheck uses cached received policy and restores collection without resetting identity','Audit chain verifies'],'company_changed':False,'system_policy_changed':False,'native_continuous_trace_acceptance':False}
        (ROOT/f'evidence/packaged-hidden-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    finally:case.tearDown()

if __name__=='__main__':main()
