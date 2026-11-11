"""Run the real category UI workload against the frozen Server, owned only."""
import hashlib,json,shutil,socket,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
import test_system
import category_wildcard_browser_smoke as smoke
from guarddesk.server_setup import secure_directory
Base=test_system.SystemTest

class FrozenSystem(Base):
    def setUp(self):
        super().setUp();self.server.shutdown();self.server.server_close();self.thread.join(5)
        parent=secure_directory(self.root/'frozen-program');app=parent/'GuardDesk';shutil.copytree(ROOT/'dist/GuardDesk',app)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        self.url='http://127.0.0.1:'+str(port)
        self.frozen=subprocess.Popen([str(app/'GuardDesk.exe'),'serve','--db',str(self.db),'--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        for _ in range(100):
            assert self.frozen.poll() is None,'Owned frozen UI Server exited'
            try:
                if self.api('/api/health')['status']=='ok':return
            except ConnectionError:pass
            except __import__('urllib.error',fromlist=['URLError']).URLError:pass
            time.sleep(.1)
        raise RuntimeError('Owned frozen UI Server startup timeout')
    def tearDown(self):
        if self.frozen.poll() is None:self.frozen.terminate()
        self.frozen.wait(timeout=15);self.temp.cleanup()

def main():
    before=set((ROOT/'evidence').glob('category-wildcard-browser-*.json'))
    report={'version':'0.4.62','scope':'frozen_server_owned_headless_category_ui','passed':False,'company_changed':False,
            'exe_sha256':hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()}
    try:
        test_system.SystemTest=FrozenSystem
        smoke.main();proofs=set((ROOT/'evidence').glob('category-wildcard-browser-*.json'))-before;assert len(proofs)==1
        proof=proofs.pop();data=json.loads(proof.read_text(encoding='utf-8'));assert data['passed']
        report.update(passed=True,ui_evidence=str(proof.relative_to(ROOT)),ui_evidence_sha256=hashlib.sha256(proof.read_bytes()).hexdigest(),probe_id=data['probe_id'])
    except Exception as exc:report['failure']=type(exc).__name__+': '+str(exc)[:1200]
    finally:
        test_system.SystemTest=Base
        path=ROOT/'evidence'/('category-wildcard-frozen-0462-'+uuid.uuid4().hex+'.json');path.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps({'evidence':str(path),**report}))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
