"""Released 0.4.26 decoder/binary interoperability, no installed Agent changes."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk import __version__
from guarddesk.agent import Agent,enroll
from guarddesk.server import serve
from guarddesk.store import Store,canonical,digest
from guarddesk.policy import DEFAULT_POLICY
ROOT=Path(__file__).resolve().parents[1]


def main():
    binary=ROOT/'dist/GuardDesk-0.4.26-windows-x64.zip';source=ROOT/'dist/GuardDesk-0.4.26-source.zip'
    assert hashlib.sha256(binary.read_bytes()).hexdigest()=='bd7a1475251c8bccca61cbeff25df0af9a4e1e019682e14d4ba2bb7e3fe626eb'
    assert hashlib.sha256(source.read_bytes()).hexdigest()=='dfd85c377f37f112d0c813c353771ec5a845b63cc543b0bfa1730f8df35e8df0'
    # Only execute our hash-pinned published pure policy definitions.
    legacy={}
    with zipfile.ZipFile(source) as z:exec(compile(z.read('guarddesk/policy.py'),'published-0.4.26-policy','exec'),legacy)
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);program=root/'legacy';program.mkdir()
        with zipfile.ZipFile(binary) as z:
            for name in z.namelist():
                if name.startswith('GuardDesk/') and not name.endswith('/'):
                    target=(program/name).resolve();assert target.is_relative_to(program)
                    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(name))
        store=Store(root/'control.db');watch=root/'owned';watch.mkdir();(watch/'fixture.txt').write_text('owned fixture')
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=['conhost.exe','docker.exe']
        with store.connect() as db:
            db.execute('INSERT INTO policies VALUES (?,?,?,?)',(2,canonical(body),time.time(),'fixture'))
            db.execute('INSERT INTO enrollments VALUES (?,?,0)',(digest('fixture-enrollment'),time.time()+300))
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url=f'http://127.0.0.1:{server.server_port}'
        try:
            config=root/'state/config.json';enroll(config,url,'fixture-enrollment',watch,name='owned-legacy')
            agent=Agent(config);packet=agent.heartbeat();self_rules=packet['body']['application_audit_exclusions'];assert self_rules==body['application_audit_exclusions']
            with agent.db() as db:wire=json.loads(db.execute("SELECT value FROM state WHERE key='policy'").fetchone()[0])
            legacy['validate_policy'](wire['body'])
            native=agent.call('/api/agent/extended-policy',{});legacy['validate_policy'](native['body'])
            assert native['audit_options']['application_exclusions']==self_rules
            old=subprocess.run([str(program/'GuardDesk/GuardDesk.exe'),'agent','--config',str(config),'--once'],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            assert old.returncode==0,old.stderr.decode('utf-8',errors='replace')
            # An old binary can read the policy cache written by the new client,
            # then refresh it; the new client still recovers the exclusion list.
            assert Agent(config).cached_policy()['body']['application_audit_exclusions']==self_rules
            assert Agent(config).heartbeat()['body']['application_audit_exclusions']==self_rules
            assert store.verify()['valid']
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'checks':['Hash-pinned released 0.4.26 strict policy validator accepts heartbeat and native extended-policy bodies','Released 0.4.26 executable scans/heartbeats successfully with new-client wire cache','New client restores exclusions after legacy refresh; event hash chain valid'],'limitations':['Owned synthetic loopback fixture; old binary --once only, no native privileged worker or installed endpoint changed']}
    (ROOT/f'evidence/application-exclusions-legacy-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
