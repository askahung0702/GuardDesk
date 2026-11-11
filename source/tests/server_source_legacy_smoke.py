"""Released 0.4.28 decoder/binary interoperability, no installed Agent changes."""
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
    binary=ROOT/'dist/GuardDesk-0.4.28-windows-x64.zip';source=ROOT/'dist/GuardDesk-0.4.28-source.zip'
    assert hashlib.sha256(binary.read_bytes()).hexdigest()=='24824ae7d52ec91b3e2c0331747fcba7a0e98799f4e103be31df27882fcff581'
    assert hashlib.sha256(source.read_bytes()).hexdigest()=='975ec0d5059f3c01a5dd0375d7ef35fd77236ddff294b1bbfe6810f89f0b5724'
    # Only execute our hash-pinned published pure policy definitions.
    legacy={'__package__':'guarddesk'}
    with zipfile.ZipFile(source) as z:
        assert z.read('guarddesk/application_exclusions.py')==(ROOT/'guarddesk/application_exclusions.py').read_bytes()
        exec(compile(z.read('guarddesk/policy.py'),'published-0.4.28-policy','exec'),legacy)
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);program=root/'legacy';program.mkdir()
        with zipfile.ZipFile(binary) as z:
            for name in z.namelist():
                if name.startswith('GuardDesk/') and not name.endswith('/'):
                    target=(program/name).resolve();assert target.is_relative_to(program)
                    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(name))
        store=Store(root/'control.db');watch=root/'owned';watch.mkdir();(watch/'fixture.txt').write_text('owned fixture')
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=['conhost.exe','docker.exe']
        body['file_audit']['exclude_paths']=[r'C:\Users\{user}\workspace']
        with store.connect() as db:
            db.execute('INSERT INTO policies VALUES (?,?,?,?)',(2,canonical(body),time.time(),'fixture'))
            db.execute('INSERT INTO enrollments VALUES (?,?,0)',(digest('fixture-enrollment'),time.time()+300))
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url=f'http://127.0.0.1:{server.server_port}'
        try:
            config=root/'state/config.json';enroll(config,url,'fixture-enrollment',watch,name='owned-legacy')
            agent=Agent(config);packet=agent.heartbeat();self_rules=packet['body']['application_audit_exclusions'];assert self_rules==body['application_audit_exclusions']
            with agent.db() as db:wire=json.loads(db.execute("SELECT value FROM state WHERE key='policy'").fetchone()[0])
            legacy['validate_policy'](legacy['decode_agent_policy'](wire)['body'])
            native=agent.call('/api/agent/extended-policy',{});legacy['validate_policy'](legacy['decode_agent_policy'](native)['body'])
            assert native['audit_options']['application_exclusions']==self_rules
            # Released old Agent drains an existing outbox through the new
            # Server ACK path; it need not understand the new source filter.
            health_path='C:\\ProgramData\\GuardDeskPilot\\USBControl\\'+'a'*24+'\\broker-health.json'
            pending=[{'event_id':eid,'kind':kind,'severity':level,'occurred':time.time(),'details':{'path':health_path}}
                     for eid,kind,level in [('legacy-health-noise','file.created','info'),('legacy-health-warning','agent.audit_gap','critical')]]
            pending.append({'event_id':'legacy-user-noise','kind':'file.created','severity':'info','occurred':time.time(),'details':{'path':r'C:\Users\user1\workspace\main.py'}})
            with agent.db() as db:
                for e in pending:db.execute('INSERT INTO outbox VALUES (?,?,?)',(e['event_id'],canonical(e),time.time()))
            old=subprocess.run([str(program/'GuardDesk/GuardDesk.exe'),'agent','--config',str(config),'--once'],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            assert old.returncode==0,old.stderr.decode('utf-8',errors='replace')
            with agent.db() as db:
                for e in pending:assert not db.execute('SELECT 1 FROM outbox WHERE event_id=?',(e['event_id'],)).fetchone()
            with store.connect() as db:
                assert not db.execute("SELECT 1 FROM events WHERE event_id='legacy-health-noise'").fetchone()
                assert not db.execute("SELECT 1 FROM events WHERE event_id='legacy-user-noise'").fetchone()
                assert db.execute("SELECT count(*) FROM events WHERE event_id='legacy-health-warning'").fetchone()[0]==1
            # An old binary can read the policy cache written by the new client,
            # then refresh it; the new client still recovers the exclusion list.
            assert Agent(config).cached_policy()['body']['application_audit_exclusions']==self_rules
            assert Agent(config).heartbeat()['body']['application_audit_exclusions']==self_rules
            assert store.verify()['valid']
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'checks':['Hash-pinned released 0.4.28 decoder/validator accepts heartbeat and native extended-policy with literal user template','Released 0.4.28 executable scans/heartbeats successfully with new-client wire cache','Released old Agent drains health and user-template outbox through new Server ACK without storing noise; critical gap preserved','New client restores exclusions after legacy refresh; event hash chain valid'],'limitations':['Owned synthetic loopback fixture; old binary --once only, no native privileged worker or installed endpoint changed']}
    (ROOT/f'evidence/server-source-legacy-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
