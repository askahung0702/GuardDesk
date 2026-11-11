"""Synthetic stdio navigation load against the actual frozen native host."""
import hashlib
import json
import os
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import psutil

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.agent import private_write


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='native-performance-') as temporary:
        root=Path(temporary);watch=root/'documents';watch.mkdir();config=root/'agent/config.json'
        private_write(config,{'server':'http://127.0.0.1:1','token':'offline-performance','device_id':'host-performance','watch':str(watch)})
        process=subprocess.Popen([str(exe),'browser-host','--config',str(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        measured=psutil.Process(process.pid);latencies=[];private=[];working=[]
        try:
            for n in range(1000):
                message=json.dumps({'type':'navigation','event_id':f'browser-performance-{n}','url':f'https://example.com/performance/{n}'}).encode()
                tick=time.perf_counter();process.stdin.write(struct.pack('<I',len(message))+message);process.stdin.flush()
                header=process.stdout.read(4);assert len(header)==4
                size=struct.unpack('<I',header)[0];reply=json.loads(process.stdout.read(size));assert reply['recorded']
                latencies.append((time.perf_counter()-tick)*1000)
                if n%10==0:
                    memory=measured.memory_info();private.append(getattr(memory,'private',memory.rss));working.append(memory.rss)
            process.stdin.close();process.wait(timeout=15);assert process.returncode==0
        finally:
            if process.poll() is None:process.terminate();process.wait(timeout=10)
            process.stdout.close();process.stderr.close()
        db=sqlite3.connect(config.with_suffix('.sqlite3'))
        try:events=db.execute('SELECT count(*) FROM outbox').fetchone()[0]
        finally:db.close()
        assert events==1000
        report={'passed':True,'events':events,'private_peak_mib':round(max(private)/1048576,2),'working_set_peak_mib':round(max(working)/1048576,2),'private_growth_mib':round((private[-1]-private[0])/1048576,2),'persist_ack_p50_ms':round(statistics.median(latencies[1:]),3),'persist_ack_p95_ms':round(sorted(latencies[1:])[int(len(latencies[1:])*.95)],3),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'limitations':['Synthetic native-messaging stdio, not real website or browser interaction timing','Offline host process only; excludes Agent, browser, PowerShell and OS audit overhead','Short burst is not a 24-hour leak test']}
    (ROOT/'evidence/performance-native-host-0.3.1.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
