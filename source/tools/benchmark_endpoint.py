"""Repeatable isolated endpoint measurements; psutil is a test-only dependency."""
import argparse
import json
import hashlib
import os
import statistics
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def isolated_agent(config):
    from copy import deepcopy
    from guarddesk.agent import Agent
    from guarddesk.store import canonical
    from guarddesk.policy import DEFAULT_POLICY
    agent=Agent(config)
    policy=deepcopy(DEFAULT_POLICY)
    policy.update(browser_audit=False,application_audit=False)
    policy['file_audit']['scope']='managed'
    with agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':1,'body':policy}),))
    return agent


def worker(config,ready):
    agent=isolated_agent(config)
    Path(ready).touch()
    agent.run(threading.Event(),interval=1)


def measure(label,seconds,executable=None,target_version=None):
    import psutil
    from guarddesk.agent import private_write
    from guarddesk import __version__
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='performance-') as temporary:
        scratch=Path(temporary);watch=scratch/'documents';watch.mkdir()
        content=b'x'*16384
        for n in range(600):(watch/f'small-{n}.txt').write_bytes(content)
        for n in range(24):(watch/f'large-{n}.bin').write_bytes(b'x'*1048576)
        config=scratch/'agent/config.json';ready=scratch/'ready'
        private_write(config,{'server':'http://127.0.0.1:1','device_id':'performance-only','token':'offline-test','watch':str(watch),'remote_enabled':False})
        isolated_agent(config)  # Seed the same explicit policy for source and frozen CLI.
        command=[str(executable),'agent','--config',str(config)] if executable else [sys.executable,str(Path(__file__)),'--worker',str(config),'--ready',str(ready)]
        process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            monitored=psutil.Process(process.pid)
            if not executable:
                deadline=time.monotonic()+20
                while not ready.exists():
                    if process.poll() is not None:raise RuntimeError('Worker exited')
                    if time.monotonic()>deadline:raise TimeoutError('Worker startup')
                    time.sleep(.05)
            else:time.sleep(2)
            start=time.monotonic();cpu_start=monitored.cpu_times();io_start=monitored.io_counters()
            rss=[];private=[];cpu_samples=[];latencies=[]
            foreground=scratch/'foreground.txt'
            monitored.cpu_percent(None)
            while time.monotonic()-start<seconds:
                if process.poll() is not None:raise RuntimeError('Worker exited')
                memory=monitored.memory_info();rss.append(memory.rss);private.append(getattr(memory,'private',memory.rss));cpu_samples.append(monitored.cpu_percent(None))
                tick=time.perf_counter();foreground.write_bytes(content);assert foreground.read_bytes()==content;latencies.append((time.perf_counter()-tick)*1000)
                time.sleep(.2)
            elapsed=time.monotonic()-start;cpu_end=monitored.cpu_times();io_end=monitored.io_counters()
            cpu_seconds=cpu_end.user+cpu_end.system-cpu_start.user-cpu_start.system
            def p95(items):return sorted(items)[min(len(items)-1,int(len(items)*.95))]
            report={'label':label,'version':__version__,'kind':'frozen' if executable else 'source','seconds':round(elapsed,2),'fixture':{'files':624,'content_bytes':600*16384+24*1048576,'native_controls_installed':False,'server':'unreachable_loopback','foreground':'16 KiB write + read outside audit root every 200 ms'},'logical_cpus':os.cpu_count(),'endpoint_only':True,'cpu_one_core_percent':round(cpu_seconds/elapsed*100,3),'cpu_machine_percent':round(cpu_seconds/elapsed*100/(os.cpu_count() or 1),3),'cpu_sample_p95_one_core_percent':round(p95(cpu_samples),2),'working_set_peak_mib':round(max(rss)/1048576,2),'private_peak_mib':round(max(private)/1048576,2),'private_growth_mib':round((private[-1]-private[0])/1048576,2),'read_bytes':io_end.read_bytes-io_start.read_bytes,'write_bytes':io_end.write_bytes-io_start.write_bytes,'foreground_io_p50_ms':round(statistics.median(latencies),3),'foreground_io_p95_ms':round(p95(latencies),3),'limitations':['Short local Windows 11 sample; file-system cache and other processes affect results','Fallback audit only; no privileged SACL/QoS/USB or active website proxy workload','Includes initial audit of fixture; frozen startup excluded','Foreground metric is a small file IO proxy, not Office/browser interaction latency']}
        finally:
            process.terminate();process.wait(timeout=10)
        with sqlite3.connect(config.with_suffix('.sqlite3')) as db:
            report['snapshot_files_recorded']=db.execute('SELECT count(*) FROM files').fetchone()[0]
            report['pending_events_preserved']=db.execute('SELECT count(*) FROM outbox').fetchone()[0]
        db.close()
        report['harness_version']=__version__
        report['isolated_policy']={'file_scope':'managed fixture only','browser_audit':False,'application_audit':False,'remote_enabled':False}
        assert report['snapshot_files_recorded']==624,'Incomplete fixture scan; do not interpret low resource use as a pass'
        if executable:
            report['version']=target_version or 'not_identified'
            report['executable_sha256']=hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    path=ROOT/'evidence'/f'performance-{label}.json';path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--label',default='candidate');parser.add_argument('--seconds',type=float,default=20);parser.add_argument('--exe');parser.add_argument('--target-version');parser.add_argument('--worker');parser.add_argument('--ready')
    args=parser.parse_args()
    if args.worker:worker(args.worker,args.ready)
    else:measure(args.label,args.seconds,args.exe,args.target_version)
