"""Isolated collector workload; not a substitute for office lag acceptance."""
import json
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from test_browser_history import make_history, history_db, visit
from guarddesk.agent import Agent
from guarddesk.browser_history import BrowserHistory, chrome_time, snapshot_history
from guarddesk.policy import DEFAULT_POLICY

with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='browser-perf-') as folder:
    root=Path(folder);history=root/'Default/History';make_history(history)
    with history_db(history) as db:
        db.executemany('INSERT INTO urls VALUES (?,?,?)',((i,'https://example.test/long/path/'+str(i),'test page '+str(i)) for i in range(1,50001)))
        db.executemany('INSERT INTO visits VALUES (?,?,?,?,?)',((i,i,chrome_time(time.time()-3600),0,'') for i in range(1,50001)))
    config=root/'config.json';config.write_text(json.dumps({'watch':str(root),'device_id':'fixture','server':'http://127.0.0.1:1','token':'fixture'}))
    agent=Agent(config)
    with agent.db() as db:db.execute("INSERT INTO state VALUES ('policy',?)",(json.dumps({'version':1,'body':DEFAULT_POLICY}),))
    collector=BrowserHistory(agent)
    with patch('guarddesk.browser_history.discover_profiles',return_value=([('chrome','Default',history)],False)):
        collector.poll()
        for i in range(50001,50101):visit(history,i)
        tracemalloc.start();times=[];cpu=time.process_time()
        for i in range(30):
            start=time.perf_counter();collector.poll();times.append((time.perf_counter()-start)*1000)
        direct_cpu=time.process_time()-cpu;direct_peak=tracemalloc.get_traced_memory()[1];tracemalloc.stop()
    tracemalloc.start();cpu=time.process_time();start=time.perf_counter()
    snapshot_history(history,root/'snapshot',threading.Event())
    snapshot_wall=time.perf_counter()-start;snapshot_cpu=time.process_time()-cpu
    snapshot_peak=tracemalloc.get_traced_memory()[1];tracemalloc.stop()
    report={'version':'0.4.12','scope':'isolated synthetic 50,000 old visits + 100 new; 30 immediate polls; only collector Python allocations/CPU, not total endpoint memory or user lag',
        'history_bytes':history.stat().st_size,'polls':len(times),'poll_median_ms':round(statistics.median(times),2),'poll_max_ms':round(max(times),2),
        'poll_cpu_seconds_total':round(direct_cpu,3),'poll_python_peak_bytes':direct_peak,
        'snapshot_wall_seconds':round(snapshot_wall,3),'snapshot_cpu_seconds':round(snapshot_cpu,3),'snapshot_python_peak_bytes':snapshot_peak,
        'not_verified':['full Agent/native/updater/browser RSS and private bytes on deployed Windows 10/11','company Defender/EDR interaction and user workload lag','large/live WAL history and sustained 20 endpoints']}
    (ROOT/'evidence/browser-history-performance.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
