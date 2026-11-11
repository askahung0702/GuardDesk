"""Owned source Agent + real context helper, before/active/after file latency.

No installation, production trace, company files, policy or AV changes.
Privileged native ETW/SACL, Office, browser and Defender aggregate acceptance
are explicitly outside this local diagnostic. psutil is development-only.
"""
import ctypes,hashlib,json,os,shutil,sqlite3,statistics,subprocess,sys,tempfile,threading,time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))


def worker(config,stop_path,ready):
    from benchmark_endpoint import isolated_agent
    agent=isolated_agent(Path(config));stop=threading.Event()
    def stopping():
        while not stop.wait(.1):
            if Path(stop_path).exists():stop.set()
    thread=threading.Thread(target=stopping,daemon=True);thread.start();Path(ready).touch()
    try:agent.run(stop,interval=1)
    finally:stop.set();agent.close_collectors();thread.join(2)


def main():
    import psutil
    from guarddesk.agent import private_write
    from benchmark_endpoint import isolated_agent
    from guarddesk.document_context import Channel,kernel_api,token_sid,valid_sample
    api=kernel_api();api.GetCurrentProcess.restype=w.HANDLE
    api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    adv=ctypes.WinDLL('advapi32',use_last_error=True);adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    process=None;helper=None;channel=None;frames=[];reports={};resources=[]
    with tempfile.TemporaryDirectory(prefix='responsive-055-',dir=ROOT/'runtime') as temporary:
        root=Path(temporary);watch=root/'documents';watch.mkdir()
        content=b'x'*16384
        for i in range(600):(watch/f'small-{i}.txt').write_bytes(content)
        for i in range(24):(watch/f'large-{i}.bin').write_bytes(b'x'*1048576)
        foreground=root/'foreground';foreground.mkdir();small=foreground/'small.txt';small.write_bytes(content)
        large=foreground/'large.bin';large.write_bytes(b'y'*1048576);copied=foreground/'copied.bin';saved=foreground/'saved.txt'
        # Runtime must be a sibling of documents: the product deliberately
        # excludes its own runtime tree. A fixture inside it measures no scan.
        config=root/'runtime/agent/config.json';stop_path=root/'stop';ready=root/'ready'
        private_write(config,{'server':'http://127.0.0.1:1','device_id':'owned-performance-only','token':'offline-test','watch':str(watch),'remote_enabled':False})
        seed=isolated_agent(config);seed.close_collectors()
        def phase(name,seconds,monitored=()):
            samples={'read_16k_ms':[],'save_read_16k_ms':[],'copy_1m_ms':[]};end=time.monotonic()+seconds
            cpu_before={p.pid:sum(p.cpu_times()[:2]) for p in monitored};started=time.monotonic();peaks=0;io_before={p.pid:p.io_counters() for p in monitored}
            while time.monotonic()<end:
                tick=time.perf_counter();assert small.read_bytes()==content;samples['read_16k_ms'].append((time.perf_counter()-tick)*1000)
                tick=time.perf_counter();saved.write_bytes(content);assert saved.read_bytes()==content;samples['save_read_16k_ms'].append((time.perf_counter()-tick)*1000)
                tick=time.perf_counter();shutil.copyfile(large,copied);assert copied.stat().st_size==1048576;samples['copy_1m_ms'].append((time.perf_counter()-tick)*1000)
                if channel:
                    batch=channel.poll()
                    for value in batch:assert valid_sample(value,value['session'],time.time())
                    frames.extend(batch)
                total=0
                for p in monitored:
                    if not p.is_running():raise RuntimeError('Owned benchmark child stopped')
                    total+=p.memory_info().private
                peaks=max(peaks,total);time.sleep(.1)
            elapsed=time.monotonic()-started
            result={kind:{'count':len(values),'p50_ms':round(statistics.median(values),4),'p95_ms':round(sorted(values)[min(len(values)-1,int(len(values)*.95))],4),'max_ms':round(max(values),4)} for kind,values in samples.items()}
            if monitored:
                cpu=sum(sum(p.cpu_times()[:2])-cpu_before[p.pid] for p in monitored)
                io={key:sum(getattr(p.io_counters(),key)-getattr(io_before[p.pid],key) for p in monitored) for key in ('read_bytes','write_bytes')}
                resources.append({'seconds':elapsed,'process_count':len(monitored),'cpu_machine_percent':round(cpu/elapsed*100/(os.cpu_count() or 1),4),'private_bytes_sum_peak':peaks,'process_io':io})
            reports[name]=result
        try:
            phase('before',15)
            process=subprocess.Popen([sys.executable,str(Path(__file__)),'--worker',str(config),str(stop_path),str(ready)],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
            deadline=time.monotonic()+20
            while not ready.exists():
                if process.poll() is not None:raise RuntimeError(process.stderr.read().decode(errors='replace'))
                if time.monotonic()>deadline:raise TimeoutError('Owned Agent startup')
                time.sleep(.05)
            token=w.HANDLE()
            if not adv.OpenProcessToken(api.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
            try:channel=Channel(token_sid(token))
            finally:api.CloseHandle(token)
            helper=subprocess.Popen([sys.executable,str(ROOT/'app.py'),'document-session-context','--pipe',channel.pipe,'--parent',str(os.getpid())],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
            channel.process=api.OpenProcess(0x101001,False,helper.pid);channel.pid=helper.pid
            if not channel.process:raise ctypes.WinError(ctypes.get_last_error())
            phase('active_agent_and_context_helper',120,[psutil.Process(process.pid),psutil.Process(helper.pid)])
            stop_path.touch();process.wait(timeout=15);assert process.returncode==0,process.stderr.read().decode(errors='replace')
            process.stderr.close();channel.close();helper.wait(timeout=5);helper.stderr.close();channel=None
            with sqlite3.connect(config.with_suffix('.sqlite3')) as db:
                files=db.execute('SELECT count(*) FROM files').fetchone()[0];pending=db.execute('SELECT count(*) FROM outbox').fetchone()[0]
            db.close()
            (ROOT/'runtime/responsiveness-055-last-phase.json').write_text(json.dumps({'files':files,'pending':pending,'phases':reports,'resources':resources,'frames':len(frames)}),encoding='utf-8')
            assert files==624 and pending>=624,'Low resource figures cannot pass without completed work and durable offline events'
            assert len(frames)>=60
            phase('after_owned_children_stopped',15)
        finally:
            stop_path.touch()
            if channel:channel.close()
            for child in (process,helper):
                if child:
                    try:child.wait(timeout=15)
                    except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=5)
                    if child.stderr and not child.stderr.closed:child.stderr.close()
        comparison={kind:round((reports['active_agent_and_context_helper'][kind]['p95_ms']/statistics.mean([reports['before'][kind]['p95_ms'],reports['after_owned_children_stopped'][kind]['p95_ms']])-1)*100,2) for kind in reports['before']}
        report={'passed_fixture_work_and_cleanup':True,'version':'0.4.55','phase_latencies':reports,'p95_increase_percent_vs_before_after_mean':comparison,
                'resources':resources,'logical_cpus':os.cpu_count(),'snapshot_files_recorded':files,'pending_events_preserved':pending,'context_frames':len(frames),
                'scope':'one_owned_source_user_Agent_fallback_and_one_real_context_helper_combined_not_installed_privileged_components',
                'own_children_stopped':True,'office_changed':False,'defender_or_policy_changed':False,'full_endpoint_performance_accepted':False,
                'limitations':['Short local cached file operations; sequential phases are affected by background load','Foreground test paths outside audit scope; no Office/Teams/browser workload','No protected native ETW/SACL/USB/QoS, OS audit or Defender cost included in process totals','Existing office Agent, hardware, antivirus and other OS activity not stopped or changed','Not an 8h/24h or multi-session resource acceptance'],
                'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('guarddesk/agent.py','guarddesk/document_context.py','guarddesk/document_worker.py','guarddesk/file_access.py','guarddesk/document_io.py')}}
        (ROOT/'evidence/endpoint-responsiveness-0.4.55.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--worker':worker(*sys.argv[2:])
    else:main()
