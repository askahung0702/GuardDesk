"""Owned ReadDirectoryChangesW fixture; no privileged component or policy edits."""
import copy
import json
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.agent import Agent,private_write
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.file_exclusions import DEVELOPMENT_RULE,excluded_activity
from guarddesk.windows_watch import DirectoryMonitor
ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);watch=root/'owned';watch.mkdir();cache=watch/'node_modules';cache.mkdir()
        config=root/'state'/'config.json';private_write(config,{'server':'http://127.0.0.1:1','token':'fixture','device_id':'fixture','watch':str(watch)})
        agent=Agent(config);policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit'].update(scope='managed',exclude_paths=[DEVELOPMENT_RULE])
        monitor=DirectoryMonitor(agent,policy)
        def rows():
            with agent.db() as db:return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox ORDER BY created')]
        def wait_for(predicate):
            until=time.monotonic()+5
            while time.monotonic()<until:
                if predicate(rows()):return
                time.sleep(.05)
            raise AssertionError(rows())
        try:
            assert monitor.start()['active']==1;time.sleep(.1)
            a=cache/'fixture.js';a.write_text('owned fixture');doc=watch/'report.docx';doc.write_text('owned fixture')
            wait_for(lambda rs:any(r['details'].get('path')==str(doc) for r in rs));time.sleep(.1)
            assert not any(r['details'].get('path')==str(a) for r in rows()),rows()
            outside=watch/'outside.js';a.rename(outside)
            wait_for(lambda rs:any(r['kind']=='file.moved' and r['details'].get('source_path')==str(a) and r['details'].get('destination_path')==str(outside) for r in rs))
            returned=cache/'returned.js';outside.rename(returned)
            wait_for(lambda rs:any(r['kind']=='file.moved' and r['details'].get('source_path')==str(outside) and r['details'].get('destination_path')==str(returned) for r in rs))
            native_rows=len(rows())
        finally:monitor.close();agent.close_collectors()
    started=time.perf_counter();filtered=0
    for i in range(10000):
        filtered+=excluded_activity('file.created',{'path':r'C:\Dev\node_modules\x.js'},[DEVELOPMENT_RULE])
        assert not excluded_activity('file.opened',{'path':r'C:\Docs\business.docx'},[DEVELOPMENT_RULE])
        assert not excluded_activity('file.moved',{'source_path':r'C:\Dev\node_modules\x.js','destination_path':r'C:\Docs\x.js'},[DEVELOPMENT_RULE])
    elapsed=(time.perf_counter()-started)*1000
    report={'passed':True,'native_events_retained':native_rows,'checks':['Actual Windows directory watcher drops opted-in cache creation','Actual ordinary document retained','Actual move out of and into excluded folder retains both paths'],'filter_benchmark':{'classifications':30000,'excluded':filtered,'elapsed_ms':round(elapsed,2),'microseconds_per_classification':round(elapsed*1000/30000,2)},'limitations':['Owned fixture only; no fleet throughput or Defender acceptance','Path classifier measurement excludes database, Windows API and network overhead']}
    (ROOT/'evidence/development-exclusions-native-0.4.26.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
