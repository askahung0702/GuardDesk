"""Synthetic 250-device read/preview costs, no company data or controls."""
import json
import statistics
import tempfile
import time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.store import Store,canonical,digest
from guarddesk import custom_settings as custom
root=Path(__file__).resolve().parents[1]
(root/'runtime').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=root/'runtime',prefix='custom-fleet-test-') as folder:
 store=Store(Path(folder)/'control.sqlite3')
 with store.connect() as db:
  for i in range(20):db.execute('INSERT INTO endpoint_groups VALUES (?,?,NULL,1,?)',(f'{i:024x}','Synthetic group '+str(i),time.time()))
  for i in range(250):
   did=f'{i+1000:024x}'
   db.execute('INSERT INTO devices(id,token,name,department,last_seen,group_id,inventory) VALUES (?,?,?,?,?,?,?)',(did,digest('synthetic-token-'+str(i)),'Synthetic device '+str(i),'Test',time.time(),f'{i%20:024x}',canonical({'agent_version':'0.4.37'})))
  for i in range(20):
   body={'network':{'ipv6':'unchanged'}}
   db.execute('INSERT INTO custom_settings VALUES (?,?,?,?,?,?)',('group',f'{i:024x}',1,canonical(body),'synthetic',time.time()))
  for d in db.execute('SELECT id,group_id FROM devices').fetchall():
   fingerprint=custom.resolve(db,dict(d))['fingerprint']
   for role in ('main','native'):db.execute('INSERT INTO custom_status VALUES (?,?,?,?)',(d['id'],role,canonical({'protocol':1,'role':role,'version':'0.4.37','fingerprint':fingerprint,'report':{'state':'reported'}}),time.time()))
 catalog_ms=[];preview_ms=[]
 for _ in range(5):
  with store.connect() as db:
   started=time.perf_counter();catalog=custom.catalog(db);catalog_ms.append((time.perf_counter()-started)*1000)
   started=time.perf_counter();preview=custom.preview(db,{'scope':'global','target':'','revision':0,'body':{'compatibility':[{'module':'browser_history','min_build':0,'max_build':999999,'expires':time.time()+3600,'reason':'Synthetic'}]}});preview_ms.append((time.perf_counter()-started)*1000)
 assert len(catalog['reports'])==500 and preview['affected_count']==250
 report={'passed':True,'synthetic_devices':250,'groups':20,'component_reports':500,'catalog_median_ms':round(statistics.median(catalog_ms),3),'catalog_max_ms':round(max(catalog_ms),3),'preview_median_ms':round(statistics.median(preview_ms),3),'preview_max_ms':round(max(preview_ms),3),'catalog_bytes':len(canonical(catalog).encode()),'preview_sample_count':len(preview['devices']),'no_event_history_queries':True,'limitations':['Local synthetic metadata benchmark, not 250 simultaneous Windows agents or office Server acceptance']}
(root/'evidence/custom-settings-250-metadata-performance.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
