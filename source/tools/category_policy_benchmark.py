"""Synthetic control-plane cost, not a 250-endpoint or employee-latency claim."""
import copy
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import uuid
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.store import Store
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire
from guarddesk.management import ControlPlane,save_set,generation
from guarddesk import category_library as cat


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        store=Store(Path(tmp)/'control.sqlite3')
        with store.connect() as db:
            c=cat.save(db,{'kind':'website','draft':{'name':'Synthetic 1000 sites','description':'','parent_id':None,'members':[{'name':f'Site {i}','type':'domain','domain':f's{i}.example.com','include_subdomains':True,'scheme':'any'} for i in range(1000)]}},'fixture')
            c=cat.publish(db,{**c,'expected_generation':generation(db)},'fixture')
            p=save_set(db,{'name':'Synthetic blocked sites','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}},'category_refs':{'website_blocked':[{'id':c['id'],'include_descendants':False}]}},'fixture')
            db.execute("INSERT INTO policy_assignments VALUES('fixture',?,'global','',100,1,1,1,'fixture')",(p['id'],))
        category_selects=[];durations=[];original=cat.expand
        with patch('guarddesk.category_library.expand',wraps=original) as expand:
            for i in range(251):
                start=time.perf_counter()
                with store.connect() as db:
                    db.set_trace_callback(lambda sql:category_selects.append(sql) if 'SELECT * FROM categories' in sql else None)
                    packet=ControlPlane(db).bundle({'id':f'{i:024x}','group_id':None,'inventory':{'user_accounts':[]}})
                    wire=agent_policy_wire(packet)
                durations.append((time.perf_counter()-start)*1000)
            expansions=expand.call_count
        report={'scope':'251_serial_synthetic_policy_requests_1000_rules_not_real_fleet','cold_ms':durations[0],
            'warm_median_ms':statistics.median(durations[1:]),'warm_p95_ms':sorted(durations[1:])[237],
            'category_table_loads':len(category_selects),'category_expansions':expansions,'wire_bytes':len(json.dumps(wire).encode()),
            'machine_policy_modified':False,'real_agent_latency_test':False,'passed':len(category_selects)==1 and expansions==1}
        out=ROOT/'evidence'/('category-policy-performance-'+uuid.uuid4().hex+'.json');out.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'evidence':str(out),**report},ensure_ascii=False))
        return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
