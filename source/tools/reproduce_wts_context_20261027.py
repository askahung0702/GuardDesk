"""Read-only real WTS comparison with the sealed 0.4.57 implementation."""
import hashlib,json,sys,types,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_context import session_states


def main():
    archive=ROOT/'dist/GuardDesk-0.4.57-source.zip'
    expected='f83266c3853af48e11a75d88cb0d864b5f6c71408b8228ff6eed0dd1f286fff7'
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
    with zipfile.ZipFile(archive) as z:source=z.read('guarddesk/document_context.py')
    old=types.ModuleType('guarddesk._sealed_0457_context');old.__package__='guarddesk'
    exec(compile(source,'sealed-0.4.57/document_context.py','exec'),old.__dict__)
    result={'company_changed':False,'sealed_source_sha256':expected,'scope':'actual_WTS_session_metadata_only_no_helper_launch'}
    try:result['before_session_count']=len(old.session_states())
    except OSError as exc:result['before_error']=str(exc)
    current=session_states();result['after']=[{'session':sid,'active':s['active'],'locked':s['locked'],'query_failed':s.get('query_failed',False)} for sid,s in current.items()]
    result['passed']=result.get('before_error')=='Session information identity mismatch' and any(s['active'] and not s.get('query_failed') for s in current.values())
    (ROOT/'evidence/maintenance/wts-context-before-after-20261027.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
