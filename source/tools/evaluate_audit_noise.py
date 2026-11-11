"""Read-only retrospective rule counts, not a collector policy or event deletion."""
import argparse
from collections import Counter
import datetime as dt
import json
import ntpath
from pathlib import Path
import re
import sqlite3
import time
from analyze_audit_capacity import category


def candidate(path):
    p=ntpath.normcase(ntpath.normpath(path or ''))
    browser=re.search(r'\\appdata\\local\\(?:google\\chrome|microsoft\\edge)\\user data\\[^\\]+\\(.+)',p)
    if browser:
        relative=browser.group(1);head=relative.split('\\',1)[0]
        if head in ('cache','code cache','gpucache','dawncache','grshadercache','shadercache'):return 'browser_cache'
        if relative.startswith('service worker\\cachestorage\\'):return 'browser_cache'
        if relative.startswith('network\\reporting and nel'):return 'browser_runtime_reporting'
    if p.startswith('c:\\programdata\\microsoft\\search\\data\\'):return 'search_index'
    if '\\workspace\\ipguard\\runtime\\' in p:return 'development_fixture_runtime'
    if re.search(r'\\\.codex\\(?:tmp|log|logs|sqlite)\\',p):return 'development_tool_cache'
    if category(p)=='temporary_files' and (ntpath.splitext(p)[1] in ('.tmp','.temp','.etl','.log') or p.endswith(('-wal','-shm','-journal'))):return 'temp_metadata_candidate'
    if ntpath.basename(p).startswith('~$') and ntpath.splitext(p)[1] in ('.doc','.docx','.xlsx','.xls','.ppt','.pptx'):return 'office_lock_candidate'
    return None


def analyze(path):
    before=path.stat();started=time.monotonic();deadline=started+90
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
    db.execute('PRAGMA query_only=ON');db.execute('PRAGMA cache_size=-4096');db.set_progress_handler(lambda:int(time.monotonic()>deadline),10000)
    kinds=Counter();file_categories=Counter();remaining_categories=Counter();candidates=Counter();candidate_kinds=Counter();processes=Counter();sources=Counter();protected_documents=0
    try:
        for kind,raw in db.execute("SELECT kind,details FROM events NOT INDEXED WHERE kind LIKE 'file.%' OR kind LIKE 'application.%'"):
            d=json.loads(raw);kinds[kind]+=1;sources[(kind,d.get('source') or '(missing)')]+=1
            if kind.startswith('application.'):
                process=d.get('process') or d.get('path') or ''
                processes[ntpath.basename(process) or '(missing)']+=1
                continue
            path_value=d.get('source_path') or d.get('path') or '';file_categories[category(path_value)]+=1
            if kind=='file.modified':continue
            remaining_categories[category(path_value)]+=1
            paths=[p for p in (path_value,d.get('destination_path')) if p]
            labels=[candidate(p) for p in paths]
            # A rename/move touching a business path is never treated as
            # entirely internal merely because its source is a temp/cache file.
            if paths and all(labels):
                label=labels[0] if len(set(labels))==1 else 'mixed_internal_candidates'
                candidates[label]+=1;candidate_kinds[kind]+=1
            elif any(ntpath.splitext(p)[1].lower() in ('.doc','.docx','.docm','.xls','.xlsx','.xlsm','.ppt','.pptx','.pdf','.odt','.ods','.csv','.txt','.zip','.7z') for p in paths):protected_documents+=1
    finally:db.close()
    after=path.stat()
    return {'events_by_kind':dict(kinds),'file_path_categories':dict(file_categories),'file_categories_after_modified_disabled':dict(remaining_categories),
            'mutually_exclusive_optional_candidates_after_modified_disabled':dict(candidates),'candidate_events_by_kind':dict(candidate_kinds),
            'document_extension_hints_not_internal_candidates':protected_documents,'application_process_basenames':processes.most_common(30),
            'sources':[{'kind':k,'source':s,'records':n} for (k,s),n in sources.most_common()],
            'elapsed_seconds':round(time.monotonic()-started,2),'source_stat_unchanged':(before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),
            'limitations':['All records in historical workspace DB evaluated, not current office Server DB',
                           'Candidates are policy-review buckets, not proof an event is useless or authorization to discard it',
                           'No blanket AppData/temp exclusion; both source and destination must qualify for move/rename candidates',
                           'Different process IDs are real process observations; frequent same-name starts are not assumed retransmissions',
                           'No original records, endpoint policies or security settings changed; no employee paths or document values exported']}


def main():
    p=argparse.ArgumentParser();p.add_argument('--db',required=True,type=Path);p.add_argument('--output',required=True,type=Path);args=p.parse_args()
    result=analyze(args.db.resolve())
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
