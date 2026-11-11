"""Read-only source/build/evidence review. Never opens or attaches a browser."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.probe_owned_browser_drop_hook import DROP_RECORDING_CONTRACT, drop_case_passed


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    build_dir = ROOT/'runtime/owned-browser-drop-build'
    build = json.loads((build_dir/'build.json').read_text(encoding='utf-8'))
    sources = {name:digest(ROOT/name) for name in build['sources']}
    scripts = ['tools/build_owned_browser_drop_hook.py','tools/probe_owned_browser_drop_hook.py',
               'tools/review_owned_browser_drop_hook.py','tests/test_browser_drop_contract.py']
    for name in scripts:ast.parse((ROOT/name).read_text(encoding='utf-8-sig'),filename=name)
    products = {name:digest(build_dir/name) for name in
                ('GuardDeskOwnedBrowserDrop.dll','GuardDeskOwnedBrowserOleSource.exe','GuardDeskOwnedBrowserBudget.exe')}
    attempts = []
    for path in sorted((ROOT/'evidence').glob('owned-browser-native-drop-*.json')):
        item = json.loads(path.read_text(encoding='utf-8'))
        if 'probe_id' not in item:continue
        attempts.append({'evidence':str(path.relative_to(ROOT)),'sha256':digest(path),
            'dll_sha256':item.get('dll_sha256'),'helper_sha256':item.get('helper_sha256'),
            'browser_version':item.get('browser_version'),'passed':item.get('passed'),
            'error':item.get('error'), 'hook_removed':item.get('hook_removed'),
            'owned_browser_exit':item.get('owned_browser_exit'),
            'cases':[{'case':v['case'],'passed':v['passed'],'helper_exit':v['helper_exit'],
                      'page_file_count':len(v['page_received']),'record_count':len(v['records']),
                      'origin_failed':v['native_status']['origin_failed']}
                     for v in item.get('cases',[])]})
    baseline = json.loads((ROOT/'evidence/native-handoff-runtime-regression-20261028.json').read_text(encoding='utf-8'))
    baseline_unchanged = all(digest(ROOT/name)==value for name,value in baseline['source_sha256'].items())
    sealed = {'dist/GuardDesk-0.4.59-windows-x64.zip':'08611476cc584e780fafab8f38d68bf12e4a3aadc7edb2ae524b7ab26d59dc0b',
              'dist/GuardDesk-0.4.59-source.zip':'cc06883e812260a402553b0209349a3304314be76cfc508f1b7d8470f81d0783'}
    sealed_check = {name:{'sha256':digest(ROOT/name),'unchanged':digest(ROOT/name)==value} for name,value in sealed.items()}
    documents = ['doc/79-native-file-handoff-prototype.md','doc/60-engineering-lessons-and-regression-rules.md']
    missing = []
    count = 0
    for name in documents:
        path = ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if urlsplit(target).scheme or target.startswith('#'):continue
            count += 1
            candidate = path.parent/unquote(target.split('#',1)[0])
            if not candidate.exists():missing.append({'document':name,'link':target})
    report = {'date':'2026-10-28','scope':'unsigned_owned_receiver_research_only',
        'recording_contract':DROP_RECORDING_CONTRACT,
        'related_gd':['GD-018','GD-020','GD-023','GD-024'],
        'related_controls':['SEC-01','SEC-02','SEC-03','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11',
                            'DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'source_sha256':sources,'script_sha256':{n:digest(ROOT/n) for n in scripts},
        'build':build,'products':products,
        'current_build_matches_source':sources==build['sources'],
        'current_build_matches_products':products['GuardDeskOwnedBrowserDrop.dll']==build['dll_sha256'] and
                                        products['GuardDeskOwnedBrowserOleSource.exe']==build['helper_sha256'] and
                                        products['GuardDeskOwnedBrowserBudget.exe']==build['budget_test_sha256'],
        'python_ast_passed':True,'attempts':attempts,
        'current_dll_successful_runtime_attempts':[a['evidence'] for a in attempts if a['passed'] and
                                                  a['dll_sha256']==build['dll_sha256']],
        'baseline_regression':{'evidence':'evidence/native-handoff-runtime-regression-20261028.json',
                               'tests_passed':103,'rerun_this_research_turn':False,'sources_unchanged':baseline_unchanged},
        'sealed':sealed_check,'documents':{'local_links_checked':count,'missing':missing},
        'current_dll_desktop_acceptance_complete':False,
        'existing_employee_profile_capture_complete':False,
        'installed_agent_end_to_end_lifecycle_complete':False,
        'native_picker_implemented_in_this_adapter':False,
        'default_agent_source_factory':None,'company_field_deployed':False,
        'new_release_created':False,'authenticode':'not_signed_research_only',
        'risks':['Undocumented OleDropTargetInterface attachment; no supported production deployment contract',
                 'Accessibility cache timing is not an atomic browser frame/request binding',
                 'Deadline checks cannot cancel a synchronous accessibility API call',
                 'DLL pinned until owned browser exits; no production unload contract',
                 'Research shared mapping/parent checks are not production source attestation',
                 'Accepted page drop is the user-defined upload trigger; it does not attest network completion or final submission',
                 'Existing profile/multisession/restart/upgrade lifecycle and whole-endpoint performance pending']}
    # Reassess retained observations without rewriting their old contract or
    # claiming a new desktop run / a fix for the remaining missing events.
    original_path = ROOT/'evidence/owned-browser-native-drop-88b8c026b4884e7da9f6638f7f01bb50.json'
    original = json.loads(original_path.read_text(encoding='utf-8'))
    case = original['cases'][0]
    report['retained_no_handler_case_reassessment'] = {
        'original_evidence':str(original_path.relative_to(ROOT)),
        'original_evidence_sha256':digest(original_path),
        'original_passed':original['passed'],
        'current_contract_passed':drop_case_passed(case['case'],case['helper_exit'],case['helper_stdout'],
            case['records'],case['page_received'],expected_pid=original['peer']['pid'],
            expected_origin=case['expected_origin'],
            fixture_path=str(ROOT/'runtime'/('owned-native-drop-'+original['probe_id'])/'owned-fixture.txt')),
        'new_desktop_run':False,'network_completion_proven':False}
    output = ROOT/'evidence'/('owned-browser-native-review-'+uuid.uuid4().hex+'.json')
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence':str(output),'build_source_match':report['current_build_matches_source'],
        'build_product_match':report['current_build_matches_products'],'baseline_unchanged':baseline_unchanged,
        'sealed_unchanged':all(v['unchanged'] for v in sealed_check.values()),'links':count,'missing_links':missing,
        'attempts':len(attempts),'current_dll_passed_attempts':report['current_dll_successful_runtime_attempts']},indent=2))
    return 0 if report['current_build_matches_source'] and report['current_build_matches_products'] and baseline_unchanged and not missing and all(v['unchanged'] for v in sealed_check.values()) else 1


if __name__=='__main__':raise SystemExit(main())
