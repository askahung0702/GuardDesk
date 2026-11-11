"""Source evidence review, not release approval or field acceptance."""
import hashlib
import json
from pathlib import Path
import re
import uuid

ROOT=Path(__file__).resolve().parents[1]
DOCUMENTS=['doc/80-category-policy-website-blocking-and-edge-plan.md',
           'doc/79-native-file-handoff-prototype.md','doc/60-engineering-lessons-and-regression-rules.md','doc/README.md']
EVIDENCE={
    'regression':'evidence/category-regression-f5a8d1b923a6493794444acd16123b72.json',
    'ui':'evidence/category-browser-smoke-ed26a9132b0242829211073f5c32be22.json',
    'performance':'evidence/category-policy-performance-3ab38e9302aa453c9a9ad51244d3e8c5.json',
    'chrome_single_drop':'evidence/owned-browser-native-drop-be2b4429a98b4ad7aceea3e856086dc9.json',
    'edge_failed_drop':'evidence/owned-browser-native-drop-30ea33946adf4bb4b776ea8a8b8914e3.json',
    'edge_sync_interruption':'evidence/owned-browser-native-drop-d4035b4f86154a7991b62d23533f7ca1.json'}
SEALED={
    'dist/GuardDesk-0.4.59-windows-x64.zip':'08611476cc584e780fafab8f38d68bf12e4a3aadc7edb2ae524b7ab26d59dc0b',
    'dist/GuardDesk-0.4.59-source.zip':'cc06883e812260a402553b0209349a3304314be76cfc508f1b7d8470f81d0783'}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    baseline=json.loads((ROOT/'evidence/category-implementation-baseline-ca81d458002b4ff4a7334207269080a3.json').read_text(encoding='utf-8'))['sha256']
    regression=json.loads((ROOT/EVIDENCE['regression']).read_text(encoding='utf-8'))
    mismatches=[name for name,value in regression['source_sha256'].items() if not (ROOT/name).is_file() or sha(ROOT/name)!=value]
    current={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'guarddesk').rglob('*') if p.suffix in ('.py','.js','.html') and '__pycache__' not in str(p)}
    changed=[name for name,value in current.items() if name in baseline and value!=baseline[name]]
    added=[name for name in current if name not in baseline]
    missing=[];link_count=0
    for name in DOCUMENTS:
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'):continue
            target=link.split('#',1)[0]
            if not target:continue
            link_count+=1
            if not (path.parent/target).exists():missing.append({'document':name,'target':target})
    sealed={name:{'actual':sha(ROOT/name),'expected':value} for name,value in SEALED.items()}
    evidence={key:{'path':name,'sha256':sha(ROOT/name)} for key,name in EVIDENCE.items()}
    checks={'regression_passed':regression['passed'],'regression_source_still_matches':not mismatches,
            'documentation_file_links_exist':not missing,'sealed_archives_unchanged':all(v['actual']==v['expected'] for v in sealed.values())}
    report={'scope':'developer_source_review_not_independent_security_review_or_release',
        'checks':checks,'passed':all(checks.values()),'regression_source_mismatches':mismatches,
        'changed_production_files':changed,'added_production_files':added,
        'file_link_count':link_count,'missing_file_links':missing,'evidence':evidence,'sealed_archives':sealed,
        'documentation_sha256':{name:sha(ROOT/name) for name in DOCUMENTS},
        'research_probe_sha256':sha(ROOT/'tools/probe_owned_browser_drop_hook.py'),
        'field_changed':False,'new_release_produced':False,'installed_agent_acceptance':False,
        'requirements':{'CAT-01':'source_and_isolated_tests_complete_field_pending',
                        'CAT-02':'source_and_isolated_tests_complete_field_pending',
                        'APP-01':'source_integration_complete_applocker_execution_pending',
                        'WEB-01':'source_and_owned_registry_complete_browser_acceptance_pending',
                        'EDGE-01':'edge_positive_failed_chrome_single_owned_positive_only',
                        'EDGE-02':'production_source_missing_not_complete'},
        'remaining':['website_match_preview','real_HKLM_SYSTEM_ACL','actual_browser_policy_and_navigation',
            'actual_AppLocker_execution','edge_native_drop','production_native_source','installed_agent_to_center',
            'old_updater_actual_package','full_endpoint_performance','Win10_Win11_Defender_matrix','signing_SBOM_supply_chain']}
    path=ROOT/'evidence'/('category-implementation-review-'+uuid.uuid4().hex+'.json')
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'evidence':str(path),'checks':checks,'missing_file_links':missing,'changed_files':len(changed),'added_files':len(added)},ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
