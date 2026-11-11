"""Normal Defender scans of the exact complete ZIP/helper/expanded payload.
No Defender settings, exclusions, installed products, or center processes change.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess,time

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--helper-root',type=Path,required=True);a=parser.parse_args()
    E=a.helper_root.resolve(strict=True);R=Path(__file__).resolve().parents[3]
    if E.parent!=R/'runtime' or not E.name.startswith('center-source-permissions-094-'):raise ValueError('Owned build required')
    record=json.loads((E/'complete-package.json').read_text());tests=json.loads((E/'final-package-tests.json').read_text())
    assert tests['passed'] and tests['no_center_started']
    archive=Path(record['archive']);root=Path(tests['fixture'])
    assert root.is_relative_to(E) and sha(archive)==record['sha256'] and sha(archive)==tests['archive_sha256']
    helper=E/'GuardDeskCenterPrepare.exe';assert sha(helper)==record['helper_sha256']
    scanner=sorted((p for p in Path('C:/ProgramData/Microsoft/Windows Defender/Platform').glob('*/MpCmdRun.exe') if p.parent.name[0].isdigit()),key=lambda p:p.parent.name)[-1]
    status=subprocess.run(['powershell.exe','-NoProfile','-Command','Get-MpComputerStatus | Select-Object AMRunningMode,AMProductVersion,AMEngineVersion,AntivirusSignatureVersion,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected | ConvertTo-Json -Compress'],capture_output=True,timeout=30)
    report={'passed':False,'settings_changed':False,'manual_sample_submission':False,'actual_exclusion_scope_verified':False,'company_Server_field_acceptance':False,'scans':[]}
    try:report['protection_status']=json.loads(status.stdout.decode('utf-8-sig'))
    except Exception:report['status_query_exit']=status.returncode
    for number,target in enumerate((archive,helper,root),1):
        started=time.monotonic();run=subprocess.run([str(scanner),'-Scan','-ScanType','3','-File',str(target)],capture_output=True,timeout=600)
        raw=run.stdout+run.stderr;(E/f'normal-defender-{number:03}.log').write_bytes(raw)
        okay=run.returncode==0 and 'found no threats' in raw.decode('utf-8',errors='replace').lower()
        row={'target':str(target),'exit':run.returncode,'no_threats_text':okay,'seconds':round(time.monotonic()-started,2)}
        report['scans'].append(row);print(json.dumps(row,ensure_ascii=False),flush=True)
        if not okay:break
    normal=report.get('protection_status',{}).get('AMRunningMode')=='Normal' and all(report.get('protection_status',{}).get(k) is True for k in ('AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IoavProtectionEnabled'))
    unchanged=sha(archive)==record['sha256'] and all(sha(root/n)==h for n,h in record['file_hashes'].items())
    report.update(passed=len(report['scans'])==3 and all(s['no_threats_text'] for s in report['scans']) and normal and unchanged,
        normal_protection_observed=normal,bytes_unchanged=unchanged,scanner_sha256=sha(scanner),deployable=False)
    (E/'normal-defender.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    raise SystemExit(not report['passed'])

if __name__=='__main__':main()
