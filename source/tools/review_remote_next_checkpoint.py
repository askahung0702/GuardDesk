"""Re-read frozen bytes, exact current receipts and unchanged stable baseline."""
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.remote_checkpoint_receipts import SOURCE,WORKSPACE,RUNTIME,ROOTS,digest,verify_receipt
EVIDENCE=WORKSPACE/'evidence/maintenance/remote-next-m2-20261030'

def main():
    if sys.argv[1:]!=['--latest']:raise SystemExit('Use --latest')
    target=sorted(p for p in EVIDENCE.glob('checkpoint-*') if p.is_dir() and re.fullmatch(r'checkpoint-[0-9]{3}',p.name))[-1]
    manifest=json.loads((target/'checkpoint.json').read_text(encoding='utf-8'));issues=[];counts={}
    if manifest['format']!=2:raise ValueError('Latest checkpoint predates this exact-receipt review')
    def check(root,name,expected):
        path=root/name
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or digest(path)!=expected:issues.append(str(path))
    for section in ('logs','field_evidence','artifacts','packaging'):
        counts[section]=len(manifest[section])
        for name,expected in manifest[section].items():check(target,name,expected)
    changed={**{name:value['current'] for name,value in manifest['modified'].items()},**manifest['added']}
    for name,expected in changed.items():
        if expected:check(target/'source',name,expected);check(SOURCE,name,expected)
        elif (SOURCE/name).exists():issues.append('Removed source exists: '+name)
    baseline=json.loads((SOURCE/'BASELINE-MANIFEST.json').read_text(encoding='utf-8'))
    for name,expected in baseline['files'].items():check(WORKSPACE/baseline['baseline'],name,expected)
    check(WORKSPACE,baseline['archive'],baseline['archive_sha256']);counts['stable_files']=len(baseline['files'])
    for kind,item in manifest['builds'].items():
        check(target,item['manifest'],item['sha256']);check(RUNTIME,item['manifest'],item['sha256'])
        try:verify_receipt(kind,target/item['manifest'])
        except Exception as error:issues.append(kind+': '+str(error))
    if any(manifest[key] for key in ('M2_complete','M3_complete','M4_complete','full_MIS_UAC_test','signing_and_Defender_acceptance','deployable')):issues.append('Unverified field/release gate marked complete')
    counts.update(current_and_frozen_sources=len(changed),Python_tests=manifest['Python_tests'],native_tests=manifest['native_tests'],WebRTC_runtime_stages=len(manifest['WebRTC_runtime_stages']))
    report={'format':2,'checkpoint':target.relative_to(WORKSPACE).as_posix(),'manifest_sha256':digest(target/'checkpoint.json'),'passed':not issues,'counts':counts,'issues':issues,'company_product_changed':False,'deployable':False}
    path=EVIDENCE/(target.name+'-review.json')
    with path.open('x',encoding='utf-8') as out:json.dump(report,out,indent=2);out.write('\n')
    print(json.dumps(report))
    if issues:raise SystemExit(1)

if __name__=='__main__':main()
