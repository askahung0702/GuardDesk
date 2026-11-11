"""Preserve intermediate failures and candidate hashes before final sealing."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    target=ROOT/'evidence/update-release-0.4.69-attempts.json';assert not target.exists()
    reports=[]
    for p in sorted((ROOT/'evidence').glob('machine-agent-regression-*.json')):
        body=json.loads(p.read_text(encoding='utf-8'))
        if body.get('version')=='0.4.69':reports.append({'path':p.relative_to(ROOT).as_posix(),**{k:body[k] for k in ('tests','passed','errors','failures','source_stable','seconds','log')}})
    candidates={}
    for label,folder in [('first','runtime/previous-built-0469-first'),('second','runtime/previous-built-0469-second'),('final','dist/GuardDesk')]:
        p=ROOT/folder/'GuardDesk.exe';candidates[label]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'path':folder}
    value={'company_changed':False,'installed_program_cache_tasks_ACL_or_policy_modified':False,'source_runs':reports,'candidates':candidates,
        'attempts':[
            {'stage':'DEV readonly','result':'ordinary account protected reads denied, admin selected metadata succeeded','proof':'evidence/maintenance/dev-update-failure-20261029-144041.json'},
            {'stage':'actual installed66 budget proof','result':'first observation filename was mistyped; corrected to actual 144041, actual installed SHA verified, owned sparse reproduction passed','proof':'evidence/maintenance/dev-0468-installed-budget-proof.json'},
            {'stage':'cache12 native fixture','result':'ordinary owned NTFS rejected by protected-tree as designed; shared retention test changed to main role, not weakened ACL','log':'runtime/update-storage-first.log'},
            {'stage':'first303','result':'six old fixtures directly scheduled current release without new explicit one-pilot attestation; fixtures adapted to new authorized contract; product gate retained','proof':'evidence/machine-agent-regression-7e135f08ee324170b4607ee09ddd8b2b.json'},
            {'stage':'second303','result':'owned repair config atomic replacement WinError5; no handle owner established; isolated unchanged case passed and subsequent full run retained','proof':'evidence/machine-agent-regression-d234aa6964634c47a128d41662114696.json','isolated_log':'runtime/endpoint-repair-0469-isolated.log'},
            {'stage':'first browser','result':'build workspace source owner rejected; read-only direct inspect confirmed source_not_private/dist/untrusted_owner. Final browser fixture uses owned private installation, no product ACL relaxation'},
            {'stage':'first312','result':'passed, then added meaningful lost-completion-ACK case which failed before fix','proof':'evidence/machine-agent-regression-91d55d55fe2b431d8afcc1dde9c3351c.json','negative_log':'runtime/update-ack-0469-before.log'},
            {'stage':'recovery receipt','result':'first fix assumed complete job metadata; two existing minimal terminal-recovery fixtures raised KeyError. Incomplete metadata now remains unknown and cannot authorize cache cleanup; idempotence retained','proof':'evidence/machine-agent-regression-e82a4cbaf9994896ae6692492e2af27c.json','focused_log':'runtime/update-recovery-0469-final.log'},
            {'stage':'second candidate smoke','result':'existing-install server-setup repeat exceeded 20-second test subprocess timeout during concurrent verification; no cause attribution, final exact candidate rerun required'},
            {'stage':'dependency selection','result':'ambient Pillow11.3 and existing isolated13 both present; earlier candidates differed. Pin environment before PyInstaller/hooks and verify RECORD, frozen pure modules and native binaries. No global package installation or modification'},
            {'stage':'dependency diagnostic','result':'a precheck imported PyInstaller before pinning Pillow and guard correctly refused. Reviewer now sets isolated path before importing readers'},
        ],
        'relocated_intermediate_proofs':'*-first-candidate and *-second-candidate preserve original JSON/image bytes. Their original screenshot path names refer to the original candidate context; final proof names now belong to final candidate, compare preserved images and SHA separately.',
        'remaining':'No company SYSTEM or endpoint upgrade acceptance. user1 mechanism not field confirmed. Raw original DEV exception, transient config handle owner and prior setup-timeout cause unavailable.'}
    target.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');print(target)

if __name__=='__main__':main()
