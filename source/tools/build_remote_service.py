"""Build fixed SCM host and run owned child/job tests. Never install a service."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT.parent
CMAKE=Path('C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe')
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    number=1
    while (RUNTIME/f'remote-service-build-{number:03}').exists():number+=1
    output=RUNTIME/f'remote-service-build-{number:03}';output.mkdir()
    paths=[*(ROOT/'native/service').iterdir(),*(ROOT/'native/remote').glob('*.hpp'),
           ROOT/'native/remote/cohort.cpp',ROOT/'native/remote/ipc_peer.cpp']
    sources={p.relative_to(ROOT).as_posix():digest(p) for p in paths if p.is_file()}
    report={'passed':False,'sources':sources,'installed':False,'SCM_tested':False,'SYSTEM_tested':False,'stages':[]}
    try:
        with (output/'build.log').open('x',encoding='utf-8') as log:
            for command in ([str(CMAKE),'-S',str(ROOT/'native/service'),'-B',str(output),'-G','Visual Studio 16 2019','-A','x64'],
                            [str(CMAKE),'--build',str(output),'--config','Release','--parallel','2']):
                result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180)
                report['stages'].append(result.returncode)
                if result.returncode:raise ValueError('Native service build failed')
            result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe')],stdout=log,stderr=subprocess.STDOUT,timeout=30)
            if result.returncode:raise ValueError('Owned service lifetime failed')
            result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe'),'--owned-recover'],stdout=log,stderr=subprocess.STDOUT,timeout=10)
            if result.returncode:raise ValueError('Owned bounded recovery failed')
            result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe'),'--owned-recovery-process'],stdout=log,stderr=subprocess.STDOUT,timeout=10)
            if result.returncode:raise ValueError('Owned real-process recovery failed')
            with tempfile.TemporaryDirectory(prefix='guarddesk-recovery-owned-') as owned:
                from guarddesk.endpoint_files import secure_directory
                # The default Temp ACL may use an OWNER_RIGHTS write ACE. The
                # product accepts only explicit trusted writer SIDs; use the
                # existing private-directory creator for this owned fixture.
                secure_directory(owned,allow_empty=True)
                result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe'),'--owned-recovery-store',owned],stdout=log,stderr=subprocess.STDOUT,timeout=10)
                if result.returncode:raise ValueError('Owned protected recovery state failed')
            with tempfile.TemporaryDirectory(prefix='guarddesk-maintenance-owned-') as owned:
                secure_directory(owned,allow_empty=True)
                result=subprocess.run([str(output/'Release/GuardDeskServiceOwnedProbe.exe'),'--owned-recovery-maintenance',owned],stdout=log,stderr=subprocess.STDOUT,timeout=10)
                if result.returncode:raise ValueError('Owned recovery maintenance transaction failed')
        image=output/'Release/GuardDeskService.exe'
        tests=[]
        for args,expected in [(['--component-info'],0),(['--recovery-help'],0),([],87),(['--owned-child','1'],87),(['--owned-zero'],87),(['--owned-recover'],87),(['--owned-recovery-process'],87),(['--owned-recovery-store','ignored'],87),(['--owned-recovery-maintenance','ignored'],87),(['--device-id','../bad'],87),(['--recovery-reset','--device-id','../bad','--review','security'],87),(['--recovery-reset','--device-id','a'*24,'--review','force'],87)]:
            result=subprocess.run([str(image),*args],capture_output=True,timeout=10)
            if result.returncode!=expected:raise ValueError('Native service entry mismatch')
            tests.append({'arguments':args,'exit':result.returncode})
            if args==['--component-info']:
                info=json.loads(result.stdout);assert info['recovery_maintenance']==1 and info['rollback_guard']=='service-disabled-v1'
        if not all(digest(ROOT/name)==value for name,value in sources.items()):raise ValueError('Source changed during build')
        report.update(passed=True,sha256=digest(image),entry_tests=tests,owned_lifetime_cases=['cooperative_stop','worker_failure_exit','coordinator_job_not_inherited_by_helper','timeout_owned_job_termination'])
        report['owned_recovery_cases']=['three_delayed_retries_then_hold','hold_survives_new_host','stop_cancels_wait','simultaneous_stop_keeps_security_hold',
            'worker_recovers','antimalware_no_retry','invalid_image_no_retry','normal_zero_exit_no_retry','clock_rollback_hold',
            'unfinished_prior_host_consumes_budget','rolling_window_without_clearing_hold',
            'state_roundtrip','parent_pin_allows_write_but_denies_delete','single_writer','torn_latest_slot_retains_previous_active_state',
            'persisted_security_marker','hold_roundtrip','hardlink_rejected','corruption_preserved']
        report['owned_recovery_process_cases']=['actual_child_failure_twice_then_normal_exit','actual_stop_event_cancels_wait']
        report['owned_maintenance_cases']=['readonly_missing_does_not_create','readonly_snapshot_cannot_save',
            'exhausted_review_preserves_errors_identity_outbox','security_requires_explicit_review',
            'security_review_archives_marker_before_clear','running_service_refused_before_state_change',
            'failed_reenable_stays_disabled_and_retry_is_possible','archive_limit_preserves_hold_and_disabled',
            'unclassified_fence_interruption_needs_security_review']
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    (output/'receipt.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'receipt':str(output/'receipt.json'),'passed':report['passed']}))
    if not report['passed']:raise SystemExit(1)
if __name__=='__main__':main()
