"""The 105 cumulative offline regression inventory: no center/Agent/UI launch."""
from pathlib import Path
import hashlib,json,os,sys,unittest,time
from contextlib import contextmanager
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'runtime/remote-next-src'
sys.path[:0]=[str(SOURCE),str(SOURCE/'tests')]
from worktree import files
NAMES=['test_remote_session_lifecycle','test_remote_consent_once','test_remote_transport_recovery',
    'test_remote_native_broker','test_mis_native_media','test_mis_heartbeat_recovery',
    'test_mis_window.EndpointSearchTest',
    'test_remote_autonomous','test_remote_broker_concurrency',
    'test_machine_agent.MachineAgentTest','test_machine_agent.SupervisorTest',
    'test_machine_remote_global.GlobalRouterTest','test_machine_remote_global.SessionLifetimeTest',
    'test_remote_admin.AdminRouterTest','test_remote_native_signaling.NativeLeaseTest',
    'test_remote_relay.RelayPolicyTest','test_remote_build_receipts','test_remote_trial.TrialTest',
    'test_service_recovery','test_agent_link_recovery','test_recovery_maintenance',
    'test_filename_prefix_exclusions','test_msi_update_coordination','test_endpoint_search_ui',
    'test_document_actions_ui','test_document_word_flow','test_document_saves','test_heartbeat_mode',
    'test_system32_process_exclusions','test_policy_defaults',
    'test_document_write_activity','test_event_upload','test_audit_collection',
    'test_document_native.CandidateBackpressureTest','test_file_handoff.HandoffQueueTest',
    'test_browser_history.BrowserHistoryTest.test_domain_mode_drops_sensitive_fields_before_persistence_and_retry',
    'test_browser_history.BrowserHistoryTest.test_one_domain_row_per_occurrence_second_across_polls_profiles_and_restart',
    'test_browser_history.BrowserHistoryTest.test_new_visits_repeat_restart_redaction_and_read_only',
    'test_endpoint_controls.EndpointTest.test_real_native_directory_create_modify_delete',
    'test_custom_settings.CustomRuntimeTest.test_process_pause_keeps_security_source_and_restores_without_network',
    'test_web_upload.WebUploadTest.test_exact_request_evidence_durable_redacted_and_deduplicated',
    'test_performance.PerformanceTest.test_background_flush_keeps_unsent_rows_and_retries_lost_ack',
    'test_performance.PerformanceTest.test_fresh_web_events_bypass_backlog_without_starving_older_files',
    'test_performance.PerformanceTest.test_serialization_batch_is_byte_bounded',
    'test_performance.PerformanceTest.test_repeated_scan_failure_only_reports_change_or_recurrence',
    'test_updates.UpdateTransactionTest','test_update_dispatch','test_update_storage','test_update_notify.UpdateNotifyPureTest','test_update_windows',
    'test_bundled_release.BundledReleaseTest',
    'test_user_path_exclusions.UserPathRuleTest',
    'test_user_path_exclusions.UserPathSourceTest','test_software_deployment',
    'test_application_exclusions.ApplicationExclusionsTest','test_application_exclusions.ApplicationSourceTest',
    'test_development_exclusions.DevelopmentPathTest','test_development_exclusions.DevelopmentSourceTest',
    'test_hidden_files.HiddenSourceTest','test_process_audit','test_remote_removal_full']
NAMES += ['test_hidden_files.HiddenMetadataTest.'+name for name in (
    'test_cache_rate_capacity_ttl_and_authoritative_delete_hint',
    'test_disabled_does_no_attribute_work_and_policy_toggle_is_immediate',
    'test_each_notification_keeps_its_own_attributes_across_reused_names',
    'test_file_type_checks_stream_base_and_refreshes_leaf_without_following_reparse',
    'test_server_rule_is_pure_and_only_fixed_root_installer_churn_is_default',
    'test_unc_reparse_and_unknown_never_traverse_or_guess',
    'test_windows_attribute_not_dot_name_and_hidden_ancestors')]
EXTERNAL_ONLY=['test_machine_agent.MachineUpdateHandoffTest','test_file_collection_scope',
    'test_hidden_files.HiddenMetadataTest.test_sealed_056_decoder_really_accepts_marker_without_new_schema']
EXTERNAL_REASONS={'test_file_collection_scope':'SystemTest setup starts a center; development-host guard denied all three constructors before listening',
    'test_hidden_files.HiddenMetadataTest.test_sealed_056_decoder_really_accepts_marker_without_new_schema':'Sealed 0.4.56 source ZIP unavailable in canonical artifact inputs; legacy hidden marker unchanged; not counted as passed'}
EXPECTED_SKIPS={
    'test_mis_native_media.ModuleLifetimePinsTest.test_real_cached_module_cannot_rename_after_session_close':
    'owned native cohort fixture unavailable'}

@contextmanager
def center_start_guard():
    """Intercept actual constructors too, including imported serve aliases."""
    attempts=[]
    def deny(*args,**kwargs):
        attempts.append('HTTP_center_start_denied')
        raise RuntimeError('Local management center prohibited on development host')
    with patch('socketserver.TCPServer.__init__',deny),patch('guarddesk.server.serve',deny):
        yield attempts
def main():
    os.chdir(SOURCE)
    import guarddesk
    if Path(guarddesk.__file__).resolve().parent!=SOURCE/'guarddesk':raise ValueError('Wrong source imported')
    before=files(ROOT/'source')
    folder=ROOT/'runtime/test-results';folder.mkdir(exist_ok=True)
    stamp=str(time.time_ns());log=folder/('unit-'+stamp+'.log')
    with center_start_guard() as denied:
        suite=unittest.defaultTestLoader.loadTestsFromNames(NAMES)
        with log.open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    skipped=[{'test':test.id(),'reason':reason} for test,reason in result.skipped]
    unexpected=[r for r in skipped if EXPECTED_SKIPS.get(r['test'])!=r['reason']]
    body={'format':1,'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),
        'skipped':len(result.skipped),'skip_details':skipped,'unexpected_skips':unexpected,
        'passed':result.wasSuccessful() and not unexpected and not denied and before==files(ROOT/'source'),
        'inventory':NAMES,'canonical_source_unchanged':before==files(ROOT/'source'),
        'source_files':before,'source_input_sha256':hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'center_start_guard':True,'center_start_attempts_denied':denied,'external_only_excluded':EXTERNAL_ONLY,'external_only_reasons':EXTERNAL_REASONS,
        'center_started':False,'Agent_installed':False,'desktop_capture_or_input':False,'deployable':False}
    log.with_suffix('.json').write_text(json.dumps(body,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in body.items() if k not in ('inventory','source_files')}));print('Report='+str(log.with_suffix('.json')))
    if not body['passed']:raise SystemExit(1)
if __name__=='__main__':main()
