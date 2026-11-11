"""Crash, old-writer and resource boundaries for the handoff phase protocol."""
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from guarddesk import transaction_status as state
from guarddesk.update_client import save, _save_plain, Transaction
from guarddesk.native_installer import assert_quiescent, read_json
from guarddesk.updater_refresh import pending, Refresh


class StatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.updates=self.root/'updates';self.updates.mkdir()
        self.path=self.updates/'transaction-native.json'
        state._cache.clear()

    def blocked(self,code=None):
        with self.assertRaises(state.JournalStateError) as error:assert_quiescent(self.root)
        if code:self.assertEqual(error.exception.code,code)

    def test_new_large_journal_gate_does_not_open_payload(self):
        body={'phase':'healthy','manifest':'x'*(2*1024*1024),'unicode':'範例'}
        save(self.path,body)
        self.assertEqual(json.loads(self.path.read_text(encoding='utf-8')),body)
        self.assertLess(state.control_path(self.path).stat().st_size,4096)
        original=Path.open
        def opened(path,*args,**kwargs):
            if path==self.path:raise AssertionError('Handoff must not read full recovery journal')
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',opened):
            for _ in range(20):assert_quiescent(self.root)
        with self.assertRaises(ValueError):read_json(self.path)

    def test_many_consecutive_versions_terminal_then_switching(self):
        for i in range(12):
            for phase in ('prepared','switching','restarting'):
                save(self.path,{'phase':phase,'version':f'0.4.{66+i}','manifest':'x'*(700000+i)})
                self.blocked('journal_in_progress')
            save(self.path,{'phase':'healthy','version':f'0.4.{66+i}','manifest':'x'*700000})
            assert_quiescent(self.root)

    def test_old_writer_atomically_replaces_same_length_and_stales_summary(self):
        save(self.path,{'phase':'healthy','payload':'old'})
        _save_plain(self.path,{'phase':'pending','payload':'old'})  # pre-66 writer
        self.blocked('journal_in_progress')
        _save_plain(self.path,{'phase':'healthy','payload':'x'*900000})
        assert_quiescent(self.root)

    def test_crash_before_full_write_blocks_then_owner_recovery_heals(self):
        body={'phase':'healthy','reported':True,'job':{},'version':'0.4.66'}
        save(self.path,body)
        def fail(path,value):
            if path==self.path:raise OSError('owned crash')
            _save_plain(path,value)
        with self.assertRaises(OSError):state.write(self.path,{'phase':'switching'},fail)
        self.blocked('journal_writing')
        agent=SimpleNamespace(config_path=self.root/'config.json')
        Transaction(agent,'native',SimpleNamespace()).recover()
        assert_quiescent(self.root)
        self.assertEqual(json.loads(self.path.read_text()),body)

    def test_crash_on_first_write_and_after_atomic_commit(self):
        def fail(path,value):
            if path==self.path:raise OSError('owned crash')
            _save_plain(path,value)
        with self.assertRaises(OSError):state.write(self.path,{'phase':'prepared'},fail)
        self.blocked('journal_writing')
        # A whole committed JSON with a newer identity supersedes the intent.
        _save_plain(self.path,{'phase':'switching'})
        self.blocked('journal_in_progress')
        _save_plain(self.path,{'phase':'healthy'})
        assert_quiescent(self.root)

    def test_failed_ready_publication_uses_whole_committed_state(self):
        calls=0
        def fail(path,value):
            nonlocal calls
            calls+=1
            if calls==3:raise OSError('owned crash after journal commit')
            _save_plain(path,value)
        with self.assertRaises(OSError):state.write(self.path,{'phase':'healthy'},fail)
        assert_quiescent(self.root)

    def test_corruption_unknown_phase_and_oversize_control_fail_closed(self):
        save(self.path,{'phase':'healthy'})
        cp=state.control_path(self.path);original=cp.read_bytes()
        for bad in (b'{}',original.replace(b'healthy',b'pending'),b'x'*4097,
                    b'{"format":1,'+original[1:]):
            cp.write_bytes(bad);self.blocked('journal_control_invalid')
        cp.write_bytes(original);self.path.unlink();self.blocked('journal_missing')
        cp.unlink();save(self.path,{'phase':'unknown'});self.blocked('journal_in_progress')

    def test_refresh_pending_and_owner_recovery(self):
        path=self.updates/'updater-refresh.json';agent=SimpleNamespace(config_path=self.root/'config.json')
        self.assertFalse(pending(agent))
        for phase in ('prepared','stopping','switching','starting'):
            save(path,{'phase':phase,'padding':'x'*900000});self.assertTrue(pending(agent))
        body={'phase':'healthy','reported':True};save(path,body)
        self.assertFalse(pending(agent))
        _save_plain(state.control_path(path),state._control(path,'switching',state.fingerprint(path),'writing'))
        Refresh(agent,SimpleNamespace(root=self.updates)).recover()
        self.assertFalse(pending(agent))

    def test_large_legacy_stream_cache_and_invalidation(self):
        self.path.write_text(json.dumps({'padding':'x'*4_000_000,'phase':'healthy'}))
        assert_quiescent(self.root)
        with patch.object(state._LegacyPhase,'phase',side_effect=AssertionError('cached')):assert_quiescent(self.root)
        self.path.write_text('{"padding":[],"phase":"switching"}')
        self.blocked('journal_in_progress')

    def test_stream_json_boundaries_and_root_phase_only(self):
        bodies=[{'phase':'healthy','padding':'x'*n+'\\"範例\n'} for n in (65520,65530,65535,65536,65540)]
        bodies += [{'padding':[None,True,False,-1.25e20,{'phase':'switching'}], 'phase':'healthy'},
                   {'phase':'healthy','padding':'x'*65531+'\x00'}]
        for body in bodies:
            for ascii_only in (True,False):
                text=json.dumps(body,ensure_ascii=ascii_only)
                self.assertEqual(state._LegacyPhase(io.StringIO(text)).phase(),'healthy')
        for raw in ('{"phase":"healthy","phase":"switching"}', '{"nested":{"phase":"healthy"}}',
                    '{"phase":"healthy","bad":01}', '{"phase":"healthy","bad":NaN}',
                    '{"phase":"healthy"}\v', '{"phase":1}', '{"phase":"healthy","bad":"\\q"}',
                    '{"phase":"healthy","bad":true,}', '{"phase":"healthy"} trailing'):
            with self.subTest(raw=raw),self.assertRaises(OSError):state._LegacyPhase(io.StringIO(raw)).phase()

    def test_depth_token_time_and_changed_during_scan_fail_closed(self):
        for raw in ('{"phase":"healthy","bad":'+'['*70+'0'+']'*70+'}',
                    '{"phase":"healthy","bad":'+'9'*200+'}'):
            with self.assertRaises(OSError):state._LegacyPhase(io.StringIO(raw)).phase()
        self.path.write_text('{"phase":"healthy"}')
        with patch.object(state,'SCAN_SECONDS',-1):self.blocked('journal_scan_budget')
        with patch.object(state._LegacyPhase,'phase',side_effect=AssertionError('failure cached')):self.blocked('journal_scan_budget')
        state._cache.clear();original=state._LegacyPhase.phase
        def changed(parser):
            # Windows disallows replacing a file opened by Python without
            # delete sharing; an in-place metadata change exercises the race.
            value=original(parser);self.path.write_text('{"phase":"switching"}');return value
        with patch.object(state._LegacyPhase,'phase',changed):self.blocked('journal_changed')

    def test_invalid_utf8_and_cache_bounded_and_unrelated_save_unchanged(self):
        self.path.write_bytes(b'{"phase":"healthy","bad":"\xff"}')
        self.blocked('journal_invalid_json')
        for i in range(20):
            self.path.write_text(json.dumps({'phase':'healthy','n':i}));assert_quiescent(self.root)
        self.assertLessEqual(len(state._cache),16)
        config=self.root/'config.json';save(config,{'server':'owned-fixture'})
        self.assertEqual(json.loads(config.read_text()),{'server':'owned-fixture'})
        self.assertFalse(config.with_name(config.name+'.state.json').exists())

    def test_install_journal_missing_phase_still_blocks(self):
        (self.root/'install-transaction.json').write_text('{}')
        self.blocked('journal_invalid_phase')

    def test_periodic_terminal_recovery_does_not_rewrite_control(self):
        body={'phase':'healthy','reported':True,'version':'0.4.66','job':{}}
        save(self.path,body);before=state.fingerprint(state.control_path(self.path))
        agent=SimpleNamespace(config_path=self.root/'config.json')
        transaction=Transaction(agent,'native',SimpleNamespace())
        with patch('guarddesk.update_client._save_plain',side_effect=AssertionError('No repeated terminal writes')):
            for _ in range(25):transaction.recover()
        self.assertEqual(before,state.fingerprint(state.control_path(self.path)))

    def test_control_churn_excludes_only_owned_paths_preserving_alerts(self):
        from guarddesk.file_exclusions import internal_health_path,excluded_internal_health_activity
        base='C:\\ProgramData\\GuardDeskPilot\\USBControl\\'+'a'*24+'\\updates\\'
        for journal in state.JOURNALS:
            for suffix in ('.state.json','.state.new'):
                path=base+journal+suffix
                self.assertTrue(internal_health_path(path))
                self.assertTrue(excluded_internal_health_activity('file.created','info',{'path':path}))
                self.assertFalse(excluded_internal_health_activity('file.created','warning',{'path':path}))
                self.assertFalse(excluded_internal_health_activity('file.moved','info',{'source_path':path,'destination_path':r'C:\\Documents\\business.txt'}))
                self.assertFalse(internal_health_path(r'C:\\Documents\\'+journal+suffix))
        self.assertFalse(internal_health_path(base+'customer.json.state.json'))


if __name__=='__main__':unittest.main()
