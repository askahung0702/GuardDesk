"""Explicit, owned native COM -> Agent -> isolated center -> Chrome UI smoke.

This does NOT attach to Chrome, observe a real website, or prove browser native
integration. Chromium here only displays the isolated management-center UI.
The origin is supplied by the self-owned COM fixture. Microbenchmark numbers
are not employee end-to-end interaction latency or whole-Agent acceptance.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_system
import test_file_handoff as fixtures
from guarddesk.file_handoff import HandoffQueue


def percentile(values, fraction):
    return sorted(values)[min(len(values)-1, int(len(values)*fraction))]


def main():
    from playwright.sync_api import sync_playwright, expect
    # Start only self-owned COM objects and temporary test Server/Agent data.
    native = fixtures.NativeHandoffTest
    native.setUpClass()
    case = test_system.SystemTest('runTest')
    case.setUp()
    agent = None
    result = {'scope': 'self_owned_com_fixture_to_isolated_center_and_ui',
              'chrome_edge_capture_verified': False, 'physical_drag_verified': False,
              'field_changed': False, 'company_file_contents_read': False,
              'employee_performance_accepted': False}
    try:
        native.trace.poll()
        # Alternate baseline/wrapped order to reduce warmup/order bias.
        direct = native.fixture.gd_fixture_drop_direct
        direct.argtypes = native.fixture.gd_fixture_drop.argtypes
        direct.restype = ctypes.c_long
        wrapped = native.fixture.gd_fixture_drop
        paths = (ctypes.c_wchar_p*1)(r'C:\Owned\fixture-only.txt')
        measurements = {'direct': [], 'wrapped': []}
        received = 0
        losses = 0
        for i in range(600):
            order = [('direct', direct), ('wrapped', wrapped)]
            if i % 2:
                order.reverse()
            for name, function in order:
                started = time.perf_counter_ns()
                code = function(paths, 1, 'https://receiver.example.test', 1, 0, False, False, 0)
                duration = (time.perf_counter_ns()-started)/1000
                assert code == 0
                if i >= 100:
                    measurements[name].append(duration)
            rows, lost = native.trace.poll()
            received += len(rows)
            losses += lost
        assert received == 600 and losses == 0
        result['microbenchmark'] = {'units': 'microseconds', 'paired_samples': 500, 'warmup_pairs': 100,
                                   'includes': 'ctypes_and_owned_COM_fixture_lifecycle',
                                   'includes_network_sqlite_browser_capture': False,
                                   'emitted': received, 'losses': losses,
                                   **{name: {'median': statistics.median(values), 'p95': percentile(values, .95), 'max': max(values)}
                                      for name, values in measurements.items()}}
        agent, did, _ = case.make_agent()
        agent.heartbeat()
        agent.config['audit_watch'] = r'C:\Owned'
        queue = HandoffQueue(agent, experimental=True)
        native.drop(native, cancel=True)
        assert native.trace.poll()[0] == []
        native.drop(native, paths=[r'C:\Owned\first\same.txt', r'C:\Owned\second\same.txt'],
                    origin='https://receiver.example.test', read_on_enter=True)
        rows, lost = native.trace.poll()
        assert len(rows) == 2 and lost == 0
        class Captured:
            def poll(self):
                return rows, lost
        assert queue.drain_native(Captured())['admitted'] == 2
        queue.flush()
        assert agent.flush()['sent'] == 2
        result['native_to_center_events'] = 2
        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel='chrome', headless=True)
            try:
                page = browser.new_page(viewport={'width': 1500, 'height': 1100})
                page.goto(case.url)
                page.locator('[name=username]').fill('admin')
                page.locator('[name=password]').fill(case.password)
                page.locator('button[type=submit]').click()
                page.locator('nav [data-page=audit]').click()
                page.locator('[data-audit-category=documents]').click()
                entries = page.locator('table.detailed-audit tbody tr').filter(has_text='檔案交付網站（原生研究版）')
                expect(entries).to_have_count(2)
                expect(entries.first).to_contain_text('https://receiver.example.test')
                expect(entries.first).to_contain_text('尚未驗證 Chrome／Edge')
                expect(entries.first).to_contain_text('未觀察網路傳送')
                assert 'receiver.example.test/same.txt' not in entries.all_text_contents()[0]
                output = ROOT/'evidence/file-handoff-prototype-ui-20261027.png'
                page.screenshot(path=str(output), full_page=True)
                result['ui'] = {'passed': True, 'screenshot': str(output.relative_to(ROOT)),
                                'rows': 2, 'browser': browser.version}
            finally:
                browser.close()
        result['build'] = json.loads((native.directory/'build.json').read_text(encoding='utf-8'))
        result['source_hashes'] = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
            'native/file_handoff.h', 'native/file_handoff.cpp', 'native/tests/file_handoff_fixture.cpp',
            'guarddesk/file_handoff.py', 'guarddesk/static/audit_ui.js', 'guarddesk/audit_sort.py',
            'guarddesk/file_exclusions.py', 'tests/test_file_handoff.py', 'tests/test_file_handoff_center.py')}
        output = ROOT/'evidence/file-handoff-prototype-smoke-20261027.json'
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False))
    finally:
        if agent:
            agent.close_collectors()
        case.tearDown()
        native.tearDownClass()


if __name__ == '__main__':
    main()
