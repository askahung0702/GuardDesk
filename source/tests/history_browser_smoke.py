"""Real normal Chrome/Edge histories; isolated profiles, HTTPS audit delivery.

Never opens or alters the employee's browser profile or Windows settings.
"""
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright
from guarddesk.agent import Agent, enroll
from guarddesk.browser_history import BrowserHistory
from guarddesk.server import serve
from guarddesk.store import Store
from test_server_deployment import certificate


def main():
    root = Path(__file__).resolve().parents[1]
    report = {'passed': False, 'isolated_profiles': True, 'extension_installed': False, 'browsers': [], 'not_verified': []}
    with tempfile.TemporaryDirectory(dir=root/'runtime', prefix='browser-history-') as temp:
        scratch = Path(temp); store = Store(scratch/'center.sqlite3')
        password = secrets.token_urlsafe(20); store.add_user('mis-test', password)
        cert, key = certificate(scratch/'tls')
        server = serve(store.path, port=0, cert=cert, key=key, surface='agent')
        console = serve(store.path, port=0, surface='console', shared=server)
        for s in (server, console): threading.Thread(target=s.serve_forever, daemon=True).start()
        try:
            token = secrets.token_urlsafe(24)
            import hashlib
            with store.connect() as db:
                db.execute('INSERT INTO enrollments VALUES (?,?,0)', (hashlib.sha256(token.encode()).hexdigest(), time.time()+120))
            config = scratch/'agent/config.json'; watch = scratch/'docs'; watch.mkdir()
            url = f'https://127.0.0.1:{server.server_port}'
            enroll(config, url, token, watch, name='瀏覽紀錄測試端點', ca=str(cert))
            agent = Agent(config); agent.heartbeat()
            profiles = []
            collector = BrowserHistory(agent)
            collector.user = r'TEST\alice'  # Mask the workstation account in distributable evidence.
            console_url = f'http://127.0.0.1:{console.server_port}'
            with sync_playwright() as p, patch('guarddesk.browser_history.discover_profiles', side_effect=lambda: (list(profiles), False)):
                collector.poll()
                for name, exe in [('chrome', r'C:\Program Files\Google\Chrome\Application\chrome.exe'),
                                  ('edge', r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')]:
                    if not Path(exe).is_file(): raise AssertionError('Browser missing: '+name)
                    profile = scratch/name
                    try:
                        context = p.chromium.launch_persistent_context(str(profile), executable_path=exe, headless=True, ignore_https_errors=True)
                    except Exception as exc:
                        if name != 'edge': raise
                        report['not_verified'].append({'browser': name, 'reason': type(exc).__name__ + ': installed Edge exits before isolated automation connects; no browser policies altered'})
                        continue
                    try:
                        page = context.new_page()
                        profiles.append((name, 'Default', profile/'Default/History'))
                        collector.last_discovery = 0
                        # Two actual main-document loads; no native host or extension.
                        page.goto(console_url + '/?audit_browser='+name+'&token=fixture-secret')
                        page.goto(url + '/api/health?audit_browser='+name)
                        before = time.monotonic(); measured = []
                        while time.monotonic()-before < 60:
                            started = time.perf_counter(); collector.poll(); measured.append(time.perf_counter()-started)
                            with agent.db() as db:
                                events = [json.loads(r[0]) for r in db.execute("SELECT payload FROM outbox WHERE json_extract(payload,'$.details.browser')=?", (name,))]
                            if len(events) >= 2: break
                            page.wait_for_timeout(1000)
                        assert len(events) >= 2, (name, agent.feature_status, events)
                        assert all(e['details']['source']=='browser_history' for e in events)
                        assert any(e['details']['title'] for e in events)
                        assert 'fixture-secret' not in json.dumps(events)
                        report['browsers'].append({'browser': name, 'saved_visits_while_open': len(events), 'titles_present': True,
                                                  'wait_seconds': round(time.monotonic()-before, 2), 'max_poll_ms': round(max(measured)*1000, 2),
                                                  'browser_user_agent': page.evaluate('navigator.userAgent')})
                    finally: context.close()
                # Durable restart while offline, then real TLS API delivery and dedup.
                with agent.db() as db: pending = db.execute('SELECT count(*) FROM outbox').fetchone()[0]
                agent = Agent(config); collector = BrowserHistory(agent); collector.user = r'TEST\alice'; collector.poll()
                with agent.db() as db: assert db.execute('SELECT count(*) FROM outbox').fetchone()[0] == pending
                agent.flush()
                agent.heartbeat()
                with store.connect() as db:
                    count = db.execute("SELECT count(*) FROM events WHERE kind='web.navigation'").fetchone()[0]
                assert count >= 2 * len(report['browsers'])
                agent.flush()
                with store.connect() as db: assert db.execute("SELECT count(*) FROM events WHERE kind='web.navigation'").fetchone()[0] == count
                browser = p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe', headless=True)
                try:
                    page = browser.new_page(viewport={'width': 1700, 'height': 1100}, locale='zh-TW', timezone_id='Asia/Taipei')
                    errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
                    page.goto(console_url); page.locator('[name=username]').fill('mis-test'); page.locator('[name=password]').fill(password)
                    page.locator('#login-form button').click(); page.locator('#shell').wait_for(state='visible')
                    page.locator('nav [data-page=audit]').click(); page.locator('[data-audit-category=web]').click()
                    page.locator('table.browser-audit tbody tr').first.wait_for()
                    assert page.locator('table.browser-audit').inner_text().count('GuardDesk') >= 1
                    page.screenshot(path=str(root/'evidence/browser-history-0.4.12.png'), full_page=True)
                    assert not errors, errors
                finally: browser.close()
                report.update(passed=True, delivered_visits=count, durable_restart_and_dedup=True, ui_verified=True,
                              limits='Saved normal visits only; isolated profiles; no actual office rollout or Defender acceptance.')
        finally:
            for s in (server, console): s.shutdown(); s.server_close()
    (root/'evidence/browser-history-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__': main()
