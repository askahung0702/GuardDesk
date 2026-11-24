// Owned UI handler regression. No center, browser, MSI execution or network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sourceIndex = process.argv.indexOf('--source');
const sourcePath = sourceIndex < 0 ? path.join(__dirname, '../guarddesk/static/software_ui.js') : process.argv[sourceIndex + 1];
const source = fs.readFileSync(sourcePath, 'utf8');
function fixture(options = {}) {
  const nodes = new Map(), notices = [], requests = [], timers = new Map();
  let nextTimer = 0, now = 100000, refreshes = 0;
  const button = () => nodes.get('button');
  const node = key => {
    if (!nodes.has(key)) nodes.set(key, { textContent: '', disabled: false, hidden: false, value: 0,
      setAttribute(name, value) { this[name] = value; }, removeAttribute(name) { delete this[name]; }, querySelector() { return node('button'); } });
    return nodes.get(key);
  };
  node('button');
  class Request {
    constructor() { this.upload = {}; this.headers = {}; requests.push(this); }
    open(method, url, async) { Object.assign(this, { method, url, async }); }
    setRequestHeader(name, value) { this.headers[name] = value; }
    send(file) { this.file = file; if (!options.pending) queueMicrotask(() => this.complete()); }
    complete() {
      this.upload.onprogress?.({ lengthComputable: true, loaded: this.file.size, total: this.file.size });
      this.upload.onload?.();
      if (options.network) { this.onerror(); return; }
      this.status = options.status ?? 400;
      this.responseText = options.raw ?? JSON.stringify(options.body ?? { error: 'MSI contains external uncompressed files' });
      this.onload();
    }
  }
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const context = vm.createContext({
    $: node, document: { querySelectorAll: () => [] }, XMLHttpRequest: Request,
    FormData: class { get(name) { return name === 'file' ? { name: 'owned.msi', size: options.size ?? 54 * 1024 ** 2 } : options.budget ?? '4'; } },
    fetch: async () => ({ ok: false, status: 400, json: async () => ({ error: 'MSI contains external uncompressed files' }) }),
    user: { csrf: 'owned-fixture-not-a-credential' }, toast: message => notices.push(message),
    refresh: async () => { ++refreshes; if (options.refreshError) throw Error('Owned refresh failed'); },
    heading: () => '', card: (title, description, body) => body, esc: escape,
    setInterval: callback => { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearInterval: id => timers.delete(id), Date: { now: () => now },
  });
  vm.runInContext(source + '\nbindSoftware();', context);
  return {
    nodes, notices, requests, timers, context, node,
    submit: () => node('#software-upload').onsubmit({ preventDefault() {}, target: { querySelector: button } }),
    busy: () => vm.runInContext('softwareBusy', context),
    page: () => context.softwarePage(),
    rerender() { nodes.delete('#software-feedback'); nodes.delete('#software-progress'); nodes.delete('button'); node('button'); context.bindSoftware(); },
    tick(seconds) { now += seconds * 1000; for (const callback of timers.values()) callback(); },
    refreshes: () => refreshes,
  };
}
const cases = [];
async function check(name, test) { await test(); cases.push(name); }
(async () => {
  await check('http400_has_persistent_failure_instead_of_uploading', async () => {
    const f = fixture(); await f.submit();
    assert.equal(f.busy(), false);
    assert.equal(f.node('button').disabled, false);
    assert.match(f.node('#software-feedback').textContent, /上傳失敗.*400/);
    assert.match(f.node('#software-feedback').textContent, /MSI contains external uncompressed files/);
    assert.equal(f.refreshes(), 0);
    assert.equal(f.timers.size, 0);
    assert.match(f.page(), /上傳失敗/);
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].url, '/api/software/import');
    assert.equal(f.requests[0].headers['X-CSRF-Token'], 'owned-fixture-not-a-credential');
    assert.equal(f.requests[0].headers['X-GuardDesk-Authorize'], 'install-msi-machine');
    assert.equal(f.requests[0].headers['X-Install-Bytes'], String(4 * 1024 ** 3));
  });
  await check('transfer_progress_is_distinct_from_validation_and_not_success', async () => {
    const f = fixture({ pending: true }); const done = f.submit();
    assert.equal(f.busy(), true);
    f.requests[0].upload.onprogress({ lengthComputable: true, loaded: 27, total: 54 });
    assert.match(f.node('#software-feedback').textContent, /50%/);
    assert.equal(f.node('#software-progress').value, 50);
    f.requests[0].upload.onload(); f.tick(65);
    assert.match(f.node('#software-feedback').textContent, /驗證中.*65 秒/);
    assert.doesNotMatch(f.node('#software-feedback').textContent, /已驗證並加入/);
    f.requests[0].complete(); await done;
    assert.equal(f.timers.size, 0);
  });
  await check('automatic_rerender_preserves_status_and_releases_current_button', async () => {
    const f = fixture({ pending: true }); const done = f.submit();
    f.requests[0].upload.onprogress({ lengthComputable: true, loaded: 1, total: 4 });
    assert.match(f.page(), /25%/); f.rerender();
    assert.match(f.page(), /25%/);
    f.requests[0].upload.onload();
    assert.match(f.node('#software-feedback').textContent, /等待管理中心驗證/);
    f.requests[0].complete(); await done;
    assert.equal(f.node('button').disabled, false);
    assert.match(f.page(), /上傳失敗/);
  });
  await check('double_click_has_one_request_and_no_automatic_retry', async () => {
    const f = fixture({ pending: true }); const first = f.submit(); await f.submit();
    assert.equal(f.requests.length, 1); f.requests[0].complete(); await first;
    assert.equal(f.requests.length, 1);
  });
  await check('success_requires_package_receipt_and_survives_refresh', async () => {
    const f = fixture({ status: 200, body: { package: { sha256: 'a'.repeat(64) } } });
    await f.submit(); assert.match(f.node('#software-feedback').textContent, /已驗證並加入軟體庫/);
    assert.equal(f.refreshes(), 1); assert.equal(f.busy(), false);
    assert.match(f.page(), /已驗證並加入軟體庫/); assert.equal(f.node('#software-progress').hidden, true);
  });
  await check('catalog_refresh_failure_does_not_turn_accepted_import_into_failure', async () => {
    const f = fixture({ status: 200, body: { package: { sha256: 'b'.repeat(64) } }, refreshError: true });
    await f.submit(); assert.match(f.node('#software-feedback').textContent, /已驗證並加入軟體庫.*清單尚未更新/);
    assert.equal(f.node('#software-feedback')['data-phase'], 'success');
  });
  await check('network_failure_is_unknown_outcome_and_stops_validation_timer', async () => {
    const f = fixture({ network: true }); await f.submit();
    assert.match(f.node('#software-feedback').textContent, /連線中斷.*尚未確認/);
    assert.equal(f.refreshes(), 0); assert.equal(f.timers.size, 0);
    assert.equal(f.requests.length, 1);
  });
  await check('malformed_or_non_JSON_response_has_persistent_status_without_HTML', async () => {
    const f = fixture({ status: 503, raw: '<html>Owned gateway error</html>' }); await f.submit();
    assert.match(f.node('#software-feedback').textContent, /上傳失敗.*503/);
    assert.doesNotMatch(f.node('#software-feedback').textContent, /<html>/);
  });
  await check('malformed_success_receipt_does_not_claim_import_success', async () => {
    const f = fixture({ status: 200, body: { ok: true } }); await f.submit();
    assert.match(f.node('#software-feedback').textContent, /回覆格式不完整.*尚未確認/);
    assert.equal(f.refreshes(), 0);
  });
  await check('late_progress_after_rejection_cannot_replace_failure', async () => {
    const f = fixture(); await f.submit(); const message = f.node('#software-feedback').textContent;
    f.requests[0].upload.onprogress({ lengthComputable: true, loaded: 1, total: 4 }); f.requests[0].upload.onload();
    assert.equal(f.node('#software-feedback').textContent, message); assert.equal(f.timers.size, 0);
  });
  await check('failed_reason_is_text_only_and_escaped_after_rerender', async () => {
    const f = fixture({ body: { error: '<img src=x onerror=owned>' } }); await f.submit();
    assert.match(f.node('#software-feedback').textContent, /<img/);
    assert.match(f.page(), /&lt;img/); assert.doesNotMatch(f.page(), /<img/);
  });
  await check('logout_during_request_does_not_show_prior_user_result', async () => {
    const f = fixture({ pending: true }); const done = f.submit();
    f.context.user = { csrf: 'different-owned-session' };
    f.requests[0].complete(); await done;
    assert.doesNotMatch(f.page(), /MSI contains external uncompressed files/);
    assert.equal(f.notices.length, 0); assert.equal(f.busy(), false);
  });
  await check('invalid_budget_fails_persistently_without_sending', async () => {
    const f = fixture({ budget: 'NaN' }); await f.submit();
    assert.match(f.node('#software-feedback').textContent, /安裝預算/);
    assert.equal(f.requests.length, 0); assert.equal(f.busy(), false);
  });
  console.log(JSON.stringify({ passed: true, cases, actual_source_handler: true, network: false, center_started: false, MSI_executed: false }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
