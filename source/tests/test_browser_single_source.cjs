// Execute the full production service worker with owned Chrome API stand-ins.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'browser-extension/background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'browser-extension/manifest.json'), 'utf8'));
const nav = (type = 'navigation', i = 0) => ({ type, event_id: 'browser-nav-' + type + i, url: 'https://owned.invalid/page' });
const upload = () => ({ type: 'web_upload', event_id: 'browser-upload' });
function fixture(queue = [], enabled = true) {
  const events = new Map(), nativeCalls = [], reads = [], proxyWrites = [];
  const local = { queue: structuredClone(queue), queue_overflow: 0, active_uploads: {}, host_status: {} };
  const event = name => ({ addListener(fn) { if (!events.has(name)) events.set(name, []); events.get(name).push(fn); } });
  const messaging = event('native.message');
  const storage = state => ({
    get: async defaults => { reads.push(Object.keys(defaults)); return structuredClone({ ...defaults, ...state }); },
    set: async update => Object.assign(state, structuredClone(update)),
    remove: async key => { delete state[key]; },
  });
  let nextId = 0;
  const context = vm.createContext({
    navigator: { userAgent: 'Owned Chrome' }, crypto: { randomUUID: () => 'owned-' + nextId++ },
    URL, Date, Promise, ArrayBuffer, console,
    setTimeout: () => nextId++, clearTimeout: () => {},
    chrome: {
      runtime: { id: 'owned-extension', getManifest: () => manifest,
        onMessage: event('runtime.message'), onInstalled: event('runtime.installed'), onStartup: event('runtime.startup'),
        connectNative: () => ({ onMessage: messaging, onDisconnect: event('native.disconnect'), postMessage(item) {
          nativeCalls.push(structuredClone(item));
          const reply = item.type === 'status' ? { browser_audit: enabled, web_upload_audit: enabled,
            proxy_required: false, proxy_policy_state: 'not_required' } : { recorded: true };
          queueMicrotask(() => { for (const fn of events.get('native.message')) fn({ ok: true, ...reply, request_id: item.request_id }); });
        } }),
      },
      storage: { local: storage(local), session: storage({}) },
      alarms: { create: () => {}, onAlarm: event('alarm') },
      action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
      proxy: { settings: { get: async () => ({ levelOfControl: 'controlled_by_other_extensions', value: { mode: 'direct' } }),
        set: async value => proxyWrites.push(value), clear: async () => proxyWrites.push('clear') } },
      webNavigation: { onCommitted: event('navigation.committed'), onHistoryStateUpdated: event('navigation.history'), onCompleted: event('navigation.completed') },
      tabs: { get: async () => ({ url: 'https://owned.invalid/page', title: 'Owned page' }) },
      webRequest: { onBeforeRequest: event('request.before'), onCompleted: event('request.completed'),
        onErrorOccurred: event('request.error'), onBeforeRedirect: event('request.redirect') },
    },
  });
  vm.runInContext(source, context, { filename: 'actual-background.js' });
  return { events, local, nativeCalls, reads, proxyWrites,
    async settle() { await vm.runInContext('Promise.all([hydration,selectionReady,serial])', context); },
    async flush() { await vm.runInContext('flush()', context); },
    async navigate() {
      for (const name of ['navigation.committed', 'navigation.history', 'navigation.completed']) {
        for (const fn of events.get(name) || []) fn({ frameId: 0, url: 'https://owned.invalid/page', tabId: 1, timeStamp: Date.now() });
      }
      await vm.runInContext('serial', context);
    },
  };
}
(async () => {
  const cases = [];
  async function check(name, fn) { await fn(); cases.push(name); }
  await check('removed_navigation_permission_with_upload_permissions_preserved', async () => {
    assert(!manifest.permissions.includes('webNavigation'));
    for (const permission of ['nativeMessaging', 'webRequest', 'storage', 'proxy']) assert(manifest.permissions.includes(permission));
  });
  await check('full_worker_has_no_browsing_producers_and_keeps_upload_listeners', async () => {
    const f = fixture(); await f.settle();
    assert.equal([...f.events.keys()].filter(key => key.startsWith('navigation.')).length, 0);
    for (const key of ['request.before', 'request.completed', 'request.error', 'request.redirect']) assert.equal(f.events.get(key).length, 1);
    const reads = f.reads.length; await f.navigate();
    assert.equal(f.reads.length, reads); assert.equal(f.local.queue.length, 0);
    assert.equal(f.nativeCalls.length, 0); assert.equal(f.proxyWrites.length, 0);
  });
  await check('pending_old_navigation_title_and_ignored_gap_never_forwarded', async () => {
    const f = fixture([nav(), nav('page_title'), { type: 'upload_gap', reason: 'request_body_unavailable', event_id: 'browser-gap' }, upload()]);
    await f.flush(); assert.deepEqual(f.nativeCalls.map(v => v.type), ['status', 'web_upload']);
    assert.equal(f.local.queue.length, 0); assert.equal(f.proxyWrites.length, 0);
  });
  await check('pending_scan_remains_bounded_and_does_not_drop_upload', async () => {
    const f = fixture([...Array.from({ length: 55 }, (_, i) => nav('navigation', i)), upload()]);
    await f.flush(); assert.equal(f.local.queue.length, 6);
    assert.deepEqual(f.nativeCalls.map(v => v.type), ['status']);
    await f.flush(); assert.equal(f.local.queue.length, 0);
    assert.deepEqual(f.nativeCalls.map(v => v.type), ['status', 'web_upload']);
  });
  await check('disabled_policy_retains_pending_queue_without_proxy_changes', async () => {
    const items = [nav(), upload()], f = fixture(items, false); await f.flush();
    assert.deepEqual(f.local.queue, items); assert.deepEqual(f.nativeCalls.map(v => v.type), ['status']);
    assert.equal(f.proxyWrites.length, 0);
  });
  console.log(JSON.stringify({ passed: true, cases, full_production_worker: true,
    real_browser_or_network: false, center_started: false }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
