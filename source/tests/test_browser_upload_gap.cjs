// Actual browser listeners with owned storage/native stand-ins; no network.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const sourcePath = path.join(__dirname, '../browser-extension/background.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const ignored = () => ({ type: 'upload_gap', reason: 'request_body_unavailable', event_id: 'browser-ignored' });
const upload = () => ({ type: 'web_upload', reason: 'request_body_unavailable', event_id: 'browser-real' });
function fixture(text = source, options = {}) {
  let listener, scheduled = 0;
  const records = [], pending = [], calls = [], storageReads = [];
  const state = { host_status: { web_upload_audit: true }, active_uploads: {}, gap_at: 0,
                  queue: structuredClone(options.queue || []), queue_overflow: 0 };
  const context = {
    currentPolicy: { web_upload_audit: true, memory_upload_v1: true },
    selections: new Map(), selectionReady: Promise.resolve(), bodyRequests: new Map(), bodyIntents: [],
    activeIds: new Set(), MAX_ACTIVE: 128, capacityNoticePending: false, filter: {}, flushing: false, policyAt: 123,
    chrome: {
      webRequest: { onBeforeRequest: { addListener(fn) { listener = fn; } } },
      storage: { local: {
        get: async defaults => { storageReads.push(defaults); return structuredClone(state); },
        set: async update => Object.assign(state, structuredClone(update)),
      } },
      action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    },
    policy: async () => ({ browser_audit: true, web_upload_audit: true }),
    native: async item => { calls.push(structuredClone(item)); return options.native ? options.native(item, state) : { ok: true, recorded: true }; },
    scheduleFlush: () => { scheduled++; },
    serialized: fn => { const result = Promise.resolve().then(fn); pending.push(result); return result; },
    event: value => value, safeUrl: value => value,
    persist: async (events, update) => { records.push(...structuredClone(events)); Object.assign(state, structuredClone(update || {})); },
    crypto: { randomUUID: () => 'owned-upload' }, URL, Date, Promise, ArrayBuffer, console, setTimeout,
  };
  const start = text.indexOf('function uploadMessage('), end = text.indexOf('function finishUpload(', start);
  assert(start >= 0 && end > start);
  vm.runInNewContext(text.slice(start, end), context, { filename: sourcePath + ':listener' });
  const flushStart = text.indexOf('async function flush()');
  const oldNav = text.indexOf('function navigate(', flushStart);
  const flushEnd = oldNav >= 0 ? oldNav : text.indexOf('// General browsing', flushStart);
  assert(flushStart >= 0 && flushEnd > flushStart);
  vm.runInNewContext(text.slice(flushStart, flushEnd), context, { filename: sourcePath + ':flush' });
  return { state, context, calls, records, storageReads, scheduled: () => scheduled,
    async request(body, selection = false) {
      if (selection) context.selections.set('1:0', { documentId: 'owned-doc', at: Date.now(), files: [{ name: 'report.pdf' }] });
      listener({ method: 'POST', url: 'https://owned.invalid/collect', tabId: 1, frameId: 0,
                 documentId: 'owned-doc', requestId: 'owned-request', timeStamp: Date.now(),
                 initiator: 'https://owned.invalid', requestBody: body });
      await Promise.all(pending);
    },
    async flush() { await context.flush(); },
  };
}
(async () => {
  const cases = [];
  async function check(name, fn) { await fn(); cases.push(name); }
  await check('unqualified_body_error_creates_no_event_or_storage_read', async () => {
    const f = fixture(); await f.request({ error: 'owned-unavailable' });
    assert.equal(f.records.length, 0); assert.equal(f.storageReads.length, 0); assert.equal(f.context.activeIds.size, 0);
  });
  await check('ordinary_request_remains_ignored', async () => {
    const f = fixture(); await f.request({}); assert.equal(f.records.length, 0);
  });
  await check('known_file_request_with_body_error_remains_upload', async () => {
    const f = fixture(); await f.request({ error: 'owned-unavailable', raw: [{ file: 'D:\\Owned\\report.pdf' }] });
    assert.equal(f.records[0].type, 'web_upload'); assert.equal(f.records[0].phase, 'started');
  });
  await check('file_context_unresolved_metadata_gap_remains', async () => {
    const f = fixture(); await f.request({ error: 'owned-unavailable' }, true);
    assert.equal(f.records[0].type, 'upload_gap'); assert.equal(f.records[0].reason, 'body_metadata_unresolved');
  });
  await check('pending_exact_reason_only_is_discarded_before_native', async () => {
    const other = { type: 'upload_gap', reason: 'request_capacity', event_id: 'browser-capacity' };
    const f = fixture(source, { queue: [ignored(), upload(), other] }); await f.flush();
    assert.deepEqual(f.calls.map(v => v.event_id), ['browser-real', 'browser-capacity']); assert.equal(f.state.queue.length, 0);
  });
  await check('policy_disabled_reply_preserves_other_pending_events', async () => {
    const f = fixture(source, { queue: [ignored(), upload()], native: () => ({ ok: true, recorded: false }) }); await f.flush();
    assert.equal(f.state.queue.length, 1); assert.equal(f.state.queue[0].event_id, 'browser-real'); assert.equal(f.context.policyAt, 0);
  });
  await check('concurrent_new_event_survives_acknowledgement', async () => {
    const f = fixture(source, { queue: [ignored(), upload()], native: (item, state) => {
      state.queue.push({ type: 'web_upload', event_id: 'browser-new' }); return { ok: true, recorded: true };
    } }); await f.flush();
    assert.deepEqual(f.state.queue.map(v => v.event_id), ['browser-new']); assert.equal(f.scheduled(), 1);
  });
  await check('discard_scan_keeps_existing_fifty_item_bound', async () => {
    const queue = Array.from({ length: 55 }, (_, i) => ({ ...ignored(), event_id: 'browser-ignore-' + i })); queue.push(upload());
    const f = fixture(source, { queue }); await f.flush(); assert.equal(f.calls.length, 0); assert.equal(f.state.queue.length, 6);
    await f.flush(); assert.equal(f.calls.length, 1); assert.equal(f.state.queue.length, 0);
  });
  const legacyIndex = process.argv.indexOf('--legacy-source');
  if (legacyIndex >= 0) {
    const replyIndex = process.argv.indexOf('--discard-reply'); assert(replyIndex >= 0);
    const legacy = fs.readFileSync(process.argv[legacyIndex + 1], 'utf8');
    const reply = JSON.parse(fs.readFileSync(process.argv[replyIndex + 1], 'utf8'));
    await check('actual_old_extension_accepts_retired_gap_and_browsing_ack_without_blocking_upload', async () => {
      const browsing = ['navigation', 'page_title'].map(type => ({ type, event_id: 'browser-old-' + type }));
      const f = fixture(legacy, { queue: [ignored(), ...browsing, upload()], native: item => item.type !== 'web_upload' ? reply : { ok: true, recorded: true } });
      await f.flush(); assert.equal(f.calls.length, 4); assert.equal(f.state.queue.length, 0);
    });
  }
  console.log(JSON.stringify({ passed: true, cases, actual_production_listener_and_flush: true,
                               real_browser_or_network: false, center_started: false }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
