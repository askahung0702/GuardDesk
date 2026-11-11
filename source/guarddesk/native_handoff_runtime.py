"""Agent-owned, bounded lifecycle for a future deployable native source.

No production browser source is available yet: the default reports the missing
adapter and starts no listener, helper, hook or thread. A source factory is an
internal code dependency, never a config/policy/URL/executable supplied remotely.
Its run(stop, inbox) must use authenticated sessions (NativeAttachmentSession),
cancelable bounded IPC and return on stop. It may not perform DB or HTTP work.
Only a separately validated source can satisfy the browser integration gate.
"""
import copy
import sqlite3
import threading
import time

from .native_connector import ConnectorInbox


class NativeHandoffRuntime:
    def __init__(self, agent, *, source_factory=None):
        self.agent = agent
        self._factory = source_factory
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._producer = None
        self._inbox = ConnectorInbox()
        self._queue = None
        self._closed = False
        self._enabled = False
        self._retry_at = 0
        self._backoff = 1
        self._report = {'status': 'native_adapter_missing', 'source_available': False,
                        'browser_connected': False, 'observed_events': 0}

    def _set(self, **values):
        with self._lock:
            self._report.update(values)

    def snapshot(self):
        with self._lock:
            result = copy.deepcopy(self._report)
        result['checked_at'] = time.time()
        result['coverage'] = 'attachment_page_origin_not_network_completion'
        result['provider_deployment_verified'] = False
        return result

    def step(self, policy):
        """Nonblocking supervisor, called by the existing Agent lifecycle.

        Queue/DB/source creation and cleanup stay on workers. A disabled/missing
        source has no worker. A stuck generation cannot spawn more generations.
        """
        from .decommission import saved
        enabled = (policy['body']['browser_audit'] and policy['body']['file_audit']['enabled']
                   and (self._factory is None or not saved(self.agent)))
        self._enabled = enabled
        if self._closed:
            return self.snapshot()
        running = self._thread is not None and self._thread.is_alive()
        if not enabled:
            self._stop.set()
            self._set(status='native_stopping' if running else 'disabled', browser_connected=False)
        elif self._factory is None:
            self._set(status='native_adapter_missing', source_available=False, browser_connected=False)
        elif self._stop.is_set() and running:
            self._set(status='native_stopping', browser_connected=False)
        elif not running and time.monotonic() >= self._retry_at:
            self._stop = threading.Event()
            self._set(status='native_source_starting', source_available=True, browser_connected=False)
            self._thread = threading.Thread(target=self._run, args=(self._stop,),
                                            name='GuardDesk native handoff drain', daemon=True)
            self._thread.start()
        return self.snapshot()

    def _run(self, stop):
        from .file_handoff import HandoffQueue
        failure = threading.Event()
        source = None
        producer = None
        failed = False
        try:
            if self._queue is None:
                self._queue = HandoffQueue(self.agent, verified_connector=True)
            source = self._factory()

            def produce():
                try:
                    source.run(stop, self._inbox)
                except Exception:
                    # Exception text may contain a source path/token; retain a
                    # fixed stage only. A source may keep separate safe codes.
                    failure.set()
                finally:
                    if not stop.is_set():
                        failure.set()

            producer = threading.Thread(target=produce, name='GuardDesk native handoff IPC', daemon=True)
            self._producer = producer
            producer.start()
            self._set(status='awaiting_native_event')
            queue_retry = 0
            while not stop.is_set() and not failure.is_set():
                if time.monotonic() >= queue_retry:
                    try:
                        self._drain()
                    except (OSError, ValueError, sqlite3.Error):
                        # Failed transactions retain the queue buffer. Avoid a
                        # busy loop; source has its own bounded inbox/loss count.
                        self._set(status='native_queue_retry', error_code='queue_transaction_failed')
                        queue_retry = time.monotonic() + 5
                stop.wait(.2)
            failed = failure.is_set()
        except Exception:
            failed = True
            self._set(error_code='source_start_failed')
        finally:
            stop.set()
            # No arbitrary close callback on the Agent thread. Keep ownership
            # of this generation until its IPC worker actually returns.
            while producer is not None and producer.is_alive():
                self._set(status='native_stopping', browser_connected=False)
                producer.join(.1)
            failed = failed or failure.is_set()
            try:
                if self._queue is not None:
                    self._drain()
                    # The shared queue survives a failed generation. Each
                    # flush is bounded to 64; at most 4 cover its 256 buffer.
                    for _ in range(3):
                        if not self._queue.buffer:
                            break
                        self._queue.flush()
            except (OSError, ValueError, sqlite3.Error):
                self._set(error_code='queue_transaction_failed')
            self._producer = None
            self._retry_at = time.monotonic() + self._backoff
            self._backoff = min(60, self._backoff * 2) if failed else 1
            self._set(status='native_source_retry' if failed else 'stopped' if self._closed else 'disabled',
                      browser_connected=False)

    def _drain(self):
        stats = self._inbox.drain(self._queue)
        if stats['received']:
            with self._lock:
                total = self._report['observed_events'] + stats['received']
            self._set(observed_events=total, last_event_at=time.time())
            self._backoff = 1
        report = self._queue.flush()
        values = {'pending': report.get('pending', 0), 'unreported_loss': report.get('unreported_loss', 0)}
        with self._lock:
            observed = self._report['observed_events']
        if observed and not self._stop.is_set():
            values.update(status='native_event_observed', error_code=None)
        self._set(**values)

    def close(self, timeout=1):
        self._closed = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(max(0, min(2, timeout)))
        running = self._thread is not None and self._thread.is_alive()
        self._set(status='native_stopping' if running else 'stopped', browser_connected=False)
        return not running
