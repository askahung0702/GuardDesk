"""Disclosed per-user background runner, bounded logs, graceful local stop."""
import ctypes
import hashlib
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path


def client_root():
    if os.name != 'nt': raise OSError('簡易端點安裝只支援 Windows')
    return Path(os.environ['LOCALAPPDATA']) / 'GuardDeskPilotClient'


def identity(config):
    return 'Global\\GuardDesk-UserAgent-' + hashlib.sha256(str(Path(config).resolve()).casefold().encode()).hexdigest()[:24]


@contextmanager
def instance(config):
    from ctypes import wintypes as w
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateMutexW.argtypes = [w.LPVOID, w.BOOL, w.LPCWSTR]; api.CreateMutexW.restype = w.HANDLE
    api.CloseHandle.argtypes = [w.HANDLE]
    ctypes.set_last_error(0)
    handle = api.CreateMutexW(None, False, identity(config)); error = ctypes.get_last_error()
    if not handle: raise ctypes.WinError(error)
    try: yield error != 183
    finally: api.CloseHandle(handle)


def active(config):
    with instance(config) as acquired: return not acquired


def run(config, stop, *, managed_session=False, managed_remote=None):
    from .remote_trial import enabled
    if enabled():raise PermissionError('Desktop collector unavailable in remote-only trial')
    from .agent import Agent
    from . import __version__
    config = Path(config).resolve()
    if not managed_session:
        settings=json.loads(config.read_text(encoding='utf-8'))
        if isinstance(settings.get('device_id'),str) and len(settings['device_id'])==24:
            from .machine_agent_session import discover
            machine=discover()
            if machine:
                if (machine['device_id']!=settings['device_id'] or machine['server']!=settings.get('server')
                    or machine.get('status')=='supervisor_unavailable'):
                    raise OSError('全機 Agent 身分或狀態尚未確認，保留舊設定並交 MIS 檢查')
                # Explicit old launchers may survive an upgrade. They must not
                # start a second directory/remote collector beside the WTS helper.
                return
    with instance(config) as acquired:
        if not acquired: return
        root = config.parent
        log = RotatingFileHandler(root / 'agent-background.log', maxBytes=131072, backupCount=2, encoding='utf-8')
        logger = logging.getLogger(); logger.addHandler(log)
        request = root / 'stop-user-agent'
        request.unlink(missing_ok=True)
        ready = root / 'desktop-status.json'
        kernel = ctypes.WinDLL('kernel32'); kernel.GetConsoleWindow.restype = ctypes.c_void_p
        ready.write_text(json.dumps({'state': 'running', 'pid': os.getpid(), 'version': __version__,
                                   'started': time.time(), 'console_attached': bool(kernel.GetConsoleWindow())}))
        def monitor():
            while not stop.wait(.5):
                if request.exists(): stop.set()
        thread = threading.Thread(target=monitor, daemon=True); thread.start()
        try:
            agent=Agent(config)
            if managed_session and agent.config.get('legacy_cleanup'):
                # Diagnostic metadata only; no automatic registry replacement.
                from .machine_agent_session import cleanup_status
                pending=cleanup_status(agent.config['legacy_cleanup'])
                if pending:agent.feature_status['legacy_migration_cleanup']={'state':'pending_review','components':pending}
            if managed_remote is not None:
                if not managed_session or not agent.config.get('machine_session'):raise PermissionError('Managed remote requires machine session')
                agent._managed_remote=managed_remote
            from .mis_support import ensure_agent_launcher
            try:ensure_agent_launcher(config)
            except (OSError,ValueError):logger.warning('MIS launcher could not be prepared; Agent continues')
            agent._installed_desktop_browser_dispatch=True
            from .decommission import saved
            if not saved(agent):
                from .browser_host import ensure_user_host
                try:agent.feature_status['browser_native_host']=ensure_user_host(config)
                except (OSError,ValueError) as exc:
                    agent.feature_status['browser_native_host']={'status':'failed','error':str(exc)[:300]}
            if not agent.config.get('machine_session'):
                from .update_client import UserPoller
                UserPoller(agent,stop).start()
            agent.run(stop)
        except Exception:
            logger.exception('GuardDesk user agent stopped unexpectedly')
            raise
        finally:
            stop.set(); thread.join(2)
            ready.write_text(json.dumps({'state': 'stopped', 'pid': os.getpid(), 'version': __version__}))
            logger.removeHandler(log); log.close()


def stop_running(config, timeout=20):
    config = Path(config).resolve()
    if not active(config): return
    (config.parent / 'stop-user-agent').write_text('stop', encoding='ascii')
    deadline = time.monotonic() + timeout
    while active(config):
        if time.monotonic() > deadline: raise OSError('一般 Agent 尚未停止，請保留資料並由 MIS 檢查')
        time.sleep(.2)
