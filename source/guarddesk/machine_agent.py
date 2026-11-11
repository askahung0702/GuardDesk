"""Machine identity stays protected; bounded user-session RPC is not a shell."""
import copy
import json
import math
import os
import threading
import time
from . import __version__

PIPE = r'\\.\pipe\GuardDesk-MachineAgent-v1'
MAX_MESSAGE = 4 * 1024 * 1024
MAX_SESSIONS = 8
USER_PATHS = frozenset(('/api/agent/heartbeat', '/api/agent/events',
    '/api/agent/custom-settings', '/api/agent/custom-status',
    '/api/agent/uninstall/poll','/api/agent/uninstall/status',
    '/api/agent/remote/poll', '/api/agent/remote/update'))


def cached_machine_policy(agent):
    from .policy import decode_agent_policy
    with agent.db() as db:
        rows=dict(db.execute("SELECT key,value FROM state WHERE key IN ('extended_policy','extended_audit_options','extended_file_access_options','extended_target_controls')"))
    if 'extended_policy' not in rows:return None
    packet={'version':0,'body':json.loads(rows['extended_policy'])}
    for name,field in [('extended_audit_options','audit_options'),('extended_file_access_options','file_access_options'),('extended_target_controls','target_controls')]:
        if name in rows:packet[field]=json.loads(rows[name])
    decode_agent_policy(packet)
    return packet


class Router:
    def __init__(self, agent, sessions, online_call=None, admin_launcher=None,native_launcher=None):
        self.agent = agent
        self.sessions = sessions
        self.online_call = online_call or agent.call
        self._remote_call = online_call or (lambda path, body: agent.call(path, body, timeout=3))
        self.remote_epochs = {}  # at most MAX_SESSIONS WTS slots
        self.remote_retired = {}  # stopped center IDs cannot be re-granted by a racing poll
        self.remote_quarantine_until = 0
        self.remote_inflight = {"frame": 0, "control": 0, "poll": 0}
        self.remote_stats = {"calls": 0, "busy": 0, "stale": 0, "io_seconds": 0.0}
        self.lock = threading.RLock()
        self.remote_owner = {}  # bounded by the center's four active requests
        self.remote_requests = {}
        self.admin_launcher = admin_launcher
        self.native_launcher = native_launcher
        self.native_stops=set()
        self.admin_stops = set()
        self.remote_stop_notifications = set()
        self.inventory = {}
        self.ready = {}
        self.removal = None
        import secrets
        self.generation = secrets.token_hex(16)

    def dispatch(self, request, peer=None):
        if not isinstance(request, dict) or set(request) != {'path', 'body'}:
            raise ValueError('Invalid machine Agent request')
        path, body = request['path'], request['body']
        from .remote_trial import enabled
        if enabled() and path in ('/local/bootstrap','/api/agent/events',
                '/api/agent/custom-settings','/api/agent/custom-status'):
            raise PermissionError('Collector routes unavailable in remote-only trial')
        if path == '/local/status' and body == {}:
            from pathlib import Path
            import hashlib
            ca=Path(self.agent.config['ca']).read_bytes() if self.agent.config.get('ca') else b''
            return {'format': 1, 'device_id': self.agent.config['device_id'],
                    'server': self.agent.config['server'], 'ca_sha256':hashlib.sha256(ca).hexdigest(),
                    'version': __version__, 'scope': 'machine',
                    'install_profile':self.agent.config.get('install_profile','standard')}
        if not peer or (path not in USER_PATHS and path not in ('/local/bootstrap','/local/remote-bootstrap')) or not isinstance(body, dict):
            raise PermissionError('Operation not available to user sessions')
        # peer is derived from Windows, never from the JSON request.
        state = self.sessions().get(peer['session'])
        if (not state or state.get('query_failed') or ('time' in state and time.time()-state['time']>15)
            or state.get('sid') != peer['sid'] or state.get('logon') != peer['logon']):
            raise PermissionError('Logon session no longer available')
        body = copy.deepcopy(body)
        if path == '/local/remote-bootstrap':
            if body != {}:raise ValueError('Invalid remote bootstrap')
            import os
            return {'device_id':self.agent.config['device_id'],'parent':os.getpid(),'generation':self.generation,
                    'session':peer['session'],'sid':peer['sid'],'logon':peer['logon'],
                    'enabled':self.agent.config.get('remote_enabled',True) is not False,
                    'admin_remote_capable':self.admin_launcher is not None or self.native_launcher is not None,
                    'native_remote_capable':self.native_launcher is not None}
        if path == '/local/bootstrap':
            if body != {}: raise ValueError('Invalid bootstrap')
            if hasattr(self.agent,'machine_session_policy') and self.agent.machine_session_policy is None:
                raise OSError('Machine policy is not ready; retain existing user Agent')
            from pathlib import Path
            settings = {k: self.agent.config[k] for k in ('server', 'device_id', 'update_key',
                'browser_deployment', 'browser_deployment_authorization') if k in self.agent.config}
            ca = Path(self.agent.config['ca']).read_bytes() if self.agent.config.get('ca') else b''
            if len(ca) > 65536 or b'PRIVATE KEY' in ca: raise ValueError('Invalid public CA')
            policy = getattr(self.agent, 'machine_session_policy', None) or self.agent.cached_policy()
            import os
            return {'config': settings, 'ca_pem': ca.decode('ascii'), 'policy': policy, 'parent':os.getpid(), 'generation':self.generation,
                    'session': peer['session'], 'logon': peer['logon'], 'sid': peer['sid']}
        if path == '/api/agent/events':
            events = body.get('events')
            if set(body) != {'events'} or not isinstance(events, list) or len(events) > 100:
                raise ValueError('Invalid session event batch')
            for event in events:
                if not isinstance(event, dict) or not isinstance(event.get('details'), dict):
                    raise ValueError('Invalid session event')
                if not str(event.get('kind', '')).startswith(('file.', 'web.', 'application.', 'agent.', 'export.')):
                    raise PermissionError('Event kind unavailable to session')
                event['details'].update(reporting_account=state['account'],user_session_id=peer['session'],
                                        collection_scope='machine_user_session')
                # A directory notification has no actor. A reporting user's
                # SID must never turn an unknown filesystem actor into A/B.
                if event['kind'].startswith('web.') or event['kind']=='file.web_handoff':
                    event['details']['user']=state['account']
        elif path == '/api/agent/heartbeat':
            inventory = body.get('inventory')
            if not isinstance(inventory, dict): raise ValueError('Invalid session inventory')
            from . import remote_trial
            if remote_trial.enabled():
                inventory=remote_trial.inventory();body['inventory']=inventory
                diagnostics=remote_trial.native_diagnostics(launcher=self.native_launcher)
                if diagnostics is not None:inventory['collectors']['remote_only_trial']['native_remote']=diagnostics
                # A user's heartbeat must not overwrite/spoof the coordinator's
                # bounded startup diagnostics with its own request body.
                startup=remote_trial.session_diagnostics(self.agent.feature_status.get('machine_agent'))
                if startup is not None:inventory['collectors']['remote_only_trial']['session_startup']=startup
            else:
                from .machine_service import enabled as full_service
                if full_service():
                    # Protected coordinator owns this fixed scalar subtree;
                    # user helpers cannot supply remote diagnostics/authority.
                    diagnostics=remote_trial.native_diagnostics(launcher=self.native_launcher)
                    collectors=inventory.get('collectors')
                    if not isinstance(collectors,dict):collectors={};inventory['collectors']=collectors
                    collectors.pop('native_remote',None)
                    if diagnostics is not None:collectors['native_remote']=diagnostics
            inventory['agent_account'] = state['account']
            self.ready[(peer['session'],peer['logon'])] = (inventory.get('agent_version'),time.monotonic())
            inventory['machine_agent'] = {'version': __version__, 'scope': 'all_logged_on_users',
                'session_id': peer['session'], 'sessions': [
                    {'id': n, 'user': s['account'], 'active': s.get('active', False)}
                    for n, s in sorted(self.sessions().items())][:MAX_SESSIONS]}
            # The shared center inventory remains a computer record; preserve
            # the current caller's collector details and show all sessions.
        elif path == '/api/agent/custom-settings':
            if body != {'protocol': 2}: raise ValueError('Invalid custom settings request')
        elif path == '/api/agent/custom-status':
            if body.get('role') != 'main': raise PermissionError('Native status is protected')
        elif path.startswith('/api/agent/uninstall/'):
            return self.uninstall(path,body,peer,state)
        elif path.startswith('/api/agent/remote/'):
            return self.remote(path, body, peer, state)
        return self.online_call(path, body)

    def uninstall(self,path,body,peer,state):
        if body.get('role')!='main':raise PermissionError('Only own user cleanup is available')
        with self.lock:
            if path.endswith('/poll'):
                result=self.online_call(path,body)
                if result.get('job'):self.removal=result['job']
                return result
            job=self.removal
            if not job or body.get('job_id')!=job['id']:raise PermissionError('Removal job mismatch')
            if body.get('state')!='ready':return self.online_call(path,body)
            # A user can acknowledge only their own logon cleanup. Inactive
            # users' private queues remain unknown, never read/erased by SYSTEM.
            with self.agent.db() as db:
                row=db.execute("SELECT value FROM state WHERE key='machine_profiles'").fetchone()
                profiles=json.loads(row[0]) if row else {}
                profiles.setdefault(peer['sid'],{})['removal_ready']=job['id']
                db.execute("INSERT OR REPLACE INTO state VALUES ('machine_profiles',?)",(json.dumps(profiles),))
            from .remote_trial import enabled
            if enabled() or (profiles and all(v.get('removal_ready')==job['id'] for v in profiles.values())):
                return self.online_call(path,body)
            return self.online_call(path,{'role':'main','job_id':job['id'],'state':'failed',
                'error':'其他已登入過的帳號尚未完成私人佇列補送／清理；請讓該帳號登入後再確認，資料保留。'})

    def _remote_epoch(self, peer):
        slot = peer['session']
        identity = (peer['logon'], peer.get('sid'))
        previous = self.remote_epochs.get(slot)
        if previous is None or previous[:2] != identity:
            if previous is not None:
                self._invalidate_remote(slot,previous[0])
            if previous is None and len(self.remote_epochs) >= MAX_SESSIONS:
                raise PermissionError('Remote logon capacity exceeded')
            previous = (*identity, object())
            self.remote_epochs[slot] = previous
        return previous

    def _remote_live(self, peer, epoch):
        current = self.sessions().get(peer['session'], {})
        return (self.remote_epochs.get(peer['session']) == epoch
                and current.get('logon') == peer['logon']
                and current.get('sid') == peer.get('sid')
                and current.get('active') and not current.get('locked')
                and not current.get('query_failed')
                and ('time' not in current or time.time()-current['time'] <= 15))

    def _invalidate_remote(self, session, logon):
        # Called under lock BEFORE any network I/O: old poll cannot revive consent.
        previous = self.remote_epochs.get(session)
        if previous and previous[0] == logon:
            self.remote_epochs.pop(session, None)
        removed = [sid for sid, (owner, _) in self.remote_owner.items()
                   if owner == (session, logon)]
        for sid in removed:
            self.remote_owner.pop(sid, None)
            self.remote_requests.pop(sid, None)
            if self.admin_launcher:
                self.admin_launcher.revoke(sid)
                self.admin_stops.add(sid)
            if self.native_launcher:
                self.native_launcher.revoke(sid);self.native_stops.add(sid)
            if len(self.remote_stop_notifications)<64:self.remote_stop_notifications.add(sid)
            if len(self.remote_retired) < 64:
                self.remote_retired[sid] = time.monotonic()+720
            else:
                # Fixed memory even under repeated stop/request churn. Fail closed.
                self.remote_quarantine_until = time.monotonic()+720
        return removed

    def _stop_admin_children(self):
        with self.lock:
            pending = self.admin_stops
            self.admin_stops = set()
        for sid in pending:
            self.admin_launcher.stop(sid)
        with self.lock:
            native=self.native_stops;self.native_stops=set()
        for sid in native:self.native_launcher.stop(sid)

    def remote(self, path, body, peer, state):
        owner = (peer['session'], peer['logon'])
        poll = path.endswith('/poll')
        stopping = not poll and body.get('action') == 'stop'
        lane = 'poll' if poll else ('frame' if body.get('action') == 'frame' else 'control')
        notify_stops = []
        skip_poll = False
        with self.lock:
            now = time.monotonic()
            for expired, (expired_owner, deadline) in list(self.remote_owner.items()):
                if deadline <= now:self._invalidate_remote(*expired_owner)
            self.remote_retired = {k: v for k, v in self.remote_retired.items() if v > now}
            self.remote_owner = {k: v for k, v in self.remote_owner.items() if v[1] > now}
            epoch = self._remote_epoch(peer)
            sid = body.get('session_id')
            forced_result = None
            if poll:
                candidates = [s for s in self.sessions().values() if s.get('active') and not s.get('locked') and not s.get('query_failed')]
                if not self._remote_live(peer, epoch) or len(candidates) != 1:
                    notify_stops = self._invalidate_remote(*owner)
                    if not candidates or (state.get('active') and not state.get('locked')):
                        reason = 'multiple_interactive_sessions' if len(candidates) > 1 else 'locked_or_disconnected'
                        body = {**body, 'account': state['account'], 'ready': False, 'readiness': reason}
                        forced_result = {'session': None, 'desktop_protocol': 2, 'reason': reason}
                    else:
                        forced_result = {'session': None, 'desktop_protocol': 2}
                        skip_poll = True
                else:
                    body = {**body, 'account': state['account']}
                body.pop('native',None)
                if self.native_launcher:body['native']=dict(self.native_launcher.capabilities)
                body['protocol'] = 6 if self.admin_launcher or self.native_launcher else min(body.get('protocol', 3), 3)
                ticket = None
            else:
                ticket = self.remote_owner.get(sid)
                if not ticket or ticket[0] != owner:
                    raise PermissionError('Remote assistance belongs to another logon')
                if stopping or not self._remote_live(peer, epoch):
                    self._invalidate_remote(*owner)
                    body = {'session_id': sid, 'action': 'stop'}
                    stopping = True
                elif 'account' in body:
                    body = {**body, 'account': state['account']}
                request = self.remote_requests.get(sid, {})
                native=request.get('transport')=='native_webrtc'
                if native and not stopping:
                    if not self.native_launcher:raise PermissionError('Native remote cohort unavailable')
                    if body.get('action') not in ('approve','deny','stop','admin_watch'):raise PermissionError('Native capture belongs to protected cohort')
                    if body.get('action')=='approve':
                        from .remote_native_broker import binding
                        body['native_logon']=binding(peer)
                    if body.get('action')=='admin_watch' and not self.native_launcher.alive(sid):
                        self._invalidate_remote(*owner);body={'session_id':sid,'action':'stop'};stopping=True
                    elif body.get('action')=='admin_watch':
                        # This is the user's stop-indicator observer, NOT a
                        # second center authority heartbeat. NativeJob and its
                        # worker enforce the original short lease independently.
                        # Do not revoke a healthy native job because a redundant
                        # HTTP status request failed. Owner/logon/epoch and the
                        # actual job lifetime were checked under this lock.
                        observe=getattr(self.native_launcher,'observe',None)
                        lifecycle=observe(sid) if callable(observe) else None
                        return {'status':'active','commands':[],
                            'native_lifecycle':lifecycle or {'state':'starting'}}
                if 'admin_nonce' in body:
                    raise PermissionError('Management credentials unavailable to user helper')
                if request.get('admin_control') and not native and not stopping:
                    if not self.admin_launcher:
                        raise PermissionError('Management assistance not installed')
                    if body.get('action') not in ('approve', 'deny', 'stop', 'admin_watch'):
                        raise PermissionError('Management capture belongs to protected child')
                    if body.get('action') == 'admin_watch' and not self.admin_launcher.alive(sid):
                        self._invalidate_remote(*owner)
                        body = {'session_id': sid, 'action': 'stop'}
                        stopping = True
            # No queues/threads allocated here; excess work is rejected immediately.
            # Two media + four control + one poll leave an existing pipe slot for stop.
            limit = {'frame': 2, 'control': 4, 'poll': 1}[lane]
            if not stopping and self.remote_inflight[lane] >= limit:
                self.remote_stats['busy'] += 1
                raise TimeoutError('Remote broker lane busy; retry latest work only')
            if not stopping:
                self.remote_inflight[lane] += 1
            notify_stops = list(set(notify_stops) | self.remote_stop_notifications)
            self.remote_stop_notifications.clear()
            if stopping:notify_stops = [old for old in notify_stops if old!=sid]
        started = time.monotonic()
        approval_tick=self.native_launcher.tick() if self.native_launcher and body.get('action')=='approve' else None
        approval_filetime=time.time_ns()//100+116444736000000000
        try:
            self._stop_admin_children()
            for old_sid in notify_stops:
                try:
                    self._remote_call('/api/agent/remote/update', {'session_id': old_sid, 'action': 'stop'})
                except (OSError, ValueError, ConnectionError):
                    pass
            result = {} if skip_poll else self._remote_call(path, body)
        except (OSError, ValueError, ConnectionError):
            with self.lock:
                # A failed old request must never revoke a replacement generation.
                if self.remote_epochs.get(peer['session']) == epoch:
                    self._invalidate_remote(*owner)
            self._stop_admin_children()
            raise
        finally:
            with self.lock:
                if not stopping:
                    self.remote_inflight[lane] -= 1
                self.remote_stats['calls'] += 1
                self.remote_stats['io_seconds'] += time.monotonic()-started
        launch = None;native_launch=None
        with self.lock:
            if stopping:
                return {'status': 'closed', 'commands': []}
            if forced_result is not None:
                return forced_result
            if not self._remote_live(peer, epoch) or (not poll and self.remote_owner.get(sid) is not ticket):
                self.remote_stats['stale'] += 1
                raise PermissionError('Remote reply belongs to an expired generation')
            if poll:
                session = result.get('session')
                if session:
                    sid = session['id']
                    if sid in self.remote_retired or time.monotonic() < self.remote_quarantine_until:
                        return {'session': None, 'desktop_protocol': 2}
                    previous = self.remote_owner.get(sid)
                    if previous and previous[0] != owner:
                        return {'session': None, 'desktop_protocol': 2}
                    if len(self.remote_owner) >= 4 and sid not in self.remote_owner:
                        raise PermissionError('Remote owner capacity exceeded')
                    if previous is None:
                        self.remote_owner[sid] = (owner, time.monotonic() + 720)
                        if session.get('transport')=='native_webrtc' and self.native_launcher:
                            self.native_launcher.reserve(sid)
                        elif session.get('admin_control') and self.admin_launcher:
                            self.admin_launcher.reserve(sid)
                    self.remote_requests[sid] = dict(session)
            native_nonce=result.pop('native_nonce',None)
            nonce = result.pop('admin_nonce', None)
            if native_nonce:
                request=self.remote_requests.get(sid,{})
                if body.get('action')!='approve' or request.get('transport')!='native_webrtc' or not self.native_launcher or approval_tick is None:
                    self._invalidate_remote(*owner);raise PermissionError('Unexpected native approval')
                if result.get('session_lifetime')=='until_stopped':
                    # Replace the request-only 720s ticket only after authenticated
                    # approval. Logon/current/stop and short native leases still apply.
                    ticket=(owner,float('inf'));self.remote_owner[sid]=ticket
                native_launch=(request,{**result,'native_nonce':native_nonce,'approval_started_tick':approval_tick,'approval_filetime':approval_filetime})
                nonce=None  # The legacy SYSTEM child never runs alongside native.
            if nonce:
                request = self.remote_requests.get(sid, {})
                if body.get('action') != 'approve' or not request.get('admin_control') or not self.admin_launcher:
                    self._invalidate_remote(*owner)
                    raise PermissionError('Unexpected management approval')
                launch = (request, {**result, 'admin_nonce': nonce})
            if not poll:result.pop('session', None)
            if result.get('status') in ('closed', 'ended', 'denied', 'expired'):
                self._invalidate_remote(*owner)
        self._stop_admin_children()
        if native_launch:
            def current():
                with self.lock:return self._remote_live(peer,epoch) and self.remote_owner.get(sid) is ticket
            try:
                self.native_launcher.launch(native_launch[0],peer,state,native_launch[1],current=current)
                if not current():
                    self.native_launcher.stop(sid);raise PermissionError('Native approval expired during launch')
            except BaseException:
                self.end_session(*owner);raise
        if launch:
            try:
                self.admin_launcher.launch(launch[0], peer, state, launch[1])
                with self.lock:
                    valid = self._remote_live(peer, epoch) and self.remote_owner.get(sid) is ticket
                if not valid:
                    self.admin_launcher.stop(sid)
                    raise PermissionError('Management approval expired during launch')
            except BaseException:
                self.end_session(*owner)
                raise
        return result

    def end_session(self, session, logon):
        with self.lock:
            removed = self._invalidate_remote(session, logon)
            removed = list(set(removed) | self.remote_stop_notifications)
            self.remote_stop_notifications.clear()
        self._stop_admin_children()
        for sid in removed:
            try:
                self._remote_call('/api/agent/remote/update', {'session_id': sid, 'action': 'stop'})
            except (OSError, ValueError, ConnectionError):
                pass


class Supervisor:
    """One native companion, no account enrollment, capped retries/processes."""
    def __init__(self, agent, stop, platform=None):
        if platform is None:
            from .machine_agent_windows import Platform
            platform = Platform(agent)
        self.agent, self.stop, self.platform = agent, stop, platform
        from .remote_trial import enabled
        if not enabled() and not getattr(agent,'machine_session_policy',None):agent.machine_session_policy=cached_machine_policy(agent)
        self.states = {}; self.children = {}; self.retry = {}; self.next_scan = 0
        self.errors = 0; self.last_error = None; self.thread = None
        self.launch_blocked_antimalware = False
        self.fatal_error = None
        self.router = Router(agent, lambda: dict(self.states), admin_launcher=getattr(platform, 'admin_launcher', None),native_launcher=getattr(platform,'native_launcher',None))
        self.listener = None
        self.monitor = None; self.monitor_policy = None

    def snapshot(self):
        result={'scope': 'machine', 'version': __version__, 'sessions': len(self.states),
                'helpers': len(self.children), 'errors': self.errors, 'last_error': self.last_error,
                'handoff': getattr(self.platform,'handoff',None)}
        native=getattr(self.platform,'native_launcher',None)
        if native:result['remote_native']=native.snapshot()
        return result

    def local_process_diagnostics(self):
        """Bounded local health evidence from owned launch handles, never RPC auth.

        This is not added to snapshot()/heartbeats. PID observations can help
        correlate an alert but must never authorize or terminate a process.
        """
        rows=[]
        for session,child in list(self.children.copy().items())[:MAX_SESSIONS]:
            pid=getattr(child,'pid',None)
            observed=getattr(child,'launch_observed_at',None)
            if (type(session) is not int or not 0<=session<=0xffffffff or
                type(pid) is not int or not 0<pid<=0xffffffff or
                type(observed) not in (int,float) or not math.isfinite(observed) or observed<=0):
                continue
            rows.append({'role':'machine_session_helper','pid':pid,'session_id':session,
                         'launch_observed_at':observed})
        return {'parent_pid':os.getpid(),'parent_role':'machine_supervisor',
                'helpers':rows,'scope':'local_health_only','observations_not_liveness_proof':True,
                'launch_blocked_antimalware':getattr(self,'launch_blocked_antimalware',False)}

    def failure(self, operation, exc):
        self.errors += 1
        self.last_error = {'operation': operation, 'type': type(exc).__name__,
                           'winerror': getattr(exc, 'winerror', None), 'time': time.time()}

    def tick(self):
        if time.monotonic() < self.next_scan: return
        self.next_scan = time.monotonic() + 5
        self.sync_collectors()
        # A failed query is unknown, not a synthetic logout of every user.
        try:
            states = copy.deepcopy(self.platform.sessions())
            if len(states) > MAX_SESSIONS: raise OSError('Machine session capacity exceeded')
        except OSError as exc:
            self.states={sid:{**state,'query_failed':True} for sid,state in self.states.items()}
            self.failure('query_sessions', exc); return
        old = self.states; self.states = states
        for sid,previous in old.items():
            current=states.get(sid,{})
            if previous.get('active') and (not current.get('active') or current.get('locked')):
                self.router.end_session(sid,previous['logon'])
        with self.agent.db() as db:
            row=db.execute("SELECT value FROM state WHERE key='machine_profiles'").fetchone()
            profiles=json.loads(row[0]) if row else {}
            changed=False
            for state in states.values():
                if state['sid'] in profiles:continue
                if len(profiles)>=128:raise OSError('Machine user history capacity exceeded; MIS review required')
                profiles[state['sid']]={'removal_ready':None};changed=True
            if changed:db.execute("INSERT OR REPLACE INTO state VALUES ('machine_profiles',?)",(json.dumps(profiles),))
        for sid, child in list(self.children.items()):
            state = states.get(sid)
            if not state or state['logon'] != old[sid]['logon'] or state['sid'] != old[sid]['sid'] or not child.alive():
                self.router.end_session(sid, old[sid]['logon'])
                child.close(); self.children.pop(sid)
                self.router.ready.pop((sid,old[sid]['logon']),None)
                if state and state['logon']!=old[sid]['logon']:self.retry.pop(sid,None)
        self.retry = {sid: t for sid, t in self.retry.items() if sid in states}
        # Never automatically repeat a launch rejected by antimalware. This
        # latch is scoped to this supervisor lifetime; it does not alter AV,
        # kill existing children, or persist company configuration changes.
        if self.launch_blocked_antimalware:return
        if hasattr(self.platform,'can_launch') and not self.platform.can_launch():return
        for sid, state in sorted(states.items()):
            if sid in self.children or time.monotonic() < self.retry.get(sid, 0): continue
            self.retry[sid] = time.monotonic() + 30
            try: self.children[sid] = self.platform.launch(sid, state, self.agent)
            except (OSError, ValueError) as exc:
                self.failure('launch', exc)
                if type(getattr(exc,'winerror',None)) is int and exc.winerror in (225,226):
                    self.launch_blocked_antimalware=True
                    return

    def report_main_update(self):
        from .remote_trial import enabled
        if enabled():return
        # This user code is in the same protected native tree. Its version is
        # acknowledged only after a real session heartbeat, not merely a task
        # registration/native version. The existing updater still does switching.
        if not any(v==__version__ and time.monotonic()-stamp<90 for v,stamp in self.router.ready.values()):return
        reply=self.agent.call('/api/agent/updates/poll',{'role':'main','version':__version__,'machine_scope':True})
        if not reply.get('job'):return
        from .update_client import validate_job
        job,manifest=validate_job(reply['job'],self.agent.config['update_key'],self.agent.config['device_id'])
        if manifest['version']==__version__:
            self.agent.call('/api/agent/updates/status',{'job_id':job['id'],'role':'main',
                'state':'healthy','version':__version__,'error':''})

    def sync_collectors(self):
        from .remote_trial import enabled
        if enabled():return
        packet=getattr(self.agent,'machine_session_policy',None)
        if not packet:return
        from .custom_client import effective_body,build_number
        from .custom_settings import compatibility_modules
        from .policy import decode_agent_policy
        body=decode_agent_policy(packet)['body'];audit=body['file_audit']
        enabled=audit['enabled'] and 'directory_notifications' not in compatibility_modules(effective_body(self.agent),build_number())
        signature=json.dumps(audit,sort_keys=True) if enabled else None
        if self.monitor and signature!=self.monitor_policy:
            self.monitor.close();self.monitor=None;self.monitor_policy=None
        if enabled and self.monitor is None:
            from .windows_watch import DirectoryMonitor
            from pathlib import Path
            from types import SimpleNamespace
            adapter=SimpleNamespace(root=Path(self.agent.config.get('audit_watch',self.agent.config['watch'])),
                config=self.agent.config,queue=self.agent.queue,db=self.agent.db,audit_runtime=self.agent.audit_runtime)
            self.monitor=DirectoryMonitor(adapter,body)
            self.agent.feature_status['machine_directory_notifications']=self.monitor.start()
            self.monitor_policy=signature

    def start(self):
        self.listener = self.platform.listen(self.router)
        def work():
            try:
                while not self.stop.is_set():
                    try:self.tick()
                    except (OSError,ValueError) as exc:self.failure('session_cycle',exc)
                    self.agent.feature_status['machine_agent'] = self.snapshot()
                    self.stop.wait(1)
            except Exception as exc:
                # A dead WTS thread must not leave an apparently healthy native
                # worker sending heartbeats with no IPC listener indefinitely.
                self.failure('supervisor_thread',exc)
                self.fatal_error=dict(self.last_error)
                self.agent.feature_status['machine_agent']=self.snapshot()
                try:
                    from .update_client import save
                    save(self.agent.config_path.parent/'machine-startup-failure.json',self.fatal_error)
                except (OSError,ValueError,AttributeError,TypeError):pass
                self.stop.set()
            finally:
                if self.monitor:self.monitor.close();self.monitor=None
                for sid, child in list(self.children.items()):
                    self.router.end_session(sid, self.states[sid]['logon']); child.close()
                self.children.clear()
                self.listener.close()
        self.thread = threading.Thread(target=work, name='GuardDesk machine sessions', daemon=True)
        self.thread.start(); return self

    def close(self):
        self.stop.set()
        native=getattr(self.platform,'native_launcher',None)
        if native:native.close()
        if self.thread: self.thread.join(15)
        if self.thread and self.thread.is_alive():raise OSError('Machine session supervisor has not stopped')


def eligible(agent):
    import os, sys
    if os.name != 'nt' or not getattr(sys, 'frozen', False): return False
    from .update_native import folder
    did = agent.config['device_id']
    from pathlib import Path
    return (Path(sys.executable).resolve() == folder(38)/'USBControl/GuardDesk.exe'
            and agent.config_path == folder(35)/'USBControl'/did/'config.json')
