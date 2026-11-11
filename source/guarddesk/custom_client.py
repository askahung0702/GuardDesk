"""Bounded custom settings companion; legacy collection/update loops stay independent."""
import copy
import json
import os
import sqlite3
import sys
import threading
import time
from . import __version__
from .serialization import canonical,digest
from .custom_settings import DEFAULT,PROTOCOL,validate,compatibility_modules,due_schedules,schedule_expiry

def build_number():return sys.getwindowsversion().build if hasattr(sys,'getwindowsversion') else 0

def load_custom(agent):
    if hasattr(agent,'custom_packet'):return
    with agent.db() as db:row=db.execute("SELECT value FROM state WHERE key='custom_packet_v1'").fetchone()
    agent.custom_packet=check_packet(agent,json.loads(row[0])) if row else None

def effective_body(agent):
    packet=getattr(agent,'custom_packet',None)
    return packet['body'] if packet else copy.deepcopy(DEFAULT)

def check_packet(agent,packet):
    if (not isinstance(packet,dict) or type(packet.get('protocol')) is not int or packet.get('protocol') not in (PROTOCOL,2) or packet.get('device_id')!=agent.config['device_id'] or type(packet.get('busy')) is not bool):raise ValueError('Custom packet identity/protocol mismatch')
    if packet['protocol']==2 and (packet.get('schema')!='named-items-v1' or type(packet.get('generation')) is not int):raise ValueError('Custom library schema mismatch')
    validate(packet.get('body'))
    if 'documents' in packet:
        from .document_settings import check
        check(packet['documents'])
    if packet.get('fingerprint')!=digest(canonical(packet['body'])):raise ValueError('Custom settings fingerprint mismatch')
    return packet

class ScheduleEngine:
    def __init__(self,agent,actions,fetch,stop,clock=time.time,monotonic=time.monotonic):
        self.agent=agent;self.actions=actions;self.fetch=fetch;self.stop=stop;self.clock=clock;self.monotonic=monotonic;self.pending=None
        self.report={'state':'idle'}
        self.notice_threads=[]
        with agent.db() as db:db.execute('CREATE TABLE IF NOT EXISTS custom_occurrences(id TEXT PRIMARY KEY,started REAL NOT NULL,outcome TEXT NOT NULL)')

    def record(self,state):
        if not self.pending:return
        pending=self.pending
        self.report={'state':state,'rule_id':pending['rule']['id'],'occurrence':pending['occurrence']}
        if 'repeat' in pending['rule']:
            self.report.update(until=pending['expires'],deferred_count=pending.get('deferred_count',0))
            if pending.get('resume'):self.report['next_prompt']=pending['resume']
        # Cancel/consume in memory before any fallible journal/queue write.
        # A busy disk must never turn a cancelled action into a late execution.
        terminal=state not in ('prompting','deferred','waiting_for_previous_notice')
        if terminal:self.pending=None
        with self.agent.db() as db:db.execute('UPDATE custom_occurrences SET outcome=? WHERE id=?',(state,pending['key']))
        if terminal:self.agent.queue('agent.custom_action',{**self.report,'action':pending['rule']['action']},'warning')

    def start_prompt(self):
        self.notice_threads=[t for t in self.notice_threads if t.is_alive()]
        if len(self.notice_threads)+len(self.pending['sessions'])>8:
            if 'repeat' in self.pending['rule']:
                pending=self.pending;pending['resume']=self.clock()+15;pending['deadline']=pending['resume']+pending['rule']['delay_seconds'];pending['mono_deadline']=self.monotonic()+15+pending['rule']['delay_seconds']
                self.record('waiting_for_previous_notice');return
            self.record('cancelled_prompt_busy');return
        pending=self.pending;pending['responses']={};pending['deadline']=self.clock()+pending['rule']['delay_seconds'];pending['mono_deadline']=self.monotonic()+pending['rule']['delay_seconds']
        responses=pending['responses']
        display_rule=copy.deepcopy(pending['rule'])
        if pending.get('deferred') and 'repeat' not in display_rule:display_rule['defer_minutes']=0
        def ask(session):
            try:answer=self.actions.prompt(session['id'],display_rule,pending['rule']['delay_seconds'])
            except (OSError,ValueError):answer='unavailable'
            responses[session['id']]=answer
        for session in pending['sessions']:
            thread=threading.Thread(target=ask,args=(session,),name='GuardDesk schedule notice',daemon=True)
            self.notice_threads.append(thread);thread.start()
        self.record('prompting')

    def tick(self,packet):
        now=self.clock();settings=packet['body']
        if self.pending:
            pending=self.pending
            if 'repeat' in pending['rule'] and now>=pending['expires']:
                self.record('repeat_window_ended');return
            if self.stop.is_set() or packet['busy'] or packet['fingerprint']!=pending['fingerprint'] or abs((pending['deadline']-now)-(pending['mono_deadline']-self.monotonic()))>60:
                self.record('cancelled_settings_or_busy');return
            responses=list(pending.get('responses',{}).values())
            if 'unavailable' in responses:self.record('cancelled_user_or_session');return
            if 'repeat' in pending['rule'] and any(r in ('cancel','defer') for r in responses):
                pending['resume']=now+pending['rule']['repeat']['interval_minutes']*60;pending['responses']={};pending['deferred_count']=pending.get('deferred_count',0)+1
                pending['deadline']=pending['resume']+pending['rule']['delay_seconds'];pending['mono_deadline']=self.monotonic()+pending['rule']['repeat']['interval_minutes']*60+pending['rule']['delay_seconds']
                self.record('deferred');return
            if 'cancel' in responses:self.record('cancelled_user_or_session');return
            if 'defer' in responses:
                if pending.get('deferred') or not pending['rule']['defer_minutes']:self.record('cancelled_user');return
                pending['deferred']=True;pending['resume']=now+pending['rule']['defer_minutes']*60;pending['responses']={}
                pending['deadline']=pending['resume']+pending['rule']['delay_seconds'];pending['mono_deadline']=self.monotonic()+pending['rule']['defer_minutes']*60+pending['rule']['delay_seconds']
                self.record('deferred');return
            if pending.get('resume'):
                if now<pending['resume']:return
                try:
                    if self.actions.sessions()!=pending['sessions']:self.record('cancelled_user_or_session');return
                except (OSError,ValueError):self.record('cancelled_user_or_session');return
                pending.pop('resume');self.start_prompt();return
            if now<pending['deadline']:return
            if len(pending['responses'])!=len(pending['sessions']):
                if now>pending['deadline']+15:self.record('cancelled_prompt_timeout')
                return
            try:
                current=self.actions.sessions()
                if current!=pending['sessions']:raise OSError('Session identity changed')
                if pending['rule']['idle_minutes'] and any(self.actions.idle_minutes(s['id'])<pending['rule']['idle_minutes'] for s in current):self.record('skipped_not_idle');return
                fresh=self.fetch()
                if fresh['fingerprint']!=pending['fingerprint'] or fresh['busy'] or self.stop.is_set():self.record('cancelled_settings_or_busy');return
                request={'fingerprint':pending['fingerprint'],'rule_id':pending['rule']['id'],'occurrence':pending['occurrence']}
                if fresh['protocol']==2:request['protocol']=2
                authorization=self.agent.call('/api/agent/custom-action/authorize',request)
                if authorization.get('action')!=pending['rule']['action']:raise ValueError('Action authorization mismatch')
                try:
                    if self.stop.is_set():self.record('cancelled_stopping');return
                    self.record('requested_windows')
                    self.actions.execute(authorization['action'],[s['id'] for s in current])
                    self.report={**self.report,'state':'windows_accepted_not_completion_attestation'}
                finally:
                    try:self.agent.call('/api/agent/custom-action/complete',{'token':authorization['token']})
                    except (OSError,ConnectionError,ValueError):pass
            except (OSError,ValueError,ConnectionError,sqlite3.Error):
                if self.pending:self.record('failed_precondition')
                else:self.report={**self.report,'state':'failed_windows_action'}
            return
        if self.stop.is_set() or packet['busy'] or self.actions.boot_age()<120:return
        for rule,occurrence in due_schedules(settings,now):
            key=rule['id']+'|'+occurrence
            with self.agent.db() as db:
                db.execute('DELETE FROM custom_occurrences WHERE started<?',(now-7*86400,))
                if db.execute('SELECT count(*) FROM custom_occurrences').fetchone()[0]>=2048:break
                created=db.execute('INSERT OR IGNORE INTO custom_occurrences VALUES (?,?,?)',(key,now,'claimed')).rowcount
            if not created:continue
            try:
                sessions=self.actions.sessions()
                if rule['idle_minutes'] and any(self.actions.idle_minutes(s['id'])<rule['idle_minutes'] for s in sessions):
                    with self.agent.db() as db:db.execute('UPDATE custom_occurrences SET outcome=? WHERE id=?',('skipped_not_idle',key))
                    self.report={'state':'skipped_not_idle','rule_id':rule['id']};continue
                self.pending={'key':key,'rule':copy.deepcopy(rule),'occurrence':occurrence,'sessions':sessions,'fingerprint':packet['fingerprint'],'expires':schedule_expiry(rule,now)}
                self.start_prompt();break
            except (OSError,ValueError):
                with self.agent.db() as db:db.execute('UPDATE custom_occurrences SET outcome=? WHERE id=?',('skipped_session_unavailable',key))
                self.report={'state':'skipped_session_unavailable','rule_id':rule['id']}

class CustomClient:
    def __init__(self,agent,stop,native=False):
        self.agent=agent;self.stop=stop;self.native=native;self.thread=None;self.local_stop=threading.Event();self.network=None;self.scheduler=None;self.next_fetch=0;self.next_report=0;self.last_report=None;self.last_contact=0;self.online=False
        self.effect_lock=threading.RLock()
        load_custom(agent)
        agent.feature_status.setdefault('custom_settings',{'state':'waiting_for_settings'})
        if native:
            from .custom_windows import trusted_native,WindowsActions
            root=trusted_native(agent.config)
            if agent.config_path!=root/'config.json':raise OSError('Custom native controls require the protected fixed configuration')
            from .update_native import protected_tree
            protected_tree(agent.config_path)
            directory=root/'CustomSettings';directory.mkdir(exist_ok=True);protected_tree(directory,recursive=False)
            from .custom_network import NetworkLease
            self.network=NetworkLease(directory/'network-lease.json')
            from types import SimpleNamespace
            signal=SimpleNamespace(is_set=lambda:self.stop.is_set() or self.local_stop.is_set())
            self.scheduler=ScheduleEngine(agent,WindowsActions(),self.fetch,signal)

    def fetch(self):
        packet=check_packet(self.agent,self.agent.call('/api/agent/custom-settings',{'protocol':2}))
        if getattr(self.agent,'custom_packet',None)!=packet:
            with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('custom_packet_v1',?)",(canonical(packet),))
        self.agent.custom_packet=packet
        return packet

    def close(self):
        self.local_stop.set()
        if not self.effect_lock.acquire(timeout=5):raise OSError('Custom action is still winding down; preserve installation and retry')
        self.effect_lock.release()
        if self.thread and self.thread is not threading.current_thread():self.thread.join(3)

    def start(self):
        self.thread=threading.Thread(target=self.run,name='GuardDesk custom settings',daemon=True);self.thread.start();return self

    def cycle(self):
        from .decommission import saved
        if saved(self.agent):self.local_stop.set();return
        now=time.monotonic();contact=False;packet=getattr(self.agent,'custom_packet',None)
        if now>=self.next_fetch:
            try:
                packet=self.fetch();contact=True;self.online=True;self.last_contact=now
            except (OSError,ConnectionError,ValueError,sqlite3.Error):self.online=False
            active=effective_body(self.agent)!=DEFAULT
            self.next_fetch=now+(30 if active else 60)
        online=self.online and now-self.last_contact<90
        report={'state':'reported' if online else 'offline','compatibility':sorted(compatibility_modules(effective_body(self.agent),build_number()))}
        if self.native:
            with self.effect_lock:
                if self.stop.is_set() or self.local_stop.is_set():return {'state':'stopped'}
                try:
                    # No registry access or writes on the default path.
                    mode=effective_body(self.agent)['network']['ipv6']
                    report['network']=self.network.apply(mode,contact and not packet.get('busy',True)) if mode!='unchanged' or self.network.path.exists() else {'state':'unchanged'}
                    if packet and packet.get('busy') and mode!='unchanged' and report['network']['state']=='unchanged':report['network']={'state':'pending_due_busy'}
                except (OSError,ValueError):report['network']={'state':'failed_or_conflict'}
                if online:
                    try:self.scheduler.tick(packet)
                    except (OSError,ValueError,sqlite3.Error):self.scheduler.report={'state':'failed_precondition'}
                elif self.scheduler.pending:self.scheduler.record('cancelled_offline')
                report['schedule']=self.scheduler.report
                report['software']=getattr(self.agent,'custom_software_status',{'state':'pending' if effective_body(self.agent)['software'] else 'disabled'})
        self.agent.feature_status['custom_settings']=report
        if online and (self.last_report!=report or now>=self.next_report):
            self.agent.call('/api/agent/custom-status',{'protocol':packet['protocol'],'role':'native' if self.native else 'main','version':__version__,'fingerprint':packet['fingerprint'],'report':report})
            self.next_report=now+60;self.last_report=copy.deepcopy(report)
        return report

    def run(self):
        while not self.stop.is_set() and not self.local_stop.is_set():
            try:self.cycle()
            except (OSError,ConnectionError,ValueError,sqlite3.Error):pass
            # Shutdown remains cooperative; no long WTS wait on this thread.
            for _ in range(15):
                if self.stop.is_set() or self.local_stop.wait(1):break
        self.local_stop.set()
