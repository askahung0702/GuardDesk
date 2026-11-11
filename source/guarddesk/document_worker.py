"""Protected bounded companion; ingestion/heartbeat never wait for tree work."""
import copy
import collections
import threading
import sqlite3
import time
from pathlib import Path
from .document_settings import check,covers


class DocumentWorker:
    def __init__(self,agent,directory):
        self.agent=agent;self.directory=Path(directory);self.stop_event=threading.Event();self.thread=None
        self.report={'status':'disabled'};self.trace=None;self.manager=None;self.next_retry=0;self.trace_signature=None;self.last_loss=0;self.policy_enabled=False;self.copy_report={'status':'disabled'}
        self.applied_fingerprint=None
        self.trusted=False
        self.next_sacl_retry=0
        self.read_report={'status':'waiting_retry'}
        from .file_access import Filter,OpenReducer
        from .document_context import Context
        self.context=Context();self.access_filter=Filter(self.context);self.open_reducer=OpenReducer();self.filtered_access={}
        self.pending_access=collections.OrderedDict()
        from .document_queue import CandidateQueue
        self.candidate_queue=CandidateQueue(agent)

    def start(self):
        self.thread=threading.Thread(target=self.run,name='GuardDesk document audit',daemon=True);self.thread.start();return self

    def close(self):
        self.stop_event.set()
        if self.thread:self.thread.join(8)
        if self.thread and self.thread.is_alive():raise OSError('Document audit is still stopping; preserve installation and retry')

    def rules(self):
        packet=getattr(self.agent,'custom_packet',None) or {}
        return check(packet['documents']) if 'documents' in packet else []

    def excluded(self,path):
        from .file_exclusions import excluded
        return excluded(path,self.policy['file_audit']['exclude_paths'],self.agent.audit_runtime)

    def emit(self,details,occurred):
        from .document_scope import permits
        watch=self.agent.config.get('audit_watch',str(self.agent.root))
        if not all(permits(details[k],self.policy['file_audit'],watch,self.agent.audit_runtime) for k in ('path','destination_path')):return
        self.candidate_queue.add(details,occurred)

    def emit_read(self,details,occurred):
        from .document_scope import permits
        if permits(details['path'],self.policy['file_audit'],self.agent.config.get('audit_watch',str(self.agent.root)),self.agent.audit_runtime):
            why=self.access_filter.check(details,self.policy['file_audit']['exclude_paths'],occurred)
            if why:
                if why in ('context_unavailable','foreground_not_observed'):
                    key=(details.get('process_id'),details.get('process_created'),details['path'],details.get('native_open_id'))
                    if key not in self.pending_access:
                        if len(self.pending_access)>=256:
                            self.filtered_access['context_pending_capacity']=self.filtered_access.get('context_pending_capacity',0)+1
                            self.candidate_queue.overflow+=1
                        else:self.pending_access[key]=(time.monotonic()+5,dict(details),occurred)
                    return
                self.filtered_access[why]=self.filtered_access.get(why,0)+1
                return
            if self.open_reducer.admit(details):self.candidate_queue.add(details,occurred,kind='file.opened')

    def drain_access(self):
        # Slow application startup may read before showing its document window.
        # Give an already observed input up to five seconds to acquire a
        # foreground association. New input after the I/O is never matched.
        deadline=time.monotonic()+.01
        for _ in range(min(32,len(self.pending_access))):
            key,(expires,details,occurred)=self.pending_access.popitem(last=False)
            why=self.access_filter.check(details,self.policy['file_audit']['exclude_paths'],occurred)
            if why is None:
                if self.open_reducer.admit(details):self.candidate_queue.add(details,occurred,kind='file.opened')
            elif time.monotonic()<expires and why in ('context_unavailable','foreground_not_observed'):
                self.pending_access[key]=(expires,details,occurred)
            else:self.filtered_access[why]=self.filtered_access.get(why,0)+1
            if time.monotonic()>=deadline:break

    def verify_installation(self):
        from .custom_windows import trusted_native
        from .update_native import protected_tree
        root=trusted_native(self.agent.config)
        if self.agent.config_path!=root/'config.json':raise OSError('Document auditing requires protected native configuration')
        protected_tree(self.agent.config_path)
        protected_tree(self.directory,recursive=False)
        for name in ('document-sacl.sqlite3','document-sacl.sqlite3-journal','document-sacl.sqlite3-wal','document-sacl.sqlite3-shm'):
            path=self.directory/name
            if path.exists():protected_tree(path)
        self.trusted=True

    def cycle(self):
        from .document_io import NativeTrace,CopyCorrelator,ReadObserver
        rules=self.rules();packet=getattr(self.agent,'custom_packet',None) or {}
        self.applied_fingerprint=None
        if not hasattr(self,'policy'):return
        rules=rules if self.policy['file_audit']['enabled'] else []
        scope_conflict=False
        if rules and self.policy['file_audit']['scope']=='managed':
            import ntpath
            watch=ntpath.normcase(ntpath.normpath(self.agent.config.get('audit_watch',str(self.agent.root))))
            if any(ntpath.normcase(ntpath.normpath(r['path']))!=watch and not covers(r['path'],{'path':watch,'recursive':True}) for r in rules):
                scope_conflict=True;rules=[]
        from .custom_settings import compatibility_modules
        import sys
        paused='security_file_events' in compatibility_modules(packet.get('body',{}),sys.getwindowsversion().build)
        general=self.policy['file_audit'];collect=general['enabled'] and not paused
        watch=self.agent.config.get('audit_watch',str(self.agent.root))
        signature=repr((general,watch,collect))
        # Revoke stale collection before any fallible ACL restoration or policy
        # query. A conflicting SACL must not keep an old ETW scope alive.
        if self.trace and (signature!=self.trace_signature or not collect):
            self.trace.stop();self.trace=None;self.correlator.gap();self.reader.gap()
            self.open_reducer.gap();self.context.close()
            self.pending_access.clear()
            self.next_retry=0
        if (collect or rules or (self.directory/'document-sacl.sqlite3').exists()) and not self.trusted:self.verify_installation()
        from .file_access import options
        if collect and options(general['exclude_paths'])['mode']=='interactive':self.context.poll()
        elif self.context.channels:self.context.close()
        if collect and not self.candidate_queue.initialized:self.candidate_queue.initialize()
        read_rules=[r for r in rules if r['read']]
        if read_rules or (self.directory/'document-sacl.sqlite3').exists():
            if not self.manager:
                from .document_sacl import Manager
                self.manager=Manager(self.directory,excluded=self.excluded)
            if packet.get('busy'):self.report={**self.report,'status':'paused_busy'}
            elif time.monotonic()>=self.next_sacl_retry:
                try:self.report=self.manager.tick(read_rules)
                except (OSError,ValueError,sqlite3.Error) as exc:
                    self.report={'status':'failed_or_conflict','error':str(exc)[:240]};self.next_sacl_retry=time.monotonic()+5
        else:self.report={'status':'disabled'}
        if collect and not self.trace and time.monotonic()>=self.next_retry and not packet.get('busy'):
            self.next_retry=time.monotonic()+60
            trace=NativeTrace()
            try:trace.start_policy(general,watch,self.agent.audit_runtime)
            except OSError:
                trace.stop();raise
            if not trace.active:raise OSError('No eligible local fixed volume for general file auditing')
            from .document_process import ProcessResolver
            self.trace=trace;self.trace_signature=signature;self.correlator=CopyCorrelator(self.emit);self.reader=ReadObserver(self.emit_read,resolver=ProcessResolver());self.last_loss=0
        if self.trace:
            events=[];drain_until=time.monotonic()+.015
            for _ in range(4):
                batch=self.trace.poll();events.extend(batch)
                if len(batch)<256 or time.monotonic()>=drain_until:break
            stats=self.trace.stats
            if stats['consumer_result']:
                self.correlator.gap();self.reader.gap();self.trace.stop();self.trace=None;self.next_retry=time.monotonic()+60
                self.open_reducer.gap()
                self.pending_access.clear()
                self.copy_report={'status':'trace_failed',**stats,'whole_file_copy_confirmed':False}
                self.read_report={'status':'trace_failed',**stats}
                return
            if stats['dropped']!=self.last_loss or stats['consumer_result']:
                self.correlator.gap();self.reader.gap()
                self.open_reducer.gap()
                self.pending_access.clear()
                if stats['dropped']!=self.last_loss:self.candidate_queue.trace_gap(stats['dropped']-self.last_loss)
                self.last_loss=stats['dropped']
                # A polled batch can straddle a kernel/ring gap. Do not join
                # pre-gap reads to post-gap writes or trust stale name mappings.
                events=[]
            for event in events:
                from .document_scope import permits
                if permits(event['path'],general,watch,self.agent.audit_runtime):
                    self.reader.feed(event);self.correlator.feed(event)
            self.reader.tick()
            self.drain_access()
            self.candidate_queue.overflow+=self.reader.pending_overflow;self.reader.pending_overflow=0
            self.copy_report={'status':'collecting_candidates','evidence':'completed_io_range_candidate','whole_file_copy_confirmed':False,**stats,'ambiguous_suppressed':self.correlator.ambiguous}
            self.read_report={'status':'collecting_native_reads','source':'general_file_policy','evidence':'completed_native_read_or_open',**stats,'read_observations':self.reader.read_observations,'open_observations':self.reader.open_observations,'sacl_required':False,'scope':general['scope'],'deduplication':'open_lifetime_and_input_generation','lifecycle_evictions':self.reader.lifecycle_evictions,'merged_logical_opens':self.open_reducer.merged,'interaction_context':self.context.status()}
            if stats.get('unsupported_volumes'):self.read_report['status']='collecting_native_reads_limited'
            from .file_access import options
            self.read_report.update(file_access_filter=options(general['exclude_paths']),filtered_access=dict(self.filtered_access),filter_minimum_version='0.4.54')
            self.read_report['pending_interaction']=len(self.pending_access)
            if options(general['exclude_paths'])['mode']=='interactive':
                context_status=self.read_report['interaction_context']
                if not context_status['fresh_samples'] or context_status['fresh_samples']<context_status.get('active_sessions',0):
                    self.read_report['status']='collecting_no_active_session' if context_status.get('session_query_available') and not context_status.get('active_sessions') else 'interaction_context_unavailable'
        else:
            state='compatibility_paused' if paused else 'waiting_retry' if collect else 'disabled'
            self.copy_report={'status':state,'whole_file_copy_confirmed':False};self.read_report={'status':state,'source':'general_file_policy'}
        admission=self.candidate_queue.flush()
        self.copy_report['outbox']=admission
        if self.trace and admission['status']=='backlog_full':self.copy_report['status']='backlog_full'
        if self.trace and admission['status']=='backlog_full':self.read_report['status']='backlog_full'
        self.read_report['outbox']=admission
        from .serialization import digest,canonical
        read_ready=self.report['status'] in ('disabled','restored') if not read_rules else self.report['status']=='monitoring_periodic'
        copy_ready=not any(r['copy'] for r in rules) or self.copy_report['status']=='collecting_candidates'
        if read_ready and copy_ready and not paused and not packet.get('busy') and not scope_conflict:self.applied_fingerprint=digest(canonical(rules))
        if scope_conflict:self.report={**self.report,'status':'policy_scope_conflict','error':'文件目錄超出原檔案策略的管理範圍；已停止複製追蹤並撤回自身 SACL，不自動擴大收集'}

    def run(self):
        # Threads do not inherit the creator's reduced priority. Apply it in
        # this companion itself, including its SQLite admission work.
        from .performance import background_work
        with background_work():self._run()

    def _run(self):
        try:
            while not self.stop_event.is_set():
                wait=.1 if self.trace else .25
                try:self.cycle()
                except (OSError,ValueError,sqlite3.Error,ConnectionError) as exc:
                    self.applied_fingerprint=None
                    self.report={**self.report,'status':'failed_or_conflict','error':str(exc)[:240]}
                    self.copy_report={**self.copy_report,'status':'collector_failed','error':str(exc)[:240]}
                    self.read_report={**self.read_report,'status':'collector_failed','error':str(exc)[:240]}
                    wait=5
                self.stop_event.wait(wait)
        finally:
            self.context.close()
            self.applied_fingerprint=None
            self.report={**self.report,'status':'stopped'};self.copy_report={**self.copy_report,'status':'stopped'};self.read_report={**self.read_report,'status':'stopped'}
            try:
                if self.trace:self.trace.stop()
            finally:
                try:
                    # At most four owned batches; preserve queued evidence when
                    # a scope is revoked or the companion exits normally.
                    for _ in range(4):
                        if not self.candidate_queue.buffer and not self.candidate_queue.overflow and not self.candidate_queue.trace_loss:break
                        self.candidate_queue.flush()
                finally:
                    if self.manager:self.manager.close()

    def status(self):
        return {'provisioning':copy.deepcopy(self.report),'read':copy.deepcopy(self.read_report),'copy':copy.deepcopy(self.copy_report),'fingerprint':self.applied_fingerprint,'applied':self.applied_fingerprint is not None}

    def restore(self,timeout=120):
        self.close()
        if not (self.directory/'document-sacl.sqlite3').exists():return {'status':'not_managed'}
        self.verify_installation()
        from .document_sacl import Manager
        manager=Manager(self.directory);deadline=time.monotonic()+timeout
        try:
            while time.monotonic()<deadline:
                result=manager.tick([])
                if result['status']=='restored':return result
                if result['status']=='restore_conflict':raise OSError('Document SACL restore conflict; preserve protected journal')
            raise OSError('Document SACL restore still pending; preserve journal and retry removal')
        finally:manager.close()
