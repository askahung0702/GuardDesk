"""Bounded completed-write bursts, not Save-button or disk-durability evidence."""
import collections
import ntpath
import time

QUIET_SECONDS=2
MAX_SECONDS=10
MAX_PENDING=256
_NTFS_METADATA = frozenset({
    '$mft', '$mftmirr', '$logfile', '$volume', '$attrdef', '$bitmap',
    '$boot', '$badclus', '$secure', '$upcase', '$extend',
})


def reserved_volume_metadata(path):
    """Recognize exact NTFS names at the volume root, including their streams."""
    drive, tail = ntpath.splitdrive(ntpath.normpath(path))
    if len(drive) != 2 or drive[1] != ':' or not tail.startswith('\\'):
        return False
    root_component = tail[1:].partition('\\')[0].partition(':')[0]
    return root_component.casefold() in _NTFS_METADATA


def file_type_evidence(event):
    path=event['path']
    _,tail=ntpath.splitdrive(path)
    if path.endswith(('\\','/')) or event.get('object_type')=='directory':return None
    if event.get('non_directory_confirmed') is True and ':' not in tail:
        return 'native_non_directory_option'
    from .hidden_files import resolver
    if resolver().file_type(path)=='file':return 'post_event_attributes'
    return None


def confirmed_write_process(details):
    pid=details.get('process_id')
    image=details.get('process')
    return (type(pid) is int and 4<pid<2**32
            and details.get('process_identity_status')=='creation_time_checked'
            and isinstance(image,str) and bool(image.strip()))


def excluded_unconfirmed_write(kind,severity,details):
    return (kind=='file.written' and severity=='info'
            and (not isinstance(details,dict) or not confirmed_write_process(details)))


class WriteObserver:
    def __init__(self,emit,*,admit=None,resolver=None,overflow=None,clock=time.monotonic):
        self.emit=emit;self.admit=admit;self.resolver=resolver;self.overflow=overflow;self.clock=clock
        self.pending=collections.OrderedDict()
        self.observed=0;self.filtered=0;self.capacity_lost=0;self.unreported=0
        self.type_unconfirmed=0
        self.next_loss_report=self.clock()+60

    def feed(self,event):
        op=event.get('op')
        if op not in ('write','set_end_of_file','overwrite') or type(event.get('status')) is not int or event['status']!=0:return
        if type(event.get('pid')) is not int or not 4<event['pid']<2**32 or type(event.get('open_id')) is not int or event['open_id']<=0:return
        if op=='write' and (type(event.get('bytes')) is not int or not 0<event['bytes']<=2**32):return
        if op=='set_end_of_file' and (type(event.get('file_size')) is not int or not 0<=event['file_size']<2**63):return
        if not isinstance(event.get('path'),str) or not ntpath.isabs(event['path']) or reserved_volume_metadata(event['path']):return
        if event.get('object_type')=='directory':return
        now=self.clock();key=(event['pid'],event['open_id'],ntpath.normcase(event['path']))
        entry=self.pending.get(key)
        if entry and (now-entry['last']>=QUIET_SECONDS or now-entry['first']>=MAX_SECONDS):
            self.tick();entry=self.pending.get(key)
        if entry is None:
            evidence=file_type_evidence(event)
            if not evidence:
                self.type_unconfirmed+=1
                return
            process=self.resolver.resolve(event) if self.resolver else {}
            details={**process,'process_id':event['pid']}
            if not confirmed_write_process(details):self.filtered+=1;return
            if len(self.pending)>=MAX_PENDING:
                oldest=next(iter(self.pending.values()))
                if now-oldest['last']>=QUIET_SECONDS or now-oldest['first']>=MAX_SECONDS:self.tick()
            if len(self.pending)>=MAX_PENDING:
                self.capacity_lost+=1;self.unreported+=1;return
            details.update(path=event['path'],thread_id=event.get('tid'),native_open_id=event['open_id'],
                           source='windows_etw_file_io',evidence='completed_native_file_mutation',
                           object_type='file',object_type_evidence=evidence,user=None,
                           human_save_confirmed=False,disk_flush_confirmed=False,
                           written_bytes=0,observed_write_ranges=0,size_updates=0,overwrite_opens=0)
            occurred=event.get('occurred',time.time())
            if self.admit and not self.admit(details,occurred):self.filtered+=1;return
            # Do not persist the reducer's internal session key.
            details.pop('_interaction_key',None)
            entry={'details':details,'first':now,'last':now,'occurred':occurred}
            self.pending[key]=entry
            details['first_write_observed']=occurred
        entry['last']=now;entry['occurred']=event.get('occurred',time.time())
        if op=='write':
            entry['details']['written_bytes']+=event['bytes']
            entry['details']['observed_write_ranges']+=1
        elif op=='set_end_of_file':
            entry['details']['size_updates']+=1
            entry['details']['file_size_after']=event['file_size']
        else:entry['details']['overwrite_opens']+=1

    def tick(self,*,force=False,interrupted=False):
        now=self.clock()
        for key,entry in list(self.pending.items()):
            if not force and now-entry['last']<QUIET_SECONDS and now-entry['first']<MAX_SECONDS:continue
            del self.pending[key]
            details=entry['details']
            details.update(last_write_observed=entry['occurred'],
                           aggregation='completed_write_burst',
                           aggregation_end='collector_interrupted' if interrupted else 'collector_stopping' if force else 'quiet_window' if now-entry['last']>=QUIET_SECONDS else 'maximum_window',
                           collection_interrupted=interrupted)
            self.emit(details,entry['occurred']);self.observed+=1
        # Coalesce capacity loss into a gap counter once per minute;
        # generating a warning for every suppressed I/O would create more noise.
        if self.unreported and (force or now>=self.next_loss_report):
            if self.overflow:self.overflow(self.unreported)
            self.unreported=0
            self.next_loss_report=now+60

    def gap(self):self.tick(force=True,interrupted=True)

    def status(self):
        return {'pending_write_bursts':len(self.pending),'write_activities':self.observed,
                'filtered_write_observations':self.filtered,'write_capacity_lost':self.capacity_lost,
                'write_without_file_type_evidence':self.type_unconfirmed,
                'write_loss_unreported':self.unreported,
                'write_activity_limit_per_minute':None,'write_collection':'all_file_types_in_scope'}
