"""Bounded outbound HTTPS notification; carries no executable commands/jobs."""
from collections import OrderedDict
import re
import secrets
import threading
import time


class Signals:
    def __init__(self,maximum=40,wait_seconds=10):
        self.condition=threading.Condition();self.slots=threading.BoundedSemaphore(maximum)
        self.epoch=secrets.token_hex(8);self.sequence=0;self.revisions=OrderedDict();self.listeners=set()
        self.wait_seconds=wait_seconds;self.stopped=False

    def cursor(self,did):return self.epoch+':'+str(self.revisions.get(did,0))

    def notify(self,ids):
        with self.condition:
            self.sequence+=1
            for did in ids:
                self.revisions[did]=self.sequence;self.revisions.move_to_end(did)
            while len(self.revisions)>1024:self.revisions.popitem(last=False)
            self.condition.notify_all()

    def connected(self,did,role):
        with self.condition:return (did,role) in self.listeners

    def wait(self,did,role,cursor):
        from .management import ManagementError
        if role not in ('native','main') or (cursor is not None and (not isinstance(cursor,str) or not re.fullmatch('[0-9a-f]{16}:[0-9]{1,16}',cursor))):
            raise ManagementError(400,'更新通知欄位不正確')
        if not self.slots.acquire(blocking=False):raise ManagementError(429,'通知連線已達上限，端點稍後重試')
        key=(did,role)
        try:
            with self.condition:
                if key in self.listeners:raise ManagementError(409,'此元件已有更新通知連線')
                self.listeners.add(key)
                try:
                    self.condition.wait_for(lambda:self.stopped or cursor!=self.cursor(did),timeout=self.wait_seconds)
                    return {'cursor':self.cursor(did),'changed':cursor!=self.cursor(did),'notification_protocol':1,'retry_after':5 if self.stopped else 0}
                finally:self.listeners.discard(key)
        finally:self.slots.release()

    def close(self):
        with self.condition:self.stopped=True;self.condition.notify_all()


class Waiter:
    """Legacy server fallback, bounded retry and no extra startup process."""
    def __init__(self,role):
        if role not in ('native','main'):raise ValueError('更新元件不正確')
        self.role=role;self.cursor=None;self.legacy_until=0

    def wait(self,agent,stop):
        if stop.is_set():return
        if time.monotonic()<self.legacy_until:stop.wait(30);return
        try:
            result=agent.call('/api/agent/updates/wait',{'role':self.role,'cursor':self.cursor},timeout=14)
            value=result.get('cursor')
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{16}:[0-9]{1,16}',value):raise ValueError('通知回應不正確')
            self.cursor=value
            if result.get('retry_after'):stop.wait(5)
        except (OSError,ConnectionError,ValueError) as exc:
            if 'HTTP 404' in str(exc):self.legacy_until=time.monotonic()+300;stop.wait(30)
            else:stop.wait(5)


def diagnostic(agent,role,code):
    # Fixed enums only; never upload exception text, private paths or key values.
    from . import __version__
    try:agent.call('/api/agent/updates/diagnostic',{'role':role,'version':__version__,'code':code})
    except (OSError,ConnectionError,ValueError):pass
