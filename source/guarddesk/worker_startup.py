"""Bounded startup milestones for the protected remote-only worker.

No exception text, command lines, account names, configuration or screen data.
This is evidence of a reached phase, never health or authorization proof.
"""
import math,os,re,time
from . import __version__

PHASES=frozenset({'construct_supervisor','start_supervisor','running','stopped'})

def snapshot(path,version,started):
    """Installer evidence only. No trace can make an installation healthy."""
    from .protected_files import read_json
    try:value=read_json(path,4096)
    except FileNotFoundError:return {'state':'missing'}
    except (OSError,ValueError):return {'state':'unreadable_or_invalid'}
    stamp=value.get('started')
    if value.get('version')!=version or type(stamp) not in (int,float) or not math.isfinite(stamp) or stamp<started:
        return {'state':'stale_or_other_version'}
    if value.get('phase') not in PHASES or value.get('state') not in ('entered','failed'):
        return {'state':'unreadable_or_invalid'}
    result={'state':value['state'],'phase':value['phase'],'started':stamp}
    pid=value.get('pid')
    if type(pid) is int and 0<pid<=0xffffffff:result['pid']=pid
    name=value.get('error_type')
    if isinstance(name,str) and re.fullmatch('[A-Za-z_]{1,64}',name):result['error_type']=name
    code=value.get('winerror')
    if type(code) is int and 0<=code<=0xffffffff:result['winerror']=code
    return result

class Trace:
    def __init__(self,root):
        self.path=root/'native-startup.json'
        self.started=time.time();self.phase='construct_supervisor'
    def record(self,phase,error=None):
        if phase not in PHASES:raise ValueError('Unknown native startup phase')
        self.phase=phase
        value={'format':1,'version':__version__,'pid':os.getpid(),'started':self.started,
               'time':time.time(),'phase':phase,'state':'failed' if error is not None else 'entered'}
        if error is not None:
            name=type(error).__name__
            value['error_type']=name if re.fullmatch('[A-Za-z_]{1,64}',name) else 'Exception'
            code=getattr(error,'winerror',None)
            if type(code) is int and 0<=code<=0xffffffff:value['winerror']=code
        try:
            from .update_client import save
            save(self.path,value)
            return True
        except (OSError,ValueError):
            # Evidence failure must not replace the original startup exception.
            return False
